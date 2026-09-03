//! The signed Warren account API client.

use rand::RngCore;
use serde::Serialize;
use serde::de::DeserializeOwned;
use warren_identity::WarrenIdentity;

use crate::dto::{
    CampaignVoucherResponse, CheckApplePaymentRequest, CheckResponse, IncidentExitDownRequest,
    IncidentPubkeyMismatchRequest, InitApplePaymentResponse, MobilePaymentResponse,
    RegisterAccountRequest, RegisterAccountResponse, SessionCloseRequest, SessionOpenRequest,
    SessionOpenResponse, SubscriptionResponse, TokenIssueRequest, TokenIssueResponse,
    TokenIssuerDirectory,
};
use crate::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};

/// Error from an API call.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The request failed at the network layer.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The server returned a non-2xx status.
    ///
    /// `Display` renders only the status code: the body is kept for programmatic
    /// inspection but is NOT in the message. No-log discipline: a server error
    /// body may echo identity material (IP, pubkey), so callers must not log the
    /// `body` field (or the struct via `{:?}`) in clear.
    #[error("server returned status {status}")]
    ServerStatus {
        /// HTTP status code.
        status: u16,
        /// Response body (may carry a server error message). See the no-log
        /// caveat on this variant: do not log it.
        body: String,
    },
    /// The response body was not valid UTF-8.
    #[error("response body is not valid UTF-8")]
    ResponseEncoding(#[source] std::string::FromUtf8Error),
    /// The response JSON did not match the expected type.
    #[error("failed to parse response JSON")]
    ResponseJson(#[source] serde_json::Error),
    /// The request body could not be serialized.
    #[error("failed to serialize request")]
    RequestSerialize(#[source] serde_json::Error),
    /// Every host in the fallback sequence (primary, alternatives, no-SNI)
    /// failed to connect: the API is likely being blocked.
    #[error("all API hosts are unreachable (possible censorship)")]
    AllHostsBlocked,
    /// The system clock is before the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    BadClock,
}

/// Signed HTTP client for the Warren account API.
///
/// Generic over an [`HttpTransport`] so the request logic is testable without a
/// network. The SDK facade pairs it with the bundled reqwest transport.
pub struct WarrenApiClient<T> {
    api_base: String,
    /// Alternative hostnames tried, in order, when the primary host fails to
    /// connect (anti-censorship). Bare DNS names; only the host is swapped.
    alternative_hosts: Vec<String>,
    identity: WarrenIdentity,
    transport: T,
}

impl<T: HttpTransport> WarrenApiClient<T> {
    /// Builds a client. `api_base` must not end with `/`
    /// (e.g. `https://api.warrenbrowse.com`).
    pub fn new(api_base: impl Into<String>, identity: WarrenIdentity, transport: T) -> Self {
        Self::new_with_fallback(api_base, Vec::new(), identity, transport)
    }

    /// Builds a client with anti-censorship host fallback. When the primary host
    /// fails to connect, the request is retried against each of
    /// `alternative_hosts` in order (with SNI), then against the primary host
    /// without SNI. A connected response (any status) stops the sequence.
    pub fn new_with_fallback(
        api_base: impl Into<String>,
        alternative_hosts: Vec<String>,
        identity: WarrenIdentity,
        transport: T,
    ) -> Self {
        Self {
            api_base: api_base.into(),
            alternative_hosts,
            identity,
            transport,
        }
    }

    /// The Warren SS58 address of the client identity.
    #[must_use]
    pub fn address(&self) -> String {
        self.identity.address()
    }

    /// The underlying transport (e.g. to inspect a test double, or reuse a
    /// configured HTTP stack).
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Unsigned `GET /v1/exits`. Returns the raw server-signed relay list JSON
    /// (verify it with `warren_discovery::verify_signed_relay_list`).
    ///
    /// # Errors
    ///
    /// [`ClientError`] on transport failure or a non-2xx status.
    pub async fn list_exits(&self) -> Result<String, ClientError> {
        let req = self.unsigned_request(Method::Get, "/v1/exits", Vec::new());
        let resp = self.send(req).await?;
        String::from_utf8(resp.body).map_err(ClientError::ResponseEncoding)
    }

    /// Public `GET /v1/multihop/directory`. Returns the raw signed multihop
    /// directory JSON, or `None` on `404` (none published). Unsigned: the body
    /// is itself signed and the caller verifies the full trust chain with
    /// `warren_discovery::verify_multihop_directory`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on transport failure or a non-200/404 status.
    pub async fn fetch_multihop_directory(&self) -> Result<Option<String>, ClientError> {
        let req = self.unsigned_request(Method::Get, "/v1/multihop/directory", Vec::new());
        match self.send(req).await {
            Ok(resp) => String::from_utf8(resp.body)
                .map(Some)
                .map_err(ClientError::ResponseEncoding),
            Err(ClientError::ServerStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Public `GET /v1/multihop/path-quality`. Returns the raw UNSIGNED
    /// path-quality advisory JSON, or `None` on `404` (an older API without
    /// the endpoint, or no advisory yet). Advisory-only data: the caller
    /// parses it with `warren_discovery::PathQualityAdvisory` and treats any
    /// failure as "no advisory".
    ///
    /// # Errors
    ///
    /// [`ClientError`] on transport failure or a non-200/404 status.
    pub async fn fetch_path_quality(&self) -> Result<Option<String>, ClientError> {
        let req = self.unsigned_request(Method::Get, "/v1/multihop/path-quality", Vec::new());
        match self.send(req).await {
            Ok(resp) => String::from_utf8(resp.body)
                .map(Some)
                .map_err(ClientError::ResponseEncoding),
            Err(ClientError::ServerStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Unsigned `POST /v1/register`. Redeems a voucher to bind a subscription to
    /// the account pubkey.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on transport failure, a non-2xx status, or a malformed
    /// response.
    pub async fn register(
        &self,
        req: &RegisterAccountRequest,
    ) -> Result<RegisterAccountResponse, ClientError> {
        let body = serialize(req)?;
        let http = self.unsigned_request(Method::Post, "/v1/register", body);
        self.send_json(http).await
    }

    /// Signed `GET /v1/subscription`.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn subscription(&self) -> Result<SubscriptionResponse, ClientError> {
        let http = self.signed_request(Method::Get, "/v1/subscription", Vec::new())?;
        self.send_json(http).await
    }

    /// Signed `GET /v1/campaign/{campaign_id}/voucher`. Returns the code this
    /// account was pre-assigned when the campaign was published, or `None` on
    /// `404` (outside the cohort, or an unknown campaign).
    ///
    /// The offer itself rides a broadcast document that is byte-identical for
    /// every caller, which is what keeps the server from learning who asks
    /// about what; a per-account value cannot ride that document, so it comes
    /// from here, behind the same wallet signature that guards
    /// `/v1/subscription`. The call is a pure lookup server-side, so repeating
    /// it is always safe and can never drain the pool.
    ///
    /// The returned code is a bearer token worth a month of service: it belongs
    /// in the account's own UI and nowhere else, never in a log, an error or a
    /// problem report.
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. A `503` surfaces as
    /// [`ClientError::ServerStatus`] rather than as `None`, so a transient
    /// backend failure never reads as "you were never eligible".
    pub async fn campaign_voucher(&self, campaign_id: &str) -> Result<Option<String>, ClientError> {
        let path = format!("/v1/campaign/{campaign_id}/voucher");
        let http = self.signed_request(Method::Get, &path, Vec::new())?;
        match self.send(http).await {
            Ok(resp) => {
                let parsed: CampaignVoucherResponse =
                    serde_json::from_slice(&resp.body).map_err(ClientError::ResponseJson)?;
                Ok(Some(parsed.code))
            }
            Err(ClientError::ServerStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Signed `GET /v1/check`. Reports the client's egress IP and whether it is
    /// an exit (useful to confirm the tunnel is active).
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn check(&self) -> Result<CheckResponse, ClientError> {
        let http = self.signed_request(Method::Get, "/v1/check", Vec::new())?;
        self.send_json(http).await
    }

    /// Signed `POST /v1/session/open`.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn open_session(
        &self,
        req: &SessionOpenRequest,
    ) -> Result<SessionOpenResponse, ClientError> {
        let body = serialize(req)?;
        let http = self.signed_request(Method::Post, "/v1/session/open", body)?;
        self.send_json(http).await
    }

    /// Signed `POST /v1/session/close`.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn close_session(&self, req: &SessionCloseRequest) -> Result<(), ClientError> {
        let body = serialize(req)?;
        let http = self.signed_request(Method::Post, "/v1/session/close", body)?;
        self.send(http).await.map(|_| ())
    }

    /// Unsigned `GET /v1/tokens/keys`. The public, self-describing issuer
    /// directory for anonymous session tokens (Privacy Pass): epoch keys plus
    /// the policy (epoch length, batch quota, challenge context label) a
    /// client needs to mint. Unsigned on purpose: fetching keys must not link
    /// the wallet to a timing pattern.
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. A `503` status surfaces as
    /// [`ClientError::ServerStatus`] when issuance is not configured
    /// server-side.
    pub async fn token_keys(&self) -> Result<TokenIssuerDirectory, ClientError> {
        self.token_keys_for(crate::tokens::CredentialClass::Session)
            .await
    }

    /// [`Self::token_keys`] for any credential class. Each class holds its own
    /// per-epoch issuer keys, so a client that blinds against the wrong
    /// directory mints credentials the server refuses.
    ///
    /// # Errors
    ///
    /// See [`Self::token_keys`].
    pub async fn token_keys_for(
        &self,
        class: crate::tokens::CredentialClass,
    ) -> Result<TokenIssuerDirectory, ClientError> {
        let http = self.unsigned_request(Method::Get, class.keys_path(), Vec::new());
        self.send_json(http).await
    }

    /// Signed `POST /v1/tokens/issue`. Submits blinded token requests for the
    /// listed epochs; the issuer enforces subscription coverage and the
    /// once-per-account-epoch quota, and returns blind signatures. This is the
    /// only token step that names the wallet; the finalized tokens are
    /// unlinkable to it.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn issue_tokens(
        &self,
        req: &TokenIssueRequest,
    ) -> Result<TokenIssueResponse, ClientError> {
        self.issue_tokens_for(crate::tokens::CredentialClass::Session, req)
            .await
    }

    /// [`Self::issue_tokens`] for any credential class.
    ///
    /// # Errors
    ///
    /// See [`Self::issue_tokens`].
    pub async fn issue_tokens_for(
        &self,
        class: crate::tokens::CredentialClass,
        req: &TokenIssueRequest,
    ) -> Result<TokenIssueResponse, ClientError> {
        let body = serialize(req)?;
        let http = self.signed_request(Method::Post, class.issue_path(), body)?;
        self.send_json(http).await
    }

    /// Signed `DELETE /v1/account`. Deletes the account's subscription.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn delete_account(&self) -> Result<(), ClientError> {
        let http = self.signed_request(Method::Delete, "/v1/account", Vec::new())?;
        self.send(http).await.map(|_| ())
    }

    /// Signed `POST /v1/payments/apple/init`. Opens an Apple IAP session bound
    /// to the signing pubkey and returns the `app_account_token` to hand to
    /// StoreKit. Empty request body.
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. A `503` status surfaces as
    /// [`ClientError::ServerStatus`] when Apple payments are not configured.
    pub async fn init_apple_payment(&self) -> Result<InitApplePaymentResponse, ClientError> {
        let http = self.signed_request(Method::Post, "/v1/payments/apple/init", Vec::new())?;
        self.send_json(http).await
    }

    /// Signed `POST /v1/payments/apple/check`. Uploads the StoreKit 2 signed
    /// transaction JWS; on success the subscription is credited and the new
    /// expiry returned.
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. Notable statuses surface as
    /// [`ClientError::ServerStatus`]: `400` invalid transaction, `404` session
    /// not found, `403` identity mismatch, `422` unknown product.
    pub async fn check_apple_payment(
        &self,
        jws_transaction: &str,
    ) -> Result<MobilePaymentResponse, ClientError> {
        let req = CheckApplePaymentRequest {
            jws_transaction: jws_transaction.to_owned(),
        };
        let body = serialize(&req)?;
        let http = self.signed_request(Method::Post, "/v1/payments/apple/check", body)?;
        self.send_json(http).await
    }

    /// Unsigned `GET /v1/checkout/{pending_id}/voucher`. Polls for a voucher
    /// minted by a web checkout (Lightning, Monero, card). Returns the voucher
    /// secret once it lands, or `None` on `404` (not landed yet, already
    /// pulled, or expired); the caller keeps polling within its own deadline.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on transport failure or any non-200/404 status.
    pub async fn pull_pending_voucher(
        &self,
        pending_id: &str,
    ) -> Result<Option<String>, ClientError> {
        let path = format!("/v1/checkout/{pending_id}/voucher");
        let req = self.unsigned_request(Method::Get, &path, Vec::new());
        match self.send(req).await {
            Ok(resp) => {
                let parsed: PullVoucherResponse =
                    serde_json::from_slice(&resp.body).map_err(ClientError::ResponseJson)?;
                Ok(Some(parsed.voucher_secret))
            }
            Err(ClientError::ServerStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Signed `POST /v1/incidents/exit-down`. Best-effort failover telemetry;
    /// the server replies 204 No Content.
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. `400` malformed body and `422` unknown
    /// `reason_code` surface as [`ClientError::ServerStatus`].
    pub async fn report_exit_down(&self, req: &IncidentExitDownRequest) -> Result<(), ClientError> {
        let body = serialize(req)?;
        let http = self.signed_request(Method::Post, "/v1/incidents/exit-down", body)?;
        self.send(http).await.map(|_| ())
    }

    /// Signed `POST /v1/incidents/pubkey-mismatch`. Reports a pinned-pubkey
    /// divergence under a known `exit_id`; the server replies 204 (log-only).
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. `400` malformed body surfaces as
    /// [`ClientError::ServerStatus`].
    pub async fn report_pubkey_mismatch(
        &self,
        req: &IncidentPubkeyMismatchRequest,
    ) -> Result<(), ClientError> {
        let body = serialize(req)?;
        let http = self.signed_request(Method::Post, "/v1/incidents/pubkey-mismatch", body)?;
        self.send(http).await.map(|_| ())
    }

    /// Builds an unsigned request (carries only `accept`/`content-type` plus
    /// the product UA).
    fn unsigned_request(&self, method: Method, path: &str, body: Vec<u8>) -> HttpRequest {
        let mut headers = vec![
            ("accept".to_owned(), "application/json".to_owned()),
            // Set in the transport-agnostic builder (not per HTTP backend) so
            // every transport sends the one product token.
            (
                "user-agent".to_owned(),
                warren_contract::product::USER_AGENT.to_owned(),
            ),
        ];
        if !body.is_empty() {
            headers.push(("content-type".to_owned(), "application/json".to_owned()));
        }
        HttpRequest {
            method,
            url: format!("{}{path}", self.api_base),
            headers,
            body,
            use_sni: true,
        }
    }

    /// Builds a signed request, attaching the four `X-Warren-*` headers.
    ///
    /// The path (including any query string) is part of the signed canonical
    /// message, so callers must pass the exact path they send.
    fn signed_request(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<HttpRequest, ClientError> {
        let timestamp = now_secs()?;
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let sig = self
            .identity
            .sign_request(method.as_str(), path, &body, timestamp, nonce);

        let mut headers: Vec<(String, String)> = sig
            .headers()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        headers.push(("accept".to_owned(), "application/json".to_owned()));
        headers.push((
            "user-agent".to_owned(),
            warren_contract::product::USER_AGENT.to_owned(),
        ));
        if !body.is_empty() {
            headers.push(("content-type".to_owned(), "application/json".to_owned()));
        }
        Ok(HttpRequest {
            method,
            url: format!("{}{path}", self.api_base),
            headers,
            body,
            use_sni: true,
        })
    }

    /// Sends a request through the anti-censorship fallback sequence: the
    /// primary host with SNI, then each alternative host with SNI, then the
    /// primary host without SNI. Only connect failures advance the sequence; a
    /// connected response (any status) or a non-connect transport error stops
    /// it. Returns [`ClientError::AllHostsBlocked`] if every attempt fails to
    /// connect.
    ///
    /// The candidate order is the canonical sequence single-homed in
    /// [`warren_contract::fallback::fallback_candidates`], so the SDK, the TS
    /// SDK and warren-core cannot drift (an alt host is only ever tried with
    /// SNI; only the primary is retried without it).
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        let primary_url = request.url.clone();
        let primary_host = host_of(&primary_url);

        for candidate in
            warren_contract::fallback::fallback_candidates(primary_host, &self.alternative_hosts)
        {
            let attempt = HttpRequest {
                url: replace_host(&primary_url, &candidate.host),
                use_sni: candidate.sni,
                ..request.clone()
            };
            match self.attempt(&attempt).await? {
                AttemptOutcome::Response(resp) => return self.finish(resp),
                AttemptOutcome::Blocked => {}
            }
        }

        Err(ClientError::AllHostsBlocked)
    }

    /// Runs one attempt. A connect failure becomes `Blocked` (advance the
    /// sequence); any other transport error propagates immediately.
    async fn attempt(&self, request: &HttpRequest) -> Result<AttemptOutcome, ClientError> {
        match self.transport.execute(request.clone()).await {
            Ok(resp) => Ok(AttemptOutcome::Response(resp)),
            Err(e) if e.is_connect() => Ok(AttemptOutcome::Blocked),
            Err(e) => Err(e.into()),
        }
    }

    /// Maps a connected response to success or a server-status error.
    fn finish(&self, resp: HttpResponse) -> Result<HttpResponse, ClientError> {
        if !(200..300).contains(&resp.status) {
            return Err(ClientError::ServerStatus {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).into_owned(),
            });
        }
        Ok(resp)
    }

    async fn send_json<R: DeserializeOwned>(&self, request: HttpRequest) -> Result<R, ClientError> {
        let resp = self.send(request).await?;
        serde_json::from_slice(&resp.body).map_err(ClientError::ResponseJson)
    }
}

/// Outcome of a single host attempt in the fallback sequence.
enum AttemptOutcome {
    /// The host answered (any HTTP status); stop the fallback.
    Response(HttpResponse),
    /// The host failed to connect; advance to the next host.
    Blocked,
}

/// Extracts the bare DNS host from an `http(s)://host[:port]/path` URL (no
/// scheme, no port, no path), the `primary_host` input the canonical fallback
/// sequence keys on. Returns the whole input if it has no `://` authority.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// Swaps the host of an `http(s)://host[:port]/path` URL, preserving scheme,
/// port and path. `new_host` is a bare DNS name. Returns the input unchanged if
/// it has no `://` authority.
fn replace_host(url: &str, new_host: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Preserve a numeric port if present (DNS-name authority, not an IPv6
    // literal: API hosts are always names).
    match authority.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            format!("{scheme}://{new_host}:{port}{path}")
        }
        _ => format!("{scheme}://{new_host}{path}"),
    }
}

/// Internal body of `GET /v1/checkout/{id}/voucher`. Only the secret is
/// surfaced to the caller as a bare `String`.
#[derive(serde::Deserialize)]
struct PullVoucherResponse {
    voucher_secret: String,
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, ClientError> {
    serde_json::to_vec(value).map_err(ClientError::RequestSerialize)
}

fn now_secs() -> Result<u64, ClientError> {
    unix_secs_from(std::time::SystemTime::now())
}

/// Seconds since the Unix epoch for `t`, or [`ClientError::BadClock`] if `t`
/// precedes the epoch. Split out so the bad-clock branch is testable without
/// waiting for a real clock to misbehave.
fn unix_secs_from(t: std::time::SystemTime) -> Result<u64, ClientError> {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ClientError::BadClock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use warren_contract::dto::{PubkeyHex, PubkeySs58};

    fn a_ss58() -> PubkeySs58 {
        PubkeySs58::try_from(warren_contract::ss58::encode(&[0xAA; 32])).unwrap()
    }
    fn a_pubkey_hex() -> PubkeyHex {
        PubkeyHex::try_from("ab".repeat(32)).unwrap()
    }
    use warren_identity::{HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};

    /// A transport that records the last request and returns a canned response.
    struct MockTransport {
        last: Mutex<Option<HttpRequest>>,
        status: u16,
        body: Vec<u8>,
    }

    impl MockTransport {
        fn new(status: u16, body: &str) -> Self {
            Self {
                last: Mutex::new(None),
                status,
                body: body.as_bytes().to_vec(),
            }
        }
    }

    impl HttpTransport for MockTransport {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
            *self.last.lock().unwrap() = Some(request);
            Ok(HttpResponse {
                status: self.status,
                body: self.body.clone(),
            })
        }
    }

    fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn client(t: MockTransport) -> WarrenApiClient<MockTransport> {
        WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x11; 32]),
            t,
        )
    }

    #[tokio::test]
    async fn subscription_parses_body() {
        let c = client(MockTransport::new(200, r#"{"expires_at":1700000000}"#));
        let sub = c.subscription().await.expect("ok");
        assert_eq!(sub.expires_at, 1_700_000_000);
    }

    #[tokio::test]
    async fn malformed_json_body_maps_to_response_json() {
        // A 200 with a non-JSON body is a response-parse failure at the trust
        // boundary, not a transport error.
        let c = client(MockTransport::new(200, "{ this is not json"));
        assert!(matches!(
            c.subscription().await.unwrap_err(),
            ClientError::ResponseJson(_)
        ));
    }

    #[tokio::test]
    async fn non_utf8_body_maps_to_response_encoding() {
        // list_exits returns the raw body as a String; invalid UTF-8 must surface
        // as ResponseEncoding rather than panicking or lossy-decoding.
        let t = MockTransport {
            last: Mutex::new(None),
            status: 200,
            body: vec![0xff, 0xfe, 0x00],
        };
        assert!(matches!(
            client(t).list_exits().await.unwrap_err(),
            ClientError::ResponseEncoding(_)
        ));
    }

    #[tokio::test]
    async fn signed_request_carries_valid_signature() {
        use ed25519_dalek::{Signature, Verifier};
        use warren_identity::canonical_message;

        let c = client(MockTransport::new(200, r#"{"expires_at":1}"#));
        c.subscription().await.expect("ok");

        let guard = c.transport.last.lock().unwrap();
        let req = guard.as_ref().expect("request captured");
        assert_eq!(req.url, "https://api.example.test/v1/subscription");
        assert_eq!(req.method, Method::Get);

        // Reconstruct the canonical message from the headers and verify the
        // signature against the client identity. This proves the wire contract
        // without freezing the clock or the nonce.
        let pubkey_ss58 = header(req, HEADER_PUBKEY).expect("pubkey header");
        let sig_hex = header(req, HEADER_SIGNATURE).expect("sig header");
        let ts: u64 = header(req, HEADER_TIMESTAMP).unwrap().parse().unwrap();
        let nonce_hex = header(req, HEADER_NONCE).unwrap();

        let id = WarrenIdentity::from_seed(&[0x11; 32]);
        assert_eq!(pubkey_ss58, id.address());
        let body_hash_hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&req.body));
        let canonical = canonical_message("GET", "/v1/subscription", ts, nonce_hex, &body_hash_hex);
        let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();
        id.verifying_key()
            .verify(canonical.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .expect("signature must verify");
        drop(guard);
    }

    #[tokio::test]
    async fn every_request_carries_the_product_user_agent() {
        // The one product UA anchor, on the signed and unsigned paths alike:
        // the API must see the same token from every Warren client (an SDK
        // that sends none is the odd one out the server can fingerprint).
        let c = client(MockTransport::new(200, r#"{"expires_at":1}"#));
        c.subscription().await.expect("ok");
        {
            let guard = c.transport.last.lock().unwrap();
            let req = guard.as_ref().expect("request captured");
            assert_eq!(
                header(req, "user-agent"),
                Some(warren_contract::product::USER_AGENT),
                "signed requests must carry the product UA"
            );
        }
        c.list_exits().await.expect("ok");
        let guard = c.transport.last.lock().unwrap();
        let req = guard.as_ref().expect("request captured");
        assert_eq!(
            header(req, "user-agent"),
            Some(warren_contract::product::USER_AGENT),
            "unsigned requests must carry the product UA"
        );
    }

    #[tokio::test]
    async fn non_2xx_is_server_status_error() {
        let c = client(MockTransport::new(402, "payment required"));
        let err = c.subscription().await.expect_err("must error");
        assert!(matches!(err, ClientError::ServerStatus { status: 402, .. }));
    }

    #[tokio::test]
    async fn list_exits_is_unsigned_and_returns_raw_body() {
        let c = client(MockTransport::new(200, "{\"signed\":true}"));
        let body = c.list_exits().await.expect("ok");
        assert_eq!(body, "{\"signed\":true}");
        let guard = c.transport.last.lock().unwrap();
        let req = guard.as_ref().unwrap();
        assert!(
            header(req, HEADER_PUBKEY).is_none(),
            "list_exits must be unsigned"
        );
    }

    #[tokio::test]
    async fn multihop_directory_returns_body_on_200_and_is_unsigned() {
        let c = client(MockTransport::new(200, "{\"directory\":true}"));
        let body = c.fetch_multihop_directory().await.expect("ok");
        assert_eq!(body.as_deref(), Some("{\"directory\":true}"));
        let guard = c.transport.last.lock().unwrap();
        let req = guard.as_ref().unwrap();
        assert!(
            header(req, HEADER_PUBKEY).is_none(),
            "fetch_multihop_directory must be unsigned"
        );
    }

    #[tokio::test]
    async fn multihop_directory_maps_404_to_none() {
        let c = client(MockTransport::new(404, "not found"));
        let body = c
            .fetch_multihop_directory()
            .await
            .expect("404 must be Ok(None), not an error");
        assert_eq!(body, None);
    }

    #[tokio::test]
    async fn path_quality_returns_body_on_200_and_is_unsigned() {
        let c = client(MockTransport::new(200, "{\"version\":1}"));
        let body = c.fetch_path_quality().await.expect("ok");
        assert_eq!(body.as_deref(), Some("{\"version\":1}"));
        let guard = c.transport.last.lock().unwrap();
        let req = guard.as_ref().unwrap();
        assert!(
            req.url.ends_with("/v1/multihop/path-quality"),
            "wrong path: {}",
            req.url
        );
        assert!(
            header(req, HEADER_PUBKEY).is_none(),
            "fetch_path_quality must be unsigned"
        );
    }

    #[tokio::test]
    async fn path_quality_maps_404_to_none() {
        let c = client(MockTransport::new(404, "not found"));
        let body = c
            .fetch_path_quality()
            .await
            .expect("404 must be Ok(None): an older API simply has no advisory");
        assert_eq!(body, None);
    }

    #[tokio::test]
    async fn campaign_voucher_is_signed_and_returns_this_account_code() {
        // The code is per-account, so the call MUST be signed: the
        // broadcast announcement that carries the offer is byte-identical
        // for every client and can never hold it.
        let c = client(MockTransport::new(200, r#"{"code":"ABCDEFGHJKMNPQRS"}"#));

        let code = c
            .campaign_voucher("prod-launch")
            .await
            .expect("ok")
            .expect("a cohort member gets a code");

        assert_eq!(code, "ABCDEFGHJKMNPQRS");
        let guard = c.transport.last.lock().unwrap();
        let req = guard.as_ref().expect("request captured");
        assert_eq!(
            req.url,
            "https://api.example.test/v1/campaign/prod-launch/voucher"
        );
        assert_eq!(req.method, Method::Get);
        assert!(
            header(req, HEADER_PUBKEY).is_some(),
            "campaign_voucher must be wallet-signed"
        );
    }

    #[tokio::test]
    async fn campaign_voucher_maps_404_to_none() {
        // Outside the cohort is a normal, quiet outcome: accounts created
        // after publication are deliberately not in the offer.
        let c = client(MockTransport::new(404, "not found"));

        assert_eq!(
            c.campaign_voucher("prod-launch")
                .await
                .expect("404 must be Ok(None), not an error"),
            None
        );
    }

    #[tokio::test]
    async fn campaign_voucher_propagates_other_errors() {
        let c = client(MockTransport::new(503, "unavailable"));

        let err = c
            .campaign_voucher("prod-launch")
            .await
            .expect_err("a 503 must not read as 'not in the cohort'");

        assert!(matches!(err, ClientError::ServerStatus { status: 503, .. }));
    }

    #[tokio::test]
    async fn multihop_directory_propagates_other_errors() {
        let c = client(MockTransport::new(500, "boom"));
        let err = c
            .fetch_multihop_directory()
            .await
            .expect_err("a 500 must propagate as a server-status error");
        assert!(matches!(err, ClientError::ServerStatus { status: 500, .. }));
    }

    type Responder =
        Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

    /// Records every attempt and returns a programmed outcome per request.
    struct ScriptedTransport {
        attempts: Mutex<Vec<HttpRequest>>,
        respond: Responder,
    }

    impl ScriptedTransport {
        fn new(
            respond: impl Fn(&HttpRequest) -> Result<HttpResponse, TransportError>
            + Send
            + Sync
            + 'static,
        ) -> Self {
            Self {
                attempts: Mutex::new(Vec::new()),
                respond: Box::new(respond),
            }
        }
    }

    impl HttpTransport for ScriptedTransport {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
            let out = (self.respond)(&request);
            self.attempts.lock().unwrap().push(request);
            out
        }
    }

    fn ok_200(body: &str) -> Result<HttpResponse, TransportError> {
        Ok(HttpResponse {
            status: 200,
            body: body.as_bytes().to_vec(),
        })
    }

    fn connect_fail() -> Result<HttpResponse, TransportError> {
        Err(TransportError::Connect("blocked".to_owned()))
    }

    fn fallback_client(t: ScriptedTransport) -> WarrenApiClient<ScriptedTransport> {
        WarrenApiClient::new_with_fallback(
            "https://api.example.test",
            vec!["alt.example.test".to_owned()],
            WarrenIdentity::from_seed(&[0x11; 32]),
            t,
        )
    }

    #[tokio::test]
    async fn fallback_retries_alternative_host_on_connect_error() {
        let c = fallback_client(ScriptedTransport::new(|req| {
            if req.url.contains("api.example.test") {
                connect_fail()
            } else {
                ok_200(r#"{"ok":true}"#)
            }
        }));
        let body = c.list_exits().await.expect("alternative host answers");
        assert_eq!(body, r#"{"ok":true}"#);
        let attempts = c.transport.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].url, "https://api.example.test/v1/exits");
        assert_eq!(attempts[1].url, "https://alt.example.test/v1/exits");
        assert!(attempts[1].use_sni);
    }

    #[tokio::test]
    async fn fallback_uses_no_sni_as_last_resort() {
        let c = fallback_client(ScriptedTransport::new(|req| {
            if req.use_sni {
                connect_fail()
            } else {
                ok_200("{}")
            }
        }));
        c.list_exits().await.expect("no-SNI attempt answers");
        let attempts = c.transport.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 3, "primary+SNI, alt+SNI, primary no-SNI");
        assert!(attempts[0].use_sni && attempts[1].use_sni);
        assert!(!attempts[2].use_sni);
        assert_eq!(attempts[2].url, "https://api.example.test/v1/exits");
    }

    #[tokio::test]
    async fn all_hosts_blocked_when_every_attempt_connect_fails() {
        let c = fallback_client(ScriptedTransport::new(|_| connect_fail()));
        let err = c.list_exits().await.expect_err("all blocked");
        assert!(matches!(err, ClientError::AllHostsBlocked));
        // primary+SNI, alt+SNI, primary no-SNI (one alt configured): the
        // canonical 3-step sequence, never an alt-without-SNI rung.
        assert_eq!(c.transport.attempts.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn alternative_host_is_never_tried_without_sni() {
        // Canonical policy: no-SNI is only ever attempted on the PRIMARY host.
        // An alt reachable solely over a no-SNI ClientHello is deliberately not
        // pursued, so a censor cannot be probed for per-alt SNI sensitivity.
        let c = fallback_client(ScriptedTransport::new(|req| {
            if req.url.contains("alt.example.test") && !req.use_sni {
                ok_200("{}")
            } else {
                connect_fail()
            }
        }));
        let err = c
            .list_exits()
            .await
            .expect_err("an alt reachable only no-SNI must not answer");
        assert!(matches!(err, ClientError::AllHostsBlocked));
        let attempts = c.transport.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 3, "no alt-without-SNI rung exists");
        assert!(
            !attempts
                .iter()
                .any(|a| a.url.contains("alt.example.test") && !a.use_sni),
            "an alternative host must never be attempted without SNI"
        );
    }

    #[tokio::test]
    async fn non_connect_error_does_not_trigger_fallback() {
        let c = fallback_client(ScriptedTransport::new(|_| {
            Err(TransportError::Io("mid-response reset".to_owned()))
        }));
        let err = c.list_exits().await.expect_err("io error propagates");
        assert!(matches!(err, ClientError::Transport(_)));
        assert_eq!(
            c.transport.attempts.lock().unwrap().len(),
            1,
            "a non-connect error must not advance the sequence"
        );
    }

    #[tokio::test]
    async fn register_is_unsigned_post_and_parses() {
        let c = client(MockTransport::new(200, r#"{"expires_at":123}"#));
        let req = RegisterAccountRequest {
            pubkey_ss58: a_ss58(),
            voucher_secret: Some("voucher".to_owned()),
            referral_code: None,
        };
        let resp = c.register(&req).await.expect("ok");
        assert_eq!(resp.expires_at, 123);
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://api.example.test/v1/register");
        assert!(header(r, HEADER_PUBKEY).is_none(), "register is unsigned");
        assert!(!r.body.is_empty());
    }

    #[tokio::test]
    async fn check_is_signed_get_and_parses() {
        let c = client(MockTransport::new(
            200,
            r#"{"ip":"1.2.3.4","is_exit":false}"#,
        ));
        let resp = c.check().await.expect("ok");
        assert_eq!(resp.ip, "1.2.3.4");
        assert!(!resp.is_exit);
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.url, "https://api.example.test/v1/check");
        assert!(header(r, HEADER_PUBKEY).is_some(), "check is signed");
    }

    #[tokio::test]
    async fn open_session_is_signed_post_and_parses() {
        let c = client(MockTransport::new(
            200,
            r#"{"admitted":true,"max":5,"current":1}"#,
        ));
        let req = SessionOpenRequest {
            pubkey_ss58: Some(a_ss58()),
            device_id_hex: Some("00".repeat(16)),
            exit_id: "exit".to_owned(),
            max_devices: None,
            token_b64: None,
        };
        let resp = c.open_session(&req).await.expect("ok");
        assert!(resp.admitted);
        assert_eq!(resp.max, 5);
        assert_eq!(resp.current, 1);
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://api.example.test/v1/session/open");
        assert!(header(r, HEADER_PUBKEY).is_some(), "open_session is signed");
    }

    #[tokio::test]
    async fn close_session_is_signed_post_returning_unit() {
        let c = client(MockTransport::new(200, ""));
        let req = SessionCloseRequest {
            pubkey_ss58: Some(a_ss58()),
            device_id_hex: Some("00".repeat(16)),
            serial_hex: None,
            exit_id: None,
        };
        c.close_session(&req).await.expect("ok");
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://api.example.test/v1/session/close");
        assert!(
            header(r, HEADER_PUBKEY).is_some(),
            "close_session is signed"
        );
    }

    #[tokio::test]
    async fn delete_account_is_signed_delete() {
        let c = client(MockTransport::new(200, ""));
        c.delete_account().await.expect("ok");
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Delete);
        assert_eq!(r.url, "https://api.example.test/v1/account");
        assert!(
            header(r, HEADER_PUBKEY).is_some(),
            "delete_account is signed"
        );
    }

    #[tokio::test]
    async fn init_apple_payment_is_signed_post_with_empty_body() {
        let c = client(MockTransport::new(
            200,
            r#"{"app_account_token":"3f1a2b3c-0000-4000-8000-000000000001"}"#,
        ));
        let resp = c.init_apple_payment().await.expect("ok");
        assert_eq!(
            resp.app_account_token,
            "3f1a2b3c-0000-4000-8000-000000000001"
        );
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://api.example.test/v1/payments/apple/init");
        assert!(header(r, HEADER_PUBKEY).is_some(), "init is signed");
        assert!(r.body.is_empty(), "init carries no body");
    }

    #[tokio::test]
    async fn check_apple_payment_sends_jws_in_body_and_parses_expiry() {
        let c = client(MockTransport::new(200, r#"{"expires_at":1800000000}"#));
        let resp = c
            .check_apple_payment("header.payload.sig")
            .await
            .expect("ok");
        assert_eq!(resp.expires_at, 1_800_000_000);
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://api.example.test/v1/payments/apple/check");
        assert!(header(r, HEADER_PUBKEY).is_some(), "check is signed");
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body["jws_transaction"], "header.payload.sig");
    }

    #[tokio::test]
    async fn check_apple_payment_404_is_server_status() {
        let c = client(MockTransport::new(404, "session not found"));
        let err = c
            .check_apple_payment("jws")
            .await
            .expect_err("missing session must error");
        assert!(matches!(err, ClientError::ServerStatus { status: 404, .. }));
    }

    #[tokio::test]
    async fn pull_pending_voucher_returns_secret_on_200_and_is_unsigned() {
        let c = client(MockTransport::new(
            200,
            r#"{"voucher_secret":"vch-abcd-1234"}"#,
        ));
        let secret = c.pull_pending_voucher("pend-1").await.expect("ok");
        assert_eq!(secret.as_deref(), Some("vch-abcd-1234"));
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.url, "https://api.example.test/v1/checkout/pend-1/voucher");
        assert!(
            header(r, HEADER_PUBKEY).is_none(),
            "voucher polling is unsigned"
        );
    }

    #[tokio::test]
    async fn pull_pending_voucher_maps_404_to_none() {
        let c = client(MockTransport::new(404, "not landed yet"));
        let secret = c
            .pull_pending_voucher("pend-1")
            .await
            .expect("404 must be Ok(None)");
        assert_eq!(secret, None);
    }

    #[tokio::test]
    async fn pull_pending_voucher_propagates_other_errors() {
        let c = client(MockTransport::new(500, "boom"));
        let err = c
            .pull_pending_voucher("pend-1")
            .await
            .expect_err("a 500 must propagate");
        assert!(matches!(err, ClientError::ServerStatus { status: 500, .. }));
    }

    #[tokio::test]
    async fn report_exit_down_is_signed_post_with_screaming_reason() {
        let c = client(MockTransport::new(204, ""));
        let req = IncidentExitDownRequest {
            exit_pubkey_hex: a_pubkey_hex(),
            reason_code: crate::dto::IncidentReason::HandshakeFail,
            ts_unix: 1_700_000_123,
        };
        c.report_exit_down(&req).await.expect("ok");
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://api.example.test/v1/incidents/exit-down");
        assert!(header(r, HEADER_PUBKEY).is_some(), "incident is signed");
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body["reason_code"], "HANDSHAKE_FAIL");
        assert_eq!(body["exit_pubkey_hex"], "ab".repeat(32));
        assert_eq!(body["ts_unix"], 1_700_000_123u64);
    }

    #[tokio::test]
    async fn report_pubkey_mismatch_is_signed_post_and_serializes_optionals() {
        let c = client(MockTransport::new(204, ""));
        let req = IncidentPubkeyMismatchRequest {
            exit_id_hex: "00".repeat(16),
            old_pubkey_hex: "11".repeat(32),
            new_pubkey_hex: "22".repeat(32),
            country_code: String::new(),
            city: String::new(),
            ts_unix: 42,
        };
        c.report_pubkey_mismatch(&req).await.expect("ok");
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(
            r.url,
            "https://api.example.test/v1/incidents/pubkey-mismatch"
        );
        assert!(header(r, HEADER_PUBKEY).is_some(), "incident is signed");
        // Empty optionals are still present on the wire (no skip_serializing).
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body["country_code"], "");
        assert_eq!(body["city"], "");
    }

    // Each new method documents specific failure statuses that surface as
    // ClientError::ServerStatus. Pin one representative documented status per
    // method so the documented `# Errors` contract cannot silently rot.

    #[tokio::test]
    async fn init_apple_payment_503_is_server_status() {
        let c = client(MockTransport::new(503, "apple payments not configured"));
        let err = c.init_apple_payment().await.expect_err("503 must surface");
        assert!(matches!(err, ClientError::ServerStatus { status: 503, .. }));
    }

    #[tokio::test]
    async fn report_exit_down_422_is_server_status() {
        let c = client(MockTransport::new(422, "unknown reason_code"));
        let req = IncidentExitDownRequest {
            exit_pubkey_hex: a_pubkey_hex(),
            reason_code: crate::dto::IncidentReason::Timeout,
            ts_unix: 1,
        };
        let err = c
            .report_exit_down(&req)
            .await
            .expect_err("422 must surface");
        assert!(matches!(err, ClientError::ServerStatus { status: 422, .. }));
    }

    #[tokio::test]
    async fn report_pubkey_mismatch_400_is_server_status() {
        let c = client(MockTransport::new(400, "malformed body"));
        let req = IncidentPubkeyMismatchRequest {
            exit_id_hex: "00".repeat(16),
            old_pubkey_hex: "11".repeat(32),
            new_pubkey_hex: "22".repeat(32),
            country_code: String::new(),
            city: String::new(),
            ts_unix: 1,
        };
        let err = c
            .report_pubkey_mismatch(&req)
            .await
            .expect_err("400 must surface");
        assert!(matches!(err, ClientError::ServerStatus { status: 400, .. }));
    }

    #[test]
    fn pre_epoch_clock_is_bad_clock() {
        let before = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert!(matches!(unix_secs_from(before), Err(ClientError::BadClock)));
    }

    #[test]
    fn replace_host_swaps_only_the_hostname() {
        assert_eq!(
            replace_host("https://api.x.com/v1/exits", "alt.x.com"),
            "https://alt.x.com/v1/exits"
        );
        assert_eq!(
            replace_host("https://api.x.com:8443/v1/exits", "alt.x.com"),
            "https://alt.x.com:8443/v1/exits"
        );
        assert_eq!(
            replace_host("https://api.x.com", "alt.x.com"),
            "https://alt.x.com"
        );
    }
}
