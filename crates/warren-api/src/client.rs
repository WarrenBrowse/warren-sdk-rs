//! The signed Warren account API client.

use std::sync::Arc;

use rand::RngCore;
use serde::Serialize;
use serde::de::DeserializeOwned;
use warren_discovery_core::{MULTIHOP_DIRECTORY_PATH_V1, MULTIHOP_DIRECTORY_PATH_V2};
use warren_identity::WarrenIdentity;

use warren_contract::auth::SIGNATURE_WINDOW_SECS;
use warren_contract::dto::AuthRefusal;

use crate::clock::ServerClock;
use crate::dto::{
    AccountStandingResponse, BanReasonCode, CampaignVoucherResponse, CheckApplePaymentRequest,
    CheckResponse, IncidentExitDownRequest, IncidentPubkeyMismatchRequest,
    InitApplePaymentResponse, IssuanceRefusal, MobilePaymentResponse, RegisterAccountRequest,
    RegisterAccountResponse, SessionCloseRequest, SessionOpenRequest, SessionOpenResponse,
    SubscriptionResponse, TokenIssueRequest, TokenIssueResponse, TokenIssuerDirectory,
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
    /// failed to connect. A censor is one cause; a host with no network at all
    /// is the other and by far the commoner one (a laptop asleep with its Wi-Fi
    /// down produced 1,752 of these in a fleet of nine members, each in under
    /// 100 ms, 2026-09-11 to 2026-09-13), and this client cannot tell them
    /// apart: a failed name lookup and a refused connection both arrive as a
    /// connect error. A caller that knows whether the host has a route (the
    /// wclaude daemon does) makes that call; this message must not.
    #[error("all API hosts are unreachable (no network, or the API is blocked)")]
    AllHostsBlocked,
    /// The system clock is before the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    BadClock,
    /// The server refused a signed request because its timestamp is outside
    /// the server's window: this device's clock is off, and the wallet key
    /// may well be fine. Raised on a `401` whose body is the contract's
    /// `{"error":"clock_skew"}`, or whose `Date` shows the stamp outside the
    /// window, once the correction learned from that `Date` (see
    /// [`crate::clock`]) could not bring the stamp back inside it: the clock
    /// is further ahead than the correction may follow, or the answer
    /// carried no usable `Date`. What a user can do is set the clock right.
    #[error("the server refused the request's timestamp: this device's clock is off")]
    ClockSkew {
        /// The server's clock minus this device's, in seconds (positive when
        /// the device is behind), read off the refusal's `Date` header.
        /// `None` when the refusal carried no usable one.
        offset_secs: Option<i64>,
    },
    /// The server refused the wallet because it is on the CRL (HTTP 403
    /// `{"error":"banned"}`, warren-core doc 105): session-token and
    /// port-entitlement issuance, and every call that credits time (a voucher
    /// redemption, the store payment calls), which refuse before consuming
    /// anything. The app shows the revocation from this answer without
    /// dialing an exit.
    #[error("the account is banned")]
    Banned {
        /// Why the account is banned.
        reason_code: BanReasonCode,
        /// When the ban lapses on its own, Unix seconds. `None` for a ban
        /// that does not lapse, or when the refusing endpoint does not say.
        lapses_at_unix_secs: Option<u64>,
    },
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
    /// The server's clock as the answers read so far tell it; every signed
    /// request is stamped with it.
    clock: Arc<ServerClock>,
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
            clock: Arc::new(ServerClock::new()),
        }
    }

    /// The same client stamping with `clock`, shared with every other client
    /// (or signer) of the wallet that holds it, so one answer read by any of
    /// them corrects all their stamps.
    #[must_use]
    pub fn with_server_clock(mut self, clock: Arc<ServerClock>) -> Self {
        self.clock = clock;
        self
    }

    /// The server clock this client stamps its signed requests with: read
    /// [`ServerClock::offset_secs`] to tell a user their clock is off, or
    /// share it with another signer of the same wallet.
    #[must_use]
    pub fn server_clock(&self) -> &Arc<ServerClock> {
        &self.clock
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

    /// The signed multi-hop directory, asked for on the DUAL-STACK route and
    /// falling back to the frozen one. Returns the raw JSON, or `None` when
    /// neither route has a directory published. Unsigned: the body is itself
    /// signed and the caller verifies the full trust chain with
    /// `warren_discovery::verify_multihop_directory`.
    ///
    /// Two routes because the `/v1` body can never gain a field (its envelope
    /// is verified against a re-serialization of the parsed nodes, so an
    /// unknown one breaks the signature), and a client on an IPv6-only network
    /// needs each relay's second address to dial anything at all. `/v2` carries
    /// it; a backend that predates the route answers `404` and the frozen copy
    /// is used, which is what keeps this SDK working against both.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on transport failure or a non-200/404 status.
    pub async fn fetch_multihop_directory(&self) -> Result<Option<String>, ClientError> {
        match self
            .fetch_multihop_directory_at(MULTIHOP_DIRECTORY_PATH_V2)
            .await
        {
            Ok(Some(body)) => Ok(Some(body)),
            // `404` here is either "no directory published" or "this backend
            // has no v2 route": the frozen route answers both.
            Ok(None) => {
                self.fetch_multihop_directory_at(MULTIHOP_DIRECTORY_PATH_V1)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    async fn fetch_multihop_directory_at(&self, path: &str) -> Result<Option<String>, ClientError> {
        let req = self.unsigned_request(Method::Get, path, Vec::new());
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
    /// response. A wallet on the revocation list is refused with
    /// [`ClientError::Banned`] and its voucher stays unredeemed, to be redeemed
    /// once the ban ends; the lapse may be absent from this unsigned answer.
    pub async fn register(
        &self,
        req: &RegisterAccountRequest,
    ) -> Result<RegisterAccountResponse, ClientError> {
        let body = serialize(req)?;
        let http = self.unsigned_request(Method::Post, "/v1/register", body);
        self.send_json(http).await.map_err(ban_refusal)
    }

    /// Signed `GET /v1/subscription`.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn subscription(&self) -> Result<SubscriptionResponse, ClientError> {
        self.send_signed_json(Method::Get, "/v1/subscription", Vec::new())
            .await
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
        match self.send_signed(Method::Get, &path, Vec::new()).await {
            Ok(resp) => {
                let parsed: CampaignVoucherResponse =
                    serde_json::from_slice(&resp.body).map_err(ClientError::ResponseJson)?;
                Ok(Some(parsed.code))
            }
            Err(ClientError::ServerStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Signed `GET /v1/account/standing`: the port-forward abuse strikes
    /// still inside the sliding window, the threshold and window that govern
    /// them, and the ban in force if any (warren-core doc 105). Poll it on the
    /// token refresh timer; a new strike is what the app warns about.
    ///
    /// The strikes carry a case reference and the port that was closed, which
    /// belong in the account's own UI and nowhere else, never in a log.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn account_standing(&self) -> Result<AccountStandingResponse, ClientError> {
        self.send_signed_json(Method::Get, "/v1/account/standing", Vec::new())
            .await
    }

    /// Signed `GET /v1/check`. Reports the client's egress IP and whether it is
    /// an exit (useful to confirm the tunnel is active).
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn check(&self) -> Result<CheckResponse, ClientError> {
        self.send_signed_json(Method::Get, "/v1/check", Vec::new())
            .await
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
        self.send_signed_json(Method::Post, "/v1/session/open", body)
            .await
    }

    /// Signed `POST /v1/session/close`.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn close_session(&self, req: &SessionCloseRequest) -> Result<(), ClientError> {
        let body = serialize(req)?;
        self.send_signed(Method::Post, "/v1/session/close", body)
            .await
            .map(|_| ())
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
    /// See [`Self::register`]. A wallet on the revocation list is refused
    /// with [`ClientError::Banned`].
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
        self.send_signed_json(Method::Post, class.issue_path(), body)
            .await
            .map_err(ban_refusal)
    }

    /// Signed `DELETE /v1/account`. Deletes the account's subscription.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn delete_account(&self) -> Result<(), ClientError> {
        self.send_signed(Method::Delete, "/v1/account", Vec::new())
            .await
            .map(|_| ())
    }

    /// Signed `POST /v1/payments/apple/init`. Opens an Apple IAP session bound
    /// to the signing pubkey and returns the `app_account_token` to hand to
    /// StoreKit. Empty request body.
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. A `503` status surfaces as
    /// [`ClientError::ServerStatus`] when Apple payments are not configured. A
    /// wallet on the revocation list is refused with [`ClientError::Banned`]
    /// and no payment session is opened: do not start the StoreKit purchase.
    pub async fn init_apple_payment(&self) -> Result<InitApplePaymentResponse, ClientError> {
        self.send_signed_json(Method::Post, "/v1/payments/apple/init", Vec::new())
            .await
            .map_err(ban_refusal)
    }

    /// Signed `POST /v1/payments/apple/check`. Uploads the StoreKit 2 signed
    /// transaction JWS; on success the subscription is credited and the new
    /// expiry returned.
    ///
    /// # Errors
    ///
    /// See [`Self::register`]. Notable statuses surface as
    /// [`ClientError::ServerStatus`]: `400` invalid transaction, `404` session
    /// not found, `403` identity mismatch, `422` unknown product. A wallet on
    /// the revocation list is refused with [`ClientError::Banned`] and the
    /// transaction is left unclaimed: keep it unfinished so it can be presented
    /// again once the ban ends.
    pub async fn check_apple_payment(
        &self,
        jws_transaction: &str,
    ) -> Result<MobilePaymentResponse, ClientError> {
        let req = CheckApplePaymentRequest {
            jws_transaction: jws_transaction.to_owned(),
        };
        let body = serialize(&req)?;
        self.send_signed_json(Method::Post, "/v1/payments/apple/check", body)
            .await
            .map_err(ban_refusal)
    }

    /// Unsigned `POST /v1/checkout/{wpid}/voucher`. Polls for the voucher a
    /// checkout purchase minted under `wpid` (card, Lightning, Monero, ...),
    /// presenting `pull_secret_hex`, the 64-hex secret the purchase was bound
    /// to when it was created. The caller mints that secret with the wpid and
    /// passes only its SHA-256 to the checkout; the secret itself travels in
    /// this request body, never in a URL. Returns the voucher secret once it
    /// lands, or `None` on `404` (not landed yet, already pulled, expired, or
    /// not this purchase's secret, deliberately indistinguishable); the caller
    /// keeps polling within its own deadline. Unsigned on purpose: a wallet
    /// signature would join the wallet and the purchase on the server.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on transport failure or any non-200/404 status.
    pub async fn pull_pending_voucher(
        &self,
        wpid: &str,
        pull_secret_hex: &str,
    ) -> Result<Option<String>, ClientError> {
        let path = format!("/v1/checkout/{wpid}/voucher");
        let body = serialize(&PullVoucherRequest {
            pull_secret: pull_secret_hex,
        })?;
        let req = self.unsigned_request(Method::Post, &path, body);
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
        self.send_signed(Method::Post, "/v1/incidents/exit-down", body)
            .await
            .map(|_| ())
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
        self.send_signed(Method::Post, "/v1/incidents/pubkey-mismatch", body)
            .await
            .map(|_| ())
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
    ) -> Result<(HttpRequest, u64), ClientError> {
        let timestamp = self.clock.stamp(now_secs()?);
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
        let request = HttpRequest {
            method,
            url: format!("{}{path}", self.api_base),
            headers,
            body,
            use_sni: true,
        };
        Ok((request, timestamp))
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
        let resp = self.send_through_fallback(request).await?;
        self.finish(resp)
    }

    /// Sends a wallet-signed request, stamped with the server clock.
    ///
    /// The clock is learned from the `Date` of a `401` only. A refusal is the
    /// one answer that is never served from a cache (it has no freshness, and
    /// it answers this request's own signature), and it is the one that says
    /// the stamp needs moving. Any other answer can be a cached copy: the
    /// relay list is `public, max-age=60`, and a browser or an intermediary
    /// cache hands it back with the `Date` it was first served under, which
    /// would move a right clock's stamp out of the window.
    ///
    /// A `401` that refuses the timestamp is signed again, once, when the
    /// stamp the refusal's own `Date` leads to fits the window: a device
    /// whose clock drifted then costs one refusal per [`ServerClock`], not
    /// every call. A stamp the correction may not follow (a server further
    /// ahead than [`crate::clock::MAX_FORWARD_CORRECTION_SECS`], or a refusal
    /// with no `Date`) is [`ClientError::ClockSkew`] at once, and any other
    /// `401` is final, so a bad key costs one request, not two.
    async fn send_signed(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, ClientError> {
        let (request, stamp) = self.signed_request(method, path, body.clone())?;
        let resp = self.send_through_fallback(request).await?;
        if !self.refused_for_the_clock(&resp, stamp) {
            return self.finish(resp);
        }
        let (retry, retry_stamp) = self.signed_request(method, path, body)?;
        if !stamp_fits_the_window(&resp, retry_stamp) {
            return Err(clock_skew(&resp));
        }
        let resp = self.send_through_fallback(retry).await?;
        if self.refused_for_the_clock(&resp, retry_stamp) {
            return Err(clock_skew(&resp));
        }
        self.finish(resp)
    }

    /// Whether `resp` is a `401` refusing `stamp` for the clock, after
    /// learning the server clock from any `401`'s `Date`.
    fn refused_for_the_clock(&self, resp: &HttpResponse, stamp: u64) -> bool {
        if resp.status != 401 {
            return false;
        }
        if let (Some(date), Ok(device_now)) = (resp.date.as_deref(), now_secs()) {
            self.clock.observe_date(date, device_now);
        }
        refuses_the_clock(resp, stamp)
    }

    async fn send_signed_json<R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<R, ClientError> {
        let resp = self.send_signed(method, path, body).await?;
        serde_json::from_slice(&resp.body).map_err(ClientError::ResponseJson)
    }

    async fn send_through_fallback(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, ClientError> {
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
                AttemptOutcome::Response(resp) => return Ok(resp),
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

/// Types the ban refusal (403 `{"error":"banned"}`) that issuance and every
/// credit path answer a wallet on the CRL; any other error, a 403 with another
/// body included, is returned as it came.
fn ban_refusal(err: ClientError) -> ClientError {
    let ClientError::ServerStatus { status: 403, body } = &err else {
        return err;
    };
    match serde_json::from_str::<IssuanceRefusal>(body) {
        Ok(IssuanceRefusal::Banned {
            reason_code,
            lapses_at_unix_secs,
        }) => ClientError::Banned {
            reason_code,
            lapses_at_unix_secs,
        },
        _ => err,
    }
}

/// Whether a `401` refuses the request's timestamp rather than its key: the
/// body says so (the contract's clock refusal), or the answer's own `Date`
/// puts the stamp that was sent outside the window. The second reading covers
/// a server that answers a bare `401`, as warren-api did before it named the
/// cause; the server checks the window before the signature, so a stamp
/// outside it can have been refused for nothing else.
fn refuses_the_clock(resp: &HttpResponse, stamp: u64) -> bool {
    if matches!(
        serde_json::from_slice::<AuthRefusal>(&resp.body),
        Ok(AuthRefusal::ClockSkew)
    ) {
        return true;
    }
    stamp_offset(resp, stamp).is_some_and(|offset| offset.unsigned_abs() > SIGNATURE_WINDOW_SECS)
}

/// Whether the server whose clock `resp`'s `Date` shows would take `stamp`.
/// False without a `Date`: nothing then says a new stamp would fare better.
fn stamp_fits_the_window(resp: &HttpResponse, stamp: u64) -> bool {
    stamp_offset(resp, stamp).is_some_and(|offset| offset.unsigned_abs() <= SIGNATURE_WINDOW_SECS)
}

/// The answer's `Date` minus `stamp`, in seconds.
fn stamp_offset(resp: &HttpResponse, stamp: u64) -> Option<i64> {
    crate::clock::clock_offset_secs(resp.date.as_deref()?, stamp)
}

/// The clock refusal `resp` stands for, with how far this device's clock is
/// from the server's when the refusal says.
fn clock_skew(resp: &HttpResponse) -> ClientError {
    let offset_secs = resp
        .date
        .as_deref()
        .and_then(|date| crate::clock::clock_offset_secs(date, now_secs().ok()?));
    ClientError::ClockSkew { offset_secs }
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

/// Internal answer of `POST /v1/checkout/{wpid}/voucher`. Only the secret is
/// surfaced to the caller as a bare `String`.
#[derive(serde::Deserialize)]
struct PullVoucherResponse {
    voucher_secret: String,
}

/// Internal body of `POST /v1/checkout/{wpid}/voucher`.
#[derive(Serialize)]
struct PullVoucherRequest<'a> {
    pull_secret: &'a str,
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
            Ok(HttpResponse::new(self.status, self.body.clone()))
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
    async fn account_standing_is_a_wallet_signed_get_returning_strikes_and_ban() {
        let body = r#"{"strikes":[{"day_unix_secs":1758758400,"category":"copyright","exit_country":"NL","port":51234,"case_reference":"case-0001"}],"threshold":3,"window_days":90,"ban":{"banned_at_unix_secs":1758800000,"lapses_at_unix_secs":1790336000,"reason_code":"port_forwarding_abuse"}}"#;
        let c = client(MockTransport::new(200, body));

        let standing = c.account_standing().await.expect("ok");

        assert_eq!(standing.threshold, 3);
        assert_eq!(standing.window_days, 90);
        assert_eq!(standing.strikes.len(), 1);
        assert_eq!(standing.strikes[0].port, 51_234);
        assert_eq!(standing.strikes[0].case_reference, "case-0001");
        let ban = standing.ban.expect("banned");
        assert_eq!(
            ban.reason_code,
            crate::dto::BanReasonCode::PortForwardingAbuse
        );
        assert_eq!(ban.lapses_at_unix_secs, Some(1_790_336_000));
        let guard = c.transport.last.lock().unwrap();
        let req = guard.as_ref().expect("request captured");
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.url, "https://api.example.test/v1/account/standing");
        assert_eq!(
            header(req, HEADER_PUBKEY),
            Some(WarrenIdentity::from_seed(&[0x11; 32]).address().as_str()),
            "the standing is the wallet's own: the request must name it"
        );
        assert!(header(req, HEADER_SIGNATURE).is_some());
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
        Ok(HttpResponse::new(200, body.as_bytes().to_vec()))
    }

    fn connect_fail() -> Result<HttpResponse, TransportError> {
        Err(TransportError::Connect("blocked".to_owned()))
    }

    /// A backend that serves BOTH routes: the dual-stack one is what the
    /// client must end up using, because it is the only copy carrying each
    /// relay's second address family.
    #[tokio::test]
    async fn the_directory_is_asked_for_on_the_dual_stack_route_first() {
        let t = ScriptedTransport::new(|req| {
            if req.url.ends_with(MULTIHOP_DIRECTORY_PATH_V2) {
                ok_200(r#"{"from":"v2"}"#)
            } else {
                ok_200(r#"{"from":"v1"}"#)
            }
        });
        let c = WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x11; 32]),
            t,
        );
        let body = c
            .fetch_multihop_directory()
            .await
            .expect("ok")
            .expect("some");
        assert_eq!(body, r#"{"from":"v2"}"#);
        let asked = c.transport().attempts.lock().unwrap();
        assert_eq!(asked.len(), 1, "the frozen route must not be asked for too");
    }

    /// A backend that predates the route answers 404 there. The client must
    /// fall back rather than report "no directory published", which would
    /// strand every circuit against an older API.
    #[tokio::test]
    async fn a_backend_without_the_dual_stack_route_falls_back_to_the_frozen_one() {
        let t = ScriptedTransport::new(|req| {
            if req.url.ends_with(MULTIHOP_DIRECTORY_PATH_V2) {
                Ok(HttpResponse::new(404, b"no such route".to_vec()))
            } else {
                ok_200(r#"{"from":"v1"}"#)
            }
        });
        let c = WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x11; 32]),
            t,
        );
        let body = c
            .fetch_multihop_directory()
            .await
            .expect("ok")
            .expect("some");
        assert_eq!(body, r#"{"from":"v1"}"#);
        let asked = c.transport().attempts.lock().unwrap();
        assert_eq!(asked.len(), 2, "v2 then v1, in that order");
        assert!(asked[0].url.ends_with(MULTIHOP_DIRECTORY_PATH_V2));
        assert!(asked[1].url.ends_with(MULTIHOP_DIRECTORY_PATH_V1));
    }

    /// Neither route has one: that is `None`, not an error, and it must not
    /// read as a transport failure.
    #[tokio::test]
    async fn no_directory_on_either_route_is_none() {
        let t = ScriptedTransport::new(|_| Ok(HttpResponse::new(404, b"none published".to_vec())));
        let c = WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x11; 32]),
            t,
        );
        assert!(c.fetch_multihop_directory().await.expect("ok").is_none());
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

    /// The refusal every credit path answers a wallet on the CRL (warren-core
    /// doc 105 section 5.3). The unsigned `/v1/register` may omit the lapse.
    const BANNED_WITH_LAPSE: &str = r#"{"error":"banned","reason_code":"port_forwarding_abuse","lapses_at_unix_secs":1790336000}"#;
    const BANNED_WITHOUT_LAPSE: &str =
        r#"{"error":"banned","reason_code":"port_forwarding_abuse"}"#;

    fn a_voucher_registration() -> RegisterAccountRequest {
        RegisterAccountRequest {
            pubkey_ss58: a_ss58(),
            voucher_secret: Some("voucher".to_owned()),
            referral_code: None,
        }
    }

    #[tokio::test]
    async fn register_of_a_banned_wallet_is_a_typed_ban_even_without_a_lapse() {
        let c = client(MockTransport::new(403, BANNED_WITHOUT_LAPSE));

        let err = c
            .register(&a_voucher_registration())
            .await
            .expect_err("a banned wallet redeems nothing");

        assert!(
            matches!(
                err,
                ClientError::Banned {
                    reason_code: BanReasonCode::PortForwardingAbuse,
                    lapses_at_unix_secs: None,
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn register_403_with_another_body_stays_a_server_status() {
        let c = client(MockTransport::new(403, r#"{"error":"forbidden"}"#));

        let err = c
            .register(&a_voucher_registration())
            .await
            .expect_err("403 must error");

        assert!(matches!(err, ClientError::ServerStatus { status: 403, .. }));
    }

    #[tokio::test]
    async fn init_apple_payment_of_a_banned_wallet_is_a_typed_ban() {
        let c = client(MockTransport::new(403, BANNED_WITH_LAPSE));

        let err = c
            .init_apple_payment()
            .await
            .expect_err("a banned wallet opens no store purchase");

        assert!(
            matches!(
                err,
                ClientError::Banned {
                    reason_code: BanReasonCode::PortForwardingAbuse,
                    lapses_at_unix_secs: Some(1_790_336_000),
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn check_apple_payment_of_a_banned_wallet_is_a_typed_ban() {
        let c = client(MockTransport::new(403, BANNED_WITH_LAPSE));

        let err = c
            .check_apple_payment("jws")
            .await
            .expect_err("a banned wallet's store transaction is not claimed");

        assert!(
            matches!(
                err,
                ClientError::Banned {
                    reason_code: BanReasonCode::PortForwardingAbuse,
                    lapses_at_unix_secs: Some(1_790_336_000),
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn check_apple_payment_identity_mismatch_stays_a_server_status() {
        let c = client(MockTransport::new(403, "identity mismatch"));

        let err = c
            .check_apple_payment("jws")
            .await
            .expect_err("identity mismatch must error");

        assert!(matches!(err, ClientError::ServerStatus { status: 403, .. }));
    }

    const WPID: &str = "0123456789abcdef0123456789abcdef";
    const PULL_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[tokio::test]
    async fn pull_pending_voucher_presents_the_pull_secret_in_an_unsigned_post() {
        let c = client(MockTransport::new(
            200,
            r#"{"voucher_secret":"vch-abcd-1234"}"#,
        ));
        let secret = c.pull_pending_voucher(WPID, PULL_SECRET).await.expect("ok");
        assert_eq!(secret.as_deref(), Some("vch-abcd-1234"));
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(
            r.url,
            format!("https://api.example.test/v1/checkout/{WPID}/voucher")
        );
        assert!(
            !r.url.contains(PULL_SECRET),
            "the pull secret must never ride in the URL"
        );
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body["pull_secret"], PULL_SECRET);
        assert!(
            header(r, HEADER_PUBKEY).is_none(),
            "voucher polling is unsigned: a signature would join wallet and purchase"
        );
    }

    #[tokio::test]
    async fn pull_pending_voucher_maps_404_to_none() {
        let c = client(MockTransport::new(404, "not landed yet"));
        let secret = c
            .pull_pending_voucher(WPID, PULL_SECRET)
            .await
            .expect("404 must be Ok(None)");
        assert_eq!(secret, None);
    }

    #[tokio::test]
    async fn pull_pending_voucher_propagates_other_errors() {
        let c = client(MockTransport::new(500, "boom"));
        let err = c
            .pull_pending_voucher(WPID, PULL_SECRET)
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

    /// A fake API whose clock is `server_offset` seconds from the device's.
    /// Every answer carries its `Date`; a signed stamp further than the
    /// window from its clock is refused 401, with the contract's clock body
    /// when `names_the_clock` (warren-api once deployed) and bare otherwise
    /// (warren-api as deployed when forum topic 219 was reported).
    struct SkewedServer {
        server_offset: i64,
        names_the_clock: bool,
        sends_date: bool,
        /// How far in the past the `Date` of an unsigned answer is, as a
        /// cache that kept it would serve it.
        unsigned_date_lag: u64,
        stamps: Mutex<Vec<u64>>,
    }

    impl SkewedServer {
        fn new(server_offset: i64, names_the_clock: bool) -> Self {
            Self {
                server_offset,
                names_the_clock,
                sends_date: true,
                unsigned_date_lag: 0,
                stamps: Mutex::new(Vec::new()),
            }
        }

        fn server_now(&self) -> u64 {
            device_now().saturating_add_signed(self.server_offset)
        }

        fn stamps(&self) -> Vec<u64> {
            self.stamps.lock().unwrap().clone()
        }
    }

    impl HttpTransport for SkewedServer {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
            let server_now = self.server_now();
            let signed = header(&request, HEADER_TIMESTAMP).is_some();
            let refused = header(&request, HEADER_TIMESTAMP).is_some_and(|ts| {
                let ts: u64 = ts.parse().unwrap();
                self.stamps.lock().unwrap().push(ts);
                ts.abs_diff(server_now) > 60
            });
            let response = if refused {
                let body = if self.names_the_clock {
                    r#"{"error":"clock_skew"}"#
                } else {
                    ""
                };
                HttpResponse::new(401, body.as_bytes().to_vec())
            } else {
                HttpResponse::new(200, br#"{"expires_at":1700000000}"#.to_vec())
            };
            let date_secs = if signed {
                server_now
            } else {
                server_now - self.unsigned_date_lag
            };
            Ok(if self.sends_date {
                response.with_date(httpdate::fmt_http_date(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(date_secs),
                ))
            } else {
                response
            })
        }
    }

    fn device_now() -> u64 {
        now_secs().unwrap()
    }

    fn skewed_client(server: SkewedServer) -> WarrenApiClient<SkewedServer> {
        WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x11; 32]),
            server,
        )
    }

    fn assert_near(actual: u64, expected: u64, why: &str) {
        assert!(
            actual.abs_diff(expected) <= 2,
            "{why}: stamped {actual}, expected about {expected}"
        );
    }

    /// Forum topic 219: a Windows clock 91 s fast was refused on every signed
    /// call by a server that answered a bare 401. The refusal's own `Date`
    /// says why, so the client re-signs once at the server's clock.
    #[tokio::test]
    async fn a_device_91_s_fast_is_refused_once_then_signs_at_the_servers_clock() {
        let c = skewed_client(SkewedServer::new(-91, false));

        let sub = c
            .subscription()
            .await
            .expect("the corrected stamp is accepted");

        assert_eq!(sub.expires_at, 1_700_000_000);
        let stamps = c.transport().stamps();
        assert_eq!(stamps.len(), 2, "one refusal, one corrected retry");
        assert_near(
            stamps[0],
            device_now(),
            "the first stamp is the device clock",
        );
        assert_near(
            stamps[1],
            c.transport().server_now(),
            "the retry is the server's clock",
        );
    }

    #[tokio::test]
    async fn a_device_91_s_slow_is_refused_once_then_signs_at_the_servers_clock() {
        let c = skewed_client(SkewedServer::new(91, true));

        c.subscription()
            .await
            .expect("the corrected stamp is accepted");

        let stamps = c.transport().stamps();
        assert_eq!(stamps.len(), 2);
        assert_near(
            stamps[1],
            c.transport().server_now(),
            "the retry is the server's clock",
        );
    }

    /// The relay list is `public, max-age=60`: a cache can hand it back with
    /// the `Date` it was first served under. Such a `Date` must never move a
    /// right clock's stamp out of the window, so only a refusal teaches.
    #[tokio::test]
    async fn a_stale_date_on_an_unsigned_answer_does_not_move_the_stamp() {
        let mut server = SkewedServer::new(0, true);
        server.unsigned_date_lag = 90;
        let c = skewed_client(server);
        c.list_exits().await.expect("unsigned read");

        c.subscription().await.expect("accepted first time");

        let stamps = c.transport().stamps();
        assert_eq!(stamps.len(), 1, "no refusal");
        assert_near(stamps[0], device_now(), "still the device clock");
    }

    /// The refusal teaches the clock once: every later call of the client is
    /// stamped right the first time.
    #[tokio::test]
    async fn a_learned_correction_is_kept_for_the_next_calls() {
        let c = skewed_client(SkewedServer::new(-91, false));
        c.subscription().await.expect("corrected");

        c.subscription().await.expect("accepted first time");

        let stamps = c.transport().stamps();
        assert_eq!(stamps.len(), 3, "one refusal, then two accepted stamps");
        assert_near(
            stamps[2],
            c.transport().server_now(),
            "stamped at the server's clock",
        );
    }

    /// The retry is spent once: a corrected stamp refused for another reason
    /// (the key) is that refusal, after exactly two calls.
    #[tokio::test]
    async fn a_corrected_stamp_refused_for_another_reason_is_a_server_status() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let c = fallback_client(ScriptedTransport::new(move |_| {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let server_now = device_now() - 91;
            let date = httpdate::fmt_http_date(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(server_now),
            );
            let body = if call == 0 {
                r#"{"error":"clock_skew"}"#
            } else {
                ""
            };
            Ok(HttpResponse::new(401, body.as_bytes().to_vec()).with_date(date))
        }));

        let err = c.subscription().await.expect_err("refused");

        assert!(
            matches!(err, ClientError::ServerStatus { status: 401, .. }),
            "got {err:?}"
        );
        assert_eq!(c.transport().attempts.lock().unwrap().len(), 2);
    }

    /// A device whose clock is right must come out exactly as it went in: one
    /// request, stamped with the device clock.
    #[tokio::test]
    async fn a_right_clock_is_signed_once_on_the_device_clock() {
        let c = skewed_client(SkewedServer::new(0, true));

        c.subscription().await.expect("ok");
        c.subscription().await.expect("ok");

        let stamps = c.transport().stamps();
        assert_eq!(stamps.len(), 2, "no retry for either call");
        assert_near(stamps[1], device_now(), "still the device clock");
        assert_eq!(c.server_clock().applied_offset_secs(), 0);
    }

    /// Past the forward bound the answer does not get to choose the instant
    /// the wallet signs at: no retry, and the refusal is named for what it is.
    #[tokio::test]
    async fn a_server_further_ahead_than_the_bound_is_not_followed_and_names_the_clock() {
        let c = skewed_client(SkewedServer::new(3_600, false));

        let err = c.subscription().await.expect_err("refused");

        assert_eq!(
            c.transport().stamps().len(),
            1,
            "the stamp was not moved, so no retry"
        );
        let ClientError::ClockSkew { offset_secs } = err else {
            panic!(
                "a bare 401 whose Date shows the stamp outside the window is a clock refusal, got {err:?}"
            );
        };
        let offset = offset_secs.expect("the answer carried a Date");
        assert!((3_598..=3_602).contains(&offset), "offset {offset}");
    }

    #[tokio::test]
    async fn the_clock_body_names_the_clock_even_without_a_date() {
        let mut server = SkewedServer::new(3_600, true);
        server.sends_date = false;
        let c = skewed_client(server);

        let err = c.subscription().await.expect_err("refused");

        assert!(
            matches!(err, ClientError::ClockSkew { offset_secs: None }),
            "got {err:?}"
        );
    }

    /// A 401 on a right clock is a key problem, not a clock one: it must not
    /// be retried nor named for the clock.
    #[tokio::test]
    async fn a_bare_401_on_a_right_clock_stays_a_server_status() {
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let c = fallback_client(ScriptedTransport::new(move |_| {
            Ok(HttpResponse::new(401, Vec::new()).with_date(date.clone()))
        }));

        let err = c.subscription().await.expect_err("refused");

        assert!(
            matches!(err, ClientError::ServerStatus { status: 401, .. }),
            "got {err:?}"
        );
        assert_eq!(c.transport().attempts.lock().unwrap().len(), 1, "no retry");
    }

    /// One wallet, one clock: a client built on a shared [`ServerClock`]
    /// stamps with what any other client of it learned.
    #[tokio::test]
    async fn clients_sharing_a_server_clock_share_what_it_learned() {
        let clock = std::sync::Arc::new(ServerClock::new());
        let first = skewed_client(SkewedServer::new(-91, false)).with_server_clock(clock.clone());
        first.subscription().await.expect("corrected");

        let second = skewed_client(SkewedServer::new(-91, false)).with_server_clock(clock);
        second.subscription().await.expect("accepted first time");

        assert_eq!(second.transport().stamps().len(), 1);
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
