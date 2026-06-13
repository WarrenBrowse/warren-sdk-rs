//! The signed Warren account API client.

use rand::RngCore;
use serde::Serialize;
use serde::de::DeserializeOwned;
use warren_identity::WarrenIdentity;

use crate::dto::{
    CheckResponse, RegisterAccountRequest, RegisterAccountResponse, SessionCloseRequest,
    SessionOpenRequest, SessionOpenResponse, SubscriptionResponse,
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
    #[error("server returned status {status}")]
    ServerStatus {
        /// HTTP status code.
        status: u16,
        /// Response body (may carry a server error message).
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

    /// Signed `DELETE /v1/account`. Deletes the account's subscription.
    ///
    /// # Errors
    ///
    /// See [`Self::register`].
    pub async fn delete_account(&self) -> Result<(), ClientError> {
        let http = self.signed_request(Method::Delete, "/v1/account", Vec::new())?;
        self.send(http).await.map(|_| ())
    }

    /// Builds an unsigned request (carries only `accept`/`content-type`).
    fn unsigned_request(&self, method: Method, path: &str, body: Vec<u8>) -> HttpRequest {
        let mut headers = vec![("accept".to_owned(), "application/json".to_owned())];
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
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        let primary_url = request.url.clone();

        // 1. Primary host, with SNI.
        match self.attempt(&request).await? {
            AttemptOutcome::Response(resp) => return self.finish(resp),
            AttemptOutcome::Blocked => {}
        }

        // 2. Alternative hosts, with SNI.
        for host in &self.alternative_hosts {
            let alt = HttpRequest {
                url: replace_host(&primary_url, host),
                ..request.clone()
            };
            match self.attempt(&alt).await? {
                AttemptOutcome::Response(resp) => return self.finish(resp),
                AttemptOutcome::Blocked => {}
            }
        }

        // 3. Primary host, without SNI.
        let no_sni = HttpRequest {
            use_sni: false,
            ..request
        };
        match self.attempt(&no_sni).await? {
            AttemptOutcome::Response(resp) => return self.finish(resp),
            AttemptOutcome::Blocked => {}
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

    type Responder = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

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
        assert_eq!(c.transport.attempts.lock().unwrap().len(), 3);
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
            pubkey_ss58: "wbAAA".to_owned(),
            voucher_secret: "voucher".to_owned(),
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
        let c = client(MockTransport::new(200, r#"{"ip":"1.2.3.4","is_exit":false}"#));
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
        let c = client(MockTransport::new(200, r#"{"admitted":true,"max":5,"current":1}"#));
        let req = SessionOpenRequest {
            pubkey_ss58: "wbAAA".to_owned(),
            device_id_hex: "00".repeat(16),
            exit_id: "exit".to_owned(),
            max_devices: None,
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
            pubkey_ss58: "wbAAA".to_owned(),
            device_id_hex: "00".repeat(16),
        };
        c.close_session(&req).await.expect("ok");
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.url, "https://api.example.test/v1/session/close");
        assert!(header(r, HEADER_PUBKEY).is_some(), "close_session is signed");
    }

    #[tokio::test]
    async fn delete_account_is_signed_delete() {
        let c = client(MockTransport::new(200, ""));
        c.delete_account().await.expect("ok");
        let g = c.transport.last.lock().unwrap();
        let r = g.as_ref().unwrap();
        assert_eq!(r.method, Method::Delete);
        assert_eq!(r.url, "https://api.example.test/v1/account");
        assert!(header(r, HEADER_PUBKEY).is_some(), "delete_account is signed");
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
