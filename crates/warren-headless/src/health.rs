//! Local liveness endpoint.
//!
//! A deliberately tiny HTTP/1.1 responder (no framework: the attack surface
//! of a health port should be a request line and a few routes):
//!
//! - `/healthz`: `200 ok` when the tunnel is `Connected` AND egress is proven
//!   for the epoch running now, `503` otherwise. The proof belongs to its
//!   epoch: leaving `Connected` clears it, and every change that lands back on
//!   `Connected` re-proves it, so a reconnect answers `503` until a fresh
//!   probe passes. Wire it to Docker `HEALTHCHECK` / Kubernetes probes.
//! - `/state`: the current [`ConnectionState`] as text, always `200`.
//! - `/port`: the granted public forward port as text, `404` while unset.
//!
//! A daemon adds its own routes through [`ExtraRoutes`]; they are consulted
//! first, so a binary can serve richer state without this module knowing what
//! that state is.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use warren_sdk::ConnectionState;

use crate::log::Log;

/// One rendered answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteReply {
    /// HTTP status code.
    pub status: u16,
    /// The body, sent as is.
    pub body: String,
    /// The `content-type` header value.
    pub content_type: &'static str,
}

impl RouteReply {
    /// A `text/plain` answer.
    #[must_use]
    pub fn text(status: u16, body: String) -> Self {
        Self {
            status,
            body,
            content_type: "text/plain",
        }
    }

    /// An `application/json` answer.
    #[must_use]
    pub fn json(status: u16, body: String) -> Self {
        Self {
            status,
            body,
            content_type: "application/json",
        }
    }
}

/// One request, as a daemon's own routes see it.
///
/// Enough to authenticate and to tell a read from a write, and nothing more:
/// this responder exists to answer an orchestrator's probe, not to be an HTTP
/// server.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The method, as the client spelled it.
    pub method: &'a str,
    /// The path, with no query string.
    pub path: &'a str,
    /// The `authorization` header value, when one was sent.
    pub authorization: Option<&'a str>,
}

/// The routes one daemon adds on top of the shared three.
pub trait ExtraRoutes: Send + Sync + 'static {
    /// Renders the request, or `None` to fall through to the shared table.
    fn render(&self, request: &Request<'_>) -> Option<RouteReply>;
}

/// Shared view the responder renders from.
#[derive(Clone)]
pub struct HealthView {
    /// Supervised tunnel state.
    pub state_rx: watch::Receiver<ConnectionState>,
    /// Whether an egress probe succeeded on the epoch running now. The daemon
    /// clears it on any state that is not `Connected` and re-proves it on
    /// every change that lands on `Connected`.
    pub egress_verified: Arc<AtomicBool>,
    /// Granted public forward port, if forwarding is on and granted.
    pub port_rx: watch::Receiver<Option<u16>>,
    /// The daemon's own routes, consulted before the shared table.
    pub extra: Option<Arc<dyn ExtraRoutes>>,
}

impl HealthView {
    /// The three shared routes and nothing else.
    #[must_use]
    pub fn new(
        state_rx: watch::Receiver<ConnectionState>,
        egress_verified: Arc<AtomicBool>,
        port_rx: watch::Receiver<Option<u16>>,
    ) -> Self {
        Self {
            state_rx,
            egress_verified,
            port_rx,
            extra: None,
        }
    }

    /// The same view, plus a daemon's own routes.
    #[must_use]
    pub fn with_routes(mut self, extra: Arc<dyn ExtraRoutes>) -> Self {
        self.extra = Some(extra);
        self
    }
}

/// Renders the response for a request path: `(status, body)`.
#[must_use]
pub fn render(
    path: &str,
    state: ConnectionState,
    egress_verified: bool,
    port: Option<u16>,
) -> (u16, String) {
    match path {
        "/healthz" => {
            if state == ConnectionState::Connected && egress_verified {
                (200, "ok\n".to_owned())
            } else {
                (503, format!("{state:?}\n"))
            }
        }
        "/state" => (200, format!("{state:?}\n")),
        "/port" => match port {
            Some(p) => (200, format!("{p}\n")),
            None => (404, "no forwarded port\n".to_owned()),
        },
        _ => (404, "not found\n".to_owned()),
    }
}

/// How long a client has to send its request line. A probe that connects and
/// says nothing would otherwise hold a task for the life of the daemon.
const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Pause after a failed `accept`, so a persistent error (the process out of
/// file descriptors) costs a slow retry loop instead of a burnt core.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// How long a failed egress recheck waits before asking the same epoch again,
/// and the cap it backs off to. An epoch that never ends publishes no further
/// state change, so without this one transient failure latches the endpoint
/// unhealthy for the life of the process.
const EGRESS_RECHECK_RETRY_MIN: std::time::Duration = std::time::Duration::from_millis(250);
const EGRESS_RECHECK_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(5);

/// Serves the health endpoint until the task is dropped.
pub async fn serve(listener: tokio::net::TcpListener, view: HealthView) {
    loop {
        let accepted = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        tokio::spawn(handle_connection(
            accepted.0,
            view.clone(),
            REQUEST_READ_TIMEOUT,
        ));
    }
}

/// Answers one client: read the request line under `read_timeout`, render, close.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    view: HealthView,
    read_timeout: std::time::Duration,
) {
    let mut buf = [0u8; 1024];
    let Ok(Ok(n)) = tokio::time::timeout(read_timeout, stream.read(&mut buf)).await else {
        return;
    };
    let raw = String::from_utf8_lossy(&buf[..n]);
    let mut start = raw.lines().next().unwrap_or_default().split_whitespace();
    let method = start.next().unwrap_or("GET");
    let path = start.next().unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);
    let request = Request {
        method,
        path,
        authorization: header(&raw, "authorization"),
    };
    let reply = view
        .extra
        .as_ref()
        .and_then(|extra| extra.render(&request))
        .unwrap_or_else(|| {
            let (status, body) = render(
                path,
                *view.state_rx.borrow(),
                view.egress_verified.load(Ordering::Relaxed),
                *view.port_rx.borrow(),
            );
            RouteReply::text(status, body)
        });
    let reason = reason(reply.status);
    let response = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        reply.status,
        reply.content_type,
        reply.body.len(),
        reply.body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// One header's value, matched without regard to case as HTTP requires.
fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// The reason phrase of a status this responder answers with.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Not Found",
    }
}

/// Synchronous `/healthz` probe for the `healthcheck` subcommand (the
/// container HEALTHCHECK shape: the binary probes its own daemon, so the image
/// needs no shell and no wget).
///
/// # Errors
///
/// I/O errors reaching the endpoint; `Ok(false)` when it answered non-200.
pub fn probe_healthz(addr: std::net::SocketAddr) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};
    let timeout = std::time::Duration::from_secs(8);
    let mut stream = std::net::TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nhost: healthcheck\r\nconnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response.starts_with("HTTP/1.1 200"))
}

/// Keeps `/healthz` honest across reconnects.
///
/// The first-egress proof belongs to the epoch it was measured on, so leaving
/// `Connected` clears it and the next `Connected` has to prove egress again
/// before the endpoint reports 200. Without this an orchestrator routes traffic
/// into a rebuilt tunnel nobody has probed, on the strength of the previous
/// epoch's result.
pub async fn track_egress_across_epochs<R, Fut>(
    log: Log,
    mut state_rx: watch::Receiver<ConnectionState>,
    egress_verified: Arc<AtomicBool>,
    mut recheck: R,
) where
    R: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    // A change raised since this receiver was cloned is still pending on the
    // first poll (tokio marks the version at clone time), which is what makes
    // cloning it before the first egress probe enough to cover that probe.
    let mut retry_in = None;
    loop {
        match retry_in {
            None => {
                if state_rx.changed().await.is_err() {
                    return;
                }
            }
            Some(delay) => {
                // A retry that ignored the state would prove an epoch that has
                // already been replaced, so whichever comes first wins.
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
            }
        }
        if *state_rx.borrow_and_update() != ConnectionState::Connected {
            egress_verified.store(false, Ordering::Relaxed);
            retry_in = None;
            continue;
        }
        // Every change that lands on Connected is re-proven, including a
        // republication of a state that never left. A watch channel coalesces,
        // so a short Reconnecting between two polls is invisible here: probing
        // once too often costs three quick connects, while trusting a state
        // this task cannot distinguish would report 200 on an unproven epoch.
        let proven = recheck().await;
        egress_verified.store(proven, Ordering::Relaxed);
        if proven {
            log.info("egress re-verified for the current epoch");
            retry_in = None;
        } else {
            if retry_in.is_none() {
                log.error("egress is not proven on this epoch, staying unhealthy");
            }
            retry_in = Some(next_recheck_delay(retry_in));
        }
    }
}

/// Backs a recheck off from [`EGRESS_RECHECK_RETRY_MIN`] to
/// [`EGRESS_RECHECK_RETRY_MAX`], so a transient failure is answered in a
/// quarter of a second while a long outage costs one probe every five.
fn next_recheck_delay(current: Option<std::time::Duration>) -> std::time::Duration {
    match current {
        None => EGRESS_RECHECK_RETRY_MIN,
        Some(delay) => delay.saturating_mul(2).min(EGRESS_RECHECK_RETRY_MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: Log = Log("warren-headless-test");

    fn view(state_rx: watch::Receiver<ConnectionState>, verified: Arc<AtomicBool>) -> HealthView {
        let (_port_tx, port_rx) = watch::channel(None);
        // The sender is dropped: a watch receiver keeps reading the last value
        // after its sender is gone, which is all these tests need.
        HealthView::new(state_rx, verified, port_rx)
    }

    #[test]
    fn healthz_needs_connected_and_verified_egress() {
        assert_eq!(
            render("/healthz", ConnectionState::Connected, true, None).0,
            200
        );
        assert_eq!(
            render("/healthz", ConnectionState::Connected, false, None).0,
            503,
            "Connected without verified egress is not healthy"
        );
        assert_eq!(
            render("/healthz", ConnectionState::Reconnecting, true, None).0,
            503
        );
        assert_eq!(
            render("/healthz", ConnectionState::Failed, true, None).0,
            503
        );
    }

    #[test]
    fn state_is_always_ok_and_names_the_state() {
        let (status, body) = render("/state", ConnectionState::Reconnecting, false, None);
        assert_eq!(status, 200);
        assert_eq!(body, "Reconnecting\n");
    }

    #[test]
    fn port_is_404_until_granted() {
        assert_eq!(
            render("/port", ConnectionState::Connected, true, None).0,
            404
        );
        let (status, body) = render("/port", ConnectionState::Connected, true, Some(51820));
        assert_eq!(status, 200);
        assert_eq!(body, "51820\n");
    }

    #[test]
    fn unknown_path_is_404() {
        assert_eq!(
            render("/nope", ConnectionState::Connected, true, None).0,
            404
        );
    }

    #[tokio::test]
    async fn probe_healthz_matches_the_served_state() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, view(state_rx, Arc::clone(&verified))));

        let healthy = tokio::task::spawn_blocking(move || probe_healthz(addr))
            .await
            .unwrap()
            .expect("probe must reach the endpoint");
        assert!(healthy, "Connected + verified must probe healthy");

        state_tx.send(ConnectionState::Reconnecting).unwrap();
        let unhealthy = tokio::task::spawn_blocking(move || probe_healthz(addr))
            .await
            .unwrap()
            .expect("probe must reach the endpoint");
        assert!(!unhealthy, "Reconnecting must probe unhealthy");
        server.abort();
    }

    /// A probe that connects and says nothing (a half-open TCP scan, a wedged
    /// orchestrator) must not pin a task for the life of the daemon.
    #[tokio::test]
    async fn a_client_that_never_sends_is_dropped_at_the_read_timeout() {
        let (_state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let view = view(state_rx, Arc::new(AtomicBool::new(true)));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, view, std::time::Duration::from_millis(50)).await;
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut response = Vec::new();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await;

        assert!(
            closed.is_ok(),
            "a silent client must be dropped at the read timeout, not held forever"
        );
        assert!(
            response.is_empty(),
            "no request was sent, so there is nothing to answer"
        );
        server.abort();
    }

    #[tokio::test]
    async fn serves_healthz_over_real_tcp() {
        let (_state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(
            listener,
            view(state_rx, Arc::new(AtomicBool::new(true))),
        ));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
        assert!(response.ends_with("ok\n"), "got: {response}");
        server.abort();
    }

    struct OneRoute;

    impl ExtraRoutes for OneRoute {
        fn render(&self, request: &Request<'_>) -> Option<RouteReply> {
            match (request.method, request.path) {
                ("GET", "/status") => Some(RouteReply::json(200, "{\"gate\":\"open\"}".to_owned())),
                // A route that only a bearer opens, to pin that the responder
                // hands the header and the method through.
                ("POST", "/admin/reload") if request.authorization == Some("Bearer opensesame") => {
                    Some(RouteReply::text(200, "reloaded\n".to_owned()))
                }
                (_, "/admin/reload") => Some(RouteReply::text(401, "unauthorized\n".to_owned())),
                _ => None,
            }
        }
    }

    /// A daemon's own route is served with its own content type, and a path it
    /// does not claim still falls through to the shared table, so adding
    /// routes can never shadow `/healthz`.
    #[tokio::test]
    async fn a_daemon_route_is_served_and_the_shared_table_still_answers() {
        let (_state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let view = view(state_rx, Arc::new(AtomicBool::new(true))).with_routes(Arc::new(OneRoute));
        let server = tokio::spawn(serve(listener, view));

        let get = |path: &'static str| async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        };

        let status = get("/status").await;
        assert!(status.starts_with("HTTP/1.1 200 OK"), "got: {status}");
        assert!(
            status.contains("content-type: application/json"),
            "got: {status}"
        );
        assert!(status.ends_with("{\"gate\":\"open\"}"), "got: {status}");

        let healthz = get("/healthz").await;
        assert!(healthz.ends_with("ok\n"), "got: {healthz}");
        server.abort();
    }

    /// A route that authenticates needs the method and the bearer, and a
    /// client is free to spell the header name in any case it likes.
    #[tokio::test]
    async fn a_daemon_route_sees_the_method_and_the_authorization_header() {
        let (_state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let view = view(state_rx, Arc::new(AtomicBool::new(true))).with_routes(Arc::new(OneRoute));
        let server = tokio::spawn(serve(listener, view));

        let send = |request: String| async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        };

        let authorized = send(
            "POST /admin/reload HTTP/1.1\r\nhost: x\r\nAuthorization: Bearer opensesame\r\n\r\n"
                .to_owned(),
        )
        .await;
        assert!(
            authorized.starts_with("HTTP/1.1 200 OK"),
            "got: {authorized}"
        );

        let bare = send("POST /admin/reload HTTP/1.1\r\nhost: x\r\n\r\n".to_owned()).await;
        assert!(
            bare.starts_with("HTTP/1.1 401 Unauthorized"),
            "a request with no bearer must be refused, and named: {bare}"
        );

        let read_only = send(
            "GET /admin/reload?after=now HTTP/1.1\r\nhost: x\r\nauthorization: Bearer opensesame\r\n\r\n"
                .to_owned(),
        )
        .await;
        assert!(
            read_only.starts_with("HTTP/1.1 401"),
            "the method reaches the route, and a query string is not part of the path: {read_only}"
        );
        server.abort();
    }

    /// Polls a latch until it reads `want`, so the assertions do not race the
    /// tracker task. Bounded, so a regression fails instead of hanging.
    async fn wait_for(flag: &AtomicBool, want: bool, what: &str) {
        for _ in 0..200u32 {
            if flag.load(Ordering::Relaxed) == want {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("{what} (still {}) after 1 s", !want);
    }

    /// A recheck that fails once on an epoch that never leaves `Connected`
    /// must not latch the endpoint at 503 for the life of the process: a
    /// healthy tunnel publishes no further state change, so a tracker that
    /// only re-proves on a transition never asks again.
    #[tokio::test]
    async fn a_recheck_that_fails_once_is_retried_on_the_same_epoch() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let answer = Arc::new(AtomicBool::new(false));

        let task = tokio::spawn({
            let verified = Arc::clone(&verified);
            let answer = Arc::clone(&answer);
            track_egress_across_epochs(LOG, state_rx, verified, move || {
                let answer = Arc::clone(&answer);
                async move { answer.load(Ordering::Relaxed) }
            })
        });

        state_tx.send(ConnectionState::Connected).unwrap();
        wait_for(&verified, false, "a failed recheck must clear the latch").await;

        // The transient is over, and the epoch it happened on is still running.
        answer.store(true, Ordering::Relaxed);
        wait_for(
            &verified,
            true,
            "the retry must re-prove the epoch that never ended",
        )
        .await;
        task.abort();
    }

    /// The egress proof belongs to the epoch it was measured on. Reporting 200
    /// again on the strength of the previous epoch's probe is what makes an
    /// orchestrator route traffic into a tunnel nobody has proven.
    #[tokio::test]
    async fn a_reconnect_clears_the_egress_proof_and_reproves_it() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let task = tokio::spawn({
            let verified = Arc::clone(&verified);
            let probes = Arc::clone(&probes);
            track_egress_across_epochs(LOG, state_rx, verified, move || {
                let probes = Arc::clone(&probes);
                async move {
                    probes.fetch_add(1, Ordering::Relaxed);
                    true
                }
            })
        });

        state_tx.send(ConnectionState::Reconnecting).unwrap();
        wait_for(
            &verified,
            false,
            "leaving Connected must clear the egress proof",
        )
        .await;
        assert_eq!(
            probes.load(Ordering::Relaxed),
            0,
            "nothing to probe while the tunnel is down"
        );

        state_tx.send(ConnectionState::Connected).unwrap();
        wait_for(
            &verified,
            true,
            "a re-proven epoch must report healthy again",
        )
        .await;
        assert_eq!(
            probes.load(Ordering::Relaxed),
            1,
            "the new epoch must be proven by its own probe"
        );
        task.abort();
    }

    /// A watch channel coalesces, so a `Reconnecting` raised and cleared
    /// between two polls of this task is invisible to it. Re-proving on every
    /// change that lands on `Connected` is what keeps that invisible epoch from
    /// being reported healthy on the previous epoch's evidence.
    #[tokio::test]
    async fn a_republished_connected_state_is_re_proven_rather_than_trusted() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let task = tokio::spawn({
            let verified = Arc::clone(&verified);
            let probes = Arc::clone(&probes);
            track_egress_across_epochs(LOG, state_rx, verified, move || {
                let probes = Arc::clone(&probes);
                async move {
                    probes.fetch_add(1, Ordering::Relaxed);
                    true
                }
            })
        });

        state_tx.send(ConnectionState::Connected).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(
            probes.load(Ordering::Relaxed),
            1,
            "a state change this task cannot interpret is re-proven, not trusted"
        );
        assert!(
            verified.load(Ordering::Relaxed),
            "and the fresh probe passed, so the endpoint stays green"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_reconnected_epoch_that_does_not_egress_stays_unhealthy() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));

        let task = tokio::spawn({
            let verified = Arc::clone(&verified);
            track_egress_across_epochs(LOG, state_rx, verified, || async { false })
        });

        state_tx.send(ConnectionState::Reconnecting).unwrap();
        state_tx.send(ConnectionState::Connected).unwrap();
        wait_for(
            &verified,
            false,
            "an epoch whose egress probe fails must not report healthy",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !verified.load(Ordering::Relaxed),
            "a failed recheck must leave the latch clear"
        );
        task.abort();
    }
}
