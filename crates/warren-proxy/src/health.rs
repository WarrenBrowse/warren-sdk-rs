//! Local liveness endpoint.
//!
//! A deliberately tiny HTTP/1.1 responder (no framework: the attack surface
//! of a health port should be a request line and three routes):
//!
//! - `/healthz`: `200 ok` when the tunnel is `Connected` AND first egress was
//!   verified, `503` otherwise. Wire it to Docker `HEALTHCHECK` / Kubernetes
//!   probes.
//! - `/state`: the current [`ConnectionState`] as text, always `200`.
//! - `/port`: the granted public forward port as text, `404` while unset.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use warren_sdk::ConnectionState;

/// Shared view the responder renders from.
#[derive(Clone)]
pub struct HealthView {
    /// Supervised tunnel state.
    pub state_rx: watch::Receiver<ConnectionState>,
    /// Set once the first SOCKS egress probe succeeded.
    pub egress_verified: Arc<AtomicBool>,
    /// Granted public forward port, if forwarding is on and granted.
    pub port_rx: watch::Receiver<Option<u16>>,
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

/// Serves the health endpoint until the task is dropped.
pub async fn serve(listener: tokio::net::TcpListener, view: HealthView) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let view = view.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let Ok(n) = stream.read(&mut buf).await else {
                return;
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            let (status, body) = render(
                path,
                *view.state_rx.borrow(),
                view.egress_verified.load(Ordering::Relaxed),
                *view.port_rx.borrow(),
            );
            let reason = match status {
                200 => "OK",
                503 => "Service Unavailable",
                _ => "Not Found",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Synchronous `/healthz` probe for the `warren-proxy healthcheck`
/// subcommand (the container HEALTHCHECK shape: the binary probes its own
/// daemon, so the image needs no shell and no wget).
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let (_port_tx, port_rx) = watch::channel(None);
        let verified = Arc::new(AtomicBool::new(true));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let view = HealthView {
            state_rx,
            egress_verified: Arc::clone(&verified),
            port_rx,
        };
        let server = tokio::spawn(serve(listener, view));

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

    #[tokio::test]
    async fn serves_healthz_over_real_tcp() {
        let (_state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let (_port_tx, port_rx) = watch::channel(None);
        let verified = Arc::new(AtomicBool::new(true));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let view = HealthView {
            state_rx,
            egress_verified: Arc::clone(&verified),
            port_rx,
        };
        let server = tokio::spawn(serve(listener, view));

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
}
