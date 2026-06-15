use std::sync::Arc;

use warren_discovery::VerifiedExit;
use warren_net::MultihopPacketSink;
use warren_transport::{Backoff, ConnectionState, MultihopClientTunnel};

use crate::error::SdkError;
use crate::proxy::{addressing_from_session, build_netstack_config};

/// An established tunnel plus the netstack addressing derived from its `IpAssign`.
/// Generic over the sink so the supervisor loop is unit-testable with a fake sink.
pub(crate) struct EstablishedTunnel<S> {
    pub(crate) sink: S,
    pub(crate) local_ip: std::net::Ipv4Addr,
    pub(crate) prefix: u8,
    pub(crate) gateway: std::net::Ipv4Addr,
    pub(crate) ipv6: Option<warren_net::Ipv6Addressing>,
}

/// A self-healing proxy datapath (see
/// [`WarrenClient::start_proxy_multihop_supervised`]). The local proxy
/// address(es) stay stable while the supervisor rebuilds the tunnel across drops.
/// Dropping the handle stops the supervisor and the datapath.
pub struct SupervisedProxyHandle {
    pub(crate) local_addr: std::net::SocketAddr,
    pub(crate) http_addr: Option<std::net::SocketAddr>,
    pub(crate) state_rx: tokio::sync::watch::Receiver<ConnectionState>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

impl SupervisedProxyHandle {
    /// The stable SOCKS5 listener address the app points at across reconnects.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// The stable HTTP CONNECT listener address, if one was configured.
    #[must_use]
    pub fn http_addr(&self) -> Option<std::net::SocketAddr> {
        self.http_addr
    }

    /// The current connection state ([`ConnectionState::Connecting`] until the
    /// first tunnel is up, then `Connected`/`Reconnecting` as it heals).
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        *self.state_rx.borrow()
    }

    /// A watch receiver for state changes, so an app can await transitions
    /// (`state_rx.changed().await`) rather than poll [`Self::state`].
    #[must_use]
    pub fn watch_state(&self) -> tokio::sync::watch::Receiver<ConnectionState> {
        self.state_rx.clone()
    }

    /// Stops the supervisor and tears down the datapath.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

impl Drop for SupervisedProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Resolves once the datapath's tunnel read side closes (or the engine is gone),
/// the signal a supervisor uses to tear the serve loops down and reconnect.
pub(crate) async fn wait_until_dead(mut alive_rx: tokio::sync::watch::Receiver<bool>) {
    while *alive_rx.borrow_and_update() {
        if alive_rx.changed().await.is_err() {
            return;
        }
    }
}

/// Aborts the wrapped task when dropped, so a spawned helper cannot outlive the
/// scope that owns it (even if that scope is itself cancelled).
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serves SOCKS5 (and optional HTTP CONNECT) on the *borrowed* stable listeners
/// using `connector`, until the tunnel dies (or an accept loop fails). Returns so
/// the supervisor can rebuild and resume on the same listeners.
pub(crate) async fn serve_epoch(
    socks_listener: &tokio::net::TcpListener,
    http_listener: Option<&tokio::net::TcpListener>,
    connector: warren_net::TunnelConnector,
    alive_rx: tokio::sync::watch::Receiver<bool>,
) {
    // `run` gates both accept loops; the bridge flips it off when the tunnel dies.
    // Wrapped in `AbortOnDrop` so cancelling this future (handle dropped mid-epoch)
    // does not leak the bridge task: it is aborted whether we return or are dropped.
    let (run_tx, run_rx) = tokio::sync::watch::channel(true);
    let _bridge = AbortOnDrop(tokio::spawn(async move {
        wait_until_dead(alive_rx).await;
        let _ = run_tx.send(false);
    }));
    let socks = warren_net::Socks5Proxy::new(connector.clone());
    // `select!`, not `join!`: the first loop to return ends the epoch. On tunnel
    // death the bridge flips `run` and whichever loop sees it first returns; if an
    // accept loop instead fails on its own, that also ends the epoch (a `join!`
    // would hang waiting on the still-running sibling while the tunnel is alive).
    match http_listener {
        Some(http_listener) => {
            let http = warren_net::HttpConnectProxy::new(connector);
            tokio::select! {
                _ = socks.serve_with_udp_until(socks_listener, run_rx.clone()) => {}
                _ = http.serve_until(http_listener, run_rx) => {}
            }
        }
        None => {
            let _ = socks.serve_with_udp_until(socks_listener, run_rx).await;
        }
    }
}

/// Supervises a proxy datapath across tunnel rebuilds, keeping the local
/// listeners (and thus the app-facing proxy addresses) stable: it establishes a
/// tunnel, serves until the tunnel dies, then reconnects (immediately after a
/// drop, with capped exponential backoff between failed attempts), reporting each
/// [`ConnectionState`] transition. `connect` is the (re)establish closure; it is
/// generic so the loop is testable with a fake sink and a fake connector.
pub(crate) async fn supervise_proxy<S, F, Fut>(
    socks_listener: tokio::net::TcpListener,
    http_listener: Option<tokio::net::TcpListener>,
    dns_server: Option<std::net::Ipv4Addr>,
    state_tx: tokio::sync::watch::Sender<ConnectionState>,
    mut connect: F,
) where
    S: warren_net::PacketSink + 'static,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<EstablishedTunnel<S>, SdkError>>,
{
    // A session that stayed up at least this long is treated as healthy, so its
    // next reconnect starts fresh. A shorter one is "flapping" (the exit accepts
    // the handshake then drops immediately): apply backoff so we do not tight-loop
    // full cryptographic handshakes and hammer the exit.
    const MIN_HEALTHY_UPTIME: std::time::Duration = std::time::Duration::from_secs(5);
    // Full-jitter backoff (base 250 ms, ceiling 20 s) so many clients losing the
    // same exit at once do not reconnect in a synchronized wave (thundering herd).
    let mut backoff = Backoff {
        base: std::time::Duration::from_millis(250),
        max: std::time::Duration::from_secs(20),
    }
    .forever();
    let mut first = true;
    loop {
        let _ = state_tx.send(if first {
            ConnectionState::Connecting
        } else {
            ConnectionState::Reconnecting
        });
        first = false;
        match connect().await {
            Ok(est) => {
                let config = build_netstack_config(
                    &est.sink,
                    est.local_ip,
                    est.prefix,
                    est.gateway,
                    est.ipv6,
                    dns_server,
                );
                let (connector, alive_rx) = warren_net::spawn_over_sink(Arc::new(est.sink), config);
                let _ = state_tx.send(ConnectionState::Connected);
                let up_since = std::time::Instant::now();
                serve_epoch(&socks_listener, http_listener.as_ref(), connector, alive_rx).await;
                // The tunnel died. A healthy session resets backoff and reconnects
                // at once; a flapping one (died almost immediately) backs off first.
                if up_since.elapsed() >= MIN_HEALTHY_UPTIME {
                    backoff.reset();
                } else {
                    tokio::time::sleep(backoff.next_delay()).await;
                }
            }
            Err(_) => {
                // No identity material is logged. Back off before the next attempt.
                tokio::time::sleep(backoff.next_delay()).await;
            }
        }
    }
}

/// Opens a sealed multihop tunnel to `exit` and packages it with the netstack
/// addressing derived from its fresh `IpAssign`. The (re)connect step shared by
/// the supervised single-exit and failover datapaths.
pub(crate) async fn establish_multihop(
    signing: warren_identity::ed25519_dalek::SigningKey,
    exit: &VerifiedExit,
) -> Result<EstablishedTunnel<MultihopPacketSink>, SdkError> {
    let session = MultihopClientTunnel::new(signing)
        .connect(
            exit.exit_ed25519_pubkey,
            exit.exit_x25519_multihop_pubkey,
            exit.exit_id,
            exit.endpoint,
        )
        .await?;
    let sink = MultihopPacketSink::new(session);
    let (local_ip, prefix, gateway, ipv6) = addressing_from_session(sink.session());
    Ok(EstablishedTunnel {
        sink,
        local_ip,
        prefix,
        gateway,
        ipv6,
    })
}
