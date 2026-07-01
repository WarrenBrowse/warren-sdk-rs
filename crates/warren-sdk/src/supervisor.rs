use std::net::SocketAddr;
use std::sync::Arc;

use warren_discovery::VerifiedExit;
use warren_net::{ForwardedPort, MapProto, MultihopPacketSink};
use warren_transport::{Backoff, ConnectionState, MultihopClientTunnel};

use crate::error::SdkError;
use crate::proxy::{ProxyForwarder, addressing_from_session, build_netstack_config};

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
/// [`WarrenClient::start_proxy_multihop_supervised`](crate::WarrenClient::start_proxy_multihop_supervised)).
/// The local proxy
/// address(es) stay stable while the supervisor rebuilds the tunnel across drops.
/// Dropping the handle stops the supervisor and the datapath.
pub struct SupervisedProxyHandle {
    pub(crate) local_addr: std::net::SocketAddr,
    pub(crate) http_addr: Option<std::net::SocketAddr>,
    pub(crate) state_rx: tokio::sync::watch::Receiver<ConnectionState>,
    /// The forwarder for the current epoch, republished by the supervisor on
    /// every (re)connect and cleared (`None`) while the tunnel is down. Drives
    /// the self-healing port forwards.
    pub(crate) forwarder_rx: tokio::sync::watch::Receiver<Option<ProxyForwarder>>,
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

    /// Forwards a tunnel-side port that survives reconnects: maps `internal_port`
    /// at the exit via NAT-PMP and relays inbound connections to `local_target`,
    /// re-establishing the mapping on every tunnel rebuild. The returned
    /// [`SupervisedForwardedPort`] keeps it alive until dropped.
    ///
    /// The forward asks the exit to re-grant the previously-allocated external
    /// port on every rebuild, so the public port "follows" the client and stays
    /// stable across reconnects/exit-changes. If the new exit already has that
    /// port taken it answers strictly (no silent random fallback) and the
    /// mapping stays unset for that epoch, so still read the live value from
    /// [`SupervisedForwardedPort::external_port`] rather than caching it. It is
    /// `None` while the tunnel is down or before the first mapping is granted.
    ///
    /// Needs an exit that runs a NAT-PMP gateway; not every exit does.
    #[must_use]
    pub fn forward_port(
        &self,
        proto: MapProto,
        internal_port: u16,
        local_target: SocketAddr,
    ) -> SupervisedForwardedPort {
        let (external_tx, external_rx) = tokio::sync::watch::channel(None);
        let forwarder_rx = self.forwarder_rx.clone();
        let task = tokio::spawn(async move {
            supervise_forward(
                forwarder_rx,
                external_tx,
                move |forwarder, suggested| async move {
                    forwarder
                        .forward_port_with_suggested(proto, internal_port, local_target, suggested)
                        .await
                },
            )
            .await;
        });
        SupervisedForwardedPort {
            internal_port,
            external_rx,
            task,
        }
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

/// A tunnel-side forwarded port that re-establishes itself across reconnects
/// (see [`SupervisedProxyHandle::forward_port`]). Dropping it tears the mapping
/// down (the exit reclaims the port when the lease lapses).
pub struct SupervisedForwardedPort {
    internal_port: u16,
    external_rx: tokio::sync::watch::Receiver<Option<u16>>,
    task: tokio::task::JoinHandle<()>,
}

impl SupervisedForwardedPort {
    /// The local internal port being forwarded (stable for the life of this
    /// handle).
    #[must_use]
    pub fn internal_port(&self) -> u16 {
        self.internal_port
    }

    /// The currently-granted external port remote peers reach the app on, or
    /// `None` while the tunnel is down or the first mapping is not yet granted.
    /// This can change across reconnects, so do not cache it.
    #[must_use]
    pub fn external_port(&self) -> Option<u16> {
        *self.external_rx.borrow()
    }

    /// A watch receiver for external-port changes, so an app can react to a
    /// re-mapping (`rx.changed().await`) rather than poll [`Self::external_port`].
    #[must_use]
    pub fn watch_external_port(&self) -> tokio::sync::watch::Receiver<Option<u16>> {
        self.external_rx.clone()
    }

    /// Tears the forward down.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

impl Drop for SupervisedForwardedPort {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An established forwarded port whose granted external port can be read. Lets
/// [`supervise_forward`] be unit-tested with a fake port (the production type is
/// [`ForwardedPort`]).
pub(crate) trait ExternalPort {
    fn external_port(&self) -> u16;
}

impl ExternalPort for ForwardedPort {
    fn external_port(&self) -> u16 {
        ForwardedPort::external_port(self)
    }
}

/// Drives one forwarded port across tunnel rebuilds: when a forwarder appears
/// (re)connect, it establishes the mapping and publishes the granted external
/// port; when the tunnel goes away (`None`), it drops the mapping and clears the
/// port. Generic over the forwarder and established-port types so the state
/// machine is testable without a real NAT-PMP gateway.
pub(crate) async fn supervise_forward<F, P, E, Fut>(
    mut forwarder_rx: tokio::sync::watch::Receiver<Option<F>>,
    external_tx: tokio::sync::watch::Sender<Option<u16>>,
    mut establish: E,
) where
    F: Clone,
    P: ExternalPort,
    E: FnMut(F, u16) -> Fut,
    Fut: std::future::Future<Output = Result<P, SdkError>>,
{
    // Holding `current` keeps the established port alive; replacing or clearing
    // it drops the previous one, which tears its mapping/relay tasks down.
    let mut current: Option<P> = None;
    // The external port to re-suggest on the next establish so the public port
    // follows the client across reconnects/exit-changes. `0` (auto) for the very
    // first establish; the last-granted port thereafter.
    let mut suggested: u16 = 0;
    loop {
        let snapshot = forwarder_rx.borrow_and_update().clone();
        match snapshot {
            Some(forwarder) if current.is_none() => {
                // A refusal or transient failure leaves the port unset; the next
                // epoch change retries. No identity material is logged.
                if let Ok(port) = establish(forwarder, suggested).await {
                    // Remember this grant so the next establish re-suggests it and
                    // the public port follows the client across reconnects.
                    suggested = port.external_port();
                    let _ = external_tx.send(Some(port.external_port()));
                    current = Some(port);
                }
            }
            Some(_) => {}
            None => {
                if current.take().is_some() {
                    let _ = external_tx.send(None);
                }
            }
        }
        if forwarder_rx.changed().await.is_err() {
            return;
        }
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
pub(crate) async fn supervise_proxy<S, F, Fut, D>(
    socks_listener: tokio::net::TcpListener,
    http_listener: Option<tokio::net::TcpListener>,
    dns_server: Option<std::net::Ipv4Addr>,
    state_tx: tokio::sync::watch::Sender<ConnectionState>,
    forwarder_tx: tokio::sync::watch::Sender<Option<ProxyForwarder>>,
    mut connect: F,
    on_drain: D,
) where
    S: warren_net::PacketSink + 'static,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<EstablishedTunnel<S>, SdkError>>,
    // Invoked once per drain advisory, BEFORE the proactive reconnect (ADR 36).
    // The failover datapath wires this to advance its rotation cursor so the
    // reconnect rotates PAST the draining exit instead of re-dialing it; the
    // single-exit datapath passes a no-op (one pinned exit, nothing to rotate).
    D: Fn(),
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
                let gateway = est.gateway;
                // ADR 36: grab the drain watch before the sink is moved into the
                // netstack engine. `None` for paths that emit no drain signal.
                let drain_rx = est.sink.drain_watch();
                let (connector, alive_rx) = warren_net::spawn_over_sink(Arc::new(est.sink), config);
                // Publish this epoch's forwarder so self-healing port forwards
                // can re-map on the fresh connector; cleared to `None` below when
                // the tunnel dies.
                let _ = forwarder_tx.send(Some(ProxyForwarder {
                    connector: connector.clone(),
                    gateway,
                }));
                let _ = state_tx.send(ConnectionState::Connected);
                let up_since = std::time::Instant::now();
                // Serve until the tunnel dies OR (ADR 36) the exit signals a
                // maintenance drain. A drain wins the race so we reconnect
                // proactively before the exit's hard close, and `on_drain`
                // (below) advances the failover cursor so the reconnect rotates
                // PAST the draining exit directly (no waiting for its hard-close
                // `Err`). Single-exit `on_drain` is a no-op (one pinned exit).
                let drained = match drain_rx {
                    Some(mut rx) => {
                        tokio::select! {
                            () = serve_epoch(
                                &socks_listener, http_listener.as_ref(), connector, alive_rx,
                            ) => false,
                            () = wait_for_drain(&mut rx) => true,
                        }
                    }
                    None => {
                        serve_epoch(&socks_listener, http_listener.as_ref(), connector, alive_rx)
                            .await;
                        false
                    }
                };
                let _ = forwarder_tx.send(None);
                if drained {
                    // Rotate the failover cursor PAST the draining exit so the
                    // reconnect lands on a different one (no-op for single-exit).
                    on_drain();
                    // Surface the maintenance migration to the host right away
                    // with a DISTINCT `Draining` state (ADR 36) so the app can
                    // show "switching server for maintenance" instead of a
                    // generic reconnect; the loop then sends `Reconnecting` as
                    // the actual redial proceeds.
                    let _ = state_tx.send(ConnectionState::Draining);
                    // Proactive drain reconnect: ALWAYS jitter-delay (never
                    // reset) so a pinned single-exit does not tight-loop on the
                    // still-draining exit, and the herd spreads (anti-stampede).
                    tokio::time::sleep(backoff.next_delay()).await;
                } else if up_since.elapsed() >= MIN_HEALTHY_UPTIME {
                    // The tunnel died after a healthy run: reconnect at once.
                    backoff.reset();
                } else {
                    // Flapped (died almost immediately): back off first.
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

/// Resolves when the exit publishes a maintenance-drain advisory on `rx`
/// (ADR 36). Parks forever if the watch sender is dropped (the session ended),
/// so on a natural tunnel death `serve_epoch` wins the race instead of this.
async fn wait_for_drain(
    rx: &mut tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>>,
) {
    loop {
        if rx.borrow_and_update().is_some() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Opens a sealed multihop tunnel to `exit` and packages it with the netstack
/// addressing derived from its fresh `IpAssign`. The (re)connect step shared by
/// the supervised single-exit and failover datapaths.
pub(crate) async fn establish_multihop(
    signing: warren_identity::ed25519_dalek::SigningKey,
    exit: &VerifiedExit,
    auto_local_ip: bool,
    wants_ipv6: bool,
    transport_config: Option<std::sync::Arc<warren_transport::TransportConfig>>,
) -> Result<EstablishedTunnel<MultihopPacketSink>, SdkError> {
    let mut tunnel = MultihopClientTunnel::new(signing);
    if auto_local_ip {
        tunnel = tunnel.with_auto_local_ip();
    }
    if wants_ipv6 {
        tunnel = tunnel.with_ipv6(true);
    }
    if let Some(cfg) = transport_config {
        tunnel = tunnel.with_transport_config(cfg);
    }
    // Thread the cover domain from the verified relay descriptor so the
    // tunnel dials in X.509 WebPKI mode when the relay roster advertises one,
    // and keeps the historical RPK path otherwise.
    if exit.cover_domain.is_some() {
        tunnel = tunnel.with_cover_domain(exit.cover_domain.clone());
    }
    let session = tunnel
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

#[cfg(test)]
mod drain_tests {
    use super::*;
    use std::time::Duration;
    use warren_transport::DrainAdvisory;

    #[tokio::test]
    async fn wait_for_drain_resolves_on_advisory() {
        // A published advisory must win the race so the supervisor reconnects.
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        tx.send(Some(DrainAdvisory {
            deadline_unix_secs: 1_700_000_000,
            reason_code: 0,
        }))
        .expect("receiver live");
        tokio::time::timeout(Duration::from_millis(200), wait_for_drain(&mut rx))
            .await
            .expect("wait_for_drain must resolve once a drain advisory is published");
    }

    #[tokio::test]
    async fn wait_for_drain_parks_when_no_advisory() {
        // No advisory, sender still alive: must NOT resolve (else serve_epoch
        // could never win the race on a healthy tunnel).
        let (_tx, mut rx) = tokio::sync::watch::channel::<Option<DrainAdvisory>>(None);
        assert!(
            tokio::time::timeout(Duration::from_millis(80), wait_for_drain(&mut rx))
                .await
                .is_err(),
            "wait_for_drain must park while the tunnel is healthy (no drain)"
        );
    }

    #[tokio::test]
    async fn wait_for_drain_parks_when_sender_dropped() {
        // Sender dropped (session ended): park forever so `serve_epoch` drives
        // the reconnect on a natural tunnel death, not a phantom drain.
        let (tx, mut rx) = tokio::sync::watch::channel::<Option<DrainAdvisory>>(None);
        drop(tx);
        assert!(
            tokio::time::timeout(Duration::from_millis(80), wait_for_drain(&mut rx))
                .await
                .is_err(),
            "a dropped drain sender must park, never resolve"
        );
    }
}
