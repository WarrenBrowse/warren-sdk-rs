use std::net::SocketAddr;
use std::sync::Arc;

use warren_discovery::VerifiedExit;
use warren_net::{ForwardedPort, MapProto, MultihopPacketSink};
use warren_transport::{Backoff, ConnectionState, FatalCause, MultihopClientTunnel, Retryability};

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

/// Reads the current epoch's datapath counters on demand.
///
/// Type-erased so the non-generic handle can hold it, and it captures a `Weak`
/// to the datapath rather than the datapath itself: a strong reference would
/// keep the QUIC connection alive past the epoch that owns it (quinn closes a
/// connection when its last handle drops), so an observability feature would
/// silently change the tunnel's lifetime. It returns `None` once the epoch is
/// gone, which is the truthful answer.
pub(crate) type MetricsProbe =
    Arc<dyn Fn() -> Option<warren_transport::MultihopMetricsSnapshot> + Send + Sync>;

/// A cheap, cloneable reader of a supervised datapath's live metrics.
///
/// [`SupervisedProxyHandle::metrics`] needs the handle in scope, which a
/// background task (a health probe, a support-report collector) does not have.
/// This detaches the read: clone it into the task and poll it for the life of
/// the session, across reconnects. Like the handle's accessor it observes
/// without owning, so a reader kept forever never extends a datapath's life.
#[derive(Clone)]
pub struct MetricsReader {
    rx: tokio::sync::watch::Receiver<Option<MetricsProbe>>,
}

impl MetricsReader {
    /// The current epoch's counters and path quality, or `None` while the tunnel
    /// is down (or once the session it came from has ended).
    #[must_use]
    pub fn read(&self) -> Option<warren_transport::MultihopMetricsSnapshot> {
        self.rx.borrow().as_ref().and_then(|probe| probe())
    }
}

impl std::fmt::Debug for MetricsReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsReader")
            .field("live", &self.rx.borrow().is_some())
            .finish()
    }
}

/// A self-healing proxy datapath (see
/// [`WarrenClient::start_proxy_supervised`](crate::WarrenClient::start_proxy_supervised)).
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
    /// Reads the current epoch's datapath counters, republished on every
    /// (re)connect and cleared while the tunnel is down.
    pub(crate) metrics_rx: tokio::sync::watch::Receiver<Option<MetricsProbe>>,
    pub(crate) migration_rx:
        tokio::sync::watch::Receiver<Option<crate::portfollow::MigrationEvent>>,
    /// Set once, to the fatal cause, when the supervisor gives up on a fatal
    /// engine verdict (and drives `state` to [`ConnectionState::Failed`]). `None`
    /// while the datapath is healing normally.
    pub(crate) fatal_rx: tokio::sync::watch::Receiver<Option<FatalCause>>,
    /// Why the most recent epoch ended, published just before the
    /// `Reconnecting` state it precedes.
    pub(crate) epoch_end_rx: tokio::sync::watch::Receiver<Option<EpochEnd>>,
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

    /// Why the most recent serving epoch ended, or `None` while the first one is
    /// still running. Published before the `Reconnecting` transition it
    /// precedes, so a host that journals the transition can attach the cause and
    /// stop recording every tunnel death as the same opaque reconnect.
    #[must_use]
    pub fn last_epoch_end(&self) -> Option<EpochEnd> {
        *self.epoch_end_rx.borrow()
    }

    /// A watch receiver for the epoch-end reports, for a host that would rather
    /// await them than sample [`Self::last_epoch_end`].
    #[must_use]
    pub fn watch_epoch_end(&self) -> tokio::sync::watch::Receiver<Option<EpochEnd>> {
        self.epoch_end_rx.clone()
    }

    /// The fatal cause the supervisor stopped on, or `None` while it is healing
    /// normally. Set exactly once, alongside the terminal
    /// [`ConnectionState::Failed`], when a (re)connect failed with a fatal engine
    /// verdict (unauthorized account, device cap, opaque policy refusal): a
    /// rejected user then sees WHY instead of an endless `Reconnecting`.
    #[must_use]
    pub fn last_fatal(&self) -> Option<FatalCause> {
        *self.fatal_rx.borrow()
    }

    /// A watch receiver for the fatal cause, so an app can await the terminal
    /// failure (`rx.changed().await`) and surface the specific reason.
    #[must_use]
    pub fn watch_fatal(&self) -> tokio::sync::watch::Receiver<Option<FatalCause>> {
        self.fatal_rx.clone()
    }

    /// A snapshot of the current epoch's datapath counters and live path quality
    /// (carrier, RTT, PMTU, black holes), or `None` while the tunnel is down.
    ///
    /// The unsupervised [`ProxyHandle::metrics`](crate::ProxyHandle::metrics) is
    /// unreachable for any app that needs reconnection, which is every real one,
    /// so this is the accessor that actually gets used. Read it fresh rather than
    /// caching it: the value belongs to one epoch, and a reconnect replaces the
    /// session it describes.
    #[must_use]
    pub fn metrics(&self) -> Option<warren_transport::MultihopMetricsSnapshot> {
        self.metrics_rx.borrow().as_ref().and_then(|probe| probe())
    }

    /// A detached [`MetricsReader`] for a background task that cannot hold this
    /// handle. Follows reconnects: it always reads the current epoch.
    #[must_use]
    pub fn metrics_reader(&self) -> MetricsReader {
        MetricsReader {
            rx: self.metrics_rx.clone(),
        }
    }

    /// The latest maintenance-migration event
    /// ([`MigrationEvent`](crate::MigrationEvent)), or `None` while no drain has
    /// been seen. Richer than the bare `Draining` state: it carries the drain
    /// advisory's deadline and reason plus the outcome (migrating, completed,
    /// or cancelled because every candidate conflicted with a pinned port).
    #[must_use]
    pub fn last_migration(&self) -> Option<crate::portfollow::MigrationEvent> {
        *self.migration_rx.borrow()
    }

    /// A watch receiver for migration events, so an app can surface
    /// "switching server for maintenance" / "migration postponed, port kept"
    /// as they happen.
    #[must_use]
    pub fn watch_migration(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<crate::portfollow::MigrationEvent>> {
        self.migration_rx.clone()
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
        self.forward_port_with_policy(
            proto,
            internal_port,
            local_target,
            crate::portfollow::PortFollowConfig::default(),
        )
    }

    /// Like [`Self::forward_port`], with an explicit follow policy and knobs
    /// (see [`PortFollowConfig`](crate::PortFollowConfig)): pin the external
    /// port (`KeepPortOrStay`, never degrades), follow it best-effort (the
    /// default; a conflict degrades to a server-assigned port), or disable the
    /// follow. Observe what happened to the port on each rebuild via
    /// [`SupervisedForwardedPort::watch_outcome`].
    #[must_use]
    pub fn forward_port_with_policy(
        &self,
        proto: MapProto,
        internal_port: u16,
        local_target: SocketAddr,
        config: crate::portfollow::PortFollowConfig,
    ) -> SupervisedForwardedPort {
        let (external_tx, external_rx) = tokio::sync::watch::channel(None);
        let (outcome_tx, outcome_rx) = tokio::sync::watch::channel(None);
        let forwarder_rx = self.forwarder_rx.clone();
        let task = tokio::spawn(async move {
            supervise_forward(
                forwarder_rx,
                external_tx,
                outcome_tx,
                config,
                move |forwarder: ProxyForwarder, suggested| async move {
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
            outcome_rx,
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
    outcome_rx: tokio::sync::watch::Receiver<Option<crate::portfollow::PortFollowOutcome>>,
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

    /// What happened to this rule's external port on the latest (re)establish
    /// ([`PortFollowOutcome`](crate::PortFollowOutcome)): kept, changed to a new
    /// server pick, held back by a conflict, or failed. `None` before the first
    /// establish attempt completes.
    #[must_use]
    pub fn last_outcome(&self) -> Option<crate::portfollow::PortFollowOutcome> {
        *self.outcome_rx.borrow()
    }

    /// A watch receiver for follow outcomes, so an app can surface "port
    /// re-mapped" / "new auto port" / "conflict, port held" as they happen.
    #[must_use]
    pub fn watch_outcome(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<crate::portfollow::PortFollowOutcome>> {
        self.outcome_rx.clone()
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
/// (re)connect, it establishes the mapping per the follow policy and publishes
/// the granted external port and a [`PortFollowOutcome`]; when the tunnel goes
/// away (`None`), it drops the mapping and clears the port. Generic over the
/// forwarder and established-port types so the state machine is testable
/// without a real NAT-PMP gateway.
///
/// Conflict semantics (the maintenance-migration service contract): a strict
/// suggestion refusal on a best-effort rule degrades ONCE to a server pick
/// (`suggested = 0`, the stale sticky is forgotten); on a pinned rule it holds
/// with no mapping for the epoch. Either way the loop stays alive. Transient
/// failures retry within the epoch with a jittered backoff.
pub(crate) async fn supervise_forward<F, P, E, Fut>(
    mut forwarder_rx: tokio::sync::watch::Receiver<Option<F>>,
    external_tx: tokio::sync::watch::Sender<Option<u16>>,
    outcome_tx: tokio::sync::watch::Sender<Option<crate::portfollow::PortFollowOutcome>>,
    config: crate::portfollow::PortFollowConfig,
    mut establish: E,
) where
    F: Clone,
    P: ExternalPort,
    E: FnMut(F, u16) -> Fut,
    Fut: std::future::Future<Output = Result<P, SdkError>>,
{
    use crate::portfollow::{PortFollowOutcome, PortFollowPolicy};

    // Holding `current` keeps the established port alive; replacing or clearing
    // it drops the previous one, which tears its mapping/relay tasks down.
    let mut current: Option<P> = None;
    // The last granted external port, re-suggested so the public port follows
    // the client across reconnects/exit-changes (policy permitting).
    let mut sticky: Option<u16> = None;
    // A pinned conflict parks the rule until the next epoch: the port is held
    // by another client on THIS exit, so re-asking before an exit change would
    // only hammer the gateway.
    let mut conflicted_epoch = false;
    let mut backoff = Backoff {
        base: config.retry_base,
        max: config.retry_max,
    }
    .forever();
    loop {
        let snapshot = forwarder_rx.borrow_and_update().clone();
        match snapshot {
            Some(forwarder) if current.is_none() && !conflicted_epoch => {
                let suggested = match config.policy {
                    PortFollowPolicy::Disabled => 0,
                    PortFollowPolicy::KeepPortOrStay => {
                        config.pinned_external_port.or(sticky).unwrap_or(0)
                    }
                    PortFollowPolicy::FollowBestEffort => sticky.unwrap_or(0),
                };
                // No identity material is logged on any of these paths.
                match establish(forwarder.clone(), suggested).await {
                    Ok(port) => {
                        let granted = port.external_port();
                        let outcome = if sticky == Some(granted) {
                            PortFollowOutcome::Kept { port: granted }
                        } else {
                            PortFollowOutcome::Changed {
                                previous: sticky,
                                port: granted,
                            }
                        };
                        sticky = Some(granted);
                        let _ = outcome_tx.send(Some(outcome));
                        let _ = external_tx.send(Some(granted));
                        current = Some(port);
                        backoff.reset();
                    }
                    Err(e) if e.is_port_conflict() && suggested != 0 => {
                        if config.policy == PortFollowPolicy::KeepPortOrStay {
                            // Never degrade a pinned rule: no mapping this
                            // epoch, the pin stays requested on the next one.
                            let _ = outcome_tx.send(Some(PortFollowOutcome::ConflictStayed {
                                pinned: suggested,
                            }));
                            conflicted_epoch = true;
                        } else {
                            // Best-effort: the sticky port is gone on this exit.
                            // Forget it and take a server-assigned port instead
                            // of killing the rule.
                            sticky = None;
                            match establish(forwarder, 0).await {
                                Ok(port) => {
                                    let granted = port.external_port();
                                    sticky = Some(granted);
                                    let _ = outcome_tx.send(Some(PortFollowOutcome::Changed {
                                        previous: Some(suggested),
                                        port: granted,
                                    }));
                                    let _ = external_tx.send(Some(granted));
                                    current = Some(port);
                                    backoff.reset();
                                }
                                Err(_) => {
                                    let _ = outcome_tx.send(Some(PortFollowOutcome::Failed));
                                }
                            }
                        }
                    }
                    Err(_) => {
                        let _ = outcome_tx.send(Some(PortFollowOutcome::Failed));
                    }
                }
                if current.is_none() && !conflicted_epoch {
                    // Transient failure: retry within the epoch after a jittered
                    // delay, yielding immediately if the epoch changes first.
                    tokio::select! {
                        () = tokio::time::sleep(backoff.next_delay()) => {}
                        changed = forwarder_rx.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                    }
                    continue;
                }
            }
            Some(_) => {}
            None => {
                conflicted_epoch = false;
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

/// The async reserve-then-switch gate the supervisor consults when a drain
/// advisory arrives, BEFORE tearing the current session down: it pre-flights
/// the migration candidates (reserving every pinned forwarded port) and
/// resolves `true` to proceed or `false` to cancel the migration (all
/// candidates conflicted), in which case the client stays on the draining exit
/// and keeps its ports. The pattern is ported from the engine supervisor's
/// `pre_swap_check`; here the gate runs before the SDK's break-before-make
/// reconnect (the SDK userland datapath has no overlap bundle).
pub(crate) type PreMigrateGate = Box<
    dyn FnMut(
            warren_transport::DrainAdvisory,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send,
>;

/// Upper bound on the pre-migrate gate. Past it the migration is CANCELLED
/// (fail-safe: an unresponsive pre-flight counts as a conflict, so a pinned
/// port is never abandoned on a hung check), mirroring the engine supervisor's
/// pre-swap timeout.
const PRE_MIGRATE_TIMEOUT: std::time::Duration = crate::portfollow::DEFAULT_PREFLIGHT_TIMEOUT;

/// Applies the optional pre-migrate gate: no gate = proceed, a verdict is
/// honoured, exceeding `timeout` cancels. Free function so the timeout
/// semantics are testable without a supervisor.
async fn pre_migrate_allows(
    gate: Option<&mut PreMigrateGate>,
    advisory: warren_transport::DrainAdvisory,
    timeout: std::time::Duration,
) -> bool {
    let Some(gate) = gate else {
        return true;
    };
    (tokio::time::timeout(timeout, gate(advisory)).await).unwrap_or(false)
}

/// Local network-path watcher armed for each connected epoch: when the host's
/// preferred route toward the exit moves to a live new path (Wi-Fi to Ethernet
/// handover, DHCP renumbering, connectivity recovery), the epoch ends and the
/// supervisor redials immediately from the new path instead of waiting for
/// idle-timeout/dead-path detection. Detection is the engine's
/// `network_monitor` home; this is only its arming seam (injectable for
/// tests).
pub(crate) struct NetworkWatch {
    pub(crate) probe: Box<dyn FnMut() -> Option<std::net::IpAddr> + Send>,
    pub(crate) interval: std::time::Duration,
}

impl NetworkWatch {
    /// The production watcher: the kernel's own route decision toward the
    /// engine probe anchor, at the engine poll cadence.
    pub(crate) fn system() -> Self {
        Self {
            probe: Box::new(|| {
                warren_transport::network_monitor::preferred_source_ip(
                    warren_transport::network_monitor::PROBE_ANCHOR,
                )
            }),
            interval: warren_transport::network_monitor::POLL_INTERVAL,
        }
    }
}

/// How the fresh socket of a migration rebind is kept out of the tunnel it
/// carries, per datapath.
///
/// The userland proxy captures nothing, so its socket needs no escape at all.
/// The privileged TUN datapath does, and the mechanism differs per OS: Linux
/// marks the socket itself (the fwmark the split-default rule matches), macOS
/// deliberately leaves the carrier unbound and escapes it with a
/// destination-keyed `<exit>/32` host route, because binding it black-holes
/// egress on multi-interface hosts.
#[derive(Debug, Clone, Default)]
pub(crate) struct MigrationPolicy {
    /// Bypass to reapply to the fresh socket before quinn can send on it;
    /// `None` when the host carries the escape by route instead.
    pub(crate) bypass: Option<warren_transport::SocketBypass>,
    /// The `<exit>/32` escape to (re)install before a rebind, as the exit IP
    /// and the PHYSICAL gateway resolved at connect time (macOS privileged
    /// TUN); `None` when nothing captures the host's routes.
    ///
    /// The connect-time gateway is the fallback, not a frozen pin:
    /// `ensure_route_escape` re-resolves the current physical default through
    /// the engine's tunnel-resistant discovery
    /// (`warrenguard_route_split::default_route_split_macos::discover_physical_default`),
    /// which refuses a tunnel source rather than guessing and falls back to
    /// `scutil` when the split capture shadows `route get default`, so
    /// re-resolving after the capture is safe and a genuine interface
    /// hand-off migrates. When the re-resolution fails, this value still
    /// recovers a flap on the same interface; when neither yields an
    /// installable route the rebind is refused and the cycle redials:
    /// fail-closed, never nested.
    pub(crate) carrier_host_route: Option<(std::net::IpAddr, String)>,
}

impl MigrationPolicy {
    /// The rebind policy this datapath hands the engine: a per-socket bypass
    /// when the platform escapes by socket, the plain wildcard bind otherwise.
    pub(crate) fn rebind_policy(&self) -> warren_transport::RebindPolicy {
        match self.bypass {
            Some(bypass) => warren_transport::RebindPolicy::Bypass(bypass),
            None => warren_transport::RebindPolicy::Plain,
        }
    }
}

/// The SDK's platform bindings for the engine migration watchdog
/// ([`warren_transport::migration_watchdog`]), armed for one connected epoch.
///
/// The decision loop, its timings and its fallback ladder are the engine's, one
/// home for every client surface. What is SDK-specific lives here: the
/// route-event source (the same preferred-path probe [`NetworkWatch`] already
/// polls), the live session reached through the epoch's sink, the per-datapath
/// escape policy, and the verdict channel.
///
/// The verdict channel is what keeps this fallback-safe: `force_reconnect` and
/// `escalate` both end the epoch, which is exactly what a network change did
/// before the watchdog existed. A migration that does not take therefore
/// degrades to today's redial, never to a stuck session.
struct EpochMigrationIo<'a> {
    watch: Option<&'a mut NetworkWatch>,
    /// Weak, like the metrics probe: the watchdog observes the datapath, it
    /// must never keep a torn-down QUIC connection alive. An empty `Weak` (a
    /// datapath with no sealed session, as the in-process fakes have) simply
    /// never upgrades.
    session: std::sync::Weak<warren_transport::MultihopSession>,
    /// Fired when the watchdog decides the session must be rebuilt; the
    /// supervisor's epoch race consumes it and redials.
    rebuild: Arc<tokio::sync::Notify>,
    policy: MigrationPolicy,
}

impl EpochMigrationIo<'_> {
    /// The epoch's live multihop session, or `None` once the datapath is gone.
    fn session(&self) -> Option<Arc<warren_transport::MultihopSession>> {
        self.session.upgrade()
    }
}

/// Sample identity for the watchdog's RX progress probe: the session's `Arc`
/// address with the local port mixed in, because the allocator can reuse a
/// freed `Arc` address for the very next session (ABA) while the wildcard
/// bind's ephemeral port cannot within any realistic window. The port is
/// rotated in, not shifted: a shift wide enough to clear a 64-bit pointer's
/// low bits overflows `usize` on the 32-bit ABIs the Dart SDK builds
/// (armeabi-v7a, x86), which the compiler rejects outright.
fn sample_identity(session_addr: usize, port: u16) -> usize {
    session_addr ^ usize::from(port).rotate_left(17)
}

/// Which gateway the migration escape pins to, in preference order: the
/// freshly re-resolved physical default when the engine discovery could name
/// one, else the connect-time value (which still recovers a flap on the same
/// interface), else nothing installable and the rebind is refused.
#[cfg(any(test, all(target_os = "macos", feature = "experimental-tun")))]
fn escape_gateway(fresh: Option<String>, connect_time: Option<String>) -> Option<String> {
    fresh.or(connect_time)
}

impl warren_transport::migration_watchdog::MigrationIo for EpochMigrationIo<'_> {
    async fn next_route_event(&mut self) -> bool {
        match self.watch.as_deref_mut() {
            Some(watch) => {
                // The engine's own preferred-path watcher, which is the SDK's
                // route-event source: it polls the kernel's routing decision
                // rather than subscribing to a platform listener the SDK has
                // no privilege to open. No address is logged from the change.
                warren_transport::network_monitor::wait_for_path_change(
                    &mut *watch.probe,
                    watch.interval,
                )
                .await;
                true
            }
            // Unarmed: nothing will ever wake the watchdog, and parking (rather
            // than reporting a closed source) keeps the epoch race owned by the
            // serve loops.
            None => std::future::pending().await,
        }
    }

    async fn has_v4_default_route(&mut self) -> bool {
        match self.watch.as_deref_mut() {
            // The probe IS "which local source would a fresh socket toward the
            // anchor bind": `None` means no usable default route.
            Some(watch) => (watch.probe)().is_some(),
            None => true,
        }
    }

    async fn nudge_bypass(&mut self) {
        // Nothing to re-point: the proxy datapath escapes nothing, the Linux
        // TUN datapath's fwmark follows the main table on its own, and the
        // macOS host route is (re)installed by `ensure_route_escape`.
    }

    fn session_can_migrate(&mut self) -> bool {
        // No published session counts as NOT migratable, so the cycle redials
        // straight away instead of spending the probe window on a datapath
        // that has no QUIC path to move. That is the pre-watchdog behavior,
        // which is the fallback this whole binding is built to preserve.
        match self.session() {
            // Distinguished from the over-carrier case the engine reports: a
            // gone session is not a TCP-carried one.
            None => {
                tracing::debug!("no live session to migrate; the cycle redials");
                false
            }
            Some(s) => !s.is_over_carrier(),
        }
    }

    async fn ensure_route_escape(&mut self) -> bool {
        let Some((exit_ip, gateway)) = self.policy.carrier_host_route.clone() else {
            // Either nothing captures the host's routes (userland proxy) or the
            // escape rides the socket itself (Linux fwmark, reapplied by the
            // rebind policy): there is no destination-keyed route to establish.
            return true;
        };
        #[cfg(all(target_os = "macos", feature = "experimental-tun"))]
        {
            // The rebind hands quinn a socket with no bind of its own, so this
            // destination-keyed route is the only thing left keeping the
            // carrier off the tunnel it carries. Install it BEFORE the rebind
            // and report whether it took: no escape, no rebind.
            //
            // Re-resolve the physical default first: the engine discovery
            // refuses a tunnel source rather than guessing (and falls back to
            // scutil when the split capture shadows `route get default`), so
            // a genuine interface hand-off pins the escape to the CURRENT
            // gateway instead of the one the host had at connect time.
            let fresh =
                match warrenguard_route_split::default_route_split_macos::discover_physical_default(
                )
                .await
                {
                    Ok((_iface, gateway)) => gateway,
                    Err(_) => {
                        // The discovery's anyhow chain can carry raw `route`
                        // output (addresses), so it is never rendered.
                        tracing::debug!(
                            "physical-default re-resolution failed; falling back to the connect-time \
                         gateway"
                        );
                        None
                    }
                };
            match escape_gateway(fresh, Some(gateway)) {
                Some(gw) => match crate::tun_setup::add_carrier_host_route_macos(exit_ip, &gw) {
                    Ok(()) => true,
                    Err(error) => {
                        // The install error is an errno; the route's addresses
                        // never enter the trace.
                        tracing::info!(
                            %error,
                            "carrier escape install failed; refusing the rebind, the cycle redials"
                        );
                        false
                    }
                },
                None => {
                    tracing::info!(
                        "no gateway to pin the carrier escape to; refusing the rebind, the cycle \
                         redials"
                    );
                    false
                }
            }
        }
        #[cfg(not(all(target_os = "macos", feature = "experimental-tun")))]
        {
            let _ = (exit_ip, gateway);
            // Only the macOS TUN datapath keys its escape on the destination.
            // A policy asking for one elsewhere cannot be honoured, and
            // fail-closed means refusing the rebind (the cycle redials) rather
            // than handing quinn a socket with no escape at all.
            tracing::info!(
                "no destination-keyed escape on this datapath; refusing the rebind, the cycle \
                 redials"
            );
            false
        }
    }

    async fn rebind_endpoint(&mut self) {
        if let Some(session) = self.session() {
            // A failed rebind leaves the session on its current socket, so the
            // probe window simply proves the old path dead and the cycle
            // redials. The engine logs "rebound socket" unconditionally, so
            // without this line a failed rebind is indistinguishable from a
            // successful one. The error is an errno or the carrier kind,
            // never an address.
            if let Err(error) = session.rebind_wildcard(self.policy.rebind_policy()) {
                tracing::info!(%error, "endpoint rebind failed; the session stays on its socket");
            }
        }
    }

    async fn send_probe(&mut self) {
        if let Some(session) = self.session() {
            let _ = session.send_daita_padding().await;
        }
    }

    fn rx_sample(&mut self) -> Option<warren_transport::migration_watchdog::RxSample> {
        let session = self.session()?;
        let port = session.local_addr().map(|a| a.port()).unwrap_or(0);
        Some(warren_transport::migration_watchdog::RxSample {
            id: sample_identity(Arc::as_ptr(&session) as usize, port),
            rx_datagrams: session.connection().stats().udp_rx.datagrams,
        })
    }

    fn force_reconnect(&mut self) -> bool {
        let had_session = match self.session() {
            Some(session) => {
                // Close with the forced-reconnect code so the datapath reads it
                // as a transient loss and the epoch ends through the ordinary
                // dead-tunnel path too.
                session.force_close_for_reconnect();
                true
            }
            None => false,
        };
        // The engine logs WHY it forced the reconnect at each call site; this
        // line records that the SDK acted on the verdict and ended the epoch.
        tracing::debug!(
            had_session,
            "watchdog verdict applied: epoch ends, supervisor redials"
        );
        self.rebuild.notify_one();
        had_session
    }

    fn escalate(&mut self, msg: String) {
        // The engine's escalation reasons are static, address-free strings.
        // Beyond the trace, the reaction is the report: the epoch ends, the
        // supervisor republishes `Reconnecting`, and the host sees it on the
        // state watch.
        tracing::warn!(reason = %msg, "watchdog escalated; ending the epoch");
        self.rebuild.notify_one();
    }
}

/// Runs the migration watchdog over a datapath that has NO supervisor of its
/// own: the privileged TUN facade, which owns a device, routing, DNS and a
/// killswitch that only its caller may rebuild.
///
/// Same engine loop and same escape contract as the supervised proxy, but the
/// fallback stops at the session close the watchdog asks for: the caller sees
/// its datapath die (as it already does on any tunnel loss) and decides whether
/// to rebuild. Resolves once the watchdog has given its verdict, so the caller
/// can drop the task with the datapath.
// Present in test builds on every platform (the loopback datapath tests need no
// TUN device), and in the privileged builds that actually own such a datapath.
#[cfg(any(test, all(unix, feature = "experimental-tun")))]
pub(crate) async fn watch_datapath_migration(
    mut watch: NetworkWatch,
    session: std::sync::Weak<warren_transport::MultihopSession>,
    policy: MigrationPolicy,
) {
    let rebuild = Arc::new(tokio::sync::Notify::new());
    let mut io = EpochMigrationIo {
        watch: Some(&mut watch),
        session,
        rebuild: Arc::clone(&rebuild),
        policy,
    };
    migration_epoch(&mut io, &rebuild).await;
}

/// Runs the migration watchdog and resolves when it decides the session must be
/// rebuilt: the engine loop itself only returns on an escalation, so the
/// verdict channel is what turns it into "this datapath is finished".
async fn migration_epoch(io: &mut EpochMigrationIo<'_>, rebuild: &tokio::sync::Notify) {
    tokio::select! {
        // Returns only on an escalation or a closed event source; both mean the
        // epoch cannot be kept.
        () = warren_transport::migration_watchdog::run_watchdog(io) => {}
        () = rebuild.notified() => {}
    }
}

/// Optional guards the supervisor arms around each connected epoch: the
/// reserve-then-switch pre-migrate gate, the network-path watcher, and the
/// escape contract the watchdog's rebind must honour on this datapath.
/// Grouped so the supervisor signature stays readable as the seams grow.
#[derive(Default)]
pub(crate) struct EpochGuards {
    pub(crate) pre_migrate: Option<PreMigrateGate>,
    pub(crate) network_watch: Option<NetworkWatch>,
    pub(crate) migration: MigrationPolicy,
}

/// Which of the supervisor's four independent epoch enders won the race.
///
/// The supervisor used to publish only THAT an epoch ended, so every tunnel
/// death in the fleet reached the host as an identical `Reconnecting` and none
/// of them could be attributed. The four causes call for opposite remedies (a
/// dead exit must be reselected; a healthy tunnel torn down by a probe verdict
/// is a client defect), so they are published apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EpochEndCause {
    /// The datapath itself died: the QUIC session closed or the netstack
    /// stopped. [`EpochEnd::close`] carries the transport verdict.
    SessionClosed,
    /// The in-tunnel egress probe convicted the exit of forwarding nothing over
    /// a session the transport still considered alive.
    EgressDead,
    /// The migration watchdog could not keep the session on a moved network
    /// path, so it ended the epoch for a redial.
    PathMoved,
    /// The exit published a planned maintenance drain (ADR 36).
    Drained,
}

/// Why one supervised epoch ended, published before the `Reconnecting` state
/// that follows it so a host can journal the two together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EpochEnd {
    /// Which epoch ender fired.
    pub cause: EpochEndCause,
    /// The QUIC close verdict at the moment the epoch ended
    /// ([`warren_transport::close_label`]), or `None` when the connection was
    /// still open (which is itself the signal: the transport was fine and
    /// something above it ended the epoch). Carries no identity material.
    pub close: Option<&'static str>,
    /// How long the epoch served, in seconds.
    pub up_s: u64,
}

impl EpochEnd {
    /// Builds a report. The struct is `#[non_exhaustive]` so it can grow a field
    /// without breaking consumers, which also means a host cannot build one with
    /// a struct expression: this constructor is how a consumer's own tests pin
    /// what they do with each cause.
    #[must_use]
    pub fn new(cause: EpochEndCause, close: Option<&'static str>, up_s: u64) -> Self {
        Self { cause, close, up_s }
    }
}

/// How a supervisor arms the per-epoch in-tunnel egress probe. Production only
/// ever spawns it; the other two arms exist because the in-process fake
/// datapaths have no resolver behind them to answer a real probe.
pub(crate) enum EgressProbeArm {
    /// Spawn the probe over this epoch's connector.
    Spawn,
    /// Do not arm it at all.
    #[cfg(test)]
    Off,
    /// Publish each epoch's escalation notifier instead of spawning a probe, so
    /// the conviction path is drivable without a real exit.
    #[cfg(test)]
    Publish(tokio::sync::mpsc::UnboundedSender<Arc<tokio::sync::Notify>>),
}

/// The watch senders a supervisor publishes on: connection state, the
/// per-epoch forwarder driving self-healing port forwards, and the structured
/// maintenance-migration events. Grouped so the supervisor signature stays
/// readable as its outputs grow.
pub(crate) struct SupervisorOutputs {
    pub(crate) state_tx: tokio::sync::watch::Sender<ConnectionState>,
    pub(crate) forwarder_tx: tokio::sync::watch::Sender<Option<ProxyForwarder>>,
    /// Reads the current epoch's datapath counters without owning the datapath,
    /// republished per epoch like `forwarder_tx` and cleared when it ends.
    pub(crate) metrics_tx: tokio::sync::watch::Sender<Option<MetricsProbe>>,
    pub(crate) migration_tx: tokio::sync::watch::Sender<Option<crate::portfollow::MigrationEvent>>,
    /// Latches the [`FatalCause`] when a (re)connect fails with a fatal engine
    /// verdict (unauthorized account, device cap, opaque policy refusal): the
    /// supervisor then stops, so this carries WHY the terminal
    /// [`ConnectionState::Failed`] was reached, distinct from a transient
    /// `Reconnecting`.
    pub(crate) fatal_tx: tokio::sync::watch::Sender<Option<FatalCause>>,
    /// Arms the in-tunnel egress-liveness probe for each connected epoch: a
    /// periodic DNS query through the tunnel catches an exit that ACKs keep-alives
    /// but forwards nothing, escalating a reselect. Off for the in-process tests
    /// (whose fake datapaths have no real exit resolver to answer), on in prod.
    pub(crate) egress_probe: EgressProbeArm,
    /// Why the epoch that just ended ended, published BEFORE the `Reconnecting`
    /// transition it precedes so a host reading both sees the cause of the
    /// death it is about to record.
    pub(crate) epoch_end_tx: tokio::sync::watch::Sender<Option<EpochEnd>>,
}

/// Supervises a proxy datapath across tunnel rebuilds, keeping the local
/// listeners (and thus the app-facing proxy addresses) stable: it establishes a
/// tunnel, serves until the tunnel dies, then reconnects (immediately after a
/// drop, with capped exponential backoff between failed attempts), reporting each
/// [`ConnectionState`] transition and each maintenance-migration event.
/// `connect` is the (re)establish closure; it is
/// generic so the loop is testable with a fake sink and a fake connector.
pub(crate) async fn supervise_proxy<S, F, Fut, D>(
    socks_listener: tokio::net::TcpListener,
    http_listener: Option<tokio::net::TcpListener>,
    dns_server: Option<std::net::Ipv4Addr>,
    outputs: SupervisorOutputs,
    guards: EpochGuards,
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
    let EpochGuards {
        mut pre_migrate,
        mut network_watch,
        migration,
    } = guards;
    // The engine redial policy: the shared full-jitter schedule (so many
    // clients losing the same exit at once do not reconnect in a synchronized
    // wave) plus the healthy-vs-flapping session verdict, both single-homed in
    // `warren_transport::redial_policy`.
    let mut backoff = warren_transport::redial_policy::REDIAL_BACKOFF.forever();
    let mut first = true;
    // The advisory of an in-flight drain migration; consumed by the next
    // successful connect to emit the `Completed` migration event.
    let mut migrating: Option<warren_transport::DrainAdvisory> = None;
    loop {
        let _ = outputs.state_tx.send(if first {
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
                let sink = Arc::new(est.sink);
                // Publish a NON-owning reader of this epoch's counters. The weak
                // reference is load-bearing: the netstack owns the datapath for
                // the epoch, and a strong clone here would hold the QUIC
                // connection open past its teardown.
                let weak_sink = Arc::downgrade(&sink);
                // Taken before the sink moves into the netstack engine, and
                // held weakly: the session it points at dies with the epoch.
                let watchdog_session = sink
                    .multihop_session()
                    .as_ref()
                    .map(Arc::downgrade)
                    .unwrap_or_default();
                let _ = outputs.metrics_tx.send(Some(Arc::new(move || {
                    weak_sink.upgrade().and_then(|s| s.metrics_snapshot())
                })));
                let (connector, alive_rx) = warren_net::spawn_over_sink(sink, config);
                // Arm the in-tunnel egress probe for this epoch: it rides the same
                // netstack UDP path and, on a debounced dead verdict (the exit ACKs
                // keep-alives but forwards nothing), fires `egress_dead` so the
                // serve races below end the epoch and the loop reselects a fresh
                // exit. Held as an `AbortOnDrop` for the epoch, so the probe is torn
                // down with the session and never outlives it.
                let egress_dead = Arc::new(tokio::sync::Notify::new());
                let _egress_probe = match &outputs.egress_probe {
                    EgressProbeArm::Spawn => Some(crate::egress_probe::spawn_egress_probe(
                        connector.clone(),
                        gateway,
                        Arc::clone(&egress_dead),
                    )),
                    #[cfg(test)]
                    EgressProbeArm::Off => None,
                    #[cfg(test)]
                    EgressProbeArm::Publish(tx) => {
                        let _ = tx.send(Arc::clone(&egress_dead));
                        None
                    }
                };
                // Publish this epoch's forwarder so self-healing port forwards
                // can re-map on the fresh connector; cleared to `None` below when
                // the tunnel dies.
                let _ = outputs.forwarder_tx.send(Some(ProxyForwarder {
                    connector: connector.clone(),
                    gateway,
                    // Supervised path is multihop, which carries no per-exit
                    // NAT-PMP flag yet; stay permissive (doc 79).
                    port_forward_supported: true,
                }));
                let _ = outputs.state_tx.send(ConnectionState::Connected);
                // A reconnect that follows a drain completes that migration:
                // tell the host (forwards re-map immediately on the fresh
                // forwarder published above).
                if let Some(advisory) = migrating.take() {
                    let _ = outputs
                        .migration_tx
                        .send(Some(crate::portfollow::MigrationEvent {
                            deadline_unix_secs: advisory.deadline_unix_secs,
                            reason_code: advisory.reason_code,
                            outcome: crate::portfollow::MigrationOutcome::Completed,
                        }));
                }
                let up_since = std::time::Instant::now();
                // Serve until the tunnel dies OR (ADR 36) the exit signals a
                // maintenance drain. A drain wins the race so we reconnect
                // proactively before the exit's hard close, and `on_drain`
                // (below) advances the failover cursor so the reconnect rotates
                // PAST the draining exit directly (no waiting for its hard-close
                // `Err`). Single-exit `on_drain` is a no-op (one pinned exit).
                // With a pre-migrate gate wired, the drain first consults it: a
                // refusal (all candidates conflicted with a pinned port) CANCELS
                // the migration and the current session keeps serving; the exit
                // is left to hard-close at its drain deadline, and the port
                // survives its swap server-side.
                // The migration watchdog races the whole epoch: a moved
                // preferred path first tries to MIGRATE the live QUIC session
                // (rebind onto a fresh socket, let the relay revalidate the
                // path in about one RTT), and only ends the epoch when that
                // does not take. The epoch end is the old, proven behavior, so
                // a migration that fails costs a redial and nothing more.
                // Same exit either way: the network moved, the exit is fine.
                let rebuild = Arc::new(tokio::sync::Notify::new());
                // Kept for the epoch-end report: the watchdog takes the other
                // clone, and reading the QUIC close verdict after the race is
                // what separates a path that timed out from one the peer closed.
                // Weak, like the watchdog's: a strong handle here would keep the
                // connection alive past the epoch that owns it.
                let closing_session = std::sync::Weak::clone(&watchdog_session);
                let mut migration_io = EpochMigrationIo {
                    watch: network_watch.as_mut(),
                    session: watchdog_session,
                    rebuild: Arc::clone(&rebuild),
                    policy: migration.clone(),
                };
                let path_moved = migration_epoch(&mut migration_io, &rebuild);
                tokio::pin!(path_moved);
                // Which arm ended the epoch. Assigned in every arm, so a future
                // arm that forgets to set it is a compile error, not a silent
                // misattribution.
                let cause;
                let drained = match drain_rx {
                    Some(mut rx) => {
                        // The serve future is pinned OUTSIDE the drain loop so a
                        // cancelled migration resumes it (active proxy
                        // connections survive the refusal) instead of
                        // re-creating the accept loops.
                        let serve = serve_epoch(
                            &socks_listener,
                            http_listener.as_ref(),
                            connector,
                            alive_rx,
                        );
                        tokio::pin!(serve);
                        let mut drain_armed = true;
                        loop {
                            tokio::select! {
                                () = &mut serve => {
                                    cause = EpochEndCause::SessionClosed;
                                    break None;
                                }
                                () = &mut path_moved => {
                                    cause = EpochEndCause::PathMoved;
                                    break None;
                                }
                                () = egress_dead.notified() => {
                                    // The exit forwards nothing over a live QUIC
                                    // session: reselect a fresh exit, exactly as
                                    // for a dead session. Not a planned drain, so
                                    // no advisory is carried out of this epoch.
                                    on_drain();
                                    cause = EpochEndCause::EgressDead;
                                    break None;
                                }
                                advisory = wait_for_drain(&mut rx), if drain_armed => {
                                    if pre_migrate_allows(
                                        pre_migrate.as_mut(), advisory, PRE_MIGRATE_TIMEOUT,
                                    )
                                    .await
                                    {
                                        cause = EpochEndCause::Drained;
                                        break Some(advisory);
                                    }
                                    let _ = outputs.migration_tx.send(Some(
                                        crate::portfollow::MigrationEvent {
                                            deadline_unix_secs: advisory.deadline_unix_secs,
                                            reason_code: advisory.reason_code,
                                            outcome: crate::portfollow::MigrationOutcome::CancelledPortConflict,
                                        },
                                    ));
                                    // One verdict per epoch: disarm the drain
                                    // arm so the still-Some advisory does not
                                    // re-fire in a tight loop.
                                    drain_armed = false;
                                }
                            }
                        }
                    }
                    None => {
                        tokio::select! {
                            () = serve_epoch(
                                &socks_listener, http_listener.as_ref(), connector, alive_rx,
                            ) => { cause = EpochEndCause::SessionClosed; }
                            () = &mut path_moved => { cause = EpochEndCause::PathMoved; }
                            () = egress_dead.notified() => {
                                // The exit forwards nothing over a live QUIC
                                // session: reselect a fresh exit, exactly as for a
                                // dead session.
                                on_drain();
                                cause = EpochEndCause::EgressDead;
                            }
                        }
                        None
                    }
                };
                // Read the transport verdict BEFORE dropping the epoch's
                // handles: `None` here means the QUIC connection was still open
                // when something above it ended the epoch, which is exactly the
                // shape a probe conviction leaves behind.
                let close = closing_session
                    .upgrade()
                    .and_then(|s| s.connection().close_reason())
                    .as_ref()
                    .map(warren_transport::close_label);
                let _ = outputs.epoch_end_tx.send(Some(EpochEnd {
                    cause,
                    close,
                    up_s: up_since.elapsed().as_secs(),
                }));
                let _ = outputs.forwarder_tx.send(None);
                let _ = outputs.metrics_tx.send(None);
                if let Some(advisory) = drained {
                    // Rotate the failover cursor PAST the draining exit so the
                    // reconnect lands on a different one (no-op for single-exit).
                    on_drain();
                    // Surface the maintenance migration to the host right away
                    // with a DISTINCT `Draining` state (ADR 36) so the app can
                    // show "switching server for maintenance" instead of a
                    // generic reconnect; the loop then sends `Reconnecting` as
                    // the actual redial proceeds. The structured event exposes
                    // the advisory's fields alongside.
                    migrating = Some(advisory);
                    let _ = outputs
                        .migration_tx
                        .send(Some(crate::portfollow::MigrationEvent {
                            deadline_unix_secs: advisory.deadline_unix_secs,
                            reason_code: advisory.reason_code,
                            outcome: crate::portfollow::MigrationOutcome::Migrating,
                        }));
                    let _ = outputs.state_tx.send(ConnectionState::Draining);
                    // Proactive drain reconnect: the engine drain policy
                    // (deadline-aware jitter) spreads the herd exactly like the
                    // app reactor, never a local backoff schedule.
                    tokio::time::sleep(drain_spread(&advisory)).await;
                } else {
                    // The engine redial verdict: a healthy run resets the
                    // schedule and reconnects at once; a flap (died almost
                    // immediately) backs off first.
                    tokio::time::sleep(warren_transport::redial_policy::delay_after_session(
                        up_since.elapsed(),
                        &mut backoff,
                    ))
                    .await;
                }
            }
            Err(e) => {
                // The engine classified this failure; the supervisor consumes the
                // verdict, it never re-decides it. No identity material is logged.
                match e.retryability() {
                    Retryability::Fatal(cause) => {
                        // A business rejection (unauthorized account, device cap,
                        // opaque policy refusal) recurs on every redial and no
                        // other exit resolves it: STOP and surface the cause as a
                        // distinct terminal state instead of looping "Reconnecting"
                        // forever.
                        let _ = outputs.fatal_tx.send(Some(cause));
                        let _ = outputs.state_tx.send(ConnectionState::Failed);
                        return;
                    }
                    Retryability::RetryReselect => {
                        // A drain / pool-exhaustion refusal is not the account's
                        // fault, but redialing THIS exit re-hits it: advance the
                        // failover cursor (no-op for a single pinned exit) so the
                        // next attempt reselects a different exit, then back off.
                        on_drain();
                        tokio::time::sleep(backoff.next_delay()).await;
                    }
                    // RetrySameTarget, and any future verdict: a transient failure,
                    // retry the same target after a backoff.
                    _ => {
                        tokio::time::sleep(backoff.next_delay()).await;
                    }
                }
            }
        }
    }
}

/// Anti-stampede spread before the proactive drain reconnect: the engine
/// drain policy (deadline-aware jitter bounded by the hard-close), so SDK
/// clients spread exactly like the app's drain reactor.
fn drain_spread(advisory: &warren_transport::DrainAdvisory) -> std::time::Duration {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    warren_transport::drain_policy::jitter_delay(
        advisory.deadline_unix_secs,
        now_unix,
        warren_transport::drain_policy::stampede_fraction(),
    )
}

/// Resolves with the advisory when the exit publishes a maintenance drain on
/// `rx` (ADR 36). Parks forever if the watch sender is dropped (the session
/// ended), so on a natural tunnel death `serve_epoch` wins the race instead.
async fn wait_for_drain(
    rx: &mut tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>>,
) -> warren_transport::DrainAdvisory {
    loop {
        if let Some(advisory) = *rx.borrow_and_update() {
            return advisory;
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
    rtt_cache: std::sync::Arc<std::sync::Mutex<warren_discovery::RttCache>>,
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
    // Arm the TLS-over-TCP anti-censorship carrier (roster v10) when the dialed
    // entry advertises it: a UDP-blocked handshake then retries over the entry's
    // :443/tcp. Dormant unless UDP fails, so no cost on an open path.
    if exit.tcp_fallback {
        tunnel = tunnel.with_tcp_fallback(true);
    }
    // Prefer the post-quantum X-Wing seal when the verified directory bound a
    // signed ML-KEM key to this exit; `None` keeps the classical seal
    // (byte-identical) and the dial never fails over a missing PQ key.
    #[cfg(feature = "pq-hpke")]
    {
        tunnel = tunnel.with_exit_mlkem768(exit.exit_mlkem768_pubkey.clone());
    }
    let session = tunnel
        .connect(
            exit.exit_ed25519_pubkey,
            exit.exit_x25519_multihop_pubkey,
            exit.exit_id,
            exit.endpoint,
        )
        .await?;
    // Feed the client RTT store on BOTH lifecycle points of every
    // supervised (re)connect: the first hop's post-handshake sample now,
    // and its parting sample when the sink drops on teardown/reconnect.
    crate::client::record_rtt_in(&rtt_cache, exit.exit_ed25519_pubkey, session.path_rtt());
    let sink = MultihopPacketSink::new(session).with_close_rtt_observer(
        crate::client::close_rtt_recorder_for(&rtt_cache, exit.exit_ed25519_pubkey),
    );
    let (local_ip, prefix, gateway, ipv6) = addressing_from_session(sink.session());
    Ok(EstablishedTunnel {
        sink,
        local_ip,
        prefix,
        gateway,
        ipv6,
    })
}

// The refusal branch under test only compiles where the platform carries no
// destination-keyed escape; the macOS TUN build takes the install branch
// against the real `route` binary, which a unit test cannot drive.
#[cfg(all(test, not(all(target_os = "macos", feature = "experimental-tun"))))]
mod migration_io_tests {
    use super::*;
    use warren_transport::migration_watchdog::MigrationIo;

    #[derive(Clone, Default)]
    struct LogCapture(Arc<std::sync::Mutex<String>>);

    impl LogCapture {
        fn contents(&self) -> String {
            self.0.lock().expect("capture lock").clone()
        }
    }

    impl tracing::Subscriber for LogCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Line<'a>(&'a mut String);
            impl tracing::field::Visit for Line<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write;
                    let _ = write!(self.0, "{}={:?} ", field.name(), value);
                }
            }
            let mut line = String::new();
            event.record(&mut Line(&mut line));
            let mut buf = self.0.lock().expect("capture lock");
            buf.push_str(&line);
            buf.push('\n');
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn refused_escape_emits_one_address_free_trace() {
        let exit_ip: std::net::IpAddr = "192.0.2.77".parse().expect("test-net IP");
        let gateway = "198.51.100.1".to_string();
        let mut io = EpochMigrationIo {
            watch: None,
            session: std::sync::Weak::new(),
            rebuild: Arc::new(tokio::sync::Notify::new()),
            policy: MigrationPolicy {
                bypass: None,
                carrier_host_route: Some((exit_ip, gateway.clone())),
            },
        };
        let capture = LogCapture::default();
        let _guard = tracing::subscriber::set_default(capture.clone());
        let allowed = io.ensure_route_escape().await;
        let logs = capture.contents();
        assert!(
            !allowed,
            "no escape mechanism here: the rebind must be refused"
        );
        assert!(
            !logs.is_empty(),
            "the refusal must be observable: one trace line expected"
        );
        assert!(
            !logs.contains("192.0.2.77") && !logs.contains(&gateway),
            "a migration trace must never carry the exit IP or the gateway: {logs}"
        );
    }
}

#[cfg(test)]
mod sample_identity_tests {
    use super::sample_identity;

    #[test]
    fn distinct_ports_distinguish_a_reused_arc_address() {
        // ABA guard: a freed `Arc` address reused by the next session must not
        // alias the old sample identity, because the fresh wildcard bind moved
        // the ephemeral port.
        let addr = 0x7f00_beef_usize;
        assert_ne!(sample_identity(addr, 443), sample_identity(addr, 8443));
    }
}

#[cfg(test)]
mod escape_gateway_tests {
    use super::escape_gateway;

    #[test]
    fn a_re_resolved_gateway_wins() {
        assert_eq!(
            escape_gateway(Some("gw-fresh".into()), Some("gw-connect".into())),
            Some("gw-fresh".into()),
            "a genuine interface hand-off must pin the escape to the current gateway"
        );
    }

    #[test]
    fn a_failed_re_resolution_falls_back_to_the_connect_time_gateway() {
        assert_eq!(
            escape_gateway(None, Some("gw-connect".into())),
            Some("gw-connect".into()),
            "the connect-time value still recovers a flap on the same interface"
        );
    }

    #[test]
    fn no_gateway_at_all_refuses_the_escape() {
        assert_eq!(
            escape_gateway(None, None),
            None,
            "nothing installable must refuse the rebind, never guess"
        );
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;
    use std::time::Duration;
    use warren_transport::DrainAdvisory;

    fn advisory() -> DrainAdvisory {
        DrainAdvisory {
            deadline_unix_secs: 1_700_000_000,
            reason_code: 0,
        }
    }

    #[test]
    fn drain_spread_rides_the_engine_policy() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Deadline inside the engine safety margin: react immediately, never
        // a blind backoff (the pre-policy behavior slept regardless).
        let imminent = DrainAdvisory {
            deadline_unix_secs: now + 3,
            reason_code: 0,
        };
        assert_eq!(drain_spread(&imminent), Duration::ZERO);
        // Soft drain: the spread must stay under the engine jitter cap.
        let soft = DrainAdvisory {
            deadline_unix_secs: u64::MAX,
            reason_code: 0,
        };
        assert!(drain_spread(&soft) <= warren_transport::drain_policy::MAX_JITTER);
    }

    #[tokio::test]
    async fn pre_migrate_without_a_gate_proceeds() {
        // No gate wired (the default): the migration proceeds unconditionally,
        // the pre-doc-59 behavior.
        assert!(pre_migrate_allows(None, advisory(), Duration::from_millis(50)).await);
    }

    #[tokio::test]
    async fn pre_migrate_honours_the_gate_verdict() {
        let mut allow: PreMigrateGate = Box::new(|_| Box::pin(async { true }));
        assert!(pre_migrate_allows(Some(&mut allow), advisory(), Duration::from_millis(50)).await);
        let mut deny: PreMigrateGate = Box::new(|_| Box::pin(async { false }));
        assert!(
            !pre_migrate_allows(Some(&mut deny), advisory(), Duration::from_millis(50)).await,
            "a refusing gate cancels the migration"
        );
    }

    #[tokio::test]
    async fn pre_migrate_timeout_cancels_the_migration() {
        // Fail-safe: a hung pre-flight must count as a conflict (stay, keep the
        // port), never as an approval.
        let mut hung: PreMigrateGate = Box::new(|_| Box::pin(std::future::pending()));
        assert!(
            !pre_migrate_allows(Some(&mut hung), advisory(), Duration::from_millis(50)).await,
            "a gate overrunning its budget cancels the migration"
        );
    }

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
