//! In-tunnel egress-liveness probe for the userland proxy datapath.
//!
//! The QUIC transport can look alive (keep-alives ACKed) while the exit forwards
//! NOTHING (drained or half-swapped during a rollout): the RX-silence guard the
//! supervisor already has cannot see this, so the UI shows "Connected" with zero
//! actual internet. This module drives the engine scheduler
//! [`warren_transport::egress_probe::run_egress_probe`] over the userland
//! datapath: a periodic DNS query THROUGH the tunnel to the exit resolver (the
//! tunnel gateway) proves the exit decapsulates and forwards, and on a debounced
//! dead verdict the probe escalates a reconnect the SAME way a dead session does,
//! so the supervisor reselects a fresh exit.
//!
//! The SDK non-root proxy tier is TUN-less, so the gateway is not OS-routable:
//! the probe rides the netstack's own UDP path
//! ([`TunnelConnector::open_udp`](warren_net::TunnelConnector::open_udp)), the
//! same path the SOCKS UDP association uses, rather than an OS socket.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::Notify;
use warren_net::{TunnelConnector, UdpConnector, UdpFlow};
use warren_transport::egress_probe::{
    EgressProbeConfig, EgressProbeIo, PROBE_QNAME, ProbeOutcome, ProbeSchedule, TransportEvidence,
    build_dns_query, is_matching_response, jittered, run_egress_probe,
};

use crate::supervisor::AbortOnDrop;

/// Reads the epoch's QUIC ACK counter, or `None` once the epoch is gone.
///
/// Type-erased and non-owning for the same reason as the metrics probe: a
/// strong reference to the session would keep the QUIC connection alive past
/// the epoch that owns it, so an observability read would change the tunnel's
/// lifetime.
#[derive(Clone)]
pub(crate) struct AckReader(Arc<dyn Fn() -> Option<u64> + Send + Sync>);

impl AckReader {
    pub(crate) fn new(read: impl Fn() -> Option<u64> + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }

    /// Non-owning reader over a live multihop session.
    pub(crate) fn over(session: std::sync::Weak<warren_transport::MultihopSession>) -> Self {
        Self::new(move || session.upgrade().map(|s| s.acks_received()))
    }

    fn read(&self) -> Option<u64> {
        (self.0)()
    }
}

/// Reads the epoch's smoothed path round trip, or `None` once the epoch is gone.
///
/// Non-owning for the same reason as [`AckReader`]. The probe deadline is sized
/// from this: a path whose queueing delay alone exceeds the shipped deadline
/// expires every datagram of the schedule together, and the exit is convicted
/// for a congestion the probe never measured.
#[derive(Clone)]
pub(crate) struct RttReader(Arc<dyn Fn() -> Option<Duration> + Send + Sync>);

impl RttReader {
    pub(crate) fn new(read: impl Fn() -> Option<Duration> + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }

    /// Non-owning reader over a live multihop session.
    pub(crate) fn over(session: std::sync::Weak<warren_transport::MultihopSession>) -> Self {
        Self::new(move || {
            session
                .upgrade()
                .map(|s| Duration::from_millis(u64::from(s.path_quality().rtt_ms)))
        })
    }

    fn read(&self) -> Option<Duration> {
        (self.0)()
    }
}

/// One in-tunnel DNS round trip: the gateway-probe seam. Production dials the
/// netstack UDP path; tests script the verdict, so the supervisor escalation is
/// testable without a real exit.
pub(crate) trait GatewayProber: Send {
    /// One end-to-end probe through the tunnel. A local error (the datapath is
    /// tearing down) never reached the exit, so it reports
    /// [`ProbeOutcome::Inconclusive`] and the scheduler spends it neither way.
    fn probe(&mut self) -> impl Future<Output = ProbeOutcome> + Send;
}

/// Production prober: sends a DNS query over the netstack UDP path to the tunnel
/// gateway resolver and waits for any matching response.
///
/// Generic over the connector so the retransmit schedule is testable against a
/// scripted flow; production instantiates it at [`TunnelConnector`].
pub(crate) struct ConnectorProber<C: UdpConnector = TunnelConnector> {
    connector: C,
    gateway_dns: SocketAddr,
    /// Per-probe query id (wrapping): a stray datagram from a previous probe must
    /// not be mistaken for this probe's answer. Sequential is fine, the probe is
    /// not adversarial and QUIC encrypts the wire.
    next_txid: u16,
    /// The path the next probe will run on, read once per probe so the schedule
    /// follows a link whose delay changes under load.
    rtt: RttReader,
}

impl<C: UdpConnector> ConnectorProber<C> {
    pub(crate) fn new(connector: C, gateway: Ipv4Addr, rtt: RttReader) -> Self {
        Self {
            connector,
            gateway_dns: SocketAddr::new(gateway.into(), 53),
            next_txid: 0,
            rtt,
        }
    }
}

impl<C: UdpConnector + Send + Sync> GatewayProber for ConnectorProber<C>
where
    C::Flow: Send,
{
    async fn probe(&mut self) -> ProbeOutcome {
        // A fresh UDP flow per probe (cheap): the netstack routes it into the
        // tunnel. A local open/send error means the datapath is gone, which is
        // inconclusive, not an egress-dead verdict.
        let mut sock = match self.connector.open_udp().await {
            Ok(s) => s,
            Err(_) => return ProbeOutcome::Inconclusive,
        };
        self.next_txid = self.next_txid.wrapping_add(1);
        let txid = self.next_txid;
        let query = Bytes::from(build_dns_query(txid, PROBE_QNAME));
        // Read once per probe, before the first datagram: the schedule has to
        // describe the path this probe will actually run on, and on a link that
        // congests under its own load that changes within a session.
        let path_rtt = self.rtt.read();
        let schedule = ProbeSchedule::for_path_rtt(path_rtt);
        // A deadline the path cannot fit a round trip into convicts nothing.
        let expired = if ProbeSchedule::carries_exit_evidence(path_rtt) {
            ProbeOutcome::Dead
        } else {
            ProbeOutcome::Inconclusive
        };
        let started = tokio::time::Instant::now();
        if sock.send_to(query.clone(), self.gateway_dns).await.is_err() {
            return ProbeOutcome::Inconclusive;
        }
        let deadline = started + schedule.deadline;
        // The deadline is only safe because a lost datagram is retransmitted
        // inside it: the engine sizes the deadline and the schedule together, so
        // sending once and waiting the deadline out would turn a single lost
        // datagram into a failed probe, and three of those convict a healthy exit.
        let mut retransmits = schedule
            .sends
            .iter()
            .skip(1)
            .map(|offset| started + *offset);
        let mut next_send = retransmits.next();
        loop {
            // Absolute instants, so re-arming on a stray datagram never shifts
            // the remaining schedule.
            let wake = next_send.unwrap_or(deadline).min(deadline);
            tokio::select! {
                recv = sock.recv_from() => match recv {
                    Some((buf, _)) if is_matching_response(&buf, txid) => {
                        return ProbeOutcome::Alive;
                    }
                    Some(_) => {} // stray datagram from an earlier probe: keep waiting
                    // The flow closed under us: teardown, not an exit verdict.
                    None => return ProbeOutcome::Inconclusive,
                },
                () = tokio::time::sleep_until(wake) => {
                    if wake >= deadline {
                        return expired;
                    }
                    let _ = sock.send_to(query.clone(), self.gateway_dns).await;
                    next_send = retransmits.next();
                }
            }
        }
    }
}

/// Drives the engine egress-probe scheduler over the userland datapath. On the
/// debounced dead verdict it notifies [`Self::escalate`], which the supervisor
/// races against `serve` to end the epoch and reselect a fresh exit.
pub(crate) struct ProxyEgressProbe<P: GatewayProber> {
    prober: P,
    cfg: EgressProbeConfig,
    escalate: Arc<Notify>,
    /// The epoch's ACK counter, and its value when the current failure streak
    /// began. Only the peer can ACK what it received from us, so a counter that
    /// has not moved across the streak means the path carried nothing and the
    /// exit is not the suspect.
    acks: AckReader,
    acks_at_streak_start: Option<u64>,
    /// splitmix64 state for the tick jitter (de-regularization only, so a fleet
    /// never probes in lockstep; not a security primitive).
    rng: u64,
}

impl<P: GatewayProber> ProxyEgressProbe<P> {
    pub(crate) fn new(
        prober: P,
        cfg: EgressProbeConfig,
        escalate: Arc<Notify>,
        acks: AckReader,
    ) -> Self {
        Self {
            prober,
            cfg,
            escalate,
            acks,
            acks_at_streak_start: None,
            rng: 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// A well-distributed fraction in `[0, 1)` for the jittered tick interval.
    fn next_fraction(&mut self) -> f64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let z = z ^ (z >> 31);
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

impl<P: GatewayProber> EgressProbeIo for ProxyEgressProbe<P> {
    async fn next_tick(&mut self, settled: bool) -> bool {
        let base = if settled {
            self.cfg.interval
        } else {
            self.cfg.startup_interval
        };
        let frac = self.next_fraction();
        tokio::time::sleep(jittered(base, frac)).await;
        true
    }

    fn session_present(&mut self) -> bool {
        // The probe task is spawned per epoch and aborted when the epoch ends, so
        // a live probe always has a published session (single supervised session).
        true
    }

    async fn probe(&mut self) -> ProbeOutcome {
        self.prober.probe().await
    }

    fn publish(&mut self, _egress_dead: bool) {
        // The SDK surfaces the outcome through the supervisor's state machine:
        // a dead verdict escalates a reconnect (Reconnecting), so there is no
        // separate banner channel to publish here (and no-log forbids logging
        // datapath state). Kept as the trait's edge-triggered hook for parity.
    }

    fn drain_active(&mut self) -> bool {
        // The supervisor owns planned-drain handling on its own advisory signal;
        // the probe only ever escalates a full reconnect (reselect), never the
        // gap-free migration path.
        false
    }

    async fn try_migrate(&mut self) -> bool {
        false
    }

    fn escalate_reconnect(&mut self, _msg: String) {
        // End the current epoch: the supervisor reselects a fresh exit, exactly
        // as it does for a dead session. The message carries no identity material,
        // but the supervisor already logs the transition, so it is dropped here.
        self.escalate.notify_one();
    }

    fn mark_streak_start(&mut self) {
        self.acks_at_streak_start = self.acks.read();
    }

    fn transport_evidence(&mut self) -> TransportEvidence {
        match (self.acks_at_streak_start, self.acks.read()) {
            // The epoch ended under us (or never had a session to read): nobody
            // observed the transport, which is not the same as observing it
            // silent, and suppressing a conviction on absent evidence would let
            // a dead exit hide behind it.
            (None, _) | (_, None) => TransportEvidence::Unknown,
            (Some(before), Some(now)) if now > before => TransportEvidence::Progressing,
            _ => TransportEvidence::Silent,
        }
    }
}

/// Spawns the egress probe for one epoch over `connector`, escalating a reconnect
/// on the dead verdict by notifying `escalate`. The returned [`AbortOnDrop`] is
/// held by the supervisor for the epoch, so the probe is torn down with it (it
/// never outlives the session). A no-op task when `WARREN_EGRESS_PROBE=0`.
pub(crate) fn spawn_egress_probe(
    connector: TunnelConnector,
    gateway: Ipv4Addr,
    escalate: Arc<Notify>,
    acks: AckReader,
    rtt: RttReader,
) -> AbortOnDrop {
    let cfg = EgressProbeConfig::from_env();
    AbortOnDrop(tokio::spawn(async move {
        if !cfg.enabled {
            return;
        }
        let threshold = cfg.failure_threshold;
        let mut probe = ProxyEgressProbe::new(
            ConnectorProber::new(connector, gateway, rtt),
            cfg,
            escalate,
            acks,
        );
        run_egress_probe(&mut probe, threshold).await;
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;

    use std::sync::Arc as StdArc;

    use warren_net::socks5::Target;
    use warren_net::{Connector, NetError};

    /// What one fake flow recorded, shared with the test after the probe ends.
    #[derive(Default)]
    struct FlowLog {
        /// Offset from the probe start at which each datagram was sent.
        sends: Vec<Duration>,
        /// The last query written, echoed back as the answer.
        last_query: Option<bytes::Bytes>,
    }

    /// A UDP flow that records its send schedule and answers only on the
    /// configured 1-based send index (`None` = never answers). The netstack is a
    /// system boundary, so this is the right seam to pin the retransmit schedule
    /// without a real exit.
    struct FakeFlow {
        log: StdArc<Mutex<FlowLog>>,
        started: tokio::time::Instant,
        answer_on: Option<usize>,
        answered: bool,
    }

    impl UdpFlow for FakeFlow {
        async fn send_to(&self, data: bytes::Bytes, _dst: SocketAddr) -> Result<(), NetError> {
            let mut log = self.log.lock().unwrap();
            log.sends.push(self.started.elapsed());
            log.last_query = Some(data);
            Ok(())
        }

        async fn recv_from(&mut self) -> Option<(bytes::Bytes, SocketAddr)> {
            let ready = {
                let log = self.log.lock().unwrap();
                self.answer_on
                    .is_some_and(|n| log.sends.len() >= n && !self.answered)
                    .then(|| log.last_query.clone())
                    .flatten()
            };
            match ready {
                Some(query) => {
                    self.answered = true;
                    // The gateway's answer is the query with the QR bit set, so
                    // it carries the same txid the prober is waiting on.
                    let mut answer = query.to_vec();
                    answer[2] |= 0x80;
                    Some((
                        bytes::Bytes::from(answer),
                        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53),
                    ))
                }
                // No answer is due: stay pending so only the send schedule and
                // the deadline drive the probe.
                None => std::future::pending().await,
            }
        }
    }

    /// Opens [`FakeFlow`]s, or refuses to open one at all (`None`), which is the
    /// datapath-gone case.
    struct FakeConnector {
        log: StdArc<Mutex<FlowLog>>,
        answer_on: Option<usize>,
        opens: bool,
    }

    impl Connector for FakeConnector {
        type Stream = tokio::net::TcpStream;
        async fn connect(&self, _target: Target) -> Result<Self::Stream, NetError> {
            Err(NetError::Unsupported("tcp unused by the egress probe"))
        }
    }

    impl UdpConnector for FakeConnector {
        type Flow = FakeFlow;
        async fn open_udp(&self) -> Result<Self::Flow, NetError> {
            if !self.opens {
                return Err(NetError::EngineStopped);
            }
            Ok(FakeFlow {
                log: StdArc::clone(&self.log),
                started: tokio::time::Instant::now(),
                answer_on: self.answer_on,
                answered: false,
            })
        }
        async fn resolve_host(&self, _host: &str) -> Result<std::net::IpAddr, NetError> {
            Err(NetError::Unsupported("no resolution in the probe test"))
        }
        fn supports_ipv6(&self) -> bool {
            false
        }
    }

    fn prober(
        answer_on: Option<usize>,
        opens: bool,
    ) -> (ConnectorProber<FakeConnector>, StdArc<Mutex<FlowLog>>) {
        prober_on_path(answer_on, opens, None)
    }

    /// A prober whose datapath reports `rtt` as its smoothed round trip.
    fn prober_on_path(
        answer_on: Option<usize>,
        opens: bool,
        rtt: Option<Duration>,
    ) -> (ConnectorProber<FakeConnector>, StdArc<Mutex<FlowLog>>) {
        let log = StdArc::new(Mutex::new(FlowLog::default()));
        let connector = FakeConnector {
            log: StdArc::clone(&log),
            answer_on,
            opens,
        };
        (
            ConnectorProber::new(
                connector,
                Ipv4Addr::new(10, 64, 0, 1),
                RttReader::new(move || rtt),
            ),
            log,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_probe_retransmits_on_the_engine_schedule() {
        // The deadline and the schedule were sized together in the engine: 2.5 s
        // is only safe because a lost datagram is retransmitted twice inside it.
        // A driver that sends once and waits the deadline out turns one lost
        // datagram into a failed probe, and three of those convict a healthy exit.
        let (mut prober, log) = prober(None, true);
        assert_eq!(prober.probe().await, ProbeOutcome::Dead);
        assert_eq!(
            log.lock().unwrap().sends,
            ProbeSchedule::SHIPPED.sends.to_vec(),
            "every datagram in the engine schedule must go out before the verdict"
        );
    }

    /// The member-line failure this plumbing exists for: on a link whose
    /// queueing delay alone is 1400 ms, the shipped schedule expires all three
    /// datagrams together and convicts an exit that was answering fine. The
    /// driver must follow the engine's path-sized schedule, not the constants.
    #[tokio::test(start_paused = true)]
    async fn a_congested_path_stretches_the_retransmit_schedule() {
        let congested = Duration::from_millis(1400);
        let (mut prober, log) = prober_on_path(None, true, Some(congested));
        assert_eq!(prober.probe().await, ProbeOutcome::Dead);
        assert_eq!(
            log.lock().unwrap().sends,
            ProbeSchedule::for_path_rtt(Some(congested)).sends.to_vec(),
            "the driver must retransmit on the schedule the engine sized for \
             this path, not on the shipped constants"
        );
    }

    /// Past the engine cap the probe cannot tell a dead exit from a path that
    /// cannot carry the query inside any deadline, so it must report no
    /// evidence rather than convict.
    #[tokio::test(start_paused = true)]
    async fn a_path_past_the_probe_cap_reports_no_evidence_about_the_exit() {
        let (mut prober, _log) = prober_on_path(None, true, Some(Duration::from_secs(20)));
        assert_eq!(prober.probe().await, ProbeOutcome::Inconclusive);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_first_datagram_is_recovered_by_the_retransmit() {
        // The whole point of the schedule: losing the first datagram costs a
        // retransmit, never the probe.
        let (mut prober, log) = prober(Some(2), true);
        assert_eq!(prober.probe().await, ProbeOutcome::Alive);
        assert_eq!(
            log.lock().unwrap().sends.len(),
            2,
            "the answer on the second datagram must end the probe there"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_datapath_that_will_not_open_is_inconclusive() {
        // Nothing reached the exit, so this is host-side evidence: reported as
        // alive it would mark a never-answered circuit proven and launder away
        // accumulated failures.
        let (mut prober, _log) = prober(None, false);
        assert_eq!(prober.probe().await, ProbeOutcome::Inconclusive);
    }

    /// A scripted gateway prober: one verdict per probe, `alive` once exhausted.
    /// The tunnel is a system boundary here, so scripting the probe verdict is the
    /// right seam to test the SDK escalation without a real exit.
    struct ScriptedProber {
        script: Mutex<VecDeque<bool>>,
    }
    impl ScriptedProber {
        fn new(script: impl IntoIterator<Item = bool>) -> Self {
            Self {
                script: Mutex::new(script.into_iter().collect()),
            }
        }
    }
    impl GatewayProber for ScriptedProber {
        async fn probe(&mut self) -> ProbeOutcome {
            match self.script.lock().unwrap().pop_front() {
                Some(false) => ProbeOutcome::Dead,
                _ => ProbeOutcome::Alive,
            }
        }
    }

    /// The conviction that tears a working tunnel down must not fire while the
    /// transport carried nothing: this probe convicts an exit that ACKs and
    /// forwards nothing, and while the peer ACKs nothing at all the premise
    /// does not hold. The evidence comes from the QUIC ACK counter, which is
    /// the only thing that separates a dead peer from a quiet one.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_path_reports_silent_and_a_live_one_reports_progress() {
        use warren_transport::egress_probe::TransportEvidence;

        let acks = StdArc::new(std::sync::atomic::AtomicU64::new(100));
        let reader = {
            let acks = StdArc::clone(&acks);
            AckReader::new(move || Some(acks.load(std::sync::atomic::Ordering::Relaxed)))
        };
        let mut probe = ProxyEgressProbe::new(
            ScriptedProber::new([false]),
            fast_cfg(),
            Arc::new(Notify::new()),
            reader,
        );

        probe.mark_streak_start();
        assert_eq!(
            probe.transport_evidence(),
            TransportEvidence::Silent,
            "no ACK arrived since the streak began: the path carried nothing"
        );

        acks.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            probe.transport_evidence(),
            TransportEvidence::Progressing,
            "the peer acknowledged what we sent, so the path is live and an \
             unanswered in-tunnel query is evidence against the exit"
        );
    }

    /// Once the epoch is gone there is no connection left to read, and reporting
    /// that as `Silent` would suppress a conviction on evidence nobody has.
    #[tokio::test(start_paused = true)]
    async fn a_datapath_with_no_session_reports_unknown_rather_than_silent() {
        use warren_transport::egress_probe::TransportEvidence;

        let mut probe = ProxyEgressProbe::new(
            ScriptedProber::new([false]),
            fast_cfg(),
            Arc::new(Notify::new()),
            AckReader::new(|| None),
        );
        probe.mark_streak_start();
        assert_eq!(probe.transport_evidence(), TransportEvidence::Unknown);
    }

    /// interval + startup 1 s so the paused-time ticks are fast; threshold 3.
    fn fast_cfg() -> EgressProbeConfig {
        EgressProbeConfig::resolve(None, Some("1"), Some("1"), Some("3"))
    }

    #[tokio::test(start_paused = true)]
    async fn three_consecutive_dead_probes_escalate_a_reconnect() {
        // The engine debounce: three consecutive failed in-tunnel probes over a
        // still-alive QUIC session must escalate a reconnect, so the supervisor
        // reselects a fresh exit instead of showing Connected over an exit that
        // forwards nothing.
        let escalate = Arc::new(Notify::new());
        let fired = Arc::clone(&escalate);
        let cfg = fast_cfg();
        let threshold = cfg.failure_threshold;
        let mut probe = ProxyEgressProbe::new(
            ScriptedProber::new([false, false, false]),
            cfg,
            escalate,
            AckReader::new(|| None),
        );

        let run = tokio::spawn(async move { run_egress_probe(&mut probe, threshold).await });
        for _ in 0..6 {
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
        }
        run.await.expect("the probe loop returns after escalation");

        tokio::time::timeout(Duration::from_millis(50), fired.notified())
            .await
            .expect("a dead egress verdict must escalate exactly one reconnect");
    }

    #[tokio::test(start_paused = true)]
    async fn a_recovered_probe_resets_and_never_escalates() {
        // fail, fail, ok, fail, fail: never three consecutive, so the debounce
        // never fires and no reconnect is escalated (a rollout hot-swap blip must
        // not flap the datapath).
        let escalate = Arc::new(Notify::new());
        let fired = Arc::clone(&escalate);
        let cfg = fast_cfg();
        let threshold = cfg.failure_threshold;
        let mut probe = ProxyEgressProbe::new(
            ScriptedProber::new([false, false, true, false, false]),
            cfg,
            escalate,
            AckReader::new(|| None),
        );

        let run = tokio::spawn(async move { run_egress_probe(&mut probe, threshold).await });
        for _ in 0..12 {
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
        }
        // The scripted verdicts are exhausted (probe reports alive), so the loop
        // keeps ticking without ever escalating: abort it and confirm no verdict.
        run.abort();
        let _ = run.await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fired.notified())
                .await
                .is_err(),
            "non-consecutive failures must never escalate a reconnect"
        );
    }
}
