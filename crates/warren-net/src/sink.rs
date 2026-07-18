//! The packet-plane seam shared by both datapaths.
//!
//! A [`PacketSink`] moves inner IP packets between a datapath (a TUN device, or
//! a userspace netstack) and the QUIC tunnel. The TUN backend reads packets from
//! the OS and writes them to the sink; the netstack/proxy backend synthesizes
//! packets from terminated L4 flows and does the same. [`MultihopPacketSink`] is
//! the tunnel-side implementation over a [`warren_transport::MultihopSession`].

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use warren_transport::{DaitaDriverHandle, MultihopSession};
use warrenguard_pump::idle_cover::{CoverSink, CoverStop, run_idle_cover};

use crate::error::NetError;

/// Arms teardown-safe idle cover over `session` when `enabled`, spawning the
/// engine cover loop and returning the drop-to-stop guard the datapath owns.
///
/// `run_idle_cover` holds only a WEAK reference to the session, so cover can
/// never keep a torn-down tunnel alive (the leak class: a strong-ref driver plus
/// the idle timeout that cover keeps resetting). Dropping the returned
/// [`CoverStop`] (when the owning sink is dropped) stops the loop promptly; the
/// weak reference is the safety net if the guard is somehow leaked.
fn arm_idle_cover_over<S: CoverSink>(session: &Arc<S>, enabled: bool) -> Option<CoverStop> {
    enabled.then(|| {
        let (fut, stop) = run_idle_cover(session);
        tokio::spawn(fut);
        stop
    })
}

/// Moves inner IP packets to and from the tunnel.
pub trait PacketSink: Send + Sync {
    /// Sends one inner IP packet toward the exit.
    ///
    /// # Errors
    ///
    /// [`NetError::Tunnel`]/[`NetError::Multihop`] if the tunnel send fails (the
    /// datagram is too large for the path, or the session has closed).
    fn send_packet(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<(), NetError>> + Send;

    /// Awaits the next inner IP packet from the exit, returned zero-copy as
    /// [`Bytes`].
    ///
    /// # Errors
    ///
    /// [`NetError::Tunnel`]/[`NetError::Multihop`] if the tunnel read side has
    /// closed (the session ended).
    fn recv_packet(&self) -> impl std::future::Future<Output = Result<Bytes, NetError>> + Send;

    /// The largest packet payload the current path can carry.
    fn max_payload(&self) -> usize;

    /// Subscribe to mid-session maintenance-drain advisories (ADR 36), if the
    /// underlying tunnel surfaces them. The default returns `None` (the path
    /// emits no drain signal); the multi-hop sink overrides it. The proxy
    /// supervisor uses this to proactively reconnect off a draining exit.
    fn drain_watch(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>>> {
        None
    }

    /// Sends a batch of packets. The default forwards them one by one; a
    /// GSO-aware implementation can override this to coalesce the syscall.
    ///
    /// # Errors
    ///
    /// The first [`send_packet`](Self::send_packet) error stops the batch and is
    /// returned.
    fn send_batch(
        &self,
        packets: &[&[u8]],
    ) -> impl std::future::Future<Output = Result<(), NetError>> + Send {
        async move {
            for packet in packets {
                self.send_packet(packet).await?;
            }
            Ok(())
        }
    }

    /// Receives at least one and at most `max` packets, blocking for the first.
    /// The default returns a single packet; a GRO-aware implementation can
    /// return several harvested from one syscall.
    ///
    /// # Errors
    ///
    /// The [`recv_packet`](Self::recv_packet) error on the first packet (the
    /// session ended).
    fn recv_batch(
        &self,
        max: usize,
    ) -> impl std::future::Future<Output = Result<Vec<Bytes>, NetError>> + Send {
        async move {
            let first = self.recv_packet().await?;
            let mut out = Vec::with_capacity(max.max(1));
            out.push(first);
            Ok(out)
        }
    }
}

/// Observer of the session's final smoothed path RTT (ms), fired once when
/// the owning sink is dropped (the datapath teardown, the natural pre-close
/// lifecycle point). The sink stays discovery-agnostic: the SDK client
/// wires this to its RTT store, keyed by the identity it dialed.
pub type CloseRttObserver = Box<dyn Fn(u32) + Send + Sync>;

/// Clamped whole-millisecond reading of a session's smoothed path RTT.
fn rtt_millis(rtt: std::time::Duration) -> u32 {
    u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX)
}

/// A [`PacketSink`] backed by a multihop tunnel session: every inner IP packet
/// is HPKE-sealed into a [`WarrenMultihopFrame`](warren_wire::WarrenMultihopFrame)
/// before it rides the QUIC datagram plane (the handshake real exits require).
pub struct MultihopPacketSink {
    session: Arc<MultihopSession>,
    /// When present, real traffic is reported to a DAITA driver so it can
    /// schedule uplink cover traffic (the driver itself emits via the session).
    daita: Option<DaitaDriverHandle>,
    /// Drop-to-stop guard for the idle-cover loop, when armed (see
    /// [`Self::arm_idle_cover`]). Held here so cover is torn down with the sink
    /// (the connection lifecycle) and never outlives the tunnel.
    cover: Option<CoverStop>,
    /// Fired with the first hop's final path RTT on drop, when wired (see
    /// [`Self::with_close_rtt_observer`]).
    close_rtt: Option<CloseRttObserver>,
}

impl Drop for MultihopPacketSink {
    fn drop(&mut self) {
        if let Some(observer) = self.close_rtt.take() {
            observer(rtt_millis(self.session.path_rtt()));
        }
    }
}

impl MultihopPacketSink {
    /// Wraps an established multihop session (no DAITA defense, cover not armed).
    #[must_use]
    pub fn new(session: MultihopSession) -> Self {
        Self::from_arc(Arc::new(session), None)
    }

    /// Wraps a shared session, optionally reporting traffic to a DAITA driver.
    /// The session is shared so the driver (which emits cover traffic) and this
    /// sink (which carries real traffic) drive the same tunnel.
    #[must_use]
    pub fn from_arc(session: Arc<MultihopSession>, daita: Option<DaitaDriverHandle>) -> Self {
        Self {
            session,
            daita,
            cover: None,
            close_rtt: None,
        }
    }

    /// Arms `observer` to receive the first hop's final smoothed path RTT
    /// when this sink is dropped, complementing the post-handshake sample the
    /// SDK records at connect so a long session's parting measurement also
    /// reaches the client RTT store.
    #[must_use]
    pub fn with_close_rtt_observer(mut self, observer: CloseRttObserver) -> Self {
        self.close_rtt = Some(observer);
        self
    }

    /// Arms teardown-safe idle cover over the session when `idle_cover` is set
    /// AND DAITA is not active on this sink (the engine's mutual exclusion: DAITA
    /// already rains its own cover, so idle cover must not double it). The stop
    /// guard is owned by this sink, so cover is torn down when the sink (the
    /// datapath) is dropped and never outlives the tunnel.
    #[must_use]
    pub fn arm_idle_cover(mut self, idle_cover: bool) -> Self {
        let enabled = idle_cover && self.daita.is_none();
        self.cover = arm_idle_cover_over(&self.session, enabled);
        self
    }

    /// True while the idle-cover loop is armed for this sink (the datapath is
    /// emitting the jittered cover footprint instead of the keep-alive PING).
    #[must_use]
    pub fn cover_is_armed(&self) -> bool {
        self.cover.is_some()
    }

    /// The underlying session.
    #[must_use]
    pub fn session(&self) -> &MultihopSession {
        &self.session
    }

    /// A cheap, cloneable handle to the session's live counters, so a caller can
    /// keep reading totals after this sink is consumed by the datapath engine.
    #[must_use]
    pub fn metrics(&self) -> std::sync::Arc<warren_transport::MultihopMetrics> {
        self.session.metrics()
    }
}

impl PacketSink for MultihopPacketSink {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
        // Report the real uplink packet so the DAITA machine can regularise around
        // it, then send. The driver emits its own cover frames on the same session.
        if let Some(daita) = &self.daita {
            daita.note_uplink();
        }
        self.session.send_packet(packet).map_err(NetError::Multihop)
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        let packet = self
            .session
            .recv_packet()
            .await
            .map(Bytes::from)
            .map_err(NetError::Multihop)?;
        // The session already drops DAITA dummies, so anything surfaced here is a
        // real downlink packet (`NormalRecv`).
        if let Some(daita) = &self.daita {
            daita.note_downlink(false);
        }
        Ok(packet)
    }

    fn max_payload(&self) -> usize {
        // The sealed frame's per-packet overhead is already subtracted, so this
        // is the inner IP MTU the netstack engine should clamp to.
        self.session.max_inner_payload()
    }

    fn drain_watch(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>>> {
        Some(self.session.watch_drain())
    }
}

/// Channel depth for the merged inbound stream of a [`BondedPacketSink`].
const BOND_INBOUND_DEPTH: usize = 1024;

/// Bonds N multihop sessions to ONE exit into a single packet plane: outbound
/// packets are striped round-robin across members and inbound packets from all
/// members are merged. Because every member authenticates with the SAME account
/// identity, a real exit's sticky allocator assigns them ONE tunnel IP, so they
/// form a coherent bundle (return traffic for that IP may arrive on any member).
///
/// IP is connectionless, so striping needs no resequencing (TCP above the tunnel
/// tolerates reorder). This lifts the single-connection bandwidth ceiling.
///
/// NOTE: like every tunnel datapath here, the bonding must be validated against a
/// real exit (its sticky-IP coherence across the bundle) before being relied on;
/// the in-process tests cover the striping/merge logic against fake exits.
pub struct BondedPacketSink<S = MultihopPacketSink> {
    members: Vec<Arc<S>>,
    next: AtomicUsize,
    inbound: Mutex<mpsc::Receiver<Result<Bytes, NetError>>>,
    max_payload: usize,
    readers: Vec<tokio::task::JoinHandle<()>>,
}

impl<S: PacketSink + 'static> BondedPacketSink<S> {
    /// Bonds the given member sinks (at least one). Spawns one reader task per
    /// member that forwards inbound packets into the merged stream.
    ///
    /// # Panics
    ///
    /// Panics if `members` is empty (the caller must supply at least one).
    #[must_use]
    pub fn new(members: Vec<S>) -> Self {
        assert!(!members.is_empty(), "a bond needs at least one session");
        let max_payload = members.iter().map(S::max_payload).min().expect("non-empty");
        let members: Vec<Arc<S>> = members.into_iter().map(Arc::new).collect();
        let (tx, rx) = mpsc::channel(BOND_INBOUND_DEPTH);
        let readers = members
            .iter()
            .map(|member| {
                let member = Arc::clone(member);
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        let packet = member.recv_packet().await;
                        let was_err = packet.is_err();
                        // Stop this reader if the merged consumer is gone, or after
                        // surfacing a member error (that member's tunnel is done).
                        if tx.send(packet).await.is_err() || was_err {
                            break;
                        }
                    }
                })
            })
            .collect();
        Self {
            members,
            next: AtomicUsize::new(0),
            inbound: Mutex::new(rx),
            max_payload,
            readers,
        }
    }

    /// The number of bonded member sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Always false (a bond is constructed with at least one member).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl<S> Drop for BondedPacketSink<S> {
    fn drop(&mut self) {
        for r in &self.readers {
            r.abort();
        }
    }
}

impl<S: PacketSink + 'static> PacketSink for BondedPacketSink<S> {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
        // Round-robin stripe across members; IP reorder is tolerated downstream.
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.members.len();
        self.members[i].send_packet(packet).await
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        // Single consumer (the engine's reader loop), so this lock is uncontended.
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .unwrap_or(Err(NetError::EngineStopped))
    }

    fn max_payload(&self) -> usize {
        self.max_payload
    }

    fn drain_watch(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>>> {
        // Every member bonds to the SAME exit, so any member's drain advisory
        // speaks for the whole bundle; the first member's watch suffices.
        self.members.first().and_then(|m| m.drain_watch())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock sink: records sent packets and emits a fixed set of inbound packets.
    struct MockSink {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        inbound: Mutex<mpsc::Receiver<Bytes>>,
        payload: usize,
    }

    impl PacketSink for MockSink {
        async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
            self.sent.lock().await.push(packet.to_vec());
            Ok(())
        }
        async fn recv_packet(&self) -> Result<Bytes, NetError> {
            self.inbound
                .lock()
                .await
                .recv()
                .await
                .ok_or(NetError::EngineStopped)
        }
        fn max_payload(&self) -> usize {
            self.payload
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bond_stripes_sends_round_robin_and_merges_receives() {
        // Two members; the bond should stripe 4 sends 2-and-2, merge both inbound
        // streams, and report the smaller member MTU.
        let sent0 = Arc::new(Mutex::new(Vec::new()));
        let sent1 = Arc::new(Mutex::new(Vec::new()));
        let (in0_tx, in0_rx) = mpsc::channel(8);
        let (in1_tx, in1_rx) = mpsc::channel(8);
        let m0 = MockSink {
            sent: Arc::clone(&sent0),
            inbound: Mutex::new(in0_rx),
            payload: 1200,
        };
        let m1 = MockSink {
            sent: Arc::clone(&sent1),
            inbound: Mutex::new(in1_rx),
            payload: 1000,
        };
        let bond = BondedPacketSink::new(vec![m0, m1]);

        assert_eq!(bond.len(), 2);
        assert_eq!(
            bond.max_payload(),
            1000,
            "bond MTU is the smallest member's"
        );

        for i in 0..4u8 {
            bond.send_packet(&[i]).await.expect("send");
        }
        assert_eq!(sent0.lock().await.len(), 2, "member 0 got half the sends");
        assert_eq!(sent1.lock().await.len(), 2, "member 1 got half the sends");

        // Inbound from either member surfaces on the merged stream.
        in0_tx.send(Bytes::from_static(b"a")).await.unwrap();
        in1_tx.send(Bytes::from_static(b"b")).await.unwrap();
        let mut got = vec![
            bond.recv_packet().await.unwrap(),
            bond.recv_packet().await.unwrap(),
        ];
        got.sort();
        assert_eq!(
            got,
            vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")]
        );
    }

    /// A fake cover-session boundary: counts the cover datagrams the driver
    /// asks it to send, so a test observes cover starting and stopping. The
    /// concrete tunnel session is a system boundary here (a real network
    /// object), so a fake at the `CoverSink` seam is the right test double.
    struct RecordingCoverSink {
        sent: std::sync::Mutex<usize>,
    }
    impl CoverSink for RecordingCoverSink {
        fn send_cover(&self, _padding_len: usize) -> bool {
            *self.sent.lock().unwrap() += 1;
            true
        }
        fn max_inner_payload(&self) -> usize {
            1280
        }
        fn cover_seed(&self) -> u64 {
            0x51
        }
    }

    #[tokio::test(start_paused = true)]
    async fn arming_drives_cover_then_stops_when_the_guard_is_dropped() {
        let session = Arc::new(RecordingCoverSink {
            sent: std::sync::Mutex::new(0),
        });
        let guard = arm_idle_cover_over(&session, true).expect("an enabled gate must arm cover");

        // Cover must flow while the datapath (which owns the guard) is alive.
        tokio::time::advance(std::time::Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert!(
            *session.sent.lock().unwrap() > 0,
            "cover must be emitted while the stop guard is held"
        );

        // Dropping the guard is the teardown path: the loop must stop, so no
        // further cover is emitted even after more idle intervals elapse. The
        // session stays strong-held here, so ONLY the guard drop can stop it.
        drop(guard);
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        let after_teardown = *session.sent.lock().unwrap();
        tokio::time::advance(std::time::Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            *session.sent.lock().unwrap(),
            after_teardown,
            "dropping the CoverStop guard must stop cover: it never outlives the datapath"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn arming_is_a_noop_when_the_gate_is_off() {
        let session = Arc::new(RecordingCoverSink {
            sent: std::sync::Mutex::new(0),
        });
        assert!(
            arm_idle_cover_over(&session, false).is_none(),
            "a disabled gate must not arm cover"
        );
        tokio::time::advance(std::time::Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            *session.sent.lock().unwrap(),
            0,
            "no cover datagram may be emitted when the gate is off"
        );
    }

    async fn loopback_multihop_session() -> MultihopSession {
        use ed25519_dalek::SigningKey;
        use warren_test_support::spawn_fake_multihop_exit;
        use warren_transport::MultihopClientTunnel;

        let exit_key = SigningKey::from_bytes(&[6u8; 32]);
        let (exit_addr, keys) = spawn_fake_multihop_exit(exit_key).await;
        MultihopClientTunnel::new(SigningKey::from_bytes(&[3u8; 32]))
            .connect(
                keys.ed25519_pubkey,
                keys.x25519_pubkey,
                keys.exit_id,
                exit_addr,
            )
            .await
            .expect("loopback multihop connect")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_sink_fires_the_close_rtt_observer_once() {
        // The drop-time sample is the datapath's parting RTT measurement:
        // it must fire exactly once, with a plausible clamped-milliseconds
        // value, or long sessions never refresh the client RTT store.
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        let sink = MultihopPacketSink::new(loopback_multihop_session().await)
            .with_close_rtt_observer(Box::new(move |rtt_ms| {
                sink_seen.lock().unwrap().push(rtt_ms);
            }));
        assert!(
            seen.lock().unwrap().is_empty(),
            "the observer must not fire while the datapath is alive"
        );
        drop(sink);
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "sink drop must fire the close-RTT observer exactly once"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unwired_sink_drops_silently() {
        drop(MultihopPacketSink::new(loopback_multihop_session().await));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multihop_sink_arms_cover_only_when_the_gate_is_on() {
        let armed = MultihopPacketSink::new(loopback_multihop_session().await).arm_idle_cover(true);
        assert!(
            armed.cover_is_armed(),
            "the enabled idle-cover gate must arm the sink's cover loop"
        );

        let off = MultihopPacketSink::new(loopback_multihop_session().await).arm_idle_cover(false);
        assert!(
            !off.cover_is_armed(),
            "a disabled gate must leave the sink cover unarmed"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multihop_sink_never_arms_cover_when_daita_is_active() {
        // DAITA rains its own cover, so idle cover must not double it (the engine
        // mutual exclusion): even with the idle gate on, a DAITA-active sink stays
        // unarmed.
        let session = Arc::new(loopback_multihop_session().await);
        let cfg = warren_daita::DaitaPool::default_pool()
            .pick_os()
            .expect("the default DAITA pool is non-empty");
        let state = warren_daita::DaitaState::from_config(&cfg, std::time::Instant::now())
            .expect("DAITA state builds from a curated config");
        let handle = warren_transport::DaitaDriver::new(Arc::clone(&session), state).handle();

        let sink = MultihopPacketSink::from_arc(session, Some(handle)).arm_idle_cover(true);
        assert!(
            !sink.cover_is_armed(),
            "an active-DAITA sink must not also arm idle cover (mutual exclusion)"
        );
    }
}
