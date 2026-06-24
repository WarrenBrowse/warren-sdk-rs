//! The packet-plane seam shared by both datapaths.
//!
//! A [`PacketSink`] moves inner IP packets between a datapath (a TUN device, or
//! a userspace netstack) and the QUIC tunnel. The TUN backend reads packets from
//! the OS and writes them to the sink; the netstack/proxy backend synthesizes
//! packets from terminated L4 flows and does the same. [`QuicPacketSink`] is the
//! tunnel-side implementation over a [`warren_transport::ClientSession`].

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use warren_transport::{ClientSession, DaitaDriverHandle, MultihopSession};

use crate::error::NetError;

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

/// A [`PacketSink`] backed by a QUIC tunnel session (RFC 9221 datagrams).
#[derive(Debug)]
pub struct QuicPacketSink {
    session: ClientSession,
}

impl QuicPacketSink {
    /// Wraps an established session.
    #[must_use]
    pub fn new(session: ClientSession) -> Self {
        Self { session }
    }

    /// The underlying session.
    #[must_use]
    pub fn session(&self) -> &ClientSession {
        &self.session
    }
}

impl PacketSink for QuicPacketSink {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
        // One copy into the refcounted Bytes quinn needs; no intermediate Vec.
        self.session
            .send_datagram(Bytes::copy_from_slice(packet))
            .map_err(NetError::Tunnel)
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        self.session.read_datagram().await.map_err(NetError::Tunnel)
    }

    fn max_payload(&self) -> usize {
        // Honor both the path MTU (once probed) and the exit's policy MTU from
        // the handshake; before the first PMTU probe, fall back to the policy.
        let policy = usize::from(self.session.assigned_max_mtu());
        self.session
            .max_datagram_size()
            .map_or(policy, |path| path.min(policy))
    }
}

/// A [`PacketSink`] backed by a multihop tunnel session: every inner IP packet
/// is HPKE-sealed into a [`WarrenMultihopFrame`](warren_wire::WarrenMultihopFrame)
/// before it rides the QUIC datagram plane (the handshake real exits require).
pub struct MultihopPacketSink {
    session: Arc<MultihopSession>,
    /// When present, real traffic is reported to a DAITA driver so it can
    /// schedule uplink cover traffic (the driver itself emits via the session).
    daita: Option<DaitaDriverHandle>,
}

impl MultihopPacketSink {
    /// Wraps an established multihop session (no DAITA defense).
    #[must_use]
    pub fn new(session: MultihopSession) -> Self {
        Self::from_arc(Arc::new(session), None)
    }

    /// Wraps a shared session, optionally reporting traffic to a DAITA driver.
    /// The session is shared so the driver (which emits cover traffic) and this
    /// sink (which carries real traffic) drive the same tunnel.
    #[must_use]
    pub fn from_arc(session: Arc<MultihopSession>, daita: Option<DaitaDriverHandle>) -> Self {
        Self { session, daita }
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
}
