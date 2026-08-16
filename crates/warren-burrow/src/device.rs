//! The gateway device: the async shell around the engine-clean core.
//!
//! One [`GatewayDevice`] owns the peers' protocol sessions, the NAT and the
//! sockets, and outlives every tunnel under it. The supervisor hands it one
//! epoch at a time through [`EpochPacketDevice::begin_epoch`], and the sink it
//! returns is what the pump runs against the tunnel.
//!
//! Two rules govern the locking, and both are load-bearing. A lock is never
//! held across an await, because a socket send that blocks would otherwise
//! stall every peer at once. And the responder lock and the NAT lock are never
//! held together, because the two are taken in opposite orders on the two
//! directions of the datapath.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use warren_burrow_core::{
    ConfError, CoreError, DropReason, Encapsulated, GatewayConf, Inbound, MapProto, Napt,
    NatConfig, PeerId, PeerLabel, PeerPlan, PeerPublicKey, PeerStatus, ReloadReport, Responder,
    ResponderOptions, ScratchBuf, StaticDnat, UnknownPeer, V6State,
};
use warren_sdk::net::{EpochAddressing, EpochPacketDevice, NetError, PacketSink, RawUdpDemux};

use crate::control::GatewayControl;
use crate::socket::DatagramSocket;

/// The IPv6 minimum MTU. Under it a stock host fragments rather than shrinking
/// its packets, and this gateway drops fragments, so IPv6 is withdrawn instead.
pub const IPV6_MIN_MTU: usize = 1280;

/// How often the protocol timers run. WireGuard's own shortest timer is one
/// second, so this is comfortably inside every deadline while costing one pass
/// over the peers.
const TICK_INTERVAL: Duration = Duration::from_millis(250);

/// How many decrypted peer packets may wait for the tunnel. Deep enough to
/// absorb a burst from several peers, bounded so a stalled tunnel costs memory
/// that stops growing rather than the host's.
const DEFAULT_UPLINK_DEPTH: usize = 2048;

/// How much memory the datagrams waiting for one socket may hold, for the same
/// reason as [`UPLINK_BYTES_MAX`].
const EGRESS_BYTES_MAX: usize = 2 * 1024 * 1024;

/// How much memory the packets waiting for one epoch's tunnel may hold. A
/// decrypted inner packet can be 64 KB, so a depth alone would let one peer
/// pin that many times [`DEFAULT_UPLINK_DEPTH`].
const UPLINK_BYTES_MAX: usize = 4 * 1024 * 1024;

/// How many control datagrams of one epoch may wait. The control plane is
/// request/response, so this is already a burst.
const CONTROL_DEPTH: usize = 64;

/// How many datagrams may wait for one peer-facing socket. A socket whose
/// buffer is full makes a send await, and the readers must keep reading while
/// that happens: this queue is what separates the two.
const DEFAULT_EGRESS_DEPTH: usize = 1024;

/// How many read errors in a row count as a socket that is broken rather than
/// one answering for a datagram a peer refused.
const SOCKET_ERROR_STREAK: u32 = 8;

/// Pause after a streak of read errors, so a permanently broken socket costs a
/// slow retry loop instead of a burnt core.
const SOCKET_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// How many peer endpoints are remembered for socket selection. A gateway
/// serves a handful of devices; the cap is what keeps a flood of strangers
/// from growing the map.
const ENDPOINT_ROUTES_MAX: usize = 1024;

/// Why a device operation was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GatewayError {
    /// The configuration breaks one of the core's rules.
    #[error(transparent)]
    Conf(#[from] ConfError),
    /// A pinned forward could not be installed.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// No peer carries that label.
    #[error(transparent)]
    UnknownPeer(#[from] UnknownPeer),
}

/// How a device is built.
#[derive(Debug, Clone)]
pub struct GatewayOptions {
    /// How the responder is configured.
    pub responder: ResponderOptions,
    /// The NAT's ranges, caps and timeouts.
    pub nat: NatConfig,
    /// The MTU the peers were configured with, which is the largest packet
    /// they will send.
    pub client_mtu: u16,
    /// Whether the operator asked for IPv6 at all.
    pub ipv6: bool,
}

impl Default for GatewayOptions {
    fn default() -> Self {
        Self {
            responder: ResponderOptions::default(),
            nat: NatConfig::default(),
            client_mtu: 1280,
            ipv6: true,
        }
    }
}

/// What only the shell can count: the queue, the sockets and the stale epochs.
#[derive(Debug, Default)]
pub struct DeviceCounters {
    uplink_queue_full: AtomicU64,
    uplink_stale_flushed: AtomicU64,
    stale_epoch_send: AtomicU64,
    socket_send_failed: AtomicU64,
    egress_queue_full: AtomicU64,
    control_delivered: AtomicU64,
    downlink_unroutable: AtomicU64,
}

/// A reading of [`DeviceCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DeviceSnapshot {
    /// Peer packets dropped because the tunnel was not draining the queue.
    pub uplink_queue_full: u64,
    /// Queued packets discarded because their epoch ended before they left.
    pub uplink_stale_flushed: u64,
    /// Downlink packets a sink of a dead epoch was handed, and dropped.
    pub stale_epoch_send: u64,
    /// Datagrams the socket refused.
    pub socket_send_failed: u64,
    /// Datagrams dropped because the sockets were not draining fast enough.
    pub egress_queue_full: u64,
    /// Downlink packets that belonged to the gateway's own control plane.
    pub control_delivered: u64,
    /// Downlink packets no peer owned once translated.
    pub downlink_unroutable: u64,
}

impl DeviceCounters {
    fn snapshot(&self) -> DeviceSnapshot {
        DeviceSnapshot {
            uplink_queue_full: self.uplink_queue_full.load(Ordering::Relaxed),
            uplink_stale_flushed: self.uplink_stale_flushed.load(Ordering::Relaxed),
            stale_epoch_send: self.stale_epoch_send.load(Ordering::Relaxed),
            socket_send_failed: self.socket_send_failed.load(Ordering::Relaxed),
            egress_queue_full: self.egress_queue_full.load(Ordering::Relaxed),
            control_delivered: self.control_delivered.load(Ordering::Relaxed),
            downlink_unroutable: self.downlink_unroutable.load(Ordering::Relaxed),
        }
    }
}

/// Everything a health route renders from one reading.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GatewaySnapshot {
    /// Which epoch the device is serving; 0 before the first one.
    pub generation: u64,
    /// Whether the gateway may emit anything toward a peer.
    pub gate_open: bool,
    /// The epoch the gate belongs to. Read under the same lock as the two
    /// fields above, so an open gate on a foreign epoch is observable rather
    /// than an artefact of three separate reads.
    pub gate_generation: u64,
    /// Whether the epoch can carry IPv6.
    pub ipv6: V6State,
    /// The live inner budget, when a tunnel has reported one.
    pub inner_budget: Option<usize>,
    /// Every peer as `/peers` renders it.
    pub peers: Vec<PeerStatus>,
    /// How many peers hold a live session.
    pub peers_with_session: usize,
    /// How many NAT mappings are live.
    pub nat_mappings: usize,
    /// The responder's counters.
    pub responder: warren_burrow_core::ResponderSnapshot,
    /// The NAT's counters.
    pub nat: warren_burrow_core::Snapshot,
    /// The shell's own counters.
    pub device: DeviceSnapshot,
}

/// One item waiting for the tunnel.
enum UplinkItem {
    /// A decrypted peer packet, not yet translated.
    Peer {
        /// The epoch it was decrypted under.
        generation: u64,
        /// Who sent it, which is what the NAT keys ownership on.
        peer: PeerId,
        /// The packet, as the peer wrote it.
        packet: Vec<u8>,
    },
}

/// One socket's outbound queue, bounded in bytes as well as in items.
struct EgressLane {
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    rx: tokio::sync::Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    queued: AtomicUsize,
}

impl EgressLane {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(DEFAULT_EGRESS_DEPTH);
        Self {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            queued: AtomicUsize::new(0),
        }
    }

    /// Queues one datagram, or reports the queue full.
    fn try_send(&self, to: SocketAddr, datagram: Vec<u8>) -> bool {
        let len = datagram.len();
        if self.queued.load(Ordering::Relaxed).saturating_add(len) > EGRESS_BYTES_MAX {
            return false;
        }
        self.queued.fetch_add(len, Ordering::Relaxed);
        if self.tx.try_send((to, datagram)).is_err() {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            return false;
        }
        true
    }
}

impl UplinkItem {
    /// What holding it costs, which is what the queue is bounded on.
    fn len(&self) -> usize {
        match self {
            Self::Peer { packet, .. } => packet.len(),
        }
    }
}

/// One epoch's uplink queue, bounded in bytes as well as in items.
struct UplinkQueue {
    tx: mpsc::Sender<UplinkItem>,
    queued: Arc<AtomicUsize>,
}

impl UplinkQueue {
    /// Enqueues one packet, or reports the queue full.
    fn try_send(&self, item: UplinkItem) -> bool {
        let len = item.len();
        if self.queued.load(Ordering::Relaxed).saturating_add(len) > UPLINK_BYTES_MAX {
            return false;
        }
        self.queued.fetch_add(len, Ordering::Relaxed);
        if self.tx.try_send(item).is_err() {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            return false;
        }
        true
    }
}

struct Inner {
    responder: Mutex<Responder>,
    nat: Mutex<Napt>,
    sockets: Vec<Arc<dyn DatagramSocket>>,
    /// Which socket last heard from an endpoint, so an answer leaves by the
    /// address the peer is talking to.
    routes: Mutex<HashMap<SocketAddr, usize>>,
    /// The queue of the epoch running now, replaced at every turnover: an
    /// epoch that is over holds a receiver nobody feeds any more, so a pump
    /// still parked on it can never keep the live epoch's packets waiting.
    uplink_tx: Mutex<Option<UplinkQueue>>,
    /// Datagrams waiting for each socket, one queue and one writer per socket.
    /// Queued rather than awaited, so a socket whose buffer is full never stops
    /// a reader from serving other peers, and never holds another socket's
    /// answers behind its own.
    egress: Vec<EgressLane>,
    /// Bumped by every epoch, and never reused: a sink stamped with an older
    /// value belongs to a tunnel that is gone.
    generation: AtomicU64,
    /// The largest inner packet the current tunnel carries, 0 until a tunnel
    /// reports one.
    inner_budget: AtomicUsize,
    ipv6_requested: bool,
    client_mtu: u16,
    /// The control plane of the current epoch, so the daemon can prove egress
    /// over the same UDP path the port forwarder rides.
    control: Mutex<Option<GatewayControl>>,
    counters: DeviceCounters,
}

/// The gateway's peer-facing device.
///
/// Cloneable: the supervisor takes one and the daemon keeps one to read the
/// snapshot, open the gate and install a pinned forward.
#[derive(Clone)]
pub struct GatewayDevice {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for GatewayDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayDevice")
            .field("generation", &self.inner.generation.load(Ordering::Relaxed))
            .field("sockets", &self.inner.sockets.len())
            .finish()
    }
}

impl GatewayDevice {
    /// Builds a device over already-bound sockets.
    ///
    /// # Errors
    ///
    /// [`GatewayError::Conf`] when the configuration and the plan disagree.
    pub fn new(
        conf: &GatewayConf,
        plan: PeerPlan,
        options: &GatewayOptions,
        sockets: Vec<Arc<dyn DatagramSocket>>,
    ) -> Result<Self, GatewayError> {
        let responder = Responder::new(conf, plan, options.responder)?;
        let mut nat = Napt::new(options.nat.clone());
        // The responder is the one place that knows which peer owns which
        // address, and the NAT refuses any source outside that view.
        nat.set_ownership(responder.ownership());
        let egress = sockets.iter().map(|_| EgressLane::new()).collect();
        Ok(Self {
            inner: Arc::new(Inner {
                responder: Mutex::new(responder),
                nat: Mutex::new(nat),
                sockets,
                routes: Mutex::new(HashMap::new()),
                uplink_tx: Mutex::new(None),
                egress,
                generation: AtomicU64::new(0),
                inner_budget: AtomicUsize::new(0),
                ipv6_requested: options.ipv6,
                client_mtu: options.client_mtu,
                control: Mutex::new(None),
                counters: DeviceCounters::default(),
            }),
        })
    }

    /// Starts one reader per socket plus the timer, and returns the guard that
    /// stops them when it is dropped.
    #[must_use]
    pub fn spawn(&self) -> GatewayTasks {
        let mut tasks = Vec::with_capacity(self.inner.sockets.len() * 2 + 1);
        for index in 0..self.inner.sockets.len() {
            let inner = Arc::clone(&self.inner);
            tasks.push(tokio::spawn(async move { read_socket(inner, index).await }));
        }
        let inner = Arc::clone(&self.inner);
        tasks.push(tokio::spawn(async move { run_timer(inner).await }));
        for index in 0..self.inner.sockets.len() {
            let inner = Arc::clone(&self.inner);
            tasks.push(tokio::spawn(
                async move { write_egress(inner, index).await },
            ));
        }
        GatewayTasks { tasks }
    }

    /// The epoch the device is serving; 0 before the first one.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    /// Opens the gate, but only while `generation` is still the current epoch.
    ///
    /// Returns `false` when it is not, which is how a caller that verified
    /// egress on an epoch that has since been replaced fails closed rather
    /// than opening the gate on an unproven tunnel.
    #[must_use]
    pub fn open_gate_for(&self, generation: u64) -> bool {
        let mut responder = self.inner.responder.lock();
        if self.inner.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        responder.set_gate(true, generation);
        true
    }

    /// Closes the gate: nothing but a stateless cookie reply leaves the
    /// gateway afterwards.
    pub fn close_gate(&self) {
        let mut responder = self.inner.responder.lock();
        let generation = self.inner.generation.load(Ordering::Acquire);
        responder.set_gate(false, generation);
    }

    /// Records the largest inner packet the tunnel currently carries.
    ///
    /// IPv6 follows it: under the v6 minimum MTU a Packet Too Big would make a
    /// stock host fragment, and this gateway drops fragments, so v6 is
    /// withdrawn with a fast unreachable instead of black-holed.
    pub fn note_inner_budget(&self, budget: usize) {
        self.inner.inner_budget.store(budget, Ordering::Relaxed);
        let state = self.v6_state_for(budget);
        self.inner.responder.lock().set_ipv6(state);
    }

    /// The live inner budget, when a tunnel has reported one.
    #[must_use]
    pub fn inner_budget(&self) -> Option<usize> {
        match self.inner.inner_budget.load(Ordering::Relaxed) {
            0 => None,
            budget => Some(budget),
        }
    }

    /// Pins an external port to one peer endpoint, in both directions.
    ///
    /// # Errors
    ///
    /// [`GatewayError::Core`] when no peer owns the target or the port cannot
    /// be reserved.
    pub fn add_static_dnat(
        &self,
        proto: MapProto,
        external_port: u16,
        target: SocketAddr,
    ) -> Result<(), GatewayError> {
        self.inner.nat.lock().add_static(
            StaticDnat {
                proto,
                external_port,
                target,
            },
            Instant::now(),
        )?;
        Ok(())
    }

    /// Applies a new configuration, keeping the sessions of every peer whose
    /// key material and allowed IPs are unchanged.
    ///
    /// # Errors
    ///
    /// [`GatewayError::Conf`] when the new configuration breaks a rule, in
    /// which case nothing changes.
    pub fn reload(&self, conf: &GatewayConf) -> Result<ReloadReport, GatewayError> {
        let (report, ownership) = {
            let mut responder = self.inner.responder.lock();
            let report = responder.reload(conf)?;
            (report, responder.ownership())
        };
        let mut nat = self.inner.nat.lock();
        nat.set_ownership(ownership);
        Ok(report)
    }

    /// Rebuilds one peer's tunnel, which clears its sessions and its handshake
    /// timestamp guard, and forgets its NAT mappings.
    ///
    /// # Errors
    ///
    /// [`GatewayError::UnknownPeer`] when no peer carries that label.
    pub fn reset_peer(&self, label: &PeerLabel) -> Result<(), GatewayError> {
        let peer = {
            let mut responder = self.inner.responder.lock();
            responder.reset_peer(label)?;
            responder.peer_by_label(label)
        };
        if let Some(peer) = peer {
            self.inner.nat.lock().flush_peer(peer);
        }
        Ok(())
    }

    /// One reading of everything a health route renders.
    #[must_use]
    pub fn snapshot(&self) -> GatewaySnapshot {
        // The epoch and the gate are read under one lock: they are written
        // under it too, and reading them apart would show a gate open on an
        // epoch that had already been replaced.
        let (peers, responder_stats, ipv6, gate, generation) = {
            let responder = self.inner.responder.lock();
            (
                responder.snapshot(),
                responder.stats(),
                responder.ipv6(),
                responder.gate(),
                self.inner.generation.load(Ordering::Acquire),
            )
        };
        let (nat_stats, nat_mappings) = {
            let nat = self.inner.nat.lock();
            (nat.stats(), nat.mapping_count())
        };
        GatewaySnapshot {
            generation,
            gate_open: gate.open,
            gate_generation: gate.generation,
            ipv6,
            inner_budget: self.inner_budget(),
            peers_with_session: peers.iter().filter(|p| p.has_session).count(),
            peers,
            nat_mappings,
            responder: responder_stats,
            nat: nat_stats,
            device: self.inner.counters.snapshot(),
        }
    }

    /// The current epoch's in-tunnel control plane, for the egress proof.
    ///
    /// `None` before the first epoch; a plane whose epoch has ended reports
    /// itself dead rather than hanging, which is what ends a probe over it.
    #[must_use]
    pub fn control(&self) -> Option<GatewayControl> {
        self.inner.control.lock().clone()
    }

    /// The gateway's public key, which is what peers encrypt to.
    #[must_use]
    pub fn public_key(&self) -> PeerPublicKey {
        self.inner.responder.lock().public_key()
    }

    /// The addresses the peer-facing sockets are bound to.
    #[must_use]
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.inner
            .sockets
            .iter()
            .filter_map(|s| s.local_addr().ok())
            .collect()
    }

    fn v6_state_for(&self, budget: usize) -> V6State {
        if !self.inner.ipv6_requested {
            return V6State::NoAssignment;
        }
        match self.inner.nat.lock().epoch() {
            // Before an epoch there is nothing to carry v6 over either.
            None => V6State::NoAssignment,
            Some(_) => {
                if budget != 0 && budget < IPV6_MIN_MTU {
                    V6State::BudgetTooSmall
                } else {
                    V6State::Available
                }
            }
        }
    }
}

/// The reader and timer tasks of one device; dropping it stops them.
#[derive(Debug)]
pub struct GatewayTasks {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for GatewayTasks {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl EpochPacketDevice for GatewayDevice {
    type Sink = GatewayEpochSink;
    type Udp = GatewayControl;

    fn begin_epoch(&self, addressing: EpochAddressing) -> (GatewayEpochSink, GatewayControl) {
        // The device's own counter, not the supervisor's: monotonicity is what
        // makes a stale sink recognisable, and a supervisor that restarted its
        // numbering would hand out a generation this device has already served.
        let previous = self.inner.generation.load(Ordering::Acquire);
        let generation = addressing.epoch.generation.max(previous + 1);

        {
            let mut nat = self.inner.nat.lock();
            nat.set_external(
                warren_burrow_core::EpochId {
                    exit: warren_burrow_core::ExitId::from_bytes(*addressing.epoch.exit.as_bytes()),
                    generation,
                },
                addressing.ipv4,
                addressing.ipv6_address(),
            );
        }
        let ipv6 = if self.inner.ipv6_requested && addressing.ipv6_address().is_some() {
            V6State::Available
        } else {
            V6State::NoAssignment
        };
        {
            // Closed until the daemon has proven this epoch egresses: an
            // authenticated packet toward a peer over a black hole feeds that
            // peer's own liveness detector and hides the outage from it.
            //
            // The epoch is published under this same lock, because that is the
            // lock `open_gate_for` compares against it: published outside, a
            // proof finishing in the window would find the previous epoch
            // still current and open the gate on this one, unproven.
            let mut responder = self.inner.responder.lock();
            responder.set_gate(false, generation);
            responder.set_ipv6(ipv6);
            self.inner.inner_budget.store(0, Ordering::Relaxed);
            self.inner.generation.store(generation, Ordering::Release);
        }

        let (uplink_tx, uplink_rx) = mpsc::channel(DEFAULT_UPLINK_DEPTH);
        let queued = Arc::new(AtomicUsize::new(0));
        // Publishing it drops the previous epoch's sender, which is what wakes
        // a pump still parked on that epoch's queue.
        *self.inner.uplink_tx.lock() = Some(UplinkQueue {
            tx: uplink_tx,
            queued: Arc::clone(&queued),
        });

        let (control_tx, control_rx) = mpsc::channel(CONTROL_DEPTH);
        let demux = Arc::new(RawUdpDemux::new(control_tx));
        let control = GatewayControl::new(Arc::clone(&demux), addressing.ipv4, addressing.gateway);
        *self.inner.control.lock() = Some(control.clone());
        let sink = GatewayEpochSink {
            inner: Arc::clone(&self.inner),
            generation,
            demux,
            control: control.clone(),
            control_rx: tokio::sync::Mutex::new(control_rx),
            uplink_rx: tokio::sync::Mutex::new(uplink_rx),
            uplink_queued: queued,
            scratch: Mutex::new(ScratchBuf::new()),
        };
        (sink, control)
    }
}

/// One epoch's packet plane.
///
/// A sink stamped with an older generation is inert toward the device: it
/// drops and counts what it is handed, reports the epoch dead when read, and
/// leaves the gate alone when it is dropped (it still closes its own epoch's
/// control plane and drains its own queue, which nothing else owns). The
/// supervisor drops the previous epoch's pump before it starts the next one,
/// but the property holds without that ordering: a pump still parked in
/// [`PacketSink::recv_packet`] waits on this epoch's own queue, whose sender
/// the turnover dropped, so it wakes to a dead epoch instead of holding
/// anything the live one needs.
pub struct GatewayEpochSink {
    inner: Arc<Inner>,
    generation: u64,
    demux: Arc<RawUdpDemux>,
    control: GatewayControl,
    control_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    uplink_rx: tokio::sync::Mutex<mpsc::Receiver<UplinkItem>>,
    /// Bytes this epoch's queue holds, released as the pump takes them.
    uplink_queued: Arc<AtomicUsize>,
    scratch: Mutex<ScratchBuf>,
}

impl std::fmt::Debug for GatewayEpochSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayEpochSink")
            .field("generation", &self.generation)
            .field("current", &self.is_current())
            .finish()
    }
}

impl GatewayEpochSink {
    fn is_current(&self) -> bool {
        self.inner.generation.load(Ordering::Acquire) == self.generation
    }
}

impl PacketSink for GatewayEpochSink {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
        if !self.is_current() {
            // The pump of a dead epoch, still draining: its packets belong to a
            // tunnel that is gone, and answering an error would only make its
            // own teardown noisier.
            self.inner
                .counters
                .stale_epoch_send
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        // The gateway's own control-plane answers first: they carry the
        // assigned address, which the NAT would refuse as an unknown mapping.
        if self.demux.deliver(packet) {
            self.inner
                .counters
                .control_delivered
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let mut owned = packet.to_vec();
        let now = Instant::now();
        let translated = match self.inner.nat.lock().translate_downlink(&mut owned, now) {
            Ok(translated) => translated,
            // A packet with no mapping is what a NAT drops: counted there,
            // never an epoch-ending error.
            Err(_) => {
                self.inner
                    .counters
                    .downlink_unroutable
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };

        let out = {
            let mut scratch = self.scratch.lock();
            let mut responder = self.inner.responder.lock();
            match responder.send_to_peer(translated.peer, &owned, &mut scratch) {
                Ok(Encapsulated::Sent(to, bytes)) => Some((to, bytes.to_vec())),
                Ok(Encapsulated::Deferred { initiation }) => {
                    initiation.map(|(to, bytes)| (to, bytes.to_vec()))
                }
                // Every refusal is already counted inside the responder, and
                // none of them is the tunnel's fault: a packet for a peer that
                // is gone, or arriving while the gate is closed, is dropped
                // the way a router drops what it cannot deliver.
                Err(_) => None,
            }
        };
        if let Some((to, datagram)) = out {
            queue_datagram(&self.inner, to, datagram);
        }
        Ok(())
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        loop {
            if !self.is_current() {
                return Err(NetError::EngineStopped);
            }
            let mut control_rx = self.control_rx.lock().await;
            let mut uplink_rx = self.uplink_rx.lock().await;
            let item = tokio::select! {
                // The control plane first when both are ready: a NAT-PMP
                // renewal or an egress probe held behind a burst of peer
                // traffic is what makes an epoch look dead.
                biased;
                control = control_rx.recv() => {
                    match control {
                        // Already sourced at the assigned address, so it needs
                        // no translation and must not get one.
                        Some(packet) => return Ok(Bytes::from(packet)),
                        None => return Err(NetError::EngineStopped),
                    }
                }
                item = uplink_rx.recv() => item,
            };
            drop(uplink_rx);
            drop(control_rx);
            let Some(item) = item else {
                return Err(NetError::EngineStopped);
            };
            self.uplink_queued.fetch_sub(item.len(), Ordering::Relaxed);
            let UplinkItem::Peer {
                generation,
                peer,
                mut packet,
            } = item;
            if generation != self.generation {
                // Queued under a tunnel that is gone: sending it now would put
                // the previous epoch's source address on the wire, which the
                // new exit refuses as a spoof.
                self.inner
                    .counters
                    .uplink_stale_flushed
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let now = Instant::now();
            if self
                .inner
                .nat
                .lock()
                .translate_uplink(peer, &mut packet, now)
                .is_ok()
            {
                return Ok(Bytes::from(packet));
            }
            // Counted by class inside the NAT; a refused packet is a drop, not
            // the end of the epoch.
        }
    }

    fn max_payload(&self) -> usize {
        usize::from(self.inner.client_mtu)
    }
}

impl Drop for GatewayEpochSink {
    fn drop(&mut self) {
        // What this epoch never carried dies with it: sending it under the
        // next epoch's address is what the new exit refuses as a spoof.
        if let Ok(mut uplink_rx) = self.uplink_rx.try_lock() {
            while uplink_rx.try_recv().is_ok() {
                self.inner
                    .counters
                    .uplink_stale_flushed
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        // Its own control plane, always: it belongs to this epoch alone, and
        // closing it is what tells the port forwarder and the egress probe
        // that the tunnel they were exchanging over is gone. A later epoch
        // built its own, so this can never reach a live one.
        self.control.close();
        if !self.is_current() {
            // The gate is the device's, and a later epoch owns it now: closing
            // it here would take down a tunnel that is working.
            return;
        }
        self.inner.responder.lock().set_gate(false, self.generation);
    }
}

/// Queues one datagram for the socket that last heard from `to`.
///
/// Never awaits the socket: a full socket buffer would otherwise stall the
/// reader that produced this answer, and with it every other peer that reader
/// serves. A queue that fills drops, which is what a congested link does.
fn queue_datagram(inner: &Arc<Inner>, to: SocketAddr, datagram: Vec<u8>) {
    let index = socket_for(inner, to);
    let queued = inner
        .egress
        .get(index)
        .is_some_and(|lane| lane.try_send(to, datagram));
    if !queued {
        inner
            .counters
            .egress_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Drains one socket's queue into that socket.
async fn write_egress(inner: Arc<Inner>, index: usize) {
    let (Some(lane), Some(socket)) = (inner.egress.get(index), inner.sockets.get(index)) else {
        return;
    };
    loop {
        let next = lane.rx.lock().await.recv().await;
        let Some((to, datagram)) = next else {
            return;
        };
        lane.queued.fetch_sub(datagram.len(), Ordering::Relaxed);
        if socket.send_to(&datagram, to).await.is_err() {
            inner
                .counters
                .socket_send_failed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Which socket answers `to`: the one it was last heard on, else the first of
/// its own address family, else the first bound.
fn socket_for(inner: &Arc<Inner>, to: SocketAddr) -> usize {
    if let Some(index) = inner.routes.lock().get(&to).copied() {
        return index;
    }
    inner
        .sockets
        .iter()
        .position(|s| {
            s.local_addr()
                .is_ok_and(|local| local.is_ipv6() == to.is_ipv6())
        })
        .unwrap_or(0)
}

/// Remembers which socket an authenticated peer was heard on.
fn note_route(inner: &Arc<Inner>, from: SocketAddr, index: usize) {
    let mut routes = inner.routes.lock();
    if routes.len() >= ENDPOINT_ROUTES_MAX && !routes.contains_key(&from) {
        // A gateway serves a handful of devices; anything past the cap is a
        // flood, and starting over costs one wrong socket choice per peer.
        routes.clear();
    }
    routes.insert(from, index);
}

/// One socket's reader: every datagram a peer sends arrives here.
async fn read_socket(inner: Arc<Inner>, index: usize) {
    let mut buf = vec![0u8; 65_535];
    // The one buffer boringtun may decapsulate into: an undersized one is a
    // panic on an unauthenticated datagram, so this type is the only way to
    // build one.
    let mut scratch = ScratchBuf::new();
    let mut consecutive_errors = 0u32;
    loop {
        let Some(socket) = inner.sockets.get(index) else {
            return;
        };
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(read) => {
                consecutive_errors = 0;
                read
            }
            // A refused datagram (an ICMP port unreachable from a peer that
            // went away) must not end the reader for every other peer. A
            // socket that fails every read is a different thing, and retrying
            // it in a tight loop would burn a core.
            Err(_) => {
                consecutive_errors += 1;
                if consecutive_errors > SOCKET_ERROR_STREAK {
                    tokio::time::sleep(SOCKET_ERROR_BACKOFF).await;
                }
                continue;
            }
        };
        handle_datagram(&inner, index, from, len, &buf, &mut scratch);
    }
}

/// One datagram, from the socket to whatever it turns into.
fn handle_datagram(
    inner: &Arc<Inner>,
    index: usize,
    from: SocketAddr,
    len: usize,
    buf: &[u8],
    scratch: &mut ScratchBuf,
) {
    let now = Instant::now();
    enum Next {
        Reply(Vec<u8>),
        Uplink(PeerId, Vec<u8>),
        Loopback(PeerId, Vec<u8>),
        Flush,
        Nothing,
    }

    let next = {
        let mut responder = inner.responder.lock();
        match responder.handle_datagram(from, &buf[..len], now, scratch) {
            Inbound::Reply(bytes) => Next::Reply(bytes.to_vec()),
            Inbound::Uplink { peer, packet } => Next::Uplink(peer, packet.to_vec()),
            Inbound::Loopback { to, packet } => Next::Loopback(to, packet.to_vec()),
            // A handshake completed or a keepalive landed: what boringtun held
            // behind the session it was waiting for can go out now.
            Inbound::Consumed => Next::Flush,
            Inbound::Dropped(_) => Next::Nothing,
        }
    };

    match next {
        Next::Reply(datagram) => {
            note_route(inner, from, index);
            queue_datagram(inner, from, datagram);
            flush_queues(inner, scratch);
        }
        Next::Uplink(peer, packet) => {
            note_route(inner, from, index);
            let generation = inner.generation.load(Ordering::Acquire);
            let item = UplinkItem::Peer {
                generation,
                peer,
                packet,
            };
            // Never blocks the reader: a tunnel that has stopped draining must
            // cost this gateway a counted drop, not every peer's liveness. With
            // no epoch there is nowhere to put it, which is the same drop.
            let refused = match inner.uplink_tx.lock().as_ref() {
                Some(queue) => !queue.try_send(item),
                None => true,
            };
            if refused {
                inner
                    .counters
                    .uplink_queue_full
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        Next::Loopback(to, packet) => {
            note_route(inner, from, index);
            let out = {
                let mut responder = inner.responder.lock();
                match responder.send_to_peer(to, &packet, scratch) {
                    Ok(Encapsulated::Sent(dst, bytes)) => Some((dst, bytes.to_vec())),
                    Ok(Encapsulated::Deferred { initiation }) => {
                        initiation.map(|(dst, bytes)| (dst, bytes.to_vec()))
                    }
                    // Counted inside the responder; a peer that cannot be
                    // reached is not this packet's sender's problem.
                    Err(_) => None,
                }
            };
            if let Some((dst, datagram)) = out {
                queue_datagram(inner, dst, datagram);
            }
        }
        Next::Flush => {
            note_route(inner, from, index);
            flush_queues(inner, scratch);
        }
        Next::Nothing => {}
    }
}

/// Drains what boringtun queued behind a handshake, for every peer.
///
/// The responder answers a handshake without naming the peer it belongs to
/// (the datagram is authenticated inside), so the drain covers all of them; it
/// costs one cheap call per peer and only runs on a handshake or a keepalive,
/// never on the data path.
fn flush_queues(inner: &Arc<Inner>, scratch: &mut ScratchBuf) {
    let peers = inner.responder.lock().peer_ids();
    for peer in peers {
        loop {
            let out = {
                let mut responder = inner.responder.lock();
                let endpoint = responder.endpoint(peer);
                responder
                    .flush(peer, scratch)
                    .map(<[u8]>::to_vec)
                    .zip(endpoint)
            };
            let Some((datagram, to)) = out else { break };
            queue_datagram(inner, to, datagram);
        }
    }
}

/// Drives the protocol timers and the NAT's expiry sweep.
async fn run_timer(inner: Arc<Inner>) {
    let mut scratch = ScratchBuf::new();
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let out = inner
            .responder
            .lock()
            .tick(now, SystemTime::now(), &mut scratch);
        for (to, datagram) in out {
            queue_datagram(&inner, to, datagram);
        }
        inner.nat.lock().sweep(now);
    }
}

/// Which drop class a reason belongs to, for the health routes.
#[must_use]
pub fn drop_class(reason: DropReason) -> &'static str {
    match reason {
        DropReason::Malformed => "malformed",
        DropReason::Auth => "auth",
        DropReason::UnknownPeer => "unknown_peer",
        DropReason::UnknownIndex => "unknown_index",
        DropReason::Replay => "replay",
        DropReason::SpoofedSource => "spoofed_source",
        DropReason::LinkLocalSource => "link_local_source",
        DropReason::GateClosed => "gate_closed",
        DropReason::SourceRateLimited => "source_rate_limited",
        DropReason::PeerIsolation => "peer_isolation",
        DropReason::NoRoute => "no_route",
        DropReason::Oversize => "oversize",
        DropReason::NonUnicast => "non_unicast",
        DropReason::SelfDestination => "self_destination",
        DropReason::UnownedPeerAddress => "unowned_peer_address",
        DropReason::PoolDestination => "pool_destination",
        DropReason::PrivateDestination => "private_destination",
        DropReason::V6Unavailable => "v6_unavailable",
        DropReason::V6Budget => "v6_budget",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::AtomicBool;

    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519;
    use ip_network::IpNetwork;
    use warren_burrow_core::{
        GatewayKey, PeerConf, PeerPublicKey, PresharedKey, PresharedKey as Psk, parse_ip,
        read_ports,
    };
    use warren_sdk::net::{EpochId, ExitId, UdpFlow, UdpOpener};

    use crate::socket::{BoxIoFuture, DatagramSocket};

    const PEER_ADDR: &str = "192.168.7.2:51820";
    const ASSIGNED_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    const GATEWAY_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    /// A socket the test drives: it hands the reader whatever the test pushes,
    /// records what the gateway sends, and can be made to stall on send the way
    /// a full socket buffer does.
    struct FakeSocket {
        inbound: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
        sent: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
        stall: AtomicBool,
        local: SocketAddr,
    }

    impl DatagramSocket for FakeSocket {
        fn send_to<'a>(
            &'a self,
            buf: &'a [u8],
            target: SocketAddr,
        ) -> BoxIoFuture<'a, std::io::Result<usize>> {
            Box::pin(async move {
                if self.stall.load(Ordering::Relaxed) {
                    std::future::pending::<()>().await;
                }
                let _ = self.sent.send((target, buf.to_vec()));
                Ok(buf.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            buf: &'a mut [u8],
        ) -> BoxIoFuture<'a, std::io::Result<(usize, SocketAddr)>> {
            Box::pin(async move {
                let Some((data, from)) = self.inbound.lock().await.recv().await else {
                    return Err(std::io::Error::from(std::io::ErrorKind::NotConnected));
                };
                buf[..data.len()].copy_from_slice(&data);
                Ok((data.len(), from))
            })
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local)
        }
    }

    /// A gateway with one peer, a stock initiator for it, and the wires to
    /// drive both.
    struct Harness {
        device: GatewayDevice,
        _tasks: GatewayTasks,
        client: Tunn,
        peer_v4: Ipv4Addr,
        inbound: Vec<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
        sent: Vec<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
        sockets: Vec<Arc<FakeSocket>>,
    }

    fn harness() -> Harness {
        harness_with(1)
    }

    fn harness_with(socket_count: usize) -> Harness {
        let key = GatewayKey::generate();
        let gateway_public = x25519::PublicKey::from(*key.public().as_bytes());
        let plan = PeerPlan::default();
        let (peer_v4, peer_v6) = plan.address_for(2).expect("the first peer address");
        let secret = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PeerPublicKey::from_bytes(x25519::PublicKey::from(&secret).to_bytes());
        let psk: Psk = PresharedKey::generate();
        let client = Tunn::new(
            secret,
            gateway_public,
            Some(*psk.as_bytes()),
            Some(25),
            42,
            None,
        );
        let conf = GatewayConf {
            key,
            peers: vec![PeerConf {
                label: PeerLabel::new("peer2").expect("a valid label"),
                public,
                psk: Some(psk),
                allowed: vec![
                    IpNetwork::new(IpAddr::V4(peer_v4), 32).expect("a host prefix"),
                    IpNetwork::new(IpAddr::V6(peer_v6), 128).expect("a host prefix"),
                ],
            }],
        };
        let mut inbound = Vec::with_capacity(socket_count);
        let mut sent = Vec::with_capacity(socket_count);
        let mut sockets = Vec::with_capacity(socket_count);
        for index in 0..socket_count {
            let (inbound_tx, inbound_rx) = mpsc::channel(64);
            let (sent_tx, sent_rx) = mpsc::unbounded_channel();
            sockets.push(Arc::new(FakeSocket {
                inbound: tokio::sync::Mutex::new(inbound_rx),
                sent: sent_tx,
                stall: AtomicBool::new(false),
                local: format!("127.0.0.{}:51820", index + 1)
                    .parse()
                    .expect("a literal address"),
            }));
            inbound.push(inbound_tx);
            sent.push(sent_rx);
        }
        let device = GatewayDevice::new(
            &conf,
            plan,
            &GatewayOptions::default(),
            sockets
                .iter()
                .map(|s| Arc::clone(s) as Arc<dyn DatagramSocket>)
                .collect(),
        )
        .expect("a valid configuration");
        let tasks = device.spawn();
        Harness {
            device,
            _tasks: tasks,
            client,
            peer_v4,
            inbound,
            sent,
            sockets,
        }
    }

    fn addressing(generation: u64) -> EpochAddressing {
        EpochAddressing {
            epoch: EpochId {
                exit: ExitId::from_bytes([7u8; 16]),
                generation,
            },
            ipv4: ASSIGNED_V4,
            prefix: 16,
            gateway: GATEWAY_V4,
            ipv6: None,
        }
    }

    impl Harness {
        /// Drives a full handshake through the reader task.
        async fn handshake(&mut self) {
            let mut buf = vec![0u8; 2048];
            let initiation = match self.client.format_handshake_initiation(&mut buf, true) {
                TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
                other => panic!("{other:?}"),
            };
            self.inbound[0]
                .send((initiation, PEER_ADDR.parse().expect("a literal address")))
                .await
                .expect("the reader takes it");
            let (_, response) = self.next_sent().await.expect("the gateway answers");
            let mut buf = vec![0u8; 2048];
            match self.client.decapsulate(None, &response, &mut buf) {
                TunnResult::WriteToNetwork(keepalive) => {
                    let keepalive = keepalive.to_vec();
                    self.inbound[0]
                        .send((keepalive, PEER_ADDR.parse().expect("a literal address")))
                        .await
                        .expect("the reader takes it");
                }
                other => panic!("{other:?}"),
            }
        }

        /// Encapsulates one inner packet and hands it to the reader.
        async fn send_from_peer(&mut self, packet: &[u8]) {
            let mut buf = vec![0u8; 70_000];
            let datagram = match self.client.encapsulate(packet, &mut buf) {
                TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
                other => panic!("{other:?}"),
            };
            self.inbound[0]
                .send((datagram, PEER_ADDR.parse().expect("a literal address")))
                .await
                .expect("the reader takes it");
        }

        async fn next_sent(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
            tokio::time::timeout(Duration::from_secs(2), self.sent[0].recv())
                .await
                .ok()
                .flatten()
        }
    }

    /// A UDP packet, the smallest thing the NAT has to translate.
    fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Vec<u8> {
        warren_sdk::net::build_udp_packet(
            SocketAddr::new(src, sport),
            SocketAddr::new(dst, dport),
            payload,
        )
        .expect("a valid packet")
    }

    /// The exit refuses any inner packet whose source is not the address it
    /// assigned, so this translation is the whole reason the gateway exists.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_packet_reaches_the_tunnel_under_the_assigned_address() {
        let mut h = harness();
        let (sink, _control) = h.device.begin_epoch(addressing(1));
        assert!(h.device.open_gate_for(1));
        h.handshake().await;

        h.send_from_peer(&udp(
            IpAddr::V4(h.peer_v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"question",
        ))
        .await;

        let packet = tokio::time::timeout(Duration::from_secs(2), sink.recv_packet())
            .await
            .expect("the tunnel is offered a packet")
            .expect("a live epoch");
        let header = parse_ip(&packet).expect("an IP packet");
        assert_eq!(
            header.src,
            IpAddr::V4(ASSIGNED_V4),
            "the exit would have refused this source"
        );
        assert_eq!(header.dst, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let (_, dport) = read_ports(&packet, header.l4_offset).expect("a UDP header");
        assert_eq!(dport, 53);
    }

    /// The gateway's own control plane is already sourced at the assigned
    /// address, so it must reach the tunnel untranslated: a NAT mapping for it
    /// would rewrite the port the exit's NAT-PMP server answers on.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_control_datagram_reaches_the_tunnel_untranslated() {
        let h = harness();
        let (sink, control) = h.device.begin_epoch(addressing(1));

        let flow = control.open_udp().await.expect("a live epoch opens flows");
        let local = flow.local_addr();
        flow.send_to(
            bytes::Bytes::from_static(b"map"),
            SocketAddr::new(GATEWAY_V4.into(), 5351),
        )
        .await
        .expect("the uplink takes it");

        let packet = tokio::time::timeout(Duration::from_secs(2), sink.recv_packet())
            .await
            .expect("the tunnel is offered a packet")
            .expect("a live epoch");
        let header = parse_ip(&packet).expect("an IP packet");
        assert_eq!(header.src, IpAddr::V4(ASSIGNED_V4));
        let (sport, dport) = read_ports(&packet, header.l4_offset).expect("a UDP header");
        assert_eq!(
            sport,
            local.port(),
            "a translated source port would answer to nobody"
        );
        assert_eq!(dport, 5351);
    }

    /// The supervisor drops the previous epoch's pump before it starts the
    /// next one, but a slow teardown must not be able to close the live
    /// epoch's gate or steal its packets.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stale_sink_is_inert_on_every_path() {
        let h = harness();
        let (stale, stale_control) = h.device.begin_epoch(addressing(1));
        let (_live, live_control) = h.device.begin_epoch(addressing(2));
        assert!(h.device.open_gate_for(2));

        // A packet handed to a dead epoch's pump is dropped and counted.
        stale
            .send_packet(&udp(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                53,
                IpAddr::V4(ASSIGNED_V4),
                40000,
                b"answer",
            ))
            .await
            .expect("a stale sink never reports an error for a droppable packet");
        assert_eq!(h.device.snapshot().device.stale_epoch_send, 1);

        // And reading it says the epoch is over, which is what ends the pump.
        assert!(matches!(
            stale.recv_packet().await,
            Err(NetError::EngineStopped)
        ));

        drop(stale);

        assert!(
            h.device.snapshot().gate_open,
            "a stale sink's drop must not close the live epoch's gate"
        );
        assert!(
            live_control.is_alive(),
            "nor tear down the live epoch's control plane"
        );
        assert!(
            !stale_control.is_alive(),
            "its own epoch's control plane is what it ends, so a forwarder \
             exchanging over it learns the tunnel is gone"
        );
    }

    /// The pump of an epoch that is over may still be parked in `recv_packet`
    /// when the next one starts, and it must hold nothing the live epoch needs:
    /// the queue it waits on is its own, and the turnover ends its wait.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sink_parked_in_recv_never_starves_the_epoch_that_replaces_it() {
        let h = harness();
        let (stale, _stale_control) = h.device.begin_epoch(addressing(1));
        let parked = tokio::spawn(async move { stale.recv_packet().await });
        // Long enough for the task to reach the wait rather than the assertions
        // racing its first poll.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (live, live_control) = h.device.begin_epoch(addressing(2));
        let flow = live_control
            .open_udp()
            .await
            .expect("a live epoch opens flows");
        flow.send_to(
            bytes::Bytes::from_static(b"map"),
            SocketAddr::new(GATEWAY_V4.into(), 5351),
        )
        .await
        .expect("the uplink takes it");

        let packet = tokio::time::timeout(Duration::from_secs(2), live.recv_packet())
            .await
            .expect("the live epoch's own control packet reaches its pump")
            .expect("a live epoch");
        assert!(!packet.is_empty());
        assert!(
            matches!(
                parked.await.expect("the parked task"),
                Err(NetError::EngineStopped)
            ),
            "and the pump of the epoch that ended learns it is over"
        );
    }

    /// The live epoch's sink owns the gate and the control plane, and dropping
    /// it is how an epoch ends: nothing may reach a peer afterwards.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_live_sink_closes_the_gate_and_the_control_plane() {
        let h = harness();
        let (sink, control) = h.device.begin_epoch(addressing(1));
        assert!(h.device.open_gate_for(1));

        drop(sink);

        assert!(!h.device.snapshot().gate_open);
        assert!(!control.is_alive());
    }

    /// A socket whose buffer is full makes a send await. The readers must keep
    /// reading through it, or one congested peer takes every other peer's
    /// traffic down with it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_socket_send_leaves_the_uplink_running() {
        let mut h = harness();
        let (sink, _control) = h.device.begin_epoch(addressing(1));
        assert!(h.device.open_gate_for(1));
        h.handshake().await;

        // From here on nothing the gateway sends ever completes.
        h.sockets[0].stall.store(true, Ordering::Relaxed);
        // A datagram that makes the gateway answer, so the writer is stuck.
        h.send_from_peer(&udp(
            IpAddr::V4(h.peer_v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            443,
            b"first",
        ))
        .await;
        let first = tokio::time::timeout(Duration::from_secs(2), sink.recv_packet())
            .await
            .expect("the first packet still reaches the tunnel")
            .expect("a live epoch");
        assert!(!first.is_empty());

        h.send_from_peer(&udp(
            IpAddr::V4(h.peer_v4),
            4001,
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            443,
            b"second",
        ))
        .await;
        let second = tokio::time::timeout(Duration::from_secs(2), sink.recv_packet())
            .await
            .expect("a stalled send must not stop the reader")
            .expect("a live epoch");
        let header = parse_ip(&second).expect("an IP packet");
        assert_eq!(header.src, IpAddr::V4(ASSIGNED_V4));
    }

    /// A queue bounded in items alone lets one authenticated peer pin its depth
    /// times the largest inner packet, which is hundreds of megabytes on a NAS.
    /// The bound that matters is the memory, so it is counted in bytes.
    #[tokio::test(flavor = "multi_thread")]
    async fn jumbo_peer_packets_fill_the_uplink_queue_by_bytes_not_by_count() {
        let mut h = harness();
        // Nothing drains it: the sink is never read, exactly as a tunnel that
        // has stopped taking packets.
        let (_sink, _control) = h.device.begin_epoch(addressing(1));
        assert!(h.device.open_gate_for(1));
        h.handshake().await;

        let jumbo = vec![0x7eu8; 60_000];
        let packets = UPLINK_BYTES_MAX / jumbo.len() + 8;
        assert!(
            packets < DEFAULT_UPLINK_DEPTH,
            "the queue must fill on bytes long before it fills on items"
        );
        for port in 0..packets {
            h.send_from_peer(&udp(
                IpAddr::V4(h.peer_v4),
                u16::try_from(4000 + port).expect("a port"),
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                443,
                &jumbo,
            ))
            .await;
        }

        for _ in 0..200u32 {
            if h.device.snapshot().device.uplink_queue_full > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{packets} jumbo packets pinned more than the queue's byte budget");
    }

    /// A socket whose buffer is full holds its own answers and nobody else's:
    /// the queue and the writer belong to the socket, so a peer talking to one
    /// listen address never waits on a peer talking to another.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_socket_does_not_hold_another_sockets_answers() {
        let mut h = harness_with(2);
        let (_sink, _control) = h.device.begin_epoch(addressing(1));
        assert!(h.device.open_gate_for(1));
        h.sockets[0].stall.store(true, Ordering::Relaxed);

        let first: SocketAddr = "192.168.7.2:51820".parse().expect("a literal address");
        let second: SocketAddr = "192.168.7.3:51820".parse().expect("a literal address");
        let mut buf = vec![0u8; 2048];
        let initiation = match h.client.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        h.inbound[0]
            .send((initiation, first))
            .await
            .expect("the first reader takes it");

        let mut buf = vec![0u8; 2048];
        let initiation = match h.client.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        h.inbound[1]
            .send((initiation, second))
            .await
            .expect("the second reader takes it");

        let (to, answer) = tokio::time::timeout(Duration::from_secs(2), h.sent[1].recv())
            .await
            .expect("the second socket answers while the first is stalled")
            .expect("a datagram");
        assert_eq!(to, second);
        assert!(!answer.is_empty());
        assert!(
            h.sent[0].try_recv().is_err(),
            "the stalled socket is still holding its own answer"
        );
    }

    /// A queued packet belongs to the tunnel it was decrypted under: sending
    /// it after a redial would put the previous epoch's source address on the
    /// wire, which the new exit refuses as a spoof.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_packet_queued_under_a_dead_epoch_is_flushed_rather_than_sent() {
        let mut h = harness();
        let (first, _control) = h.device.begin_epoch(addressing(1));
        assert!(h.device.open_gate_for(1));
        h.handshake().await;
        h.send_from_peer(&udp(
            IpAddr::V4(h.peer_v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"stale",
        ))
        .await;
        // Give the reader time to queue it before the epoch turns over.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(first);

        let (second, _control) = h.device.begin_epoch(EpochAddressing {
            ipv4: Ipv4Addr::new(10, 66, 0, 9),
            ..addressing(2)
        });
        assert!(h.device.open_gate_for(2));
        h.send_from_peer(&udp(
            IpAddr::V4(h.peer_v4),
            4002,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"fresh",
        ))
        .await;

        let packet = tokio::time::timeout(Duration::from_secs(2), second.recv_packet())
            .await
            .expect("the fresh packet reaches the tunnel")
            .expect("a live epoch");
        let header = parse_ip(&packet).expect("an IP packet");
        assert_eq!(
            header.src,
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 9)),
            "only the new epoch's address may reach the new exit"
        );
        assert_eq!(
            &packet[header.l4_offset + 8..],
            b"fresh",
            "the packet from the dead epoch must not be what came out"
        );
        assert_eq!(h.device.snapshot().device.uplink_stale_flushed, 1);
    }

    /// The epoch is published under the lock the gate is opened under. A proof
    /// that finishes while the next epoch is being installed would otherwise
    /// open the gate on a tunnel nobody proved, and the responder consults the
    /// gate alone: a peer's traffic would ride an unproven epoch until it ends.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_proof_racing_the_next_epoch_never_opens_the_gate_on_it() {
        let h = harness();
        let device = h.device.clone();
        let installer = std::thread::spawn(move || {
            for generation in 2..=20_000 {
                let _epoch = device.begin_epoch(addressing(generation));
            }
        });

        let mut opened = 0u64;
        while !installer.is_finished() {
            let generation = h.device.generation();
            if h.device.open_gate_for(generation) {
                opened += 1;
                let snapshot = h.device.snapshot();
                assert!(
                    !snapshot.gate_open || snapshot.gate_generation == snapshot.generation,
                    "the gate is open for epoch {} while the device serves {}",
                    snapshot.gate_generation,
                    snapshot.generation
                );
            }
        }
        installer.join().expect("the installer thread");
        assert!(opened > 0, "the probe never opened the gate at all");
    }

    /// IPv6 follows the path: under its minimum MTU a Packet Too Big makes a
    /// stock host fragment, and this gateway drops fragments.
    #[tokio::test(flavor = "multi_thread")]
    async fn ipv6_is_withdrawn_under_its_minimum_mtu() {
        let h = harness();
        let (_sink, _control) = h.device.begin_epoch(EpochAddressing {
            ipv6: Some(warren_sdk::net::Ipv6Addressing {
                local_ip: Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 2),
                prefix: 64,
                gateway: Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 1),
            }),
            ..addressing(1)
        });
        assert_eq!(h.device.snapshot().ipv6, V6State::Available);

        h.device.note_inner_budget(1114);
        assert_eq!(h.device.snapshot().ipv6, V6State::BudgetTooSmall);

        h.device.note_inner_budget(1414);
        assert_eq!(h.device.snapshot().ipv6, V6State::Available);
    }
}
