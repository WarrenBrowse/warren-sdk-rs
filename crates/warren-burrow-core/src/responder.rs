//! The WireGuard-protocol responder.
//!
//! One `Responder` terminates every peer's protocol session and decides what
//! each decrypted packet is allowed to be. It owns no socket and no clock: the
//! caller hands it a datagram with the address it arrived from, and gets back
//! what to do with it.
//!
//! Two rules shape everything here. Work is refused in the cheapest order the
//! protocol allows, so an unauthenticated stranger cannot make the gateway
//! spend a Diffie-Hellman. And while the gate is closed, meaning the Warren
//! tunnel is not carrying traffic, the gateway emits nothing at all toward a
//! peer except a stateless cookie reply: a keepalive over a black hole would
//! feed the peer's own liveness detector and stretch its recovery from fifteen
//! seconds to two minutes.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

use crate::conf::{ConfError, GatewayConf, PeerConf};
use crate::icmp::{
    build_echo_reply_v4, build_echo_reply_v6, build_unreachable_v4, build_unreachable_v6,
};
use crate::index::IndexGen;
use crate::ip::{
    ICMPV4_ECHO_REQUEST, ICMPV6_ECHO_REQUEST, PROTO_TCP, PROTO_UDP, parse_ip, read_icmp, read_ports,
};
use crate::keys::{GatewayKey, PeerPublicKey, PresharedKey};
use crate::nat::Ownership;
use crate::peer::{DropReason, PeerId, PeerLabel, PeerStats, PeerStatus};
use crate::plan::{PeerPlan, is_tunnel_gateway, is_tunnel_pool};
use crate::ratelimit::{
    ANSWER_BURST, ANSWER_RATE_PER_SECOND, HANDSHAKE_BURST_PER_IP, HANDSHAKE_RATE_PER_IP,
    HANDSHAKE_SOURCES_TRACKED, HandshakeBuckets, TokenBucket,
};
use crate::scratch::ScratchBuf;
use crate::stats::{ResponderCounters, ResponderSnapshot};

/// Threshold of the shared cookie limiter.
///
/// Doubled on purpose: an accepted initiation is counted twice, once at the
/// demux and once inside boringtun's own `decapsulate`, so this is the value
/// that puts the cookie demand at a hundred initiations a second, where a
/// WireGuard device puts it. A unit test pins the relationship, because
/// nothing in boringtun guarantees it.
pub const DEFAULT_HANDSHAKE_RATE: u64 = 200;

/// How far the wall clock must move between two ticks to count as a suspend.
const CLOCK_JUMP: Duration = Duration::from_secs(30);

/// Whether the gateway may emit anything toward a peer.
///
/// The generation is the epoch the gate was last set for, so a stale caller
/// can tell that the tunnel it belonged to is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gate {
    /// The tunnel is carrying traffic.
    pub open: bool,
    /// The epoch this state belongs to.
    pub generation: u64,
}

/// Whether the epoch can carry IPv6 at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum V6State {
    /// The exit assigned an IPv6 address and the path can carry it.
    Available,
    /// The exit assigned no IPv6 address.
    NoAssignment,
    /// The path budget is under the IPv6 minimum MTU, so a Packet Too Big
    /// would make a stock host fragment and this gateway drops fragments.
    BudgetTooSmall,
}

/// What the gateway does with a decrypted packet or a datagram.
pub enum Inbound<'a> {
    /// A peer packet cleared for the tunnel.
    Uplink {
        /// Who sent it, which is what the NAT keys ownership on.
        peer: PeerId,
        /// The packet itself, inside the caller's scratch buffer.
        packet: &'a [u8],
    },
    /// A datagram to send straight back to the source address.
    Reply(&'a [u8]),
    /// A packet for another peer of this same gateway.
    Loopback {
        /// The peer that owns the destination.
        to: PeerId,
        /// The packet itself, inside the caller's scratch buffer.
        packet: &'a [u8],
    },
    /// Authenticated, and nothing to send or forward: a keepalive, or a cookie
    /// reply the handshake absorbed.
    Consumed,
    /// Refused, with the rule that refused it.
    Dropped(DropReason),
}

impl std::fmt::Debug for Inbound<'_> {
    // Renders lengths, never a packet: between two datagrams the buffer holds
    // some peer's plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uplink { peer, packet } => f
                .debug_struct("Uplink")
                .field("peer", peer)
                .field("len", &packet.len())
                .finish(),
            Self::Reply(bytes) => f.debug_tuple("Reply").field(&bytes.len()).finish(),
            Self::Loopback { to, packet } => f
                .debug_struct("Loopback")
                .field("to", to)
                .field("len", &packet.len())
                .finish(),
            Self::Consumed => f.write_str("Consumed"),
            Self::Dropped(reason) => f.debug_tuple("Dropped").field(reason).finish(),
        }
    }
}

/// What came out of an encapsulation.
pub enum Encapsulated<'a> {
    /// An encrypted data packet, and where to send it.
    Sent(SocketAddr, &'a [u8]),
    /// boringtun queued the packet for want of a session, and may have
    /// produced a handshake initiation to get one.
    Deferred {
        /// The initiation, when the peer's endpoint is known.
        initiation: Option<(SocketAddr, &'a [u8])>,
    },
}

impl std::fmt::Debug for Encapsulated<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sent(_, bytes) => f.debug_tuple("Sent").field(&bytes.len()).finish(),
            Self::Deferred { initiation } => f
                .debug_struct("Deferred")
                .field("initiation", &initiation.is_some())
                .finish(),
        }
    }
}

/// Why a packet could not be handed to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteError {
    /// No peer owns the destination address.
    #[error("no peer owns that destination")]
    NoRoute,
    /// The peer identifier belongs to no live peer.
    #[error("unknown peer")]
    UnknownPeer,
    /// The tunnel is not carrying traffic, so nothing may leave the gateway.
    #[error("gate closed")]
    GateClosed,
    /// boringtun refused to encapsulate.
    #[error("encapsulation refused")]
    Encapsulation,
}

/// The peer named in a request does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown peer")]
pub struct UnknownPeer;

/// What a reload changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReloadReport {
    /// Peers that did not exist before.
    pub added: Vec<PeerLabel>,
    /// Peers that are gone, with their sessions and endpoints.
    pub removed: Vec<PeerLabel>,
    /// Peers whose key material or allowed IPs changed, so their sessions
    /// could not be kept.
    pub rebuilt: Vec<PeerLabel>,
    /// Peers left exactly as they were, sessions included.
    pub unchanged: usize,
}

/// How the responder is built.
#[derive(Debug, Clone, Copy)]
pub struct ResponderOptions {
    /// Drop traffic between two peers of this gateway.
    pub peer_isolation: bool,
    /// Threshold of the shared cookie limiter.
    pub handshake_rate: u64,
    /// Handshakes per second one source address may spend.
    pub per_source_rate: u32,
    /// Handshakes one source may spend at once.
    pub per_source_burst: u32,
    /// How many source addresses the per-source limiter tracks.
    pub sources_tracked: usize,
    /// ICMP answers the gateway may generate per second, every peer together.
    pub answer_rate: u32,
    /// How many it may generate at once after a quiet period.
    pub answer_burst: u32,
}

impl Default for ResponderOptions {
    fn default() -> Self {
        Self {
            peer_isolation: true,
            handshake_rate: DEFAULT_HANDSHAKE_RATE,
            per_source_rate: HANDSHAKE_RATE_PER_IP,
            per_source_burst: HANDSHAKE_BURST_PER_IP,
            sources_tracked: HANDSHAKE_SOURCES_TRACKED,
            answer_rate: ANSWER_RATE_PER_SECOND,
            answer_burst: ANSWER_BURST,
        }
    }
}

struct Peer {
    label: PeerLabel,
    public: PeerPublicKey,
    psk: Option<PresharedKey>,
    allowed: Vec<IpNetwork>,
    tunn: Tunn,
    endpoint: Option<SocketAddr>,
    stats: PeerStats,
    last_drop: Option<DropReason>,
}

impl Peer {
    fn owns(&self, addr: IpAddr) -> bool {
        self.allowed.iter().any(|network| network.contains(addr))
    }

    fn conf(&self) -> PeerConf {
        PeerConf {
            label: self.label.clone(),
            public: self.public,
            psk: self.psk.clone(),
            allowed: self.allowed.clone(),
        }
    }

    fn same_material(&self, conf: &PeerConf) -> bool {
        self.public == conf.public && self.psk == conf.psk && self.allowed == conf.allowed
    }
}

/// The gateway's WireGuard-protocol side.
pub struct Responder {
    key: GatewayKey,
    // One limiter for the whole gateway, keyed on the gateway public key, as a
    // WireGuard device has: a per-peer limiter would give every peer its own
    // cookie secret and a ceiling a single misconfigured client reaches alone.
    limiter: Arc<RateLimiter>,
    peers: BTreeMap<PeerId, Peer>,
    by_pubkey: HashMap<[u8; 32], PeerId>,
    by_label: HashMap<PeerLabel, PeerId>,
    routes: IpNetworkTable<PeerId>,
    per_source: HandshakeBuckets,
    // The gateway's own ICMP generation, bounded the way a router bounds its
    // own: an answer costs a build and a full AEAD seal, and a withdrawn IPv6
    // makes one the response to every packet a dual-stack peer sends.
    answers: TokenBucket,
    indexes: IndexGen,
    plan: PeerPlan,
    isolation: bool,
    gate: Gate,
    v6: V6State,
    counters: ResponderCounters,
    last_reset: Option<Instant>,
    last_wall: Option<SystemTime>,
}

impl std::fmt::Debug for Responder {
    // No address, no key, no label: this is what a panic message would carry.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("peers", &self.peers.len())
            .field("gate", &self.gate)
            .field("ipv6", &self.v6)
            .finish()
    }
}

impl Responder {
    /// Builds a responder from a gateway configuration.
    ///
    /// # Errors
    ///
    /// A [`ConfError`] when the configuration breaks a rule the parser also
    /// enforces, or when a peer claims the gateway's own address.
    pub fn new(
        conf: &GatewayConf,
        plan: PeerPlan,
        options: ResponderOptions,
    ) -> Result<Self, ConfError> {
        Self::with_indexes(conf, plan, options, IndexGen::new())
    }

    /// Builds a responder over a given index sequence.
    ///
    /// # Errors
    ///
    /// The same refusals as [`Responder::new`].
    pub fn with_indexes(
        conf: &GatewayConf,
        plan: PeerPlan,
        options: ResponderOptions,
        indexes: IndexGen,
    ) -> Result<Self, ConfError> {
        conf.validate()?;
        conf.check_against(&plan)?;
        let public = x25519_dalek::PublicKey::from(*conf.key.public().as_bytes());
        let mut responder = Self {
            limiter: Arc::new(RateLimiter::new(&public, options.handshake_rate)),
            key: conf.key.clone(),
            peers: BTreeMap::new(),
            by_pubkey: HashMap::new(),
            by_label: HashMap::new(),
            routes: IpNetworkTable::new(),
            per_source: HandshakeBuckets::with_limits(
                options.per_source_rate,
                options.per_source_burst,
                options.sources_tracked,
            ),
            answers: TokenBucket::new(options.answer_rate, options.answer_burst),
            indexes,
            plan,
            isolation: options.peer_isolation,
            gate: Gate::default(),
            v6: V6State::Available,
            counters: ResponderCounters::default(),
            last_reset: None,
            last_wall: None,
        };
        for peer in &conf.peers {
            responder.insert_peer(peer)?;
        }
        responder.rebuild_routes();
        Ok(responder)
    }

    fn insert_peer(&mut self, conf: &PeerConf) -> Result<PeerId, ConfError> {
        // Sixteen million peers on one gateway is not a deployment, but a
        // silently absent peer is a device that never connects with nothing to
        // read about why, so the refusal is explicit.
        let index = self.indexes.next().ok_or(ConfError::TooManyPeers)?;
        Ok(self.insert_peer_at(conf, index))
    }

    fn insert_peer_at(&mut self, conf: &PeerConf, index: u32) -> PeerId {
        let id = PeerId::new(index);
        let tunn = self.build_tunn(conf, index);
        self.by_pubkey.insert(*conf.public.as_bytes(), id);
        self.by_label.insert(conf.label.clone(), id);
        self.peers.insert(
            id,
            Peer {
                label: conf.label.clone(),
                public: conf.public,
                psk: conf.psk.clone(),
                allowed: conf.allowed.clone(),
                tunn,
                endpoint: None,
                stats: PeerStats::default(),
                last_drop: None,
            },
        );
        id
    }

    fn build_tunn(&self, conf: &PeerConf, index: u32) -> Tunn {
        Tunn::new(
            self.key.secret().clone(),
            x25519_dalek::PublicKey::from(*conf.public.as_bytes()),
            conf.psk.as_ref().map(|psk| *psk.as_bytes()),
            // The gateway sends no persistent keepalive of its own: the peer
            // is the side behind a NAT, and its own config carries one.
            None,
            index,
            Some(Arc::clone(&self.limiter)),
        )
    }

    // Both lookup maps are derived views of `peers`, so they are rebuilt from
    // it rather than patched entry by entry: a reload that moves a key from one
    // peer to another otherwise deletes the entry the earlier peer just wrote,
    // and that peer is unknown to every later initiation.
    fn rebuild_lookups(&mut self) {
        let mut by_pubkey = HashMap::new();
        let mut by_label = HashMap::new();
        for (id, peer) in &self.peers {
            by_pubkey.insert(*peer.public.as_bytes(), *id);
            by_label.insert(peer.label.clone(), *id);
        }
        self.by_pubkey = by_pubkey;
        self.by_label = by_label;
    }

    fn rebuild_routes(&mut self) {
        let mut routes = IpNetworkTable::new();
        for (id, peer) in &self.peers {
            for network in &peer.allowed {
                routes.insert(*network, *id);
            }
        }
        self.routes = routes;
    }

    /// The gateway's public key, which is what peers encrypt to.
    #[must_use]
    pub fn public_key(&self) -> PeerPublicKey {
        self.key.public()
    }

    /// The gateway's key pair, for an admin path that rewrites the file.
    #[must_use]
    pub fn key(&self) -> &GatewayKey {
        &self.key
    }

    /// Opens or closes the gate for an epoch.
    pub fn set_gate(&mut self, open: bool, generation: u64) {
        self.gate = Gate { open, generation };
    }

    /// The current gate.
    #[must_use]
    pub fn gate(&self) -> Gate {
        self.gate
    }

    /// Declares whether the epoch can carry IPv6.
    pub fn set_ipv6(&mut self, state: V6State) {
        self.v6 = state;
    }

    /// Whether the epoch can carry IPv6.
    #[must_use]
    pub fn ipv6(&self) -> V6State {
        self.v6
    }

    /// The peer an operator label names.
    #[must_use]
    pub fn peer_by_label(&self, label: &PeerLabel) -> Option<PeerId> {
        self.by_label.get(label).copied()
    }

    /// Where a peer was last heard from.
    #[must_use]
    pub fn endpoint(&self, peer: PeerId) -> Option<SocketAddr> {
        self.peers.get(&peer).and_then(|peer| peer.endpoint)
    }

    /// Which peer owns which address, as the NAT needs it.
    #[must_use]
    pub fn ownership(&self) -> Ownership {
        let mut ownership = Ownership::new();
        for (id, peer) in &self.peers {
            for network in &peer.allowed {
                ownership.insert(*network, *id);
            }
        }
        ownership
    }

    /// Every peer as the configuration would spell it.
    #[must_use]
    pub fn peer_confs(&self) -> Vec<PeerConf> {
        self.peers.values().map(Peer::conf).collect()
    }

    /// The counters as one reading.
    #[must_use]
    pub fn stats(&self) -> ResponderSnapshot {
        self.counters.snapshot()
    }

    /// Every peer as a health route renders it.
    #[must_use]
    pub fn snapshot(&self) -> Vec<PeerStatus> {
        self.peers
            .values()
            .map(|peer| {
                let (handshake, tx, rx, _, _) = peer.tunn.stats();
                PeerStatus {
                    label: peer.label.clone(),
                    has_session: handshake.is_some(),
                    last_handshake_secs: handshake.map(|since| since.as_secs()),
                    endpoint_seen: peer.endpoint.is_some(),
                    stats: PeerStats {
                        rx_bytes: rx as u64,
                        tx_bytes: tx as u64,
                        ..peer.stats
                    },
                    allowed_ips: peer.allowed.clone(),
                    last_drop: peer.last_drop,
                }
            })
            .collect()
    }

    fn note(&mut self, reason: DropReason) -> DropReason {
        self.counters.dropped(reason);
        reason
    }

    fn note_for(&mut self, peer: PeerId, reason: DropReason) -> DropReason {
        if let Some(peer) = self.peers.get_mut(&peer) {
            peer.last_drop = Some(reason);
            peer.stats.drops += 1;
        }
        self.note(reason)
    }

    /// Handles one datagram from the network.
    ///
    /// The order is the protocol's own: parse and verify mac1 first, so an
    /// unauthenticated stranger cannot make the gateway spend a
    /// Diffie-Hellman, then the gate, then the per-source budget, then the
    /// anonymous parse that names a peer, and only then the handshake itself.
    pub fn handle_datagram<'a>(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        now: Instant,
        scratch: &'a mut ScratchBuf,
    ) -> Inbound<'a> {
        self.counters.datagram();
        if datagram.len() > 65_535 {
            // Unreachable through a socket; kept so the invariant that keeps
            // boringtun's copy inside the scratch buffer is local to this file.
            return Inbound::Dropped(self.note(DropReason::Oversize));
        }

        let limiter = Arc::clone(&self.limiter);
        let mut cookie_buf = [0u8; 64];
        let packet = match limiter.verify_packet(Some(src.ip()), datagram, &mut cookie_buf) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                let len = cookie.len();
                let out = &mut scratch.as_mut()[..len];
                out.copy_from_slice(cookie);
                self.counters.reply(true);
                return Inbound::Reply(out);
            }
            Err(_) => return Inbound::Dropped(self.note(DropReason::Malformed)),
        };

        match packet {
            Packet::HandshakeInit(ref init) => {
                if !self.gate.open {
                    self.counters.handshake_refused_gate_closed();
                    return Inbound::Dropped(DropReason::GateClosed);
                }
                if !self.per_source.admit(src.ip(), now) {
                    return Inbound::Dropped(self.note(DropReason::SourceRateLimited));
                }
                let public = x25519_dalek::PublicKey::from(*self.key.public().as_bytes());
                let Ok(half) = parse_handshake_anon(self.key.secret(), &public, init) else {
                    return Inbound::Dropped(self.note(DropReason::Auth));
                };
                let Some(&id) = self.by_pubkey.get(&half.peer_static_public) else {
                    return Inbound::Dropped(self.note(DropReason::UnknownPeer));
                };
                let outcome = self.decapsulate(id, src, datagram, scratch);
                match outcome {
                    Outcome::Network { len, kind } => {
                        if kind == 2 {
                            if let Some(peer) = self.peers.get_mut(&id) {
                                peer.endpoint = Some(src);
                                peer.stats.handshakes += 1;
                            }
                            self.counters.handshake();
                        }
                        self.counters.reply(kind == 3);
                        Inbound::Reply(&scratch.as_mut()[..len])
                    }
                    Outcome::Failed(reason) => Inbound::Dropped(self.note_for(id, reason)),
                    Outcome::Tunnel { .. } | Outcome::Done => {
                        Inbound::Dropped(self.note_for(id, DropReason::Auth))
                    }
                }
            }
            Packet::HandshakeResponse(ref response) => {
                self.demux(src, datagram, response.receiver_idx, 2, now, scratch)
            }
            Packet::PacketCookieReply(ref cookie) => {
                self.demux(src, datagram, cookie.receiver_idx, 3, now, scratch)
            }
            Packet::PacketData(ref data) => {
                self.demux(src, datagram, data.receiver_idx, 4, now, scratch)
            }
        }
    }

    fn demux<'a>(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        receiver_idx: u32,
        kind: u8,
        now: Instant,
        scratch: &'a mut ScratchBuf,
    ) -> Inbound<'a> {
        // boringtun derives every session index of a peer from the peer index
        // it was built with, so the high 24 bits name the peer.
        let id = PeerId::new(receiver_idx >> 8);
        if !self.peers.contains_key(&id) {
            return Inbound::Dropped(self.note(DropReason::UnknownIndex));
        }
        let outcome = self.decapsulate(id, src, datagram, scratch);

        // Roaming: only an authenticated packet may move a peer's endpoint. A
        // cookie reply is sealed under material an eavesdropper reads off the
        // wire, so honouring one would let an insider black-hole a peer.
        let roam = match &outcome {
            Outcome::Failed(_) => false,
            Outcome::Network { kind: out, .. } => kind == 4 || (kind == 2 && *out != 3),
            Outcome::Tunnel { .. } | Outcome::Done => kind == 4,
        };
        if roam && let Some(peer) = self.peers.get_mut(&id) {
            peer.endpoint = Some(src);
        }

        match outcome {
            Outcome::Failed(reason) => Inbound::Dropped(self.note_for(id, reason)),
            Outcome::Done => Inbound::Consumed,
            Outcome::Network { len, .. } => {
                if !self.gate.open {
                    return Inbound::Dropped(self.note_for(id, DropReason::GateClosed));
                }
                self.counters.reply(false);
                Inbound::Reply(&scratch.as_mut()[..len])
            }
            Outcome::Tunnel { len, src: inner } => {
                let Some(peer) = self.peers.get(&id) else {
                    return Inbound::Dropped(self.note(DropReason::UnknownIndex));
                };
                if !peer.owns(inner) {
                    // The second wall behind cryptokey routing: the exit only
                    // ever sees the address this gateway rewrites onto the
                    // packet, so a peer sourcing another peer's address must be
                    // refused here or nowhere.
                    return Inbound::Dropped(self.note_for(id, DropReason::SpoofedSource));
                }
                if !self.gate.open {
                    return Inbound::Dropped(self.note_for(id, DropReason::GateClosed));
                }
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.stats.rx_bytes += len as u64;
                }
                self.deliver(id, len, now, scratch)
            }
        }
    }

    fn deliver<'a>(
        &mut self,
        id: PeerId,
        len: usize,
        now: Instant,
        scratch: &'a mut ScratchBuf,
    ) -> Inbound<'a> {
        let verdict = self.verdict(&scratch.as_mut()[..len]);
        match verdict {
            Verdict::Forward => {
                self.counters.uplink();
                Inbound::Uplink {
                    peer: id,
                    packet: &scratch.as_mut()[..len],
                }
            }
            Verdict::Loopback(to) => {
                self.counters.loopback();
                Inbound::Loopback {
                    to,
                    packet: &scratch.as_mut()[..len],
                }
            }
            Verdict::Answer(reason) => {
                if let Some(class) = reason.counted() {
                    self.counters.dropped(class);
                }
                if !self.answers.admit(now) {
                    // The refusal above stands; the peer is simply not told.
                    self.counters.answer_suppressed();
                    return Inbound::Consumed;
                }
                let built = match reason {
                    Answer::Echo => {
                        let request = &scratch.as_mut()[..len];
                        if request[0] >> 4 == 4 {
                            build_echo_reply_v4(request)
                        } else {
                            build_echo_reply_v6(request)
                        }
                    }
                    Answer::Unreachable => {
                        let offending = &scratch.as_mut()[..len];
                        if offending[0] >> 4 == 4 {
                            build_unreachable_v4(offending, self.plan.gateway_v4())
                        } else {
                            build_unreachable_v6(offending, self.plan.gateway_v6())
                        }
                    }
                    Answer::NoRouteV6(_) => {
                        build_unreachable_v6(&scratch.as_mut()[..len], self.plan.gateway_v6())
                    }
                };
                let Some(packet) = built else {
                    // The offending packet is itself an ICMP error, and an
                    // error never answers an error. Its refusal is already
                    // counted under its own class; a second class here would
                    // count one packet twice.
                    return Inbound::Consumed;
                };
                match self.encapsulate_into(id, &packet, scratch) {
                    Some(out) => {
                        self.counters.reply(false);
                        Inbound::Reply(&scratch.as_mut()[..out])
                    }
                    None => Inbound::Consumed,
                }
            }
            Verdict::Drop(reason) => Inbound::Dropped(self.note_for(id, reason)),
        }
    }

    fn verdict(&self, packet: &[u8]) -> Verdict {
        let Some(dst) = Tunn::dst_address(packet) else {
            return Verdict::Drop(DropReason::Malformed);
        };
        if !is_unicast(dst) {
            // A router peer with a default route into the tunnel leaks mDNS
            // and SSDP continuously; none of it may reach an exit.
            return Verdict::Drop(DropReason::NonUnicast);
        }
        if self.plan.is_gateway(dst) {
            return if is_echo_request(packet) {
                Verdict::Answer(Answer::Echo)
            } else {
                Verdict::Drop(DropReason::SelfDestination)
            };
        }
        if let Some((_, &owner)) = self.routes.longest_match(dst) {
            return if self.isolation {
                Verdict::Drop(DropReason::PeerIsolation)
            } else {
                Verdict::Loopback(owner)
            };
        }
        if self.plan.contains(dst) {
            return Verdict::Drop(DropReason::UnownedPeerAddress);
        }
        if is_tunnel_pool(dst) {
            // The exit's resolver is the one address on the far side a peer may
            // reach; anything else would be a hairpin through the exit's own
            // forwarding, or a NAT-PMP request burning a fleet-wide slot.
            return if is_tunnel_gateway(dst) && is_resolver_port(packet) {
                Verdict::Forward
            } else {
                Verdict::Drop(DropReason::PoolDestination)
            };
        }
        if is_private(dst) {
            // A masqueraded exit can never reach it, and a fast refusal beats a
            // black hole for a peer talking to its own LAN through a full
            // tunnel config.
            return Verdict::Answer(Answer::Unreachable);
        }
        if dst.is_ipv6() {
            match self.v6 {
                V6State::Available => {}
                V6State::NoAssignment => {
                    return Verdict::Answer(Answer::NoRouteV6(DropReason::V6Unavailable));
                }
                // Never reflect a Packet Too Big under the IPv6 minimum: a
                // stock host answers that by keeping 1280 and adding a
                // Fragment header, which this gateway drops, so the flow would
                // be black-holed instead of failing over to IPv4.
                V6State::BudgetTooSmall => {
                    return Verdict::Answer(Answer::NoRouteV6(DropReason::V6Budget));
                }
            }
        }
        Verdict::Forward
    }

    fn decapsulate(
        &mut self,
        id: PeerId,
        src: SocketAddr,
        datagram: &[u8],
        scratch: &mut ScratchBuf,
    ) -> Outcome {
        let Some(peer) = self.peers.get_mut(&id) else {
            return Outcome::Failed(DropReason::UnknownIndex);
        };
        summarize(
            peer.tunn
                .decapsulate(Some(src.ip()), datagram, scratch.as_mut()),
        )
    }

    fn encapsulate_into(
        &mut self,
        id: PeerId,
        packet: &[u8],
        scratch: &mut ScratchBuf,
    ) -> Option<usize> {
        let peer = self.peers.get_mut(&id)?;
        match peer.tunn.encapsulate(packet, scratch.as_mut()) {
            TunnResult::WriteToNetwork(bytes) if bytes.first() == Some(&4) => {
                let len = bytes.len();
                peer.stats.tx_bytes += packet.len() as u64;
                Some(len)
            }
            _ => None,
        }
    }

    /// Drains what boringtun queued behind a handshake.
    ///
    /// The caller repeats until `None`, sending each datagram to the peer's
    /// endpoint. Empty while the gate is closed.
    pub fn flush<'a>(&mut self, peer: PeerId, scratch: &'a mut ScratchBuf) -> Option<&'a [u8]> {
        if !self.gate.open {
            return None;
        }
        let entry = self.peers.get_mut(&peer)?;
        let len = match entry.tunn.decapsulate(None, &[], scratch.as_mut()) {
            TunnResult::WriteToNetwork(bytes) => bytes.len(),
            _ => return None,
        };
        Some(&scratch.as_mut()[..len])
    }

    /// Encapsulates a packet for the peer that owns its destination.
    ///
    /// # Errors
    ///
    /// [`RouteError::NoRoute`] when no peer owns the destination, and whatever
    /// [`Responder::send_to_peer`] refuses.
    pub fn encapsulate_to<'a>(
        &mut self,
        dst: IpAddr,
        packet: &[u8],
        scratch: &'a mut ScratchBuf,
    ) -> Result<Encapsulated<'a>, RouteError> {
        let Some((_, &owner)) = self.routes.longest_match(dst) else {
            self.counters.dropped(DropReason::NoRoute);
            return Err(RouteError::NoRoute);
        };
        self.send_to_peer(owner, packet, scratch)
    }

    /// Encapsulates a packet for one peer.
    ///
    /// # Errors
    ///
    /// [`RouteError::GateClosed`] while the tunnel is not carrying traffic,
    /// [`RouteError::UnknownPeer`] for an identifier no peer holds,
    /// [`RouteError::Encapsulation`] when boringtun refuses.
    pub fn send_to_peer<'a>(
        &mut self,
        peer: PeerId,
        packet: &[u8],
        scratch: &'a mut ScratchBuf,
    ) -> Result<Encapsulated<'a>, RouteError> {
        if !self.gate.open {
            return Err(RouteError::GateClosed);
        }
        let Some(entry) = self.peers.get_mut(&peer) else {
            return Err(RouteError::UnknownPeer);
        };
        let endpoint = entry.endpoint;
        let sent = packet.len();
        let outcome = match entry.tunn.encapsulate(packet, scratch.as_mut()) {
            TunnResult::WriteToNetwork(bytes) => {
                let len = bytes.len();
                let kind = bytes.first().copied().unwrap_or(0);
                if kind == 4 {
                    entry.stats.tx_bytes += sent as u64;
                }
                Some((len, kind))
            }
            TunnResult::Done => None,
            _ => return Err(RouteError::Encapsulation),
        };
        if !matches!(outcome, Some((_, 4))) {
            // boringtun took the packet onto its own 256-deep queue behind a
            // handshake and drops silently over that cap, so a peer whose
            // endpoint never answers is only visible through this counter.
            entry.stats.deferred += 1;
        }
        match (outcome, endpoint) {
            (Some((len, 4)), Some(to)) => Ok(Encapsulated::Sent(to, &scratch.as_mut()[..len])),
            (Some((_, 4)), None) => {
                // An encrypted packet with nowhere to go: the session exists but
                // the peer has never been heard from.
                self.counters.dropped_without_endpoint();
                Ok(Encapsulated::Deferred { initiation: None })
            }
            (Some((len, _)), Some(to)) => {
                self.counters.downlink_queued();
                Ok(Encapsulated::Deferred {
                    initiation: Some((to, &scratch.as_mut()[..len])),
                })
            }
            (Some(_), None) => {
                self.counters.downlink_queued();
                self.counters.dropped_without_endpoint();
                Ok(Encapsulated::Deferred { initiation: None })
            }
            (None, _) => {
                self.counters.downlink_queued();
                Ok(Encapsulated::Deferred { initiation: None })
            }
        }
    }

    /// Drives the protocol timers.
    ///
    /// Follows boringtun's own device rule and touches only peers with a known
    /// endpoint: a peer that has never connected has nowhere to be reached, and
    /// would otherwise trip an expiry its zero-initialised timers invented.
    /// While the gate is closed the timers keep running and everything they
    /// produce is discarded.
    pub fn tick(
        &mut self,
        now: Instant,
        wall: SystemTime,
        scratch: &mut ScratchBuf,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        if self
            .last_reset
            .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(1))
        {
            self.limiter.reset_count();
            self.last_reset = Some(now);
        }
        self.detect_clock_jump(wall);

        let open = self.gate.open;
        let mut out = Vec::new();
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for id in ids {
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            let Some(endpoint) = peer.endpoint else {
                continue;
            };
            match peer.tunn.update_timers(scratch.as_mut()) {
                TunnResult::WriteToNetwork(bytes) => {
                    if open {
                        out.push((endpoint, bytes.to_vec()));
                    }
                }
                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    peer.endpoint = None;
                }
                _ => {}
            }
        }
        out
    }

    fn detect_clock_jump(&mut self, wall: SystemTime) {
        let jumped = self.last_wall.is_some_and(|last| {
            wall.duration_since(last).unwrap_or_default() > CLOCK_JUMP
                || last.duration_since(wall).unwrap_or_default() > CLOCK_JUMP
        });
        self.last_wall = Some(wall);
        if !jumped {
            return;
        }
        // Apple platforms count suspend out of the monotonic clock boringtun
        // reads, so a laptop that slept an hour wakes holding sessions the peer
        // discarded long ago and would answer none of.
        let stale: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.endpoint.is_some())
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.rebuild(id);
            self.counters.clock_jump_reset();
        }
    }

    fn rebuild(&mut self, id: PeerId) {
        let Some(conf) = self.peers.get(&id).map(Peer::conf) else {
            return;
        };
        let tunn = self.build_tunn(&conf, id.index());
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.tunn = tunn;
        }
    }

    /// Rebuilds one peer's tunnel, keeping its keys and its index.
    ///
    /// This is the escape for a peer whose clock jumped backwards: the
    /// handshake timestamp guard would otherwise refuse it forever.
    ///
    /// # Errors
    ///
    /// [`UnknownPeer`] when no peer carries that label.
    pub fn reset_peer(&mut self, label: &PeerLabel) -> Result<(), UnknownPeer> {
        let id = self.by_label.get(label).copied().ok_or(UnknownPeer)?;
        self.rebuild(id);
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.last_drop = None;
        }
        Ok(())
    }

    /// Applies a new configuration.
    ///
    /// Peers whose key material and allowed IPs are unchanged keep their
    /// sessions, their endpoints and their counters; a removed peer loses
    /// everything at once, which is the revocation path for a lost device.
    ///
    /// # Errors
    ///
    /// A [`ConfError`] when the new configuration breaks a rule, in which case
    /// nothing changes.
    pub fn reload(&mut self, conf: &GatewayConf) -> Result<ReloadReport, ConfError> {
        conf.validate()?;
        conf.check_against(&self.plan)?;

        // Every index the new configuration needs is drawn before anything is
        // mutated: an exhausted generator halfway through would leave the
        // gateway carrying neither the old configuration nor the new one, and
        // the documented contract is that a refused reload changes nothing.
        let mut indexes = self.indexes.clone();
        let mut fresh: Vec<u32> = Vec::new();
        for peer in &conf.peers {
            if !self.by_label.contains_key(&peer.label) {
                fresh.push(indexes.next().ok_or(ConfError::TooManyPeers)?);
            }
        }
        self.indexes = indexes;
        let mut fresh = fresh.into_iter();

        let mut report = ReloadReport::default();
        let wanted: HashMap<PeerLabel, &PeerConf> = conf
            .peers
            .iter()
            .map(|peer| (peer.label.clone(), peer))
            .collect();

        let gone: Vec<(PeerId, PeerLabel)> = self
            .peers
            .iter()
            .filter(|(_, peer)| !wanted.contains_key(&peer.label))
            .map(|(id, peer)| (*id, peer.label.clone()))
            .collect();
        for (id, label) in gone {
            self.peers.remove(&id);
            self.by_label.remove(&label);
            report.removed.push(label);
        }

        for peer in &conf.peers {
            match self.by_label.get(&peer.label).copied() {
                Some(id) => {
                    let same = self
                        .peers
                        .get(&id)
                        .is_some_and(|live| live.same_material(peer));
                    if same {
                        report.unchanged += 1;
                        continue;
                    }
                    let tunn = self.build_tunn(peer, id.index());
                    if let Some(live) = self.peers.get_mut(&id) {
                        live.public = peer.public;
                        live.psk = peer.psk.clone();
                        live.allowed = peer.allowed.clone();
                        live.tunn = tunn;
                        live.endpoint = None;
                        live.last_drop = None;
                    }
                    report.rebuilt.push(peer.label.clone());
                }
                None => {
                    let index = fresh.next().expect("one index was drawn per added peer");
                    self.insert_peer_at(peer, index);
                    report.added.push(peer.label.clone());
                }
            }
        }
        self.rebuild_lookups();
        self.rebuild_routes();
        Ok(report)
    }
}

enum Outcome {
    Network { len: usize, kind: u8 },
    Tunnel { len: usize, src: IpAddr },
    Done,
    Failed(DropReason),
}

// Takes the result by value so the scratch borrow it carries ends here, which
// is what lets the caller write into the same buffer afterwards.
fn summarize(result: TunnResult<'_>) -> Outcome {
    match result {
        TunnResult::Done => Outcome::Done,
        TunnResult::Err(WireGuardError::WrongTai64nTimestamp) => {
            Outcome::Failed(DropReason::Replay)
        }
        TunnResult::Err(_) => Outcome::Failed(DropReason::Auth),
        TunnResult::WriteToNetwork(bytes) => Outcome::Network {
            len: bytes.len(),
            kind: bytes.first().copied().unwrap_or(0),
        },
        TunnResult::WriteToTunnelV4(bytes, src) => Outcome::Tunnel {
            len: bytes.len(),
            src: IpAddr::V4(src),
        },
        TunnResult::WriteToTunnelV6(bytes, src) => Outcome::Tunnel {
            len: bytes.len(),
            src: IpAddr::V6(src),
        },
    }
}

#[derive(Debug, Clone, Copy)]
enum Answer {
    Echo,
    Unreachable,
    NoRouteV6(DropReason),
}

impl Answer {
    fn counted(self) -> Option<DropReason> {
        match self {
            Self::Echo => None,
            Self::Unreachable => Some(DropReason::PrivateDestination),
            Self::NoRouteV6(reason) => Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Verdict {
    Forward,
    Loopback(PeerId),
    Answer(Answer),
    Drop(DropReason),
}

fn is_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            !(v6.is_multicast() || v6.is_loopback() || v6.is_unspecified() || is_v6_link_local(v6))
        }
    }
}

fn is_v6_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

fn is_private(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || is_cgnat(v4),
        // Unique local addresses, which no masqueraded exit routes.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_cgnat(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..128).contains(&octets[1])
}

fn is_echo_request(packet: &[u8]) -> bool {
    let Ok(header) = parse_ip(packet) else {
        return false;
    };
    let Ok(icmp) = read_icmp(packet, header.l4_offset) else {
        return false;
    };
    (header.is_v6() && icmp.kind == ICMPV6_ECHO_REQUEST)
        || (!header.is_v6() && icmp.kind == ICMPV4_ECHO_REQUEST)
}

fn is_resolver_port(packet: &[u8]) -> bool {
    let Ok(header) = parse_ip(packet) else {
        return false;
    };
    if header.protocol != PROTO_UDP && header.protocol != PROTO_TCP {
        return false;
    }
    read_ports(packet, header.l4_offset).is_ok_and(|(_, destination)| destination == 53)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf::{GatewayConf, PeerConf};
    use crate::ip::{ICMPV4_DEST_UNREACHABLE, ICMPV4_ECHO_REPLY, ICMPV6_DEST_UNREACHABLE};
    use crate::keys::GatewayKey;
    use crate::plan::TUNNEL_GATEWAY_V4;
    use crate::testpkt;
    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519;
    use ip_network::IpNetwork;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr as _;
    use std::time::{Duration, Instant, SystemTime};

    struct Client {
        tunn: Tunn,
        label: PeerLabel,
        addr: SocketAddr,
        v4: Ipv4Addr,
        v6: Ipv6Addr,
    }

    impl Client {
        fn initiation(&mut self) -> Vec<u8> {
            let mut buf = vec![0u8; 2048];
            match self.tunn.format_handshake_initiation(&mut buf, true) {
                TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
                other => panic!("expected an initiation, got {other:?}"),
            }
        }

        fn encapsulate(&mut self, packet: &[u8]) -> Vec<u8> {
            let mut buf = vec![0u8; 2048];
            match self.tunn.encapsulate(packet, &mut buf) {
                TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
                other => panic!("expected a data packet, got {other:?}"),
            }
        }

        fn decapsulate(&mut self, datagram: &[u8]) -> Vec<u8> {
            let mut buf = vec![0u8; 2048];
            match self.tunn.decapsulate(None, datagram, &mut buf) {
                TunnResult::WriteToNetwork(bytes) | TunnResult::WriteToTunnelV4(bytes, _) => {
                    bytes.to_vec()
                }
                TunnResult::WriteToTunnelV6(bytes, _) => bytes.to_vec(),
                other => panic!("nothing came back out of the peer: {other:?}"),
            }
        }
    }

    fn build(count: usize, isolation: bool) -> (Responder, Vec<Client>) {
        build_with(
            count,
            ResponderOptions {
                peer_isolation: isolation,
                ..ResponderOptions::default()
            },
        )
    }

    fn build_with(count: usize, options: ResponderOptions) -> (Responder, Vec<Client>) {
        let gateway = GatewayKey::generate();
        let gateway_public = x25519::PublicKey::from(*gateway.public().as_bytes());
        let plan = PeerPlan::default();
        let mut peers = Vec::new();
        let mut clients = Vec::new();
        for number in 0..count {
            let index = u32::try_from(number).unwrap() + 2;
            let (v4, v6) = plan.address_for(index).unwrap();
            let secret = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let public = PeerPublicKey::from_bytes(x25519::PublicKey::from(&secret).to_bytes());
            let psk = PresharedKey::generate();
            let label = PeerLabel::new(&format!("peer{index}")).unwrap();
            clients.push(Client {
                tunn: Tunn::new(
                    secret,
                    gateway_public,
                    Some(*psk.as_bytes()),
                    Some(25),
                    100 + index,
                    None,
                ),
                label: label.clone(),
                addr: SocketAddr::from(([192, 168, 7, u8::try_from(index).unwrap()], 51820)),
                v4,
                v6,
            });
            peers.push(PeerConf {
                label,
                public,
                psk: Some(psk),
                allowed: vec![
                    IpNetwork::new(IpAddr::V4(v4), 32).unwrap(),
                    IpNetwork::new(IpAddr::V6(v6), 128).unwrap(),
                ],
            });
        }
        let conf = GatewayConf {
            key: gateway,
            peers,
        };
        let mut responder = Responder::new(&conf, plan, options).expect("a valid configuration");
        responder.set_gate(true, 1);
        (responder, clients)
    }

    fn handshake(responder: &mut Responder, client: &mut Client, now: Instant) {
        let mut scratch = ScratchBuf::new();
        let initiation = client.initiation();
        let response = match responder.handle_datagram(client.addr, &initiation, now, &mut scratch)
        {
            Inbound::Reply(bytes) => bytes.to_vec(),
            other => panic!("the gateway did not answer the handshake: {other:?}"),
        };
        let keepalive = client.decapsulate(&response);
        match responder.handle_datagram(client.addr, &keepalive, now, &mut scratch) {
            Inbound::Consumed => {}
            other => panic!("the keepalive was not consumed: {other:?}"),
        }
    }

    fn uplink(
        responder: &mut Responder,
        client: &mut Client,
        packet: &[u8],
        now: Instant,
    ) -> Vec<u8> {
        let datagram = client.encapsulate(packet);
        let mut scratch = ScratchBuf::new();
        match responder.handle_datagram(client.addr, &datagram, now, &mut scratch) {
            Inbound::Uplink { packet, .. } => packet.to_vec(),
            other => panic!("the packet was not released to the tunnel: {other:?}"),
        }
    }

    fn verdict(
        responder: &mut Responder,
        client: &mut Client,
        packet: &[u8],
        now: Instant,
    ) -> String {
        let datagram = client.encapsulate(packet);
        let mut scratch = ScratchBuf::new();
        format!(
            "{:?}",
            responder.handle_datagram(client.addr, &datagram, now, &mut scratch)
        )
    }

    #[test]
    fn completes_a_handshake_with_a_stock_initiator() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        assert!(!responder.snapshot()[0].has_session);

        handshake(&mut responder, &mut clients[0], now);

        let status = responder.snapshot();
        assert!(status[0].has_session);
        assert!(status[0].endpoint_seen);
        assert_eq!(status[0].label, clients[0].label);
        assert_eq!(responder.stats().handshakes, 1);
        assert_eq!(
            responder.endpoint(peer_of(&responder, &clients[0])),
            Some(clients[0].addr)
        );
    }

    fn peer_of(responder: &Responder, client: &Client) -> PeerId {
        responder
            .peer_by_label(&client.label)
            .expect("a known peer")
    }

    #[test]
    fn demuxes_a_data_packet_to_the_peer_that_owns_its_session() {
        let (mut responder, mut clients) = build(2, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        handshake(&mut responder, &mut clients[1], now);

        let second = peer_of(&responder, &clients[1]);
        let packet = testpkt::udp(
            IpAddr::V4(clients[1].v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"query",
        );
        let datagram = clients[1].encapsulate(&packet);
        let mut scratch = ScratchBuf::new();
        match responder.handle_datagram(clients[1].addr, &datagram, now, &mut scratch) {
            Inbound::Uplink { peer, packet: out } => {
                assert_eq!(peer, second);
                assert_eq!(out, &packet[..]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn drops_an_initiation_from_an_unknown_public_key() {
        let (mut responder, clients) = build(1, true);
        let now = Instant::now();
        let gateway_public = x25519::PublicKey::from(*responder.public_key().as_bytes());
        let stranger = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let mut tunn = Tunn::new(stranger, gateway_public, None, None, 9, None);
        let mut buf = vec![0u8; 2048];
        let initiation = match tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };

        let mut scratch = ScratchBuf::new();
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch),
            Inbound::Dropped(DropReason::UnknownPeer)
        ));
        assert_eq!(responder.stats().unknown_peer, 1);
        assert!(!responder.snapshot()[0].has_session);
    }

    #[test]
    fn refuses_an_initiation_and_holds_everything_while_the_gate_is_closed() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        let peer = peer_of(&responder, &clients[0]);

        responder.set_gate(false, 2);

        let mut scratch = ScratchBuf::new();
        let initiation = clients[0].initiation();
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch),
            Inbound::Dropped(DropReason::GateClosed)
        ));
        assert_eq!(responder.stats().handshake_refused_gate_closed, 1);

        let packet = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"query",
        );
        let datagram = clients[0].encapsulate(&packet);
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch),
            Inbound::Dropped(DropReason::GateClosed)
        ));
        assert!(responder.flush(peer, &mut scratch).is_none());
        assert!(
            responder
                .tick(now, SystemTime::now(), &mut scratch)
                .is_empty()
        );
        assert_eq!(
            responder
                .send_to_peer(peer, &packet, &mut scratch)
                .unwrap_err(),
            RouteError::GateClosed
        );
        // The session survived the outage, so the peer resumes without a
        // handshake once the tunnel is back.
        responder.set_gate(true, 3);
        assert!(responder.snapshot()[0].has_session);
        let datagram = clients[0].encapsulate(&packet);
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch),
            Inbound::Uplink { .. }
        ));
    }

    #[test]
    fn answers_a_cookie_under_load_but_nothing_else_while_the_gate_is_closed() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        let initiation = clients[0].initiation();
        responder.set_gate(false, 1);

        let mut scratch = ScratchBuf::new();
        // The gate check runs after the shared limiter, so the limiter counts
        // once per initiation here instead of the two counts an accepted
        // initiation costs.
        for attempt in 1..=DEFAULT_HANDSHAKE_RATE {
            match responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch) {
                Inbound::Dropped(DropReason::GateClosed) => {}
                other => panic!("attempt {attempt} was answered: {other:?}"),
            }
        }
        match responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch) {
            Inbound::Reply(cookie) => assert_eq!(cookie[0], 3, "not a cookie reply"),
            other => panic!("the cookie was not emitted: {other:?}"),
        }
        assert_eq!(responder.stats().cookies, 1);
    }

    #[test]
    fn demands_a_cookie_at_the_hundred_and_first_initiation_of_a_second() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        let initiation = clients[0].initiation();
        let mut scratch = ScratchBuf::new();

        // Each accepted initiation is counted twice by the shared limiter: once
        // at the demux, once inside boringtun's own decapsulate. The threshold
        // is doubled to match, so the cookie demand lands where a WireGuard
        // device puts it. Each attempt comes from its own source so the
        // per-source bucket in front never fires.
        for attempt in 1..=100u32 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0xc633_6400 + attempt)), 51820);
            match responder.handle_datagram(addr, &initiation, now, &mut scratch) {
                Inbound::Reply(bytes) => assert_ne!(bytes[0], 3, "cookie demanded at {attempt}"),
                Inbound::Dropped(DropReason::Replay) => {}
                other => panic!("attempt {attempt}: {other:?}"),
            }
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0xc633_6400 + 101)), 51820);
        match responder.handle_datagram(addr, &initiation, now, &mut scratch) {
            Inbound::Reply(cookie) => assert_eq!(cookie[0], 3),
            other => {
                panic!("the hundred and first initiation was not answered with a cookie: {other:?}")
            }
        }
    }

    #[test]
    fn drops_a_source_the_peer_does_not_own() {
        let (mut responder, mut clients) = build(2, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);

        let stolen = clients[1].v4;
        let packet = testpkt::udp(
            IpAddr::V4(stolen),
            4000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"query",
        );
        let datagram = clients[0].encapsulate(&packet);
        let mut scratch = ScratchBuf::new();
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch),
            Inbound::Dropped(DropReason::SpoofedSource)
        ));
        assert_eq!(responder.stats().spoofed_source, 1);
    }

    #[test]
    fn moves_the_endpoint_on_a_data_packet_and_never_on_a_cookie_reply() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        let peer = peer_of(&responder, &clients[0]);
        let first = clients[0].addr;

        let roamed = SocketAddr::from(([203, 0, 113, 9], 4444));
        let packet = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"query",
        );
        let datagram = clients[0].encapsulate(&packet);
        let mut scratch = ScratchBuf::new();
        assert!(matches!(
            responder.handle_datagram(roamed, &datagram, now, &mut scratch),
            Inbound::Uplink { .. }
        ));
        assert_eq!(responder.endpoint(peer), Some(roamed));
        assert_ne!(first, roamed);

        // A cookie reply is sealed under material an eavesdropper can read off
        // the wire, so it may never move a peer's endpoint.
        let session = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
        let mut cookie = vec![0u8; 64];
        cookie[0] = 3;
        cookie[4..8].copy_from_slice(&session.to_le_bytes());
        let elsewhere = SocketAddr::from(([198, 51, 100, 4], 9999));
        assert!(matches!(
            responder.handle_datagram(elsewhere, &cookie, now, &mut scratch),
            Inbound::Dropped(_)
        ));
        assert_eq!(responder.endpoint(peer), Some(roamed));
    }

    #[test]
    fn refuses_the_eleventh_initiation_from_one_source_in_a_second() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        let initiation = clients[0].initiation();
        let mut scratch = ScratchBuf::new();

        for attempt in 1..=HANDSHAKE_BURST_PER_IP {
            match responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch) {
                Inbound::Reply(_) | Inbound::Dropped(DropReason::Replay) => {}
                other => panic!("attempt {attempt}: {other:?}"),
            }
        }
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch),
            Inbound::Dropped(DropReason::SourceRateLimited)
        ));
    }

    #[test]
    fn keeps_peers_apart_by_default_and_loops_them_back_with_isolation_off() {
        for isolation in [true, false] {
            let (mut responder, mut clients) = build(2, isolation);
            let now = Instant::now();
            handshake(&mut responder, &mut clients[0], now);
            let second = peer_of(&responder, &clients[1]);
            let packet = testpkt::udp(
                IpAddr::V4(clients[0].v4),
                4000,
                IpAddr::V4(clients[1].v4),
                8080,
                b"hello",
            );
            let datagram = clients[0].encapsulate(&packet);
            let mut scratch = ScratchBuf::new();
            match responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch) {
                Inbound::Dropped(DropReason::PeerIsolation) => assert!(isolation),
                Inbound::Loopback { to, packet: out } => {
                    assert!(!isolation);
                    assert_eq!(to, second);
                    assert_eq!(out, &packet[..]);
                }
                other => panic!("isolation {isolation}: {other:?}"),
            }
        }
    }

    #[test]
    fn answers_an_echo_request_addressed_to_the_gateway() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        let plan = PeerPlan::default();

        let request = testpkt::echo(
            IpAddr::V4(clients[0].v4),
            IpAddr::V4(plan.gateway_v4()),
            0x1234,
            1,
            b"ping",
        );
        let datagram = clients[0].encapsulate(&request);
        let mut scratch = ScratchBuf::new();
        let reply = match responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch) {
            Inbound::Reply(bytes) => bytes.to_vec(),
            other => panic!("the gateway did not answer its own address: {other:?}"),
        };
        let inner = clients[0].decapsulate(&reply);
        let header = crate::ip::parse_ip(&inner).expect("an IP packet");
        assert_eq!(header.src, IpAddr::V4(plan.gateway_v4()));
        assert_eq!(header.dst, IpAddr::V4(clients[0].v4));
        assert_eq!(inner[header.l4_offset], ICMPV4_ECHO_REPLY);

        // Anything else addressed to the gateway itself is refused.
        let packet = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(plan.gateway_v4()),
            22,
            b"ssh",
        );
        assert!(verdict(&mut responder, &mut clients[0], &packet, now).contains("SelfDestination"));
    }

    #[test]
    fn passes_only_the_exit_resolver_out_of_the_tunnel_pool() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);

        let resolver = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(TUNNEL_GATEWAY_V4),
            53,
            b"query",
        );
        assert_eq!(
            uplink(&mut responder, &mut clients[0], &resolver, now),
            resolver
        );

        let natpmp = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(TUNNEL_GATEWAY_V4),
            5351,
            b"map",
        );
        assert!(verdict(&mut responder, &mut clients[0], &natpmp, now).contains("PoolDestination"));

        let other_session = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 7)),
            80,
            b"hairpin",
        );
        assert!(
            verdict(&mut responder, &mut clients[0], &other_session, now)
                .contains("PoolDestination")
        );
    }

    #[test]
    fn answers_a_private_destination_with_an_unreachable() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);

        let packet = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            445,
            b"smb",
        );
        let datagram = clients[0].encapsulate(&packet);
        let mut scratch = ScratchBuf::new();
        let reply = match responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch) {
            Inbound::Reply(bytes) => bytes.to_vec(),
            other => panic!("a private destination was not refused fast: {other:?}"),
        };
        let inner = clients[0].decapsulate(&reply);
        let header = crate::ip::parse_ip(&inner).expect("an IP packet");
        assert_eq!(header.dst, IpAddr::V4(clients[0].v4));
        assert_eq!(inner[header.l4_offset], ICMPV4_DEST_UNREACHABLE);
        assert_eq!(responder.stats().private_destination, 1);
    }

    #[test]
    fn stops_answering_once_it_has_spent_its_own_icmp_budget() {
        // Every router bounds the errors it generates itself. This one must
        // too: with IPv6 withdrawn for the epoch, an answer is the response to
        // every packet a dual-stack peer sends, and each one costs a build plus
        // a full AEAD seal.
        let (mut responder, mut clients) = build_with(
            1,
            ResponderOptions {
                answer_rate: 0,
                answer_burst: 2,
                ..ResponderOptions::default()
            },
        );
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);

        let mut scratch = ScratchBuf::new();
        for attempt in 1..=2 {
            let packet = testpkt::udp(
                IpAddr::V4(clients[0].v4),
                4000 + attempt,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
                445,
                b"smb",
            );
            let datagram = clients[0].encapsulate(&packet);
            assert!(
                matches!(
                    responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch),
                    Inbound::Reply(_)
                ),
                "answer {attempt} was not emitted"
            );
        }

        let packet = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4003,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            445,
            b"smb",
        );
        let datagram = clients[0].encapsulate(&packet);
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch),
            Inbound::Consumed
        ));
        let stats = responder.stats();
        assert_eq!(stats.answers_suppressed, 1);
        assert_eq!(
            stats.private_destination, 3,
            "a refusal is counted whether or not the peer is told"
        );
    }

    #[test]
    fn drops_a_non_unicast_destination() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);

        for destination in [
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ] {
            let packet = testpkt::udp(IpAddr::V4(clients[0].v4), 5353, destination, 5353, b"mdns");
            assert!(
                verdict(&mut responder, &mut clients[0], &packet, now).contains("NonUnicast"),
                "{destination}"
            );
        }
    }

    #[test]
    fn fast_fails_ipv6_while_the_epoch_cannot_carry_it() {
        for (state, expected) in [
            (V6State::NoAssignment, "V6Unavailable"),
            (V6State::BudgetTooSmall, "V6Budget"),
        ] {
            let (mut responder, mut clients) = build(1, true);
            let now = Instant::now();
            handshake(&mut responder, &mut clients[0], now);
            responder.set_ipv6(state);

            let packet = testpkt::udp(
                IpAddr::V6(clients[0].v6),
                4000,
                IpAddr::V6(Ipv6Addr::from_str("2001:4860:4860::8888").unwrap()),
                53,
                b"query",
            );
            let datagram = clients[0].encapsulate(&packet);
            let mut scratch = ScratchBuf::new();
            let reply =
                match responder.handle_datagram(clients[0].addr, &datagram, now, &mut scratch) {
                    Inbound::Reply(bytes) => bytes.to_vec(),
                    other => panic!("{expected}: {other:?}"),
                };
            let inner = clients[0].decapsulate(&reply);
            let header = crate::ip::parse_ip(&inner).expect("an IP packet");
            assert_eq!(header.dst, IpAddr::V6(clients[0].v6));
            assert_eq!(inner[header.l4_offset], ICMPV6_DEST_UNREACHABLE);
            assert_eq!(inner[header.l4_offset + 1], 0, "no route to destination");

            let stats = responder.stats();
            match state {
                V6State::NoAssignment => assert_eq!(stats.v6_unavailable, 1),
                V6State::BudgetTooSmall => assert_eq!(stats.v6_budget, 1),
                V6State::Available => unreachable!(),
            }

            responder.set_ipv6(V6State::Available);
            assert_eq!(
                uplink(&mut responder, &mut clients[0], &packet, now),
                packet
            );
        }
    }

    #[test]
    fn drops_a_datagram_no_socket_could_have_delivered() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        let mut scratch = ScratchBuf::new();

        let mut oversize = vec![0u8; 65_536];
        oversize[0] = 4;
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &oversize, now, &mut scratch),
            Inbound::Dropped(DropReason::Oversize)
        ));

        // Everything a socket can deliver goes through boringtun, which copies
        // the ciphertext before authenticating it.
        let live = clients[0].encapsulate(b"");
        let session = u32::from_le_bytes(live[4..8].try_into().unwrap());
        for len in [8 * 1024_usize, 65_000] {
            let mut forged = vec![0u8; len];
            forged[0] = 4;
            forged[4..8].copy_from_slice(&session.to_le_bytes());
            forged[8..16].copy_from_slice(&4096u64.to_le_bytes());
            assert!(matches!(
                responder.handle_datagram(clients[0].addr, &forged, now, &mut scratch),
                Inbound::Dropped(DropReason::Auth)
            ));
        }
    }

    #[test]
    fn rebuilds_reachable_peers_when_the_wall_clock_jumps() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        let mut scratch = ScratchBuf::new();
        let wall = SystemTime::now();

        assert!(responder.tick(now, wall, &mut scratch).is_empty());
        assert!(responder.snapshot()[0].has_session);

        // A laptop that slept an hour wakes with sessions the monotonic clock
        // still believes young and the peer discarded long ago.
        let woken = wall + Duration::from_secs(3600);
        assert!(responder.tick(now, woken, &mut scratch).is_empty());
        assert!(!responder.snapshot()[0].has_session);
        assert_eq!(responder.stats().clock_jump_resets, 1);
    }

    #[test]
    fn refuses_a_replayed_initiation_until_the_peer_is_reset() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        let initiation = clients[0].initiation();
        let mut scratch = ScratchBuf::new();

        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch),
            Inbound::Reply(_)
        ));
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch),
            Inbound::Dropped(DropReason::Replay)
        ));
        assert_eq!(responder.snapshot()[0].last_drop, Some(DropReason::Replay));

        responder
            .reset_peer(&clients[0].label)
            .expect("a known peer");
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &initiation, now, &mut scratch),
            Inbound::Reply(_)
        ));
        assert_eq!(
            responder.reset_peer(&PeerLabel::new("nobody").unwrap()),
            Err(UnknownPeer)
        );
    }

    #[test]
    fn defers_a_downlink_packet_until_the_peer_has_a_session() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        let peer = peer_of(&responder, &clients[0]);
        let packet = testpkt::udp(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            IpAddr::V4(clients[0].v4),
            4000,
            b"answer",
        );
        let mut scratch = ScratchBuf::new();

        match responder.send_to_peer(peer, &packet, &mut scratch) {
            Ok(Encapsulated::Deferred { initiation }) => assert!(initiation.is_none()),
            other => panic!("a peer with no endpoint was not deferred: {other:?}"),
        }
        assert_eq!(responder.stats().downlink_queued, 1);
        assert_eq!(responder.snapshot()[0].stats.deferred, 1);

        handshake(&mut responder, &mut clients[0], now);
        // What boringtun queued behind the handshake comes out of the flush
        // loop, in its own order, before anything the caller sends next.
        let queued = responder
            .flush(peer, &mut scratch)
            .expect("the queued packet");
        assert_eq!(queued[0], 4);
        let queued = queued.to_vec();
        assert_eq!(clients[0].decapsulate(&queued), packet);
        assert!(responder.flush(peer, &mut scratch).is_none());

        match responder.send_to_peer(peer, &packet, &mut scratch) {
            Ok(Encapsulated::Sent(to, datagram)) => {
                assert_eq!(to, clients[0].addr);
                assert_eq!(datagram[0], 4);
            }
            other => panic!("{other:?}"),
        }

        // A peer whose tunnel was rebuilt keeps its endpoint, so the next
        // downlink packet is deferred behind an initiation the gateway can
        // actually send.
        responder
            .reset_peer(&clients[0].label)
            .expect("a known peer");
        match responder.send_to_peer(peer, &packet, &mut scratch) {
            Ok(Encapsulated::Deferred { initiation }) => {
                let (to, datagram) = initiation.expect("an initiation to send");
                assert_eq!(to, clients[0].addr);
                assert_eq!(datagram[0], 1, "a handshake initiation");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn routes_a_downlink_packet_by_its_destination() {
        let (mut responder, mut clients) = build(2, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        handshake(&mut responder, &mut clients[1], now);

        let packet = testpkt::udp(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            IpAddr::V4(clients[1].v4),
            4000,
            b"answer",
        );
        let mut scratch = ScratchBuf::new();
        let datagram =
            match responder.encapsulate_to(IpAddr::V4(clients[1].v4), &packet, &mut scratch) {
                Ok(Encapsulated::Sent(to, bytes)) => {
                    assert_eq!(to, clients[1].addr);
                    bytes.to_vec()
                }
                other => panic!("{other:?}"),
            };
        assert_eq!(clients[1].decapsulate(&datagram), packet);

        assert_eq!(
            responder
                .encapsulate_to(
                    IpAddr::V4(Ipv4Addr::new(10, 67, 0, 200)),
                    &packet,
                    &mut scratch
                )
                .unwrap_err(),
            RouteError::NoRoute
        );
    }

    #[test]
    fn reload_that_swaps_two_peers_key_material_keeps_both_reachable() {
        let (mut responder, mut clients) = build(2, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        handshake(&mut responder, &mut clients[1], now);

        // Two devices trade places in one edit. Removing a live key and
        // inserting the new one peer by peer deletes the entry the previous
        // peer just wrote, and the loser is unknown to every later initiation.
        let mut peers = responder.peer_confs();
        let public = peers[0].public;
        peers[0].public = peers[1].public;
        peers[1].public = public;
        let psk = peers[0].psk.take();
        peers[0].psk = peers[1].psk.take();
        peers[1].psk = psk;
        let conf = GatewayConf {
            key: responder.key().clone(),
            peers,
        };

        let report = responder.reload(&conf).expect("a valid configuration");
        assert_eq!(report.rebuilt.len(), 2);

        handshake(&mut responder, &mut clients[0], now);
        handshake(&mut responder, &mut clients[1], now);
    }

    #[test]
    fn reload_adds_removes_and_leaves_an_untouched_peer_alone() {
        let (mut responder, mut clients) = build(2, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        handshake(&mut responder, &mut clients[1], now);

        // Rebuild the same configuration minus the second peer, plus a third.
        let plan = PeerPlan::default();
        let (v4, v6) = plan.address_for(4).unwrap();
        let secret = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PeerPublicKey::from_bytes(x25519::PublicKey::from(&secret).to_bytes());
        let mut peers = responder.peer_confs();
        peers.retain(|peer| peer.label != clients[1].label);
        peers.push(PeerConf {
            label: PeerLabel::new("peer4").unwrap(),
            public,
            psk: None,
            allowed: vec![
                IpNetwork::new(IpAddr::V4(v4), 32).unwrap(),
                IpNetwork::new(IpAddr::V6(v6), 128).unwrap(),
            ],
        });
        let conf = GatewayConf {
            key: responder.key().clone(),
            peers,
        };

        let report = responder.reload(&conf).expect("a valid configuration");
        assert_eq!(report.added, vec![PeerLabel::new("peer4").unwrap()]);
        assert_eq!(report.removed, vec![clients[1].label.clone()]);
        assert!(report.rebuilt.is_empty());
        assert_eq!(report.unchanged, 1);

        let status = responder.snapshot();
        assert_eq!(status.len(), 2);
        let kept = status
            .iter()
            .find(|peer| peer.label == clients[0].label)
            .expect("the untouched peer");
        assert!(kept.has_session, "an untouched peer lost its session");
        assert!(responder.peer_by_label(&clients[1].label).is_none());

        // Changing what a peer is allowed to source rebuilds it: the old
        // session would keep passing an address the new configuration refuses.
        let mut peers = responder.peer_confs();
        for peer in &mut peers {
            if peer.label == clients[0].label {
                peer.allowed = vec![IpNetwork::new(IpAddr::V4(clients[0].v4), 32).unwrap()];
            }
        }
        let conf = GatewayConf {
            key: responder.key().clone(),
            peers,
        };
        let report = responder.reload(&conf).expect("a valid configuration");
        assert_eq!(report.rebuilt, vec![clients[0].label.clone()]);
        assert_eq!(report.unchanged, 1);
        assert!(report.added.is_empty() && report.removed.is_empty());
        let status = responder.snapshot();
        let rebuilt = status
            .iter()
            .find(|peer| peer.label == clients[0].label)
            .expect("the rebuilt peer");
        assert!(!rebuilt.has_session);
    }

    #[test]
    fn a_reload_that_runs_out_of_indexes_leaves_the_gateway_untouched() {
        // One index left, and a reload that wants three peers. Drawing them one
        // at a time would rebuild the first peer and insert the second before
        // the third refused, which is a configuration nobody wrote.
        let mut indexes = IndexGen::from_seed(1, 0);
        for _ in 0..(1u32 << 24) - 3 {
            indexes.next().expect("still inside the period");
        }

        let key = GatewayKey::generate();
        let live = PeerConf {
            label: PeerLabel::new("peer2").unwrap(),
            public: fresh_public(),
            psk: None,
            allowed: vec![IpNetwork::from_str("10.67.0.2/32").unwrap()],
        };
        let conf = GatewayConf {
            key: key.clone(),
            peers: vec![live],
        };
        let mut responder = Responder::with_indexes(
            &conf,
            PeerPlan::default(),
            ResponderOptions::default(),
            indexes,
        )
        .expect("the last index numbers the only peer");

        let mut peers = responder.peer_confs();
        peers[0]
            .allowed
            .push(IpNetwork::from_str("10.67.0.10/32").unwrap());
        for (number, address) in [(3u8, "10.67.0.3/32"), (4, "10.67.0.4/32")] {
            peers.push(PeerConf {
                label: PeerLabel::new(&format!("peer{number}")).unwrap(),
                public: fresh_public(),
                psk: None,
                allowed: vec![IpNetwork::from_str(address).unwrap()],
            });
        }
        let wanted = GatewayConf { key, peers };

        assert_eq!(
            responder.reload(&wanted).unwrap_err(),
            ConfError::TooManyPeers
        );
        let after = responder.peer_confs();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].allowed.len(), 1);
    }

    fn fresh_public() -> PeerPublicKey {
        let secret = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
        PeerPublicKey::from_bytes(x25519::PublicKey::from(&secret).to_bytes())
    }

    #[test]
    fn refuses_a_peer_it_has_no_index_left_to_number() {
        let mut indexes = IndexGen::from_seed(1, 0);
        while indexes.next().is_some() {}

        let key = GatewayKey::generate();
        let secret = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let conf = GatewayConf {
            key,
            peers: vec![PeerConf {
                label: PeerLabel::new("peer2").unwrap(),
                public: PeerPublicKey::from_bytes(x25519::PublicKey::from(&secret).to_bytes()),
                psk: None,
                allowed: vec![IpNetwork::from_str("10.67.0.2/32").unwrap()],
            }],
        };
        assert_eq!(
            Responder::with_indexes(
                &conf,
                PeerPlan::default(),
                ResponderOptions::default(),
                indexes
            )
            .unwrap_err(),
            ConfError::TooManyPeers
        );
    }

    #[test]
    fn renders_no_address_or_key_when_a_responder_is_printed() {
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        let rendered = format!("{responder:?}");
        assert!(!rendered.contains("192.168.7"), "{rendered}");
        assert!(!rendered.contains("10.67."), "{rendered}");

        let status = format!("{:?}", responder.snapshot());
        assert!(!status.contains("192.168.7"), "{status}");
    }

    #[test]
    fn emits_a_passive_keepalive_only_once_the_gate_reopens() {
        // boringtun reads its own monotonic clock, so the only way to observe a
        // keepalive rule is to let the time pass. The gate rule this pins cost
        // an incident: a keepalive over a black hole feeds the peer's own
        // liveness detector and turns a 15 second recovery into a 120 second one.
        let (mut responder, mut clients) = build(1, true);
        let now = Instant::now();
        handshake(&mut responder, &mut clients[0], now);
        let mut scratch = ScratchBuf::new();
        let packet = testpkt::udp(
            IpAddr::V4(clients[0].v4),
            4000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            b"query",
        );

        std::thread::sleep(Duration::from_millis(10_100));
        responder.set_gate(false, 2);
        assert!(
            responder
                .tick(Instant::now(), SystemTime::now(), &mut scratch)
                .is_empty()
        );
        let datagram = clients[0].encapsulate(&packet);
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &datagram, Instant::now(), &mut scratch),
            Inbound::Dropped(DropReason::GateClosed)
        ));
        assert!(
            responder
                .tick(Instant::now(), SystemTime::now(), &mut scratch)
                .is_empty(),
            "a closed gate emitted a keepalive"
        );

        std::thread::sleep(Duration::from_millis(10_100));
        responder.set_gate(true, 3);
        assert!(
            responder
                .tick(Instant::now(), SystemTime::now(), &mut scratch)
                .is_empty()
        );
        let datagram = clients[0].encapsulate(&packet);
        assert!(matches!(
            responder.handle_datagram(clients[0].addr, &datagram, Instant::now(), &mut scratch),
            Inbound::Uplink { .. }
        ));
        let out = responder.tick(Instant::now(), SystemTime::now(), &mut scratch);
        assert_eq!(out.len(), 1, "no keepalive once the gate reopened");
        assert_eq!(out[0].0, clients[0].addr);
        assert_eq!(out[0].1[0], 4, "a keepalive is a data packet");
    }
}
