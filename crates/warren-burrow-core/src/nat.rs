//! The peer-aware NAPT.
//!
//! A stock WireGuard-protocol peer keeps its own interface address, and the
//! Warren exit refuses any inner packet whose source is not the address it
//! assigned to the session. Every peer packet is therefore rewritten onto that
//! one address on the way up and back onto the peer on the way down: ports for
//! TCP and UDP, identifiers for ICMP echo, and the header quoted inside an ICMP
//! error so path MTU discovery and connection refusals still reach the peer.
//!
//! Ownership is part of every translation. A peer may only send a source
//! address its own allowed IPs cover, and a mapping belongs to the peer that
//! opened it, so one peer can neither create nor refresh nor inherit another
//! peer's mapping. The exit's own anti-spoof gate can no longer see a spoofed
//! inner source once this NAT has run, which is why both walls live here.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::error::{CoreError, PacketError};
use crate::icmp::{parse_error_quote, rewrite_error_quote};
use crate::ip::{
    PROTO_ICMPV4, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, Side, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN,
    is_echo, is_icmp_error, parse_ip, read_icmp, read_ports, rewrite_endpoint, tcp_flags,
};
use crate::peer::PeerId;
use crate::ports::{DYNAMIC_POOL_END, DYNAMIC_POOL_START, PortAllocator};
use crate::stats::{Counters, Snapshot};

/// Length of an [`ExitId`].
pub const EXIT_ID_LEN: usize = 16;

/// Opaque identifier of the exit an epoch was dialed to.
///
/// Deliberately without a `Debug` of its bytes: it names a node, and the no-log
/// discipline keeps that out of traces.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExitId([u8; EXIT_ID_LEN]);

impl ExitId {
    /// The identifier of a datapath with no exit behind it.
    pub const UNKNOWN: Self = Self([0u8; EXIT_ID_LEN]);

    /// Wraps the raw identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EXIT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EXIT_ID_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for ExitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if *self == Self::UNKNOWN {
            "ExitId(unknown)"
        } else {
            "ExitId(set)"
        })
    }
}

/// Which tunnel epoch the external addresses belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochId {
    /// The exit this epoch reached.
    pub exit: ExitId,
    /// Bumped on every reconnect.
    pub generation: u64,
}

/// The protocol a mapping serves. ICMP covers the echo identifiers, which are
/// their own space and not ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MapProto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP and ICMPv6 echo.
    Icmp,
}

impl MapProto {
    const COUNT: usize = 3;

    const fn slot(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Udp => 1,
            Self::Icmp => 2,
        }
    }
}

/// Identifier of one mapping, unique for the life of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MappingId(u64);

/// Where a translated downlink packet must go.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Translated {
    /// The peer that opened the mapping.
    pub peer: PeerId,
    /// The peer address the packet now carries.
    pub destination: IpAddr,
}

impl std::fmt::Debug for Translated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The destination is a peer's own address, which stays out of traces.
        f.debug_struct("Translated")
            .field("peer", &self.peer.index())
            .field("v6", &self.destination.is_ipv6())
            .finish()
    }
}

/// A forward the operator pinned: an external port that always reaches one
/// peer endpoint, whoever the remote is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StaticDnat {
    /// The protocol the forward serves.
    pub proto: MapProto,
    /// The external port, taken out of the dynamic pool for good.
    pub external_port: u16,
    /// The peer endpoint it reaches.
    pub target: SocketAddr,
}

impl std::fmt::Debug for StaticDnat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticDnat")
            .field("proto", &self.proto)
            .field("external_port", &self.external_port)
            .field("v6", &self.target.is_ipv6())
            .finish()
    }
}

/// Why the NAT refused a packet. Each variant is one counter on `/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NatDrop {
    /// The sending peer does not own the source address, or the mapping it
    /// would have used belongs to another peer.
    #[error("source not owned by the sending peer")]
    SourceNotOwned,
    /// No mapping matched, or the answer came from a remote the peer never
    /// addressed.
    #[error("no mapping")]
    NoMapping,
    /// The external port space for that protocol and family is full.
    #[error("external port space exhausted")]
    PortExhausted,
    /// The sending peer is at its own mapping cap.
    #[error("peer mapping cap reached")]
    PeerCap,
    /// A fragment, which this NAT does not reassemble.
    #[error("fragment")]
    Fragment,
    /// An IPv6 extension header.
    #[error("IPv6 extension header")]
    ExtensionHeader,
    /// A protocol this gateway does not translate.
    #[error("unsupported protocol")]
    UnsupportedProtocol,
    /// Headers that do not parse.
    #[error("malformed packet")]
    Malformed,
    /// The epoch has no external address of that family.
    #[error("address family unavailable in this epoch")]
    FamilyUnavailable,
}

impl From<PacketError> for NatDrop {
    fn from(err: PacketError) -> Self {
        match err {
            PacketError::Fragment => Self::Fragment,
            PacketError::ExtensionHeader => Self::ExtensionHeader,
            PacketError::UnsupportedProtocol => Self::UnsupportedProtocol,
            PacketError::Truncated
            | PacketError::BadVersion
            | PacketError::FamilyMismatch
            | PacketError::NotAnEcho
            | PacketError::NotAnIcmpError => Self::Malformed,
        }
    }
}

/// Which peer owns which address, as the peers' allowed IPs declare it.
///
/// The same longest-match structure cryptokey routing uses, so an address
/// resolves to exactly one peer and a mapping can never be claimed by two.
pub struct Ownership {
    table: IpNetworkTable<PeerId>,
}

impl Ownership {
    /// An empty view: until it is filled, every source is refused.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: IpNetworkTable::new(),
        }
    }

    /// Gives `network` to `peer`.
    pub fn insert(&mut self, network: IpNetwork, peer: PeerId) {
        self.table.insert(network, peer);
    }

    /// Gives one address to `peer`.
    pub fn insert_addr(&mut self, addr: IpAddr, peer: PeerId) {
        self.table.insert(IpNetwork::from(addr), peer);
    }

    /// The peer that owns `addr`, if any.
    #[must_use]
    pub fn owner_of(&self, addr: IpAddr) -> Option<PeerId> {
        self.table.longest_match(addr).map(|(_, peer)| *peer)
    }

    /// True while no peer owns anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

impl Default for Ownership {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Ownership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The prefixes are the peers' addresses; only the count is rendered.
        let (v4, v6) = self.table.len();
        f.debug_struct("Ownership")
            .field("networks", &(v4 + v6))
            .finish()
    }
}

/// The ranges, caps and timeouts the NAT runs on.
///
/// The timeout defaults are the RFC 4787 and RFC 5382 floors, which is what
/// makes a long-lived TCP connection survive an idle night and a UDP flow
/// survive a pause in a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatConfig {
    /// The dynamic external port pool, for TCP and UDP, per family. The range
    /// the gateway keeps for its own control-plane flows is taken out of it by
    /// the allocator whatever this says. ICMP echo identifiers are a separate
    /// fixed space and ignore it.
    pub pool: RangeInclusive<u16>,
    /// How many mappings one peer may hold per protocol.
    pub per_peer_mappings: usize,
    /// How many ICMP echo identifiers one peer may hold.
    pub per_peer_identifiers: usize,
    /// How many distinct remotes one mapping tracks before the oldest is
    /// forgotten.
    pub remotes_per_mapping: usize,
    /// A UDP flow that has not been answered yet.
    pub udp_initial: Duration,
    /// A UDP flow answered at least once (RFC 4787 REQ-5).
    pub udp_established: Duration,
    /// A TCP connection whose handshake has not completed (RFC 5382 REQ-5).
    pub tcp_syn: Duration,
    /// An established TCP connection (RFC 5382 REQ-5).
    pub tcp_established: Duration,
    /// A TCP connection closed by FIN in both directions or by RST.
    pub tcp_closing: Duration,
    /// An ICMP echo exchange.
    pub icmp: Duration,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            pool: DYNAMIC_POOL_START..=DYNAMIC_POOL_END,
            per_peer_mappings: 4096,
            per_peer_identifiers: 1024,
            remotes_per_mapping: 64,
            udp_initial: Duration::from_secs(30),
            udp_established: Duration::from_secs(120),
            tcp_syn: Duration::from_secs(60),
            tcp_established: Duration::from_secs(7440),
            tcp_closing: Duration::from_secs(60),
            icmp: Duration::from_secs(60),
        }
    }
}

/// What a mapping knows about one remote it has exchanged packets with.
#[derive(Clone, Copy)]
struct RemoteFlow {
    addr: IpAddr,
    port: u16,
    state: FlowState,
    fin_up: bool,
    fin_down: bool,
    last_seen: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowState {
    UdpOneWay,
    UdpAnswered,
    TcpSyn,
    TcpEstablished,
    TcpClosed,
    Icmp,
}

struct Mapping {
    owner: PeerId,
    proto: MapProto,
    internal: SocketAddr,
    external_port: u16,
    remotes: Vec<RemoteFlow>,
    last_seen: Instant,
    pinned: bool,
    // Position in the owner's recency list. A pinned forward is never linked:
    // it is not a candidate for eviction and does not count against the cap.
    older: Option<MappingId>,
    newer: Option<MappingId>,
}

impl Mapping {
    fn remote_index(&self, addr: IpAddr, port: u16) -> Option<usize> {
        self.remotes
            .iter()
            .position(|r| r.addr == addr && r.port == port)
    }
}

/// The peer-aware network address and port translator.
pub struct Napt {
    config: NatConfig,
    ownership: Ownership,
    exit: Option<ExitId>,
    epoch: Option<EpochId>,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    mappings: HashMap<MappingId, Mapping>,
    // Least-recently-used first, per peer and protocol: the eviction a peer at
    // its cap pays has to be a constant, or one device holding its 4,096
    // mappings turns every further flow of every peer into a walk of the whole
    // table, on the packet path.
    recency: HashMap<(PeerId, MapProto), (MappingId, MappingId)>,
    outbound: HashMap<(MapProto, IpAddr, u16), MappingId>,
    inbound: HashMap<(MapProto, bool, u16), MappingId>,
    peer_counts: HashMap<(PeerId, MapProto), usize>,
    ports: [[PortAllocator; MapProto::COUNT]; 2],
    expiry: BinaryHeap<Reverse<(Instant, MappingId)>>,
    next_id: u64,
    counters: Counters,
    rng: StdRng,
}

impl std::fmt::Debug for Napt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every mapping names a peer address and a remote it talks to, so the
        // table is summarised and never rendered.
        f.debug_struct("Napt")
            .field("epoch", &self.epoch.map(|e| e.generation))
            .field("mappings", &self.mappings.len())
            .field("dual_stack", &self.v6.is_some())
            .field("counters", &self.counters.snapshot())
            .finish()
    }
}

impl Napt {
    /// A NAT with no peer, no epoch and an empty table, seeded from the
    /// operating system.
    #[must_use]
    pub fn new(config: NatConfig) -> Self {
        Self::with_rng(config, StdRng::from_entropy())
    }

    /// The same, with the port draw driven by a caller-supplied generator.
    #[must_use]
    pub fn with_rng(config: NatConfig, rng: StdRng) -> Self {
        let pool = || PortAllocator::ports(config.pool.clone());
        Self {
            ownership: Ownership::new(),
            exit: None,
            epoch: None,
            v4: None,
            v6: None,
            mappings: HashMap::new(),
            recency: HashMap::new(),
            outbound: HashMap::new(),
            inbound: HashMap::new(),
            peer_counts: HashMap::new(),
            ports: [
                [pool(), pool(), PortAllocator::identifiers()],
                [pool(), pool(), PortAllocator::identifiers()],
            ],
            expiry: BinaryHeap::new(),
            next_id: 1,
            counters: Counters::default(),
            rng,
            config,
        }
    }

    /// Replaces the ownership view, after a configuration reload.
    ///
    /// Mappings are kept: each one names the peer that opened it, so a peer
    /// that inherits another's address still cannot inherit its flows.
    pub fn set_ownership(&mut self, ownership: Ownership) {
        self.ownership = ownership;
    }

    /// Points the NAT at the addresses this epoch was assigned.
    ///
    /// The table survives only when the exit and the address are both
    /// unchanged, which is a redial to the same exit. The tunnel pool is one
    /// engine-wide constant, so two different exits routinely assign the same
    /// address: keeping the table on the address alone would leave every dead
    /// flow alive under a new public IP, and would let a remote tie two exit
    /// addresses to one client through a flow that never broke. Pinned
    /// forwards are kept and re-armed on the new address.
    pub fn set_external(&mut self, epoch: EpochId, v4: Ipv4Addr, v6: Option<Ipv6Addr>) {
        let same_exit = self.exit == Some(epoch.exit);
        if !(same_exit && self.v4 == Some(v4)) {
            self.flush_family(false);
        }
        if !(same_exit && self.v6 == v6) {
            self.flush_family(true);
        }
        self.exit = Some(epoch.exit);
        self.epoch = Some(epoch);
        self.v4 = Some(v4);
        self.v6 = v6;
    }

    /// The epoch the external addresses belong to.
    #[must_use]
    pub fn epoch(&self) -> Option<EpochId> {
        self.epoch
    }

    /// How many mappings the table holds, pinned forwards included.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// The drop and translation counters.
    #[must_use]
    pub fn stats(&self) -> Snapshot {
        self.counters.snapshot()
    }

    /// Pins an external port to one peer endpoint, in both directions.
    ///
    /// The port is reserved out of the dynamic pool, so no flow can ever be
    /// given it. Any dynamic mapping the target endpoint already held is
    /// replaced, which is why a forward is installed before the peers connect.
    ///
    /// # Errors
    ///
    /// [`CoreError::TargetNotOwned`] when no peer owns the target address, and
    /// the reservation errors of [`PortAllocator::reserve`].
    pub fn add_static(&mut self, dnat: StaticDnat, now: Instant) -> Result<MappingId, CoreError> {
        let owner = self
            .ownership
            .owner_of(dnat.target.ip())
            .ok_or(CoreError::TargetNotOwned)?;
        let v6 = dnat.target.is_ipv6();
        self.allocator(dnat.proto, v6).reserve(dnat.external_port)?;
        if let Some(id) = self
            .outbound
            .get(&(dnat.proto, dnat.target.ip(), dnat.target.port()))
            .copied()
        {
            self.remove_mapping(id);
        }
        if let Some(id) = self
            .inbound
            .get(&(dnat.proto, v6, dnat.external_port))
            .copied()
        {
            self.remove_mapping(id);
        }
        let id = self.insert_mapping(Mapping {
            owner,
            proto: dnat.proto,
            internal: dnat.target,
            external_port: dnat.external_port,
            remotes: Vec::new(),
            last_seen: now,
            pinned: true,
            older: None,
            newer: None,
        });
        Ok(id)
    }

    /// Removes a pinned forward and returns its port to the pool. `false` when
    /// no forward held that port.
    pub fn remove_static(&mut self, proto: MapProto, external_port: u16, v6: bool) -> bool {
        let Some(id) = self.inbound.get(&(proto, v6, external_port)).copied() else {
            return false;
        };
        if !self.mappings.get(&id).is_some_and(|m| m.pinned) {
            return false;
        }
        self.remove_mapping(id);
        self.allocator(proto, v6).unreserve(external_port);
        true
    }

    /// Forgets every mapping a peer holds, after a reload or a reset.
    pub fn flush_peer(&mut self, peer: PeerId) {
        let doomed: Vec<MappingId> = self
            .mappings
            .iter()
            .filter(|(_, m)| m.owner == peer && !m.pinned)
            .map(|(id, _)| *id)
            .collect();
        for id in doomed {
            self.remove_mapping(id);
        }
    }

    /// Drops every mapping whose flows have all been idle past their timeout,
    /// and returns how many went. Pinned forwards never expire.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let mut removed = 0;
        while let Some(Reverse((deadline, id))) = self.expiry.peek().copied() {
            if deadline > now {
                break;
            }
            self.expiry.pop();
            let Some(mapping) = self.mappings.get(&id) else {
                continue;
            };
            let real = self.deadline_of(mapping);
            if real > now {
                self.expiry.push(Reverse((real, id)));
                continue;
            }
            self.remove_mapping(id);
            removed += 1;
        }
        removed
    }

    /// Translates one packet from a peer onto the address the exit assigned.
    ///
    /// # Errors
    ///
    /// A [`NatDrop`] naming the class the packet was refused under; the packet
    /// is left untouched and the counter for that class is bumped.
    pub fn translate_uplink(
        &mut self,
        peer: PeerId,
        pkt: &mut [u8],
        now: Instant,
    ) -> Result<(), NatDrop> {
        match self.uplink(peer, pkt, now) {
            Ok(()) => {
                self.counters.uplink_translated();
                Ok(())
            }
            Err(drop) => {
                self.counters.uplink_dropped(drop);
                Err(drop)
            }
        }
    }

    /// Translates one packet from the tunnel back to the peer that owns the
    /// mapping it matches.
    ///
    /// # Errors
    ///
    /// A [`NatDrop`] naming the class the packet was refused under.
    pub fn translate_downlink(
        &mut self,
        pkt: &mut [u8],
        now: Instant,
    ) -> Result<Translated, NatDrop> {
        match self.downlink(pkt, now) {
            Ok(out) => {
                self.counters.downlink_translated();
                Ok(out)
            }
            Err(drop) => {
                self.counters.downlink_dropped(drop);
                Err(drop)
            }
        }
    }

    fn uplink(&mut self, peer: PeerId, pkt: &mut [u8], now: Instant) -> Result<(), NatDrop> {
        let hdr = parse_ip(pkt)?;
        let external = self
            .external(hdr.is_v6())
            .ok_or(NatDrop::FamilyUnavailable)?;
        if self.ownership.owner_of(hdr.src) != Some(peer) {
            return Err(NatDrop::SourceNotOwned);
        }
        match (hdr.is_v6(), hdr.protocol) {
            (_, PROTO_TCP) | (_, PROTO_UDP) => {
                let proto = if hdr.protocol == PROTO_TCP {
                    MapProto::Tcp
                } else {
                    MapProto::Udp
                };
                let (sport, dport) = read_ports(pkt, hdr.l4_offset)?;
                let flags = if proto == MapProto::Tcp {
                    tcp_flags(pkt, hdr.l4_offset)?
                } else {
                    0
                };
                let id =
                    self.mapping_for_uplink(peer, proto, SocketAddr::new(hdr.src, sport), now)?;
                self.touch_uplink(id, hdr.dst, dport, flags, now);
                let port = self.external_port(id)?;
                rewrite_endpoint(pkt, &hdr, Side::Source, external, Some(port))?;
                Ok(())
            }
            (false, PROTO_ICMPV4) | (true, PROTO_ICMPV6) => {
                let icmp = read_icmp(pkt, hdr.l4_offset)?;
                if is_echo(hdr.protocol, icmp.kind) {
                    let echo_id = icmp.echo_id.ok_or(NatDrop::Malformed)?;
                    let id = self.mapping_for_uplink(
                        peer,
                        MapProto::Icmp,
                        SocketAddr::new(hdr.src, echo_id),
                        now,
                    )?;
                    self.touch_uplink(id, hdr.dst, 0, 0, now);
                    let external_id = self.external_port(id)?;
                    rewrite_endpoint(pkt, &hdr, Side::Source, external, Some(external_id))?;
                    Ok(())
                } else if is_icmp_error(hdr.protocol, icmp.kind) {
                    self.uplink_error(peer, pkt, &hdr, external)
                } else {
                    Err(NatDrop::UnsupportedProtocol)
                }
            }
            _ => Err(NatDrop::UnsupportedProtocol),
        }
    }

    /// A peer answering an error about a packet that reached it through a
    /// mapping: the quote names the peer, so it is rewritten the same way the
    /// outer header is.
    fn uplink_error(
        &mut self,
        peer: PeerId,
        pkt: &mut [u8],
        hdr: &crate::ip::IpHeader,
        external: IpAddr,
    ) -> Result<(), NatDrop> {
        let quote = parse_error_quote(pkt, hdr)?;
        let proto = map_proto(quote.inner.protocol, quote.inner.is_v6())
            .ok_or(NatDrop::UnsupportedProtocol)?;
        let port = quote.port(Side::Destination).ok_or(NatDrop::Malformed)?;
        let id = self
            .outbound
            .get(&(proto, quote.inner.dst, port))
            .copied()
            .ok_or(NatDrop::NoMapping)?;
        let mapping = self.mappings.get(&id).ok_or(NatDrop::NoMapping)?;
        if mapping.owner != peer {
            return Err(NatDrop::SourceNotOwned);
        }
        let external_port = mapping.external_port;
        rewrite_endpoint(pkt, hdr, Side::Source, external, None)?;
        rewrite_error_quote(
            pkt,
            hdr,
            &quote,
            Side::Destination,
            external,
            Some(external_port),
        )?;
        Ok(())
    }

    fn downlink(&mut self, pkt: &mut [u8], now: Instant) -> Result<Translated, NatDrop> {
        let hdr = parse_ip(pkt)?;
        let external = self
            .external(hdr.is_v6())
            .ok_or(NatDrop::FamilyUnavailable)?;
        if hdr.dst != external {
            return Err(NatDrop::NoMapping);
        }
        match (hdr.is_v6(), hdr.protocol) {
            (_, PROTO_TCP) | (_, PROTO_UDP) => {
                let proto = if hdr.protocol == PROTO_TCP {
                    MapProto::Tcp
                } else {
                    MapProto::Udp
                };
                let (sport, dport) = read_ports(pkt, hdr.l4_offset)?;
                let flags = if proto == MapProto::Tcp {
                    tcp_flags(pkt, hdr.l4_offset)?
                } else {
                    0
                };
                let id = self
                    .inbound
                    .get(&(proto, hdr.is_v6(), dport))
                    .copied()
                    .ok_or(NatDrop::NoMapping)?;
                let internal = self.accept_downlink(id, hdr.src, sport, flags, now)?;
                rewrite_endpoint(
                    pkt,
                    &hdr,
                    Side::Destination,
                    internal.ip(),
                    Some(internal.port()),
                )?;
                self.translated(id, internal)
            }
            (false, PROTO_ICMPV4) | (true, PROTO_ICMPV6) => {
                let icmp = read_icmp(pkt, hdr.l4_offset)?;
                if is_echo(hdr.protocol, icmp.kind) {
                    let echo_id = icmp.echo_id.ok_or(NatDrop::Malformed)?;
                    let id = self
                        .inbound
                        .get(&(MapProto::Icmp, hdr.is_v6(), echo_id))
                        .copied()
                        .ok_or(NatDrop::NoMapping)?;
                    let internal = self.accept_downlink(id, hdr.src, 0, 0, now)?;
                    rewrite_endpoint(
                        pkt,
                        &hdr,
                        Side::Destination,
                        internal.ip(),
                        Some(internal.port()),
                    )?;
                    self.translated(id, internal)
                } else if is_icmp_error(hdr.protocol, icmp.kind) {
                    self.downlink_error(pkt, &hdr, external)
                } else {
                    Err(NatDrop::UnsupportedProtocol)
                }
            }
            _ => Err(NatDrop::UnsupportedProtocol),
        }
    }

    /// An error about a packet the gateway sent: the quote names the external
    /// address, and only the mapping it matches says which peer sent it.
    ///
    /// The remote filter does not apply, because an error legitimately comes
    /// from a router on the path rather than from the remote the peer
    /// addressed.
    fn downlink_error(
        &mut self,
        pkt: &mut [u8],
        hdr: &crate::ip::IpHeader,
        external: IpAddr,
    ) -> Result<Translated, NatDrop> {
        let quote = parse_error_quote(pkt, hdr)?;
        if quote.inner.src != external {
            return Err(NatDrop::NoMapping);
        }
        let proto = map_proto(quote.inner.protocol, quote.inner.is_v6())
            .ok_or(NatDrop::UnsupportedProtocol)?;
        let port = quote.port(Side::Source).ok_or(NatDrop::Malformed)?;
        let id = self
            .inbound
            .get(&(proto, hdr.is_v6(), port))
            .copied()
            .ok_or(NatDrop::NoMapping)?;
        let mapping = self.mappings.get(&id).ok_or(NatDrop::NoMapping)?;
        let internal = mapping.internal;
        rewrite_endpoint(pkt, hdr, Side::Destination, internal.ip(), None)?;
        rewrite_error_quote(
            pkt,
            hdr,
            &quote,
            Side::Source,
            internal.ip(),
            Some(internal.port()),
        )?;
        self.translated(id, internal)
    }

    fn translated(&self, id: MappingId, internal: SocketAddr) -> Result<Translated, NatDrop> {
        let mapping = self.mappings.get(&id).ok_or(NatDrop::NoMapping)?;
        Ok(Translated {
            peer: mapping.owner,
            destination: internal.ip(),
        })
    }

    fn external(&self, v6: bool) -> Option<IpAddr> {
        if v6 {
            self.v6.map(IpAddr::V6)
        } else {
            self.v4.map(IpAddr::V4)
        }
    }

    fn external_port(&self, id: MappingId) -> Result<u16, NatDrop> {
        self.mappings
            .get(&id)
            .map(|m| m.external_port)
            .ok_or(NatDrop::NoMapping)
    }

    fn allocator(&mut self, proto: MapProto, v6: bool) -> &mut PortAllocator {
        &mut self.ports[usize::from(v6)][proto.slot()]
    }

    /// The mapping an uplink packet uses, creating one when the peer has none
    /// for that internal endpoint.
    fn mapping_for_uplink(
        &mut self,
        peer: PeerId,
        proto: MapProto,
        internal: SocketAddr,
        now: Instant,
    ) -> Result<MappingId, NatDrop> {
        if let Some(id) = self
            .outbound
            .get(&(proto, internal.ip(), internal.port()))
            .copied()
        {
            let mapping = self.mappings.get(&id).ok_or(NatDrop::NoMapping)?;
            if mapping.owner != peer {
                return Err(NatDrop::SourceNotOwned);
            }
            return Ok(id);
        }
        self.create_mapping(peer, proto, internal, now)
    }

    fn create_mapping(
        &mut self,
        peer: PeerId,
        proto: MapProto,
        internal: SocketAddr,
        now: Instant,
    ) -> Result<MappingId, NatDrop> {
        let cap = if proto == MapProto::Icmp {
            self.config.per_peer_identifiers
        } else {
            self.config.per_peer_mappings
        };
        if self.peer_counts.get(&(peer, proto)).copied().unwrap_or(0) >= cap {
            // A peer over its cap only ever loses its own oldest flow: making
            // one peer able to evict another's mapping would be a denial of
            // service one LAN device could aim at the others.
            if proto == MapProto::Tcp {
                return Err(NatDrop::PeerCap);
            }
            let victim = self.oldest_of(peer, proto).ok_or(NatDrop::PeerCap)?;
            self.remove_mapping(victim);
        }
        let v6 = internal.is_ipv6();
        let allocator = &mut self.ports[usize::from(v6)][proto.slot()];
        // Port preservation: the peer's own port when it is inside the pool and
        // free, otherwise a uniform draw.
        let external_port = allocator
            .alloc(Some(internal.port()), &mut self.rng)
            .ok_or(NatDrop::PortExhausted)?;
        let id = self.insert_mapping(Mapping {
            owner: peer,
            proto,
            internal,
            external_port,
            remotes: Vec::new(),
            last_seen: now,
            pinned: false,
            older: None,
            newer: None,
        });
        self.link_newest(id);
        *self.peer_counts.entry((peer, proto)).or_insert(0) += 1;
        let initial = match proto {
            MapProto::Tcp => self.config.tcp_syn,
            MapProto::Udp => self.config.udp_initial,
            MapProto::Icmp => self.config.icmp,
        };
        self.expiry.push(Reverse((now + initial, id)));
        Ok(id)
    }

    fn insert_mapping(&mut self, mapping: Mapping) -> MappingId {
        let id = MappingId(self.next_id);
        self.next_id += 1;
        self.outbound.insert(
            (
                mapping.proto,
                mapping.internal.ip(),
                mapping.internal.port(),
            ),
            id,
        );
        self.inbound.insert(
            (
                mapping.proto,
                mapping.internal.is_ipv6(),
                mapping.external_port,
            ),
            id,
        );
        self.mappings.insert(id, mapping);
        id
    }

    fn remove_mapping(&mut self, id: MappingId) {
        self.unlink(id);
        let Some(mapping) = self.mappings.remove(&id) else {
            return;
        };
        let v6 = mapping.internal.is_ipv6();
        self.outbound.remove(&(
            mapping.proto,
            mapping.internal.ip(),
            mapping.internal.port(),
        ));
        self.inbound
            .remove(&(mapping.proto, v6, mapping.external_port));
        if mapping.pinned {
            return;
        }
        self.allocator(mapping.proto, v6)
            .release(mapping.external_port);
        if let Some(count) = self.peer_counts.get_mut(&(mapping.owner, mapping.proto)) {
            *count = count.saturating_sub(1);
        }
    }

    fn oldest_of(&self, peer: PeerId, proto: MapProto) -> Option<MappingId> {
        self.recency.get(&(peer, proto)).map(|(oldest, _)| *oldest)
    }

    /// Appends a mapping at the recent end of its owner's list.
    fn link_newest(&mut self, id: MappingId) {
        let Some(mapping) = self.mappings.get(&id) else {
            return;
        };
        if mapping.pinned {
            return;
        }
        let key = (mapping.owner, mapping.proto);
        let previous = match self.recency.get_mut(&key) {
            Some((_, newest)) => {
                let previous = *newest;
                *newest = id;
                Some(previous)
            }
            None => {
                self.recency.insert(key, (id, id));
                None
            }
        };
        if let Some(previous) = previous
            && let Some(mapping) = self.mappings.get_mut(&previous)
        {
            mapping.newer = Some(id);
        }
        if let Some(mapping) = self.mappings.get_mut(&id) {
            mapping.older = previous;
            mapping.newer = None;
        }
    }

    /// Takes a mapping out of its owner's list, leaving the list consistent.
    fn unlink(&mut self, id: MappingId) {
        let Some(mapping) = self.mappings.get_mut(&id) else {
            return;
        };
        if mapping.pinned {
            return;
        }
        let key = (mapping.owner, mapping.proto);
        let older = mapping.older.take();
        let newer = mapping.newer.take();
        match older {
            Some(older) => {
                if let Some(mapping) = self.mappings.get_mut(&older) {
                    mapping.newer = newer;
                }
            }
            None => {
                if let Some(entry) = self.recency.get_mut(&key) {
                    match newer {
                        Some(newer) => entry.0 = newer,
                        None => {
                            self.recency.remove(&key);
                            return;
                        }
                    }
                }
            }
        }
        match newer {
            Some(newer) => {
                if let Some(mapping) = self.mappings.get_mut(&newer) {
                    mapping.older = older;
                }
            }
            None => {
                if let Some(entry) = self.recency.get_mut(&key)
                    && let Some(older) = older
                {
                    entry.1 = older;
                }
            }
        }
    }

    /// Moves a mapping to the recent end after a packet touched it.
    fn touch_recency(&mut self, id: MappingId) {
        let Some(mapping) = self.mappings.get(&id) else {
            return;
        };
        // Already the most recent, which is every packet of a burst on one
        // flow: nothing to relink.
        if mapping.pinned || mapping.newer.is_none() {
            return;
        }
        self.unlink(id);
        self.link_newest(id);
    }

    fn flush_family(&mut self, v6: bool) {
        let doomed: Vec<MappingId> = self
            .mappings
            .iter()
            .filter(|(_, m)| m.internal.is_ipv6() == v6 && !m.pinned)
            .map(|(id, _)| *id)
            .collect();
        for id in doomed {
            self.remove_mapping(id);
        }
    }

    /// Records what an uplink packet says about its flow.
    fn touch_uplink(&mut self, id: MappingId, remote: IpAddr, port: u16, flags: u8, now: Instant) {
        let cap = self.config.remotes_per_mapping;
        let mut closed = false;
        let Some(mapping) = self.mappings.get_mut(&id) else {
            return;
        };
        mapping.last_seen = now;
        let proto = mapping.proto;
        match mapping.remote_index(remote, port) {
            Some(at) => {
                if let Some(flow) = mapping.remotes.get_mut(at) {
                    flow.last_seen = now;
                    closed = advance(flow, proto, flags, true);
                }
            }
            None => {
                if mapping.remotes.len() >= cap {
                    // Forget the least recently used remote rather than grow
                    // without bound under a port scan.
                    if let Some(at) = oldest_remote(&mapping.remotes) {
                        mapping.remotes.swap_remove(at);
                    }
                }
                let mut flow = RemoteFlow {
                    addr: remote,
                    port,
                    state: match proto {
                        MapProto::Tcp => FlowState::TcpSyn,
                        MapProto::Udp => FlowState::UdpOneWay,
                        MapProto::Icmp => FlowState::Icmp,
                    },
                    fin_up: false,
                    fin_down: false,
                    last_seen: now,
                };
                closed = advance(&mut flow, proto, flags, true);
                mapping.remotes.push(flow);
            }
        }
        self.touch_recency(id);
        if closed {
            self.expiry
                .push(Reverse((now + self.config.tcp_closing, id)));
        }
    }

    /// Applies the filtering rule to a downlink packet and records what it says
    /// about its flow. A pinned forward accepts any remote; a dynamic mapping
    /// accepts only a remote the peer addressed first.
    fn accept_downlink(
        &mut self,
        id: MappingId,
        remote: IpAddr,
        port: u16,
        flags: u8,
        now: Instant,
    ) -> Result<SocketAddr, NatDrop> {
        let cap = self.config.remotes_per_mapping;
        let mut closed = false;
        let mapping = self.mappings.get_mut(&id).ok_or(NatDrop::NoMapping)?;
        let proto = mapping.proto;
        let internal = mapping.internal;
        match mapping.remote_index(remote, port) {
            Some(at) => {
                if let Some(flow) = mapping.remotes.get_mut(at) {
                    flow.last_seen = now;
                    closed = advance(flow, proto, flags, false);
                }
            }
            None => {
                if !mapping.pinned {
                    return Err(NatDrop::NoMapping);
                }
                if mapping.remotes.len() >= cap
                    && let Some(at) = oldest_remote(&mapping.remotes)
                {
                    mapping.remotes.swap_remove(at);
                }
                let mut flow = RemoteFlow {
                    addr: remote,
                    port,
                    state: match proto {
                        MapProto::Tcp => FlowState::TcpSyn,
                        MapProto::Udp => FlowState::UdpOneWay,
                        MapProto::Icmp => FlowState::Icmp,
                    },
                    fin_up: false,
                    fin_down: false,
                    last_seen: now,
                };
                closed = advance(&mut flow, proto, flags, false);
                mapping.remotes.push(flow);
            }
        }
        mapping.last_seen = now;
        self.touch_recency(id);
        if closed {
            self.expiry
                .push(Reverse((now + self.config.tcp_closing, id)));
        }
        Ok(internal)
    }

    fn deadline_of(&self, mapping: &Mapping) -> Instant {
        if mapping.pinned {
            // Never swept; the sweep re-pushes it far ahead if it ever sees it.
            return mapping.last_seen + Duration::from_secs(86_400);
        }
        let mut deadline = mapping.last_seen
            + match mapping.proto {
                MapProto::Tcp => self.config.tcp_syn,
                MapProto::Udp => self.config.udp_initial,
                MapProto::Icmp => self.config.icmp,
            };
        for flow in &mapping.remotes {
            let timeout = match flow.state {
                FlowState::UdpOneWay => self.config.udp_initial,
                FlowState::UdpAnswered => self.config.udp_established,
                FlowState::TcpSyn => self.config.tcp_syn,
                FlowState::TcpEstablished => self.config.tcp_established,
                FlowState::TcpClosed => self.config.tcp_closing,
                FlowState::Icmp => self.config.icmp,
            };
            deadline = deadline.max(flow.last_seen + timeout);
        }
        deadline
    }
}

/// Moves one flow's state on what a packet carries, and reports whether it just
/// closed, which is the one transition that shortens a deadline already in the
/// expiry heap.
fn advance(flow: &mut RemoteFlow, proto: MapProto, flags: u8, uplink: bool) -> bool {
    let was_open = flow.state != FlowState::TcpClosed;
    match proto {
        MapProto::Udp => {
            if !uplink {
                flow.state = FlowState::UdpAnswered;
            }
        }
        MapProto::Icmp => flow.state = FlowState::Icmp,
        MapProto::Tcp => {
            if flags & TCP_RST != 0 {
                flow.state = FlowState::TcpClosed;
                return was_open;
            }
            if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 && !uplink {
                flow.state = FlowState::TcpEstablished;
            } else if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 && uplink {
                flow.state = FlowState::TcpSyn;
                flow.fin_up = false;
                flow.fin_down = false;
            }
            if flags & TCP_FIN != 0 {
                if uplink {
                    flow.fin_up = true;
                } else {
                    flow.fin_down = true;
                }
            }
            if flow.fin_up && flow.fin_down {
                flow.state = FlowState::TcpClosed;
            }
        }
    }
    was_open && flow.state == FlowState::TcpClosed
}

fn oldest_remote(remotes: &[RemoteFlow]) -> Option<usize> {
    remotes
        .iter()
        .enumerate()
        .min_by_key(|(_, r)| r.last_seen)
        .map(|(at, _)| at)
}

/// The mapping protocol a packet's transport belongs to, for its family.
fn map_proto(protocol: u8, v6: bool) -> Option<MapProto> {
    match (v6, protocol) {
        (_, PROTO_TCP) => Some(MapProto::Tcp),
        (_, PROTO_UDP) => Some(MapProto::Udp),
        (false, PROTO_ICMPV4) | (true, PROTO_ICMPV6) => Some(MapProto::Icmp),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{TCP_ACK, TCP_RST, TCP_SYN, parse_ip, read_icmp, read_ports};
    use crate::testpkt;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    const A: PeerId = PeerId::new(1);
    const B: PeerId = PeerId::new(2);

    const A4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 67, 0, 2));
    const B4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 67, 0, 3));
    const A6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd77, 0x6172, 0x7265, 0, 0, 0, 0, 2));
    const EXT4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    const EXT6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 2);
    const REMOTE4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    const OTHER4: IpAddr = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    const REMOTE6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888));

    fn ext4() -> IpAddr {
        IpAddr::V4(EXT4)
    }

    fn ext6() -> IpAddr {
        IpAddr::V6(EXT6)
    }

    fn epoch(exit: u8, generation: u64) -> EpochId {
        EpochId {
            exit: ExitId::from_bytes([exit; EXIT_ID_LEN]),
            generation,
        }
    }

    fn ownership() -> Ownership {
        let mut own = Ownership::new();
        own.insert_addr(A4, A);
        own.insert_addr(A6, A);
        own.insert_addr(B4, B);
        own
    }

    fn napt_with(config: NatConfig) -> Napt {
        let mut nat = Napt::with_rng(config, StdRng::seed_from_u64(0xbeef));
        nat.set_ownership(ownership());
        nat.set_external(epoch(1, 1), EXT4, Some(EXT6));
        nat
    }

    fn napt() -> Napt {
        napt_with(NatConfig::default())
    }

    fn small_pool(ports: u16, per_peer: usize) -> NatConfig {
        NatConfig {
            pool: 32_768..=(32_768 + ports - 1),
            per_peer_mappings: per_peer,
            ..NatConfig::default()
        }
    }

    #[test]
    fn translates_a_flow_out_and_back_for_every_protocol_and_family() {
        for (name, peer_ip, ext, remote, tcp) in [
            ("v4 udp", A4, ext4(), REMOTE4, false),
            ("v4 tcp", A4, ext4(), REMOTE4, true),
            ("v6 udp", A6, ext6(), REMOTE6, false),
            ("v6 tcp", A6, ext6(), REMOTE6, true),
        ] {
            let mut nat = napt();
            let now = Instant::now();
            let mut up = if tcp {
                testpkt::tcp(peer_ip, 5000, remote, 443, TCP_SYN, b"")
            } else {
                testpkt::udp(peer_ip, 5000, remote, 443, b"query")
            };
            nat.translate_uplink(A, &mut up, now)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let hdr = parse_ip(&up).expect("valid uplink");
            assert_eq!(
                hdr.src, ext,
                "{name}: the exit only accepts its own address"
            );
            assert_eq!(hdr.dst, remote, "{name}");
            let (external_port, dport) = read_ports(&up, hdr.l4_offset).expect("ports");
            assert_eq!(dport, 443, "{name}");
            assert!(testpkt::checksums_valid(&up), "{name}: uplink checksums");

            let mut down = if tcp {
                testpkt::tcp(remote, 443, ext, external_port, TCP_SYN | TCP_ACK, b"")
            } else {
                testpkt::udp(remote, 443, ext, external_port, b"answer")
            };
            let out = nat
                .translate_downlink(&mut down, now)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(out.peer, A, "{name}");
            assert_eq!(out.destination, peer_ip, "{name}");
            let hdr = parse_ip(&down).expect("valid downlink");
            assert_eq!(hdr.dst, peer_ip, "{name}");
            assert_eq!(read_ports(&down, hdr.l4_offset), Ok((443, 5000)), "{name}");
            assert!(
                testpkt::checksums_valid(&down),
                "{name}: downlink checksums"
            );
        }
    }

    #[test]
    fn preserves_a_source_port_inside_the_pool_and_replaces_one_outside_it() {
        let mut nat = napt();
        let now = Instant::now();
        let mut inside = testpkt::udp(A4, 40_000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut inside, now).expect("uplink");
        assert_eq!(read_ports(&inside, 20), Ok((40_000, 53)));

        let mut outside = testpkt::udp(A4, 1024, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut outside, now).expect("uplink");
        let (port, _) = read_ports(&outside, 20).expect("ports");
        assert_ne!(port, 1024, "a port outside the pool cannot be preserved");
        assert!((DYNAMIC_POOL_START..=DYNAMIC_POOL_END).contains(&port));
    }

    #[test]
    fn gives_one_internal_endpoint_the_same_external_port_whatever_the_remote() {
        let mut nat = napt();
        let now = Instant::now();
        let mut first = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut first, now).expect("uplink");
        let mut second = testpkt::udp(A4, 5000, OTHER4, 53, b"q");
        nat.translate_uplink(A, &mut second, now).expect("uplink");
        assert_eq!(
            read_ports(&first, 20).expect("ports").0,
            read_ports(&second, 20).expect("ports").0,
            "endpoint-independent mapping"
        );
        assert_eq!(nat.mapping_count(), 1);
    }

    #[test]
    fn refuses_a_downlink_from_a_remote_the_peer_never_addressed() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;

        let mut stranger = testpkt::udp(OTHER4, 53, ext4(), port, b"unsolicited");
        assert_eq!(
            nat.translate_downlink(&mut stranger, now),
            Err(NatDrop::NoMapping),
            "address-and-port-dependent filtering"
        );
        let mut wrong_port = testpkt::udp(REMOTE4, 54, ext4(), port, b"unsolicited");
        assert_eq!(
            nat.translate_downlink(&mut wrong_port, now),
            Err(NatDrop::NoMapping)
        );
        assert_eq!(nat.stats().no_mapping, 2);
    }

    #[test]
    fn refuses_a_source_the_peer_does_not_own() {
        let mut nat = napt();
        let now = Instant::now();
        let mut spoofed = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        assert_eq!(
            nat.translate_uplink(B, &mut spoofed, now),
            Err(NatDrop::SourceNotOwned),
            "peer B may not send peer A's address"
        );
        assert_eq!(nat.mapping_count(), 0, "a refusal creates nothing");
        assert_eq!(nat.stats().source_not_owned, 1);

        let unknown = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let mut foreign = testpkt::udp(unknown, 5000, REMOTE4, 53, b"q");
        assert_eq!(
            nat.translate_uplink(A, &mut foreign, now),
            Err(NatDrop::SourceNotOwned),
            "an address no peer owns belongs to no peer"
        );
    }

    #[test]
    fn refuses_a_peer_the_mapping_it_would_inherit_from_another() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");

        // A reload hands A's address to B while A's mapping is still live.
        let mut own = Ownership::new();
        own.insert_addr(A4, B);
        nat.set_ownership(own);
        let mut inherited = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        assert_eq!(
            nat.translate_uplink(B, &mut inherited, now),
            Err(NatDrop::SourceNotOwned),
            "a mapping belongs to the peer that opened it"
        );
    }

    #[test]
    fn a_peer_at_its_cap_evicts_only_its_own_mapping() {
        let mut nat = napt_with(small_pool(8, 2));
        let now = Instant::now();
        // The other peer's mapping is the oldest of the whole table, so a
        // gateway that evicted the globally oldest would take this one.
        let mut other_peer = testpkt::udp(B4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(B, &mut other_peer, now)
            .expect("uplink");
        let b_port = read_ports(&other_peer, 20).expect("ports").0;

        let mut first = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut first, now + Duration::from_secs(1))
            .expect("uplink");
        let evicted_port = read_ports(&first, 20).expect("ports").0;
        let mut second = testpkt::udp(A4, 5001, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut second, now + Duration::from_secs(2))
            .expect("uplink");

        let mut third = testpkt::udp(A4, 5002, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut third, now + Duration::from_secs(3))
            .expect("a peer at its cap evicts its own oldest flow");

        let mut to_b = testpkt::udp(REMOTE4, 53, ext4(), b_port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut to_b, now)
                .expect("B still answers")
                .peer,
            B,
            "no peer may evict another peer's mapping"
        );
        let mut to_evicted = testpkt::udp(REMOTE4, 53, ext4(), evicted_port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut to_evicted, now),
            Err(NatDrop::NoMapping),
            "peer A's own oldest mapping was the one evicted"
        );
    }

    #[test]
    fn a_flow_a_peer_keeps_using_outlives_one_it_opened_later() {
        // The victim is the least recently used, not the first created: a
        // recency list maintained only at creation would evict the long call
        // and keep the flow that went quiet after one packet.
        let mut nat = napt_with(small_pool(16, 3));
        let now = Instant::now();
        let mut ports = Vec::new();
        for (offset, port) in [(0u64, 5000u16), (1, 5001), (2, 5002)] {
            let mut packet = testpkt::udp(A4, port, REMOTE4, 53, b"q");
            nat.translate_uplink(A, &mut packet, now + Duration::from_secs(offset))
                .expect("uplink");
            ports.push(read_ports(&packet, 20).expect("ports").0);
        }

        // The oldest flow speaks again, which puts the second one at the back.
        let mut again = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut again, now + Duration::from_secs(3))
            .expect("uplink");

        let mut fourth = testpkt::udp(A4, 5003, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut fourth, now + Duration::from_secs(4))
            .expect("a peer at its cap makes room");

        let mut to_first = testpkt::udp(REMOTE4, 53, ext4(), ports[0], b"a");
        assert!(
            nat.translate_downlink(&mut to_first, now + Duration::from_secs(4))
                .is_ok(),
            "the flow that kept speaking was evicted"
        );
        let mut to_second = testpkt::udp(REMOTE4, 53, ext4(), ports[1], b"a");
        assert_eq!(
            nat.translate_downlink(&mut to_second, now + Duration::from_secs(4)),
            Err(NatDrop::NoMapping),
            "the least recently used flow is the one that goes"
        );
    }

    #[test]
    fn drops_a_tcp_connection_a_peer_opens_over_its_cap() {
        let mut nat = napt_with(small_pool(8, 1));
        let now = Instant::now();
        let mut first = testpkt::tcp(A4, 5000, REMOTE4, 443, TCP_SYN, b"");
        nat.translate_uplink(A, &mut first, now).expect("uplink");
        let mut second = testpkt::tcp(A4, 5001, REMOTE4, 443, TCP_SYN, b"");
        assert_eq!(
            nat.translate_uplink(A, &mut second, now),
            Err(NatDrop::PeerCap),
            "a TCP handshake is dropped rather than breaking a live connection"
        );
        assert_eq!(nat.stats().peer_cap, 1);
    }

    #[test]
    fn drops_and_counts_when_the_port_space_is_exhausted() {
        let mut nat = napt_with(small_pool(2, 16));
        let now = Instant::now();
        for port in [5000u16, 5001] {
            let mut pkt = testpkt::udp(A4, port, REMOTE4, 53, b"q");
            nat.translate_uplink(A, &mut pkt, now).expect("uplink");
        }
        let mut over = testpkt::udp(A4, 5002, REMOTE4, 53, b"q");
        assert_eq!(
            nat.translate_uplink(A, &mut over, now),
            Err(NatDrop::PortExhausted)
        );
        assert_eq!(nat.stats().port_exhausted, 1);
    }

    #[test]
    fn never_hands_a_flow_the_port_a_static_forward_holds() {
        let mut nat = napt_with(small_pool(4, 16));
        let now = Instant::now();
        nat.add_static(
            StaticDnat {
                proto: MapProto::Udp,
                external_port: 32_770,
                target: SocketAddr::new(A4, 8080),
            },
            now,
        )
        .expect("a free pool port can be pinned");

        let mut ports = Vec::new();
        for source in 5000u16..5003 {
            let mut pkt = testpkt::udp(A4, source, REMOTE4, 53, b"q");
            nat.translate_uplink(A, &mut pkt, now).expect("uplink");
            ports.push(read_ports(&pkt, 20).expect("ports").0);
        }
        assert!(!ports.contains(&32_770), "the pinned port went to a flow");
        let mut over = testpkt::udp(A4, 5100, REMOTE4, 53, b"q");
        assert_eq!(
            nat.translate_uplink(A, &mut over, now),
            Err(NatDrop::PortExhausted),
            "the pool is one port smaller while the forward is pinned"
        );
    }

    #[test]
    fn serves_a_static_forward_in_both_directions() {
        let mut nat = napt();
        let now = Instant::now();
        nat.add_static(
            StaticDnat {
                proto: MapProto::Udp,
                external_port: 51_820,
                target: SocketAddr::new(A4, 8080),
            },
            now,
        )
        .expect("pin");

        // Unsolicited inbound: a pinned forward answers any remote.
        let mut inbound = testpkt::udp(OTHER4, 40_000, ext4(), 51_820, b"hello");
        let out = nat
            .translate_downlink(&mut inbound, now)
            .expect("forwarded");
        assert_eq!(out.peer, A);
        let hdr = parse_ip(&inbound).expect("valid");
        assert_eq!(hdr.dst, A4);
        assert_eq!(read_ports(&inbound, hdr.l4_offset), Ok((40_000, 8080)));
        assert!(testpkt::checksums_valid(&inbound));

        // The answer leaves through the same external port.
        let mut reply = testpkt::udp(A4, 8080, OTHER4, 40_000, b"hi");
        nat.translate_uplink(A, &mut reply, now).expect("uplink");
        assert_eq!(
            read_ports(&reply, 20).expect("ports").0,
            51_820,
            "a static forward is symmetric"
        );
    }

    #[test]
    fn refuses_a_static_forward_no_peer_owns() {
        let mut nat = napt();
        let orphan = IpAddr::V4(Ipv4Addr::new(10, 67, 9, 9));
        assert_eq!(
            nat.add_static(
                StaticDnat {
                    proto: MapProto::Udp,
                    external_port: 51_820,
                    target: SocketAddr::new(orphan, 8080),
                },
                Instant::now()
            ),
            Err(CoreError::TargetNotOwned)
        );
        assert_eq!(
            nat.add_static(
                StaticDnat {
                    proto: MapProto::Udp,
                    external_port: 80,
                    target: SocketAddr::new(A4, 8080),
                },
                Instant::now()
            ),
            Err(CoreError::PortOutsidePool),
            "a forward outside the pool cannot be reserved"
        );
    }

    #[test]
    fn translates_an_icmp_echo_identifier_in_both_directions() {
        let mut nat = napt();
        let now = Instant::now();
        let mut ping = testpkt::echo(A4, REMOTE4, 0x4142, 1, b"ping");
        nat.translate_uplink(A, &mut ping, now).expect("uplink");
        let hdr = parse_ip(&ping).expect("valid");
        assert_eq!(hdr.src, ext4());
        let external_id = read_icmp(&ping, hdr.l4_offset)
            .expect("icmp")
            .echo_id
            .expect("an identifier");
        assert!(testpkt::checksums_valid(&ping));

        let mut pong = testpkt::echo(REMOTE4, ext4(), external_id, 1, b"ping");
        pong[20] = crate::ip::ICMPV4_ECHO_REPLY;
        let hdr = parse_ip(&pong).expect("valid");
        crate::icmp::recompute_icmp_checksum(&mut pong, &hdr).expect("checksum");
        let out = nat.translate_downlink(&mut pong, now).expect("the reply");
        assert_eq!(out.peer, A);
        let hdr = parse_ip(&pong).expect("valid");
        assert_eq!(hdr.dst, A4);
        assert_eq!(
            read_icmp(&pong, hdr.l4_offset).expect("icmp").echo_id,
            Some(0x4142)
        );
        assert!(testpkt::checksums_valid(&pong));
    }

    #[test]
    fn caps_the_echo_identifiers_one_peer_may_hold() {
        let mut nat = napt_with(NatConfig {
            per_peer_identifiers: 2,
            ..NatConfig::default()
        });
        let now = Instant::now();
        for (i, id) in [1u16, 2, 3].into_iter().enumerate() {
            let mut ping = testpkt::echo(A4, REMOTE4, id, 1, b"p");
            nat.translate_uplink(A, &mut ping, now + Duration::from_millis(i as u64))
                .expect("uplink");
        }
        assert_eq!(
            nat.mapping_count(),
            2,
            "the oldest identifier is evicted, never a third slot"
        );
    }

    #[test]
    fn rewrites_an_icmp_error_by_the_packet_it_quotes() {
        for (peer_ip, ext, remote) in [(A4, ext4(), REMOTE4), (A6, ext6(), REMOTE6)] {
            let mut nat = napt();
            let now = Instant::now();
            let original = testpkt::udp(peer_ip, 5000, remote, 443, b"payload");
            let mut up = original.clone();
            nat.translate_uplink(A, &mut up, now).expect("uplink");

            let mut err = if ext.is_ipv6() {
                crate::icmp::build_unreachable_v6(&up, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1))
                    .expect("an error")
            } else {
                crate::icmp::build_unreachable_v4(&up, Ipv4Addr::new(2, 2, 2, 2)).expect("an error")
            };
            let out = nat.translate_downlink(&mut err, now).expect("the error");
            assert_eq!(out.peer, A);
            let outer = parse_ip(&err).expect("valid");
            assert_eq!(outer.dst, peer_ip);
            let quote = crate::icmp::parse_error_quote(&err, &outer).expect("a quote");
            assert_eq!(quote.inner.src, peer_ip);
            assert_eq!(quote.ports.map(|p| p.0), Some(5000));
            assert!(testpkt::checksums_valid(&err));
        }
    }

    #[test]
    fn carries_the_tunnels_own_packet_too_big_back_to_the_peer() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 443, &[0u8; 1400]);
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        // What the client pump writes into the device sink for an oversize
        // packet, built from the post-NAT packet it sees.
        let mut ptb = warrenguard_transport_core::uplink_frag_needed(&up, 1114)
            .expect("the engine builds a Packet Too Big");
        let out = nat.translate_downlink(&mut ptb, now).expect("the PTB");
        assert_eq!(out.peer, A);
        let outer = parse_ip(&ptb).expect("valid");
        assert_eq!(outer.dst, A4, "the peer must recognise the destination");
        let quote = crate::icmp::parse_error_quote(&ptb, &outer).expect("a quote");
        assert_eq!(quote.inner.src, A4);
        assert_eq!(quote.ports, Some((5000, 443)));
        assert_eq!(
            u16::from_be_bytes([ptb[outer.l4_offset + 6], ptb[outer.l4_offset + 7]]),
            1114,
            "the next-hop MTU the peer must adopt"
        );
        assert!(testpkt::checksums_valid(&ptb));
    }

    #[test]
    fn rewrites_an_icmp_error_a_peer_sends_about_an_inbound_packet() {
        let mut nat = napt();
        let now = Instant::now();
        nat.add_static(
            StaticDnat {
                proto: MapProto::Udp,
                external_port: 51_820,
                target: SocketAddr::new(A4, 8080),
            },
            now,
        )
        .expect("pin");
        let mut inbound = testpkt::udp(OTHER4, 40_000, ext4(), 51_820, b"hello");
        nat.translate_downlink(&mut inbound, now).expect("forward");

        // The peer answers "port unreachable" about the packet it received.
        let mut err = crate::icmp::build_unreachable_v4(&inbound, Ipv4Addr::new(10, 67, 0, 2))
            .expect("an error");
        nat.translate_uplink(A, &mut err, now).expect("uplink");
        let outer = parse_ip(&err).expect("valid");
        assert_eq!(outer.src, ext4());
        let quote = crate::icmp::parse_error_quote(&err, &outer).expect("a quote");
        assert_eq!(quote.inner.dst, ext4());
        assert_eq!(quote.ports.map(|p| p.1), Some(51_820));
        assert!(testpkt::checksums_valid(&err));
    }

    #[test]
    fn expires_an_idle_mapping_and_never_a_pinned_one() {
        let mut nat = napt();
        let now = Instant::now();
        nat.add_static(
            StaticDnat {
                proto: MapProto::Udp,
                external_port: 51_820,
                target: SocketAddr::new(A4, 8080),
            },
            now,
        )
        .expect("pin");
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;

        assert_eq!(nat.sweep(now + Duration::from_secs(29)), 0);
        assert_eq!(nat.sweep(now + Duration::from_secs(31)), 1);
        assert_eq!(nat.mapping_count(), 1, "the pinned forward survives");
        let mut late = testpkt::udp(REMOTE4, 53, ext4(), port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut late, now + Duration::from_secs(31)),
            Err(NatDrop::NoMapping)
        );
        assert_eq!(nat.sweep(now + Duration::from_secs(100_000)), 0);
    }

    #[test]
    fn a_flow_that_was_answered_lives_the_bidirectional_timeout() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;
        let mut down = testpkt::udp(REMOTE4, 53, ext4(), port, b"a");
        nat.translate_downlink(&mut down, now).expect("answer");

        assert_eq!(nat.sweep(now + Duration::from_secs(31)), 0);
        assert_eq!(nat.sweep(now + Duration::from_secs(121)), 1);
    }

    #[test]
    fn a_tcp_connection_lives_by_its_handshake_and_dies_on_a_reset() {
        let mut nat = napt();
        let now = Instant::now();
        let mut syn = testpkt::tcp(A4, 5000, REMOTE4, 443, TCP_SYN, b"");
        nat.translate_uplink(A, &mut syn, now).expect("uplink");
        assert_eq!(
            nat.sweep(now + Duration::from_secs(61)),
            1,
            "a handshake nobody answered expires"
        );

        let mut syn = testpkt::tcp(A4, 5000, REMOTE4, 443, TCP_SYN, b"");
        nat.translate_uplink(A, &mut syn, now).expect("uplink");
        let port = read_ports(&syn, 20).expect("ports").0;
        let mut synack = testpkt::tcp(REMOTE4, 443, ext4(), port, TCP_SYN | TCP_ACK, b"");
        nat.translate_downlink(&mut synack, now).expect("answer");
        assert_eq!(
            nat.sweep(now + Duration::from_secs(61)),
            0,
            "an established connection outlives an idle hour"
        );

        let mut rst = testpkt::tcp(REMOTE4, 443, ext4(), port, TCP_RST, b"");
        nat.translate_downlink(&mut rst, now).expect("reset");
        assert_eq!(
            nat.sweep(now + Duration::from_secs(61)),
            1,
            "a reset connection is forgotten on the closing timeout"
        );
    }

    #[test]
    fn keeps_the_table_when_the_same_exit_returns_with_the_same_address() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;

        nat.set_external(epoch(1, 2), EXT4, Some(EXT6));
        let mut down = testpkt::udp(REMOTE4, 53, ext4(), port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut down, now).expect("answer").peer,
            A,
            "a redial to the same exit with the same address keeps the flows"
        );
    }

    #[test]
    fn flushes_the_table_when_another_exit_grants_the_same_address() {
        let mut nat = napt();
        let now = Instant::now();
        nat.add_static(
            StaticDnat {
                proto: MapProto::Udp,
                external_port: 51_820,
                target: SocketAddr::new(A4, 8080),
            },
            now,
        )
        .expect("pin");
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;

        // Same assigned address, a different exit: the public IP changed under
        // every flow.
        nat.set_external(epoch(2, 2), EXT4, Some(EXT6));
        assert_eq!(nat.mapping_count(), 1, "only the pinned forward survives");
        let mut down = testpkt::udp(REMOTE4, 53, ext4(), port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut down, now),
            Err(NatDrop::NoMapping)
        );
        let mut inbound = testpkt::udp(OTHER4, 40_000, ext4(), 51_820, b"hello");
        assert_eq!(
            nat.translate_downlink(&mut inbound, now)
                .expect("the forward is re-armed")
                .peer,
            A
        );
    }

    #[test]
    fn drops_a_family_the_epoch_has_no_address_for() {
        let mut nat = napt();
        let now = Instant::now();
        nat.set_external(epoch(1, 3), EXT4, None);
        let mut up = testpkt::udp(A6, 5000, REMOTE6, 53, b"q");
        assert_eq!(
            nat.translate_uplink(A, &mut up, now),
            Err(NatDrop::FamilyUnavailable)
        );
        assert_eq!(nat.stats().family_unavailable, 1);
    }

    #[test]
    fn drops_and_counts_what_it_cannot_translate() {
        let mut nat = napt();
        let now = Instant::now();

        let mut fragment = testpkt::udp(A4, 5000, REMOTE4, 53, b"body");
        fragment[6] = 0x20;
        assert_eq!(
            nat.translate_uplink(A, &mut fragment, now),
            Err(NatDrop::Fragment)
        );

        let mut extension = testpkt::udp(A6, 5000, REMOTE6, 53, b"body");
        extension[6] = 44;
        assert_eq!(
            nat.translate_uplink(A, &mut extension, now),
            Err(NatDrop::ExtensionHeader)
        );

        let mut gre = testpkt::udp(A4, 5000, REMOTE4, 53, b"body");
        gre[9] = 47;
        let hdr = parse_ip(&gre).expect("valid");
        crate::ip::rewrite_endpoint(&mut gre, &hdr, Side::Source, A4, None).ok();
        assert_eq!(
            nat.translate_uplink(A, &mut gre, now),
            Err(NatDrop::UnsupportedProtocol)
        );

        let mut short = vec![0x45u8, 0, 0, 30];
        assert_eq!(
            nat.translate_uplink(A, &mut short, now),
            Err(NatDrop::Malformed)
        );

        let mut orphan = testpkt::udp(REMOTE4, 53, ext4(), 40_000, b"a");
        assert_eq!(
            nat.translate_downlink(&mut orphan, now),
            Err(NatDrop::NoMapping)
        );

        let stats = nat.stats();
        assert_eq!(stats.fragment, 1);
        assert_eq!(stats.v6_extension_header, 1);
        assert_eq!(stats.unsupported_protocol, 1);
        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.no_mapping, 1);
        assert_eq!(stats.uplink_dropped, 4);
        assert_eq!(stats.downlink_dropped, 1);
        assert_eq!(stats.uplink_translated, 0);
        assert_eq!(nat.mapping_count(), 0);
    }

    #[test]
    fn counts_what_it_did_translate() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;
        let mut down = testpkt::udp(REMOTE4, 53, ext4(), port, b"a");
        nat.translate_downlink(&mut down, now).expect("answer");
        let stats = nat.stats();
        assert_eq!(stats.uplink_translated, 1);
        assert_eq!(stats.downlink_translated, 1);
        assert_eq!(stats.uplink_dropped, 0);
        assert_eq!(stats.downlink_dropped, 0);
    }

    #[test]
    fn drops_a_downlink_addressed_to_something_that_is_not_the_external_address() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;
        let elsewhere = IpAddr::V4(Ipv4Addr::new(10, 66, 0, 3));
        let mut down = testpkt::udp(REMOTE4, 53, elsewhere, port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut down, now),
            Err(NatDrop::NoMapping)
        );
    }

    #[test]
    fn a_prefix_owner_covers_every_address_inside_it() {
        let mut own = Ownership::new();
        assert!(own.is_empty());
        own.insert(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 67, 1, 0)), 24).expect("a prefix"),
            A,
        );
        assert!(!own.is_empty());
        assert_eq!(
            own.owner_of(IpAddr::V4(Ipv4Addr::new(10, 67, 1, 55))),
            Some(A)
        );
        assert_eq!(own.owner_of(IpAddr::V4(Ipv4Addr::new(10, 67, 2, 55))), None);
    }

    #[test]
    fn forgets_every_mapping_one_peer_holds_and_no_other() {
        let mut nat = napt();
        let now = Instant::now();
        let mut mine = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut mine, now).expect("uplink");
        let mine_port = read_ports(&mine, 20).expect("ports").0;
        let mut theirs = testpkt::udp(B4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(B, &mut theirs, now).expect("uplink");
        let theirs_port = read_ports(&theirs, 20).expect("ports").0;

        nat.flush_peer(A);
        assert_eq!(nat.mapping_count(), 1);
        let mut to_mine = testpkt::udp(REMOTE4, 53, ext4(), mine_port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut to_mine, now),
            Err(NatDrop::NoMapping)
        );
        let mut to_theirs = testpkt::udp(REMOTE4, 53, ext4(), theirs_port, b"a");
        assert_eq!(
            nat.translate_downlink(&mut to_theirs, now)
                .expect("the other peer keeps its flows")
                .peer,
            B
        );
    }

    #[test]
    fn removing_a_static_forward_returns_its_port_to_the_pool() {
        let mut nat = napt();
        let now = Instant::now();
        nat.add_static(
            StaticDnat {
                proto: MapProto::Udp,
                external_port: 51_820,
                target: SocketAddr::new(A4, 8080),
            },
            now,
        )
        .expect("pin");
        assert!(nat.remove_static(MapProto::Udp, 51_820, false));
        assert!(
            !nat.remove_static(MapProto::Udp, 51_820, false),
            "nothing holds that port any more"
        );
        assert_eq!(nat.mapping_count(), 0);
        let mut inbound = testpkt::udp(OTHER4, 40_000, ext4(), 51_820, b"hello");
        assert_eq!(
            nat.translate_downlink(&mut inbound, now),
            Err(NatDrop::NoMapping)
        );
        let mut up = testpkt::udp(A4, 51_820, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        assert_eq!(
            read_ports(&up, 20).expect("ports").0,
            51_820,
            "the port is allocatable again"
        );
    }

    #[test]
    fn reports_the_epoch_its_addresses_belong_to() {
        let mut nat = napt();
        assert_eq!(nat.epoch(), Some(epoch(1, 1)));
        nat.set_external(epoch(2, 5), EXT4, None);
        assert_eq!(nat.epoch(), Some(epoch(2, 5)));
    }

    #[test]
    fn an_exit_with_no_identity_is_not_a_configured_one() {
        assert_eq!(ExitId::UNKNOWN.as_bytes(), &[0u8; EXIT_ID_LEN]);
        assert_ne!(ExitId::from_bytes([1; EXIT_ID_LEN]), ExitId::UNKNOWN);
        assert_eq!(format!("{:?}", ExitId::UNKNOWN), "ExitId(unknown)");
        assert_eq!(
            format!("{:?}", ExitId::from_bytes([1; EXIT_ID_LEN])),
            "ExitId(set)"
        );
    }

    #[test]
    fn seeds_its_port_draw_from_the_system_when_given_no_generator() {
        let mut nat = Napt::new(NatConfig::default());
        nat.set_ownership(ownership());
        nat.set_external(epoch(1, 1), EXT4, None);
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, Instant::now())
            .expect("uplink");
        assert_eq!(nat.mapping_count(), 1);
    }

    #[test]
    fn renders_no_address_of_a_peer_or_of_the_tunnel() {
        let mut nat = napt();
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let port = read_ports(&up, 20).expect("ports").0;
        let mut down = testpkt::udp(REMOTE4, 53, ext4(), port, b"a");
        let out = nat.translate_downlink(&mut down, now).expect("answer");

        for rendered in [format!("{nat:?}"), format!("{out:?}")] {
            for forbidden in ["10.67", "10.66", "1.1.1.1"] {
                assert!(
                    !rendered.contains(forbidden),
                    "an address reached a Debug rendering: {rendered}"
                );
            }
        }
    }

    #[test]
    fn releases_the_external_port_of_a_flow_it_forgets() {
        let mut nat = napt_with(small_pool(1, 16));
        let now = Instant::now();
        let mut up = testpkt::udp(A4, 5000, REMOTE4, 53, b"q");
        nat.translate_uplink(A, &mut up, now).expect("uplink");
        let mut second = testpkt::udp(A4, 5001, REMOTE4, 53, b"q");
        assert_eq!(
            nat.translate_uplink(A, &mut second, now),
            Err(NatDrop::PortExhausted)
        );
        assert_eq!(nat.sweep(now + Duration::from_secs(31)), 1);
        nat.translate_uplink(A, &mut second, now + Duration::from_secs(31))
            .expect("the port came back into the pool");
    }
}
