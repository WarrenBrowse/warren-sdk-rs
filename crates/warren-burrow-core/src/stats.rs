//! Drop accounting.
//!
//! A NAT bug looks like "some sites do not load", so every refusal is counted
//! by class and the classes are what `/status` renders. Nothing here holds an
//! address, a port or a peer: the counters answer "what is being refused", and
//! answering "to whom" would build the log a privacy gateway must not keep.

use crate::nat::NatDrop;
use crate::peer::DropReason;

/// The counters as one reading, carrying no address.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Snapshot {
    /// Packets translated from a peer onto the tunnel.
    pub uplink_translated: u64,
    /// Packets translated from the tunnel back to a peer.
    pub downlink_translated: u64,
    /// Uplink packets refused, all classes.
    pub uplink_dropped: u64,
    /// Downlink packets refused, all classes.
    pub downlink_dropped: u64,
    /// A peer sent a source address it does not own.
    pub source_not_owned: u64,
    /// No mapping matched, or the answer came from a remote the peer never
    /// addressed.
    pub no_mapping: u64,
    /// The external port space for that protocol and family is full.
    pub port_exhausted: u64,
    /// The sending peer is at its own mapping cap.
    pub peer_cap: u64,
    /// A fragment, which this NAT does not reassemble.
    pub fragment: u64,
    /// An IPv6 packet carrying an extension header.
    pub v6_extension_header: u64,
    /// A protocol this gateway does not translate.
    pub unsupported_protocol: u64,
    /// A packet whose headers do not parse.
    pub malformed: u64,
    /// The epoch has no external address of that family.
    pub family_unavailable: u64,
}

/// The mutable counters the NAT bumps.
#[derive(Debug, Default, Clone)]
pub struct Counters {
    totals: Snapshot,
}

impl Counters {
    /// Counts one packet translated onto the tunnel.
    pub fn uplink_translated(&mut self) {
        self.totals.uplink_translated += 1;
    }

    /// Counts one packet translated back to a peer.
    pub fn downlink_translated(&mut self) {
        self.totals.downlink_translated += 1;
    }

    /// Counts one uplink refusal, by class.
    pub fn uplink_dropped(&mut self, class: NatDrop) {
        self.totals.uplink_dropped += 1;
        self.by_class(class);
    }

    /// Counts one downlink refusal, by class.
    pub fn downlink_dropped(&mut self, class: NatDrop) {
        self.totals.downlink_dropped += 1;
        self.by_class(class);
    }

    fn by_class(&mut self, class: NatDrop) {
        let counter = match class {
            NatDrop::SourceNotOwned => &mut self.totals.source_not_owned,
            NatDrop::NoMapping => &mut self.totals.no_mapping,
            NatDrop::PortExhausted => &mut self.totals.port_exhausted,
            NatDrop::PeerCap => &mut self.totals.peer_cap,
            NatDrop::Fragment => &mut self.totals.fragment,
            NatDrop::ExtensionHeader => &mut self.totals.v6_extension_header,
            NatDrop::UnsupportedProtocol => &mut self.totals.unsupported_protocol,
            NatDrop::Malformed => &mut self.totals.malformed,
            NatDrop::FamilyUnavailable => &mut self.totals.family_unavailable,
        };
        *counter += 1;
    }

    /// The counters as one reading.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.totals
    }
}

/// The responder's counters as one reading, carrying no address.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResponderSnapshot {
    /// Datagrams handed to the responder.
    pub datagrams: u64,
    /// Handshakes completed with a peer.
    pub handshakes: u64,
    /// Decrypted packets released toward the tunnel.
    pub uplink: u64,
    /// Datagrams sent straight back to the source.
    pub replies: u64,
    /// Cookie replies, which are the one thing a closed gate still answers.
    pub cookies: u64,
    /// Packets routed from one peer to another.
    pub loopback: u64,
    /// Datagrams and packets refused, all classes.
    pub dropped: u64,
    /// Handshake initiations refused before any Diffie-Hellman because the
    /// tunnel was not carrying traffic.
    pub handshake_refused_gate_closed: u64,
    /// Decrypted packets dropped because the tunnel was not carrying traffic.
    pub dropped_gate_closed: u64,
    /// Initiations refused because their source had spent its budget.
    pub source_rate_limited: u64,
    /// Initiations whose static public key belongs to no peer.
    pub unknown_peer: u64,
    /// Datagrams naming a session index no peer holds.
    pub unknown_index: u64,
    /// Datagrams that did not authenticate.
    pub auth_failed: u64,
    /// Initiations whose timestamp was not newer than the peer's last.
    pub replayed: u64,
    /// Decrypted packets whose source the sending peer does not own.
    pub spoofed_source: u64,
    /// Datagrams larger than a socket can deliver.
    pub oversize: u64,
    /// Datagrams that are not WireGuard, or whose mac1 did not verify.
    pub malformed: u64,
    /// Packets to a multicast, broadcast, link-local or loopback address.
    pub non_unicast: u64,
    /// Packets to the gateway's own address that are not an echo request.
    pub self_destination: u64,
    /// Packets to another peer while peer isolation is on.
    pub peer_isolation: u64,
    /// Packets to a peer-subnet address no peer owns.
    pub unowned_peer_address: u64,
    /// Packets into the tunnel pool other than to the exit resolver.
    pub pool_destination: u64,
    /// Packets to a private range a masqueraded exit cannot reach.
    pub private_destination: u64,
    /// IPv6 packets while the epoch has no IPv6 assignment.
    pub v6_unavailable: u64,
    /// IPv6 packets while the path budget is under the IPv6 minimum.
    pub v6_budget: u64,
    /// Packets from the tunnel that no peer owns.
    pub no_route: u64,
    /// Downlink packets boringtun queued for want of a session.
    pub downlink_queued: u64,
    /// Handshake initiations discarded because the peer has no known endpoint.
    pub downlink_initiation_dropped_no_endpoint: u64,
    /// ICMP answers the gateway did not generate because it had spent its own
    /// budget. The refusal itself is still counted under its class; this says
    /// the peer was refused without being told.
    pub answers_suppressed: u64,
    /// Peers rebuilt because the wall clock jumped under a monotonic clock
    /// that does not count suspend.
    pub clock_jump_resets: u64,
}

/// The mutable counters the responder bumps.
#[derive(Debug, Default, Clone)]
pub struct ResponderCounters {
    totals: ResponderSnapshot,
}

impl ResponderCounters {
    /// Counts one datagram handed in.
    pub fn datagram(&mut self) {
        self.totals.datagrams += 1;
    }

    /// Counts one completed handshake.
    pub fn handshake(&mut self) {
        self.totals.handshakes += 1;
    }

    /// Counts one decrypted packet released toward the tunnel.
    pub fn uplink(&mut self) {
        self.totals.uplink += 1;
    }

    /// Counts one datagram sent straight back to its source.
    pub fn reply(&mut self, cookie: bool) {
        self.totals.replies += 1;
        if cookie {
            self.totals.cookies += 1;
        }
    }

    /// Counts one packet routed from one peer to another.
    pub fn loopback(&mut self) {
        self.totals.loopback += 1;
    }

    /// Counts one downlink packet boringtun queued for want of a session.
    pub fn downlink_queued(&mut self) {
        self.totals.downlink_queued += 1;
    }

    /// Counts one initiation discarded for want of an endpoint.
    pub fn initiation_without_endpoint(&mut self) {
        self.totals.downlink_initiation_dropped_no_endpoint += 1;
    }

    /// Counts one ICMP answer the gateway refused itself.
    pub fn answer_suppressed(&mut self) {
        self.totals.answers_suppressed += 1;
    }

    /// Counts one peer rebuilt after a wall-clock jump.
    pub fn clock_jump_reset(&mut self) {
        self.totals.clock_jump_resets += 1;
    }

    /// Counts one refusal, by class.
    pub fn dropped(&mut self, reason: DropReason) {
        self.totals.dropped += 1;
        let counter = match reason {
            DropReason::Oversize => &mut self.totals.oversize,
            DropReason::Malformed => &mut self.totals.malformed,
            DropReason::GateClosed => &mut self.totals.dropped_gate_closed,
            DropReason::SourceRateLimited => &mut self.totals.source_rate_limited,
            DropReason::UnknownPeer => &mut self.totals.unknown_peer,
            DropReason::UnknownIndex => &mut self.totals.unknown_index,
            DropReason::Auth => &mut self.totals.auth_failed,
            DropReason::Replay => &mut self.totals.replayed,
            DropReason::SpoofedSource => &mut self.totals.spoofed_source,
            DropReason::NonUnicast => &mut self.totals.non_unicast,
            DropReason::SelfDestination => &mut self.totals.self_destination,
            DropReason::PeerIsolation => &mut self.totals.peer_isolation,
            DropReason::UnownedPeerAddress => &mut self.totals.unowned_peer_address,
            DropReason::PoolDestination => &mut self.totals.pool_destination,
            DropReason::PrivateDestination => &mut self.totals.private_destination,
            DropReason::V6Unavailable => &mut self.totals.v6_unavailable,
            DropReason::V6Budget => &mut self.totals.v6_budget,
            DropReason::NoRoute => &mut self.totals.no_route,
        };
        *counter += 1;
    }

    /// Counts one initiation refused before any Diffie-Hellman because the
    /// tunnel was not carrying traffic.
    pub fn handshake_refused_gate_closed(&mut self) {
        self.totals.handshake_refused_gate_closed += 1;
        self.dropped(DropReason::GateClosed);
    }

    /// The counters as one reading.
    #[must_use]
    pub fn snapshot(&self) -> ResponderSnapshot {
        self.totals
    }
}
