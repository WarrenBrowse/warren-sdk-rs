//! Drop accounting.
//!
//! A NAT bug looks like "some sites do not load", so every refusal is counted
//! by class and the classes are what `/status` renders. Nothing here holds an
//! address, a port or a peer: the counters answer "what is being refused", and
//! answering "to whom" would build the log a privacy gateway must not keep.

use crate::nat::NatDrop;

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
