//! Peer identity.

/// A peer of the gateway, as the responder numbered it.
///
/// The NAT keys ownership and per-peer accounting on this rather than on an
/// address, so a peer that owns several prefixes still faces one cap, and a
/// mapping always names the peer its packets go back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(u32);

impl PeerId {
    /// Wraps the index the responder assigned.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The index this peer was assigned.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Why a label was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LabelError {
    /// The label is empty.
    #[error("peer label is empty")]
    Empty,
    /// The label is longer than 32 bytes.
    #[error("peer label longer than 32 characters")]
    TooLong,
    /// The label carries something other than an ASCII letter, digit, dash,
    /// underscore or dot.
    #[error("peer label carries a character that is not allowed")]
    BadCharacter,
}

/// The operator's name for a peer.
///
/// Keys are never printed, so this is the only handle a log line, a health
/// route or a CLI subcommand has on a device. The character set is narrow on
/// purpose: a label ends up in a file name, in a config section comment and in
/// a URL path, and none of those may need quoting or escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerLabel(String);

impl PeerLabel {
    /// The placeholder a parser uses while it does not yet know a peer's
    /// position in the file, which is what numbers an unlabelled peer.
    pub(crate) const EMPTY: Self = Self(String::new());

    /// Validates an operator-supplied label.
    ///
    /// # Errors
    ///
    /// [`LabelError::Empty`], [`LabelError::TooLong`] past 32 bytes, or
    /// [`LabelError::BadCharacter`].
    pub fn new(value: &str) -> Result<Self, LabelError> {
        if value.is_empty() {
            return Err(LabelError::Empty);
        }
        if value.len() > 32 {
            return Err(LabelError::TooLong);
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(LabelError::BadCharacter);
        }
        Ok(Self(value.to_owned()))
    }

    /// The label itself.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeerLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why the gateway refused a datagram or a decrypted packet.
///
/// Every variant names a rule, never a value: an operator reads these on the
/// health route and in counters, and none of them may carry an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DropReason {
    /// Larger than any datagram a socket can deliver.
    Oversize,
    /// Not a WireGuard datagram, or its mac1 did not verify.
    Malformed,
    /// The tunnel is not carrying traffic, so nothing may leave the gateway.
    GateClosed,
    /// The source address has spent its handshake budget.
    SourceRateLimited,
    /// No configured peer holds that static public key.
    UnknownPeer,
    /// No live session carries that receiver index.
    UnknownIndex,
    /// The datagram did not authenticate.
    Auth,
    /// The handshake timestamp is not newer than the last one this peer used.
    Replay,
    /// The decrypted packet's source is not an address the peer owns.
    SpoofedSource,
    /// Multicast, broadcast, loopback, link-local or unspecified.
    NonUnicast,
    /// Addressed to the gateway itself and not an echo request.
    SelfDestination,
    /// Addressed to another peer while peer isolation is on.
    PeerIsolation,
    /// Addressed inside the peer subnet, to an address no peer owns.
    UnownedPeerAddress,
    /// Addressed inside the tunnel pool, which only the exit resolver answers.
    PoolDestination,
    /// Addressed to a private range a masqueraded exit can never reach.
    PrivateDestination,
    /// IPv6 while the epoch has no IPv6 assignment.
    V6Unavailable,
    /// IPv6 while the path budget is under the IPv6 minimum MTU.
    V6Budget,
    /// No peer owns the destination of a packet from the tunnel.
    NoRoute,
}

/// What one peer has carried.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerStats {
    /// Bytes decrypted from this peer.
    pub rx_bytes: u64,
    /// Bytes encrypted to this peer.
    pub tx_bytes: u64,
    /// Handshakes completed with this peer.
    pub handshakes: u64,
    /// Datagrams and packets refused for this peer.
    pub drops: u64,
}

/// One peer as a health route renders it.
///
/// Carries no key material and no endpoint address: `endpoint_seen` says only
/// whether the gateway has ever heard from the peer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PeerStatus {
    /// The operator's name for the device.
    pub label: PeerLabel,
    /// A session is live, so the peer can be reached right now.
    pub has_session: bool,
    /// Seconds since the current session was established.
    pub last_handshake_secs: Option<u64>,
    /// The gateway has heard an authenticated datagram from this peer.
    pub endpoint_seen: bool,
    /// What the peer has carried.
    pub stats: PeerStats,
    /// Packets waiting for a session, which boringtun drops past 256.
    pub queued: usize,
    /// The prefixes this peer is allowed to source from and is routed.
    pub allowed_ips: Vec<ip_network::IpNetwork>,
    /// Why the last refusal happened, which is what explains a peer that
    /// never comes back.
    pub last_drop: Option<DropReason>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_index_the_responder_assigned() {
        assert_eq!(PeerId::new(7).index(), 7);
        assert_ne!(PeerId::new(7), PeerId::new(8));
    }

    #[test]
    fn accepts_the_names_an_operator_writes_in_a_config() {
        for name in ["peer1", "livingroom-tv", "nas_02", "a"] {
            assert_eq!(PeerLabel::new(name).expect(name).as_str(), name);
        }
    }

    #[test]
    fn refuses_a_label_that_cannot_be_read_back_out_of_a_log_line() {
        assert_eq!(PeerLabel::new("").unwrap_err(), LabelError::Empty);
        assert_eq!(
            PeerLabel::new(&"x".repeat(33)).unwrap_err(),
            LabelError::TooLong
        );
        for name in ["has space", "quote\"", "new\nline", "=equals", "café"] {
            assert_eq!(
                PeerLabel::new(name).unwrap_err(),
                LabelError::BadCharacter,
                "{name}"
            );
        }
    }
}
