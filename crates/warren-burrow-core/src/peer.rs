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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_index_the_responder_assigned() {
        assert_eq!(PeerId::new(7).index(), 7);
        assert_ne!(PeerId::new(7), PeerId::new(8));
    }
}
