//! Warren exit discovery and selection (Phase P4, not yet implemented).
//!
//! Planned surface, ported from warren-core `warren-relay-selector`:
//! - Verify the `SignedRelayList` (v5): canonical JSON, Ed25519 signature
//!   against the pinned server pubkey, `generation` anti-rollback and
//!   `expires_at` anti-freeze checks.
//! - `RelaySelector` with weighted random selection over active exits, filtered
//!   by `LocationConstraint` (country/city), `IpAvailability`, and a
//!   deterministic per-attempt failover seed.
//!
//! The list itself is fetched by [`warren_api`]; this crate is pure verification
//! plus selection so it ports cleanly to every sibling-language SDK.

#[cfg(test)]
mod roadmap {
    #[test]
    #[ignore = "P4: implement SignedRelayList verify + weighted selector with vectors"]
    fn placeholder() {}
}
