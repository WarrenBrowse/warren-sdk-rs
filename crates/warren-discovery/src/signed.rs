//! Signed relay-list verification, delegated to the neutral
//! `warren-discovery-core` crate (the single verifier, shared with the backend).
//! Keeps the SDK-facing flat `RelayList` / `VerifiedRelayList` (projected from
//! the neutral's rich `WarrenRelay` model) so the SDK's public API is unchanged.

use warren_discovery_core::WarrenRelay;

pub use warren_discovery_core::{
    JsonEgress, JsonEndpoint, JsonListener, JsonLocation, JsonNode, SIGNED_VERSION, SignedError,
    SignedRelayList, sign_relay_list,
};

use crate::relay::{Location, Relay, RelayList};

/// Verified relay list: the SDK's flat `Relay` model plus the freshness metadata
/// the caller enforces (`generation` anti-rollback, `expires_at`).
#[derive(Debug, Clone)]
pub struct VerifiedRelayList {
    /// Resolved relays (flat client model).
    pub relays: RelayList,
    /// Monotonic content version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the list was signed.
    pub signed_at: u64,
    /// Unix epoch seconds the list expires.
    pub expires_at: u64,
    /// Hex of the server key that signed this list (for TOFU pinning).
    pub server_pubkey_hex: String,
}

impl VerifiedRelayList {
    /// True once `now_unix_secs` reaches `expires_at`.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }
}

/// Projects the neutral verifier's rich `WarrenRelay` to the SDK's flat `Relay`.
/// The client dials the single derived endpoint; the rich entry/relay/exit
/// listener structure is not needed by the userland datapath.
fn relay_from_warren(wr: &WarrenRelay) -> Relay {
    let addrs = wr.endpoint_addr().ip_addrs().collect();
    let location = Location::new(wr.location().country_code(), wr.location().city());
    Relay::new(
        *wr.endpoint_id().as_bytes(),
        crate::exit_id::ExitId::from_bytes(*wr.exit_id().as_bytes()),
        addrs,
        location,
        wr.weight(),
        wr.is_active(),
    )
    .with_ipv6_egress(wr.egress_v6())
    .with_cover_domain(wr.endpoint_addr().cover_domain.clone())
}

fn project(v: warren_discovery_core::VerifiedRelayList) -> VerifiedRelayList {
    VerifiedRelayList {
        relays: RelayList::new(v.relays.relays().iter().map(relay_from_warren).collect()),
        generation: v.generation,
        signed_at: v.signed_at,
        expires_at: v.expires_at,
        server_pubkey_hex: v.server_pubkey_hex,
    }
}

/// Verifies a signed relay list against a single pinned server key (None = TOFU).
///
/// # Errors
///
/// [`SignedError`] on any verification failure.
pub fn verify_signed_relay_list(
    s: &str,
    expected_server_pubkey: Option<&str>,
) -> Result<VerifiedRelayList, SignedError> {
    warren_discovery_core::verify_signed_relay_list(s, expected_server_pubkey).map(project)
}

/// Multi-key variant for pinned-key rotation (empty slice = TOFU).
///
/// # Errors
///
/// See [`SignedError`].
pub fn verify_signed_relay_list_any(
    s: &str,
    expected_server_pubkeys: &[&str],
) -> Result<VerifiedRelayList, SignedError> {
    warren_discovery_core::verify_signed_relay_list_any(s, expected_server_pubkeys).map(project)
}
