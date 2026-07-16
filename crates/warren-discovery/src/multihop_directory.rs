//! Multi-hop directory verification, delegated to the neutral
//! `warren-discovery-core` crate (the single cryptographic verifier, shared with
//! the backend). This module keeps the SDK-facing `VerifiedDirectory` wrapper
//! (the freshness metadata the caller enforces) over the neutral verifier's flat
//! exit view, so the SDK's public API is unchanged.

pub use warren_discovery_core::{CircuitPolicy, DirectoryError, VerifiedEntry, VerifiedExit};

/// Verified directory: trusted exits plus the freshness metadata the caller
/// enforces (`generation` anti-rollback, `expires_at`).
#[derive(Debug, Clone)]
pub struct VerifiedDirectory {
    /// The trusted exits (flat client dial view).
    pub exits: Vec<VerifiedExit>,
    /// The same trusted nodes projected as entry hops; pair one with an exit
    /// via [`VerifiedExit::via_entry`] under [`Self::policy`] for an
    /// entry-selected circuit.
    pub entries: Vec<VerifiedEntry>,
    /// The fleet-wide circuit diversity policy (country + AS + distinct node),
    /// gating every entry-selected circuit so an SDK client cannot build a
    /// topology the app's security rule forbids.
    pub policy: CircuitPolicy,
    /// Monotonic generation; the caller pins a rollback floor.
    pub generation: u64,
    /// Unix seconds the directory was signed.
    pub signed_at: u64,
    /// Unix seconds the directory expires; the caller refuses a stale one.
    pub expires_at: u64,
    /// Nodes dropped during verification (unvouched or anti-downgrade).
    pub dropped: usize,
}

impl VerifiedDirectory {
    /// True once `now_unix_secs` reaches `expires_at`.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }
}

/// Verifies the multi-hop directory and returns the trusted exits plus freshness.
///
/// Delegates the full cryptographic verification (server envelope, operational
/// cert, per-node relay + exit descriptors, geo attestation, and the
/// anti-downgrade DNS-attestation policy) to the neutral crate; the exit set is
/// the neutral verifier's flat projection.
///
/// # Errors
///
/// [`DirectoryError`] on any verification failure.
pub fn verify_multihop_directory(
    json: &str,
    expected_server_pubkeys: &[&str],
    expected_root_pubkeys: &[&str],
) -> Result<VerifiedDirectory, DirectoryError> {
    let v = warren_discovery_core::verify_multihop_directory_any(
        json,
        expected_server_pubkeys,
        expected_root_pubkeys,
    )?;
    Ok(VerifiedDirectory {
        exits: v.exits(),
        entries: v.entries(),
        policy: CircuitPolicy::for_directory(&v),
        generation: v.generation,
        signed_at: v.signed_at,
        expires_at: v.expires_at,
        dropped: v.dropped,
    })
}

/// Directory-minting fixtures, re-exported from the neutral crate for other
/// crates' tests (the SDK facade). Gated behind `test-helpers`.
#[cfg(feature = "test-helpers")]
pub mod test_helpers {
    pub use warren_discovery_core::test_helpers::mint_directory_json;
}
