//! Warren exit discovery: verify the signed relay list and select an exit.
//!
//! Two pure, portable concerns (the HTTP fetch lives in `warren-api`):
//! - [`verify_signed_relay_list`]: check the Ed25519 signature of the exit list
//!   against a pinned (or TOFU) server pubkey, with anti-rollback
//!   (`generation`) and anti-freeze (`expires_at`) metadata surfaced to the
//!   caller via [`VerifiedRelayList`].
//! - [`ExitSelector`]: weighted random selection over the resolved relays,
//!   filtered by geography ([`LocationConstraint`]) and IP availability
//!   ([`IpAvailability`]).
//!
//! Wire-compatible with warren-core (`SignedRelayList` v7).

pub mod exit_id;
pub mod multihop_directory;
pub mod query;
pub mod relay;
pub mod selector;
pub mod signed;

pub use exit_id::{EXIT_ID_LEN, ExitId, ExitIdError};
pub use multihop_directory::{
    DirectoryError, VerifiedDirectory, VerifiedEntry, VerifiedExit, verify_multihop_directory,
};
pub use query::{ExitQuery, IpAvailability, LocationConstraint};
pub use relay::{Location, Relay, RelayList};
pub use selector::{ExitSelector, SelectorError};
/// Test-only signed-list minting (off in production; see [`signed::sign_relay_list`]).
#[cfg(any(test, feature = "test-helpers"))]
pub use signed::sign_relay_list;
pub use signed::{
    JsonEgress, JsonEndpoint, JsonListener, JsonLocation, JsonNode, SIGNED_VERSION, SignedError,
    SignedRelayList, VerifiedRelayList, verify_signed_relay_list, verify_signed_relay_list_any,
};
/// Wire identity types (ExitId, WarrenPubkey) for building test fixtures.
pub use warren_discovery_core::warren_types;
