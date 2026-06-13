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
//! Wire-compatible with warren-core (`SignedRelayList` v5).

pub mod exit_id;
pub mod query;
pub mod relay;
pub mod selector;
pub mod signed;

pub use exit_id::{EXIT_ID_LEN, ExitId, ExitIdError};
pub use query::{ExitQuery, IpAvailability, LocationConstraint};
pub use relay::{Location, Relay, RelayList};
pub use selector::{ExitSelector, SelectorError};
pub use signed::{
    JsonRelay, SIGNED_VERSION, SignedError, SignedRelayList, VerifiedRelayList, sign_relay_list,
    verify_signed_relay_list, verify_signed_relay_list_any,
};
