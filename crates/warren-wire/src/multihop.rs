//! Multihop dispatch frame wire codec (the first frame every connection sends),
//! now sourced from the engine's `warrenguard-multihop` so a single codec is
//! shared with warren-core. HPKE sealing/opening and the exit X25519 descriptor
//! PKI live in the multihop session layer (`warren-multihop`).
//!
//! Re-exported here to keep the `warren_wire::multihop::` paths stable; byte-
//! compatibility is pinned by the shared `vectors/multihop_frame.json` and the
//! engine crate's own tests. Frame-codec failures surface as the engine's
//! [`MultihopError`] (`Decode` / `TrailingBytes` / `UnsupportedVersion`).

pub use warrenguard_multihop::{
    MULTIHOP_FRAME_MAX_OVERHEAD, MultihopError, WARREN_HPKE_AAD_V1, WARREN_HPKE_VERSION_V1,
    WARREN_PKI_OPERATIONAL_EXIT_V1, WarrenMultihopFrame,
};
pub use warrenguard_wire::{EXIT_ID_LEN, ExitId};
