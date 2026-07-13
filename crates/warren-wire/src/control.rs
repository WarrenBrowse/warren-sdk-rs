//! Multihop control messages (the sealed inner setup protocol carried as the
//! plaintext inside a multihop frame), now sourced from the engine's
//! `warrenguard-multihop` so a single codec is shared with warren-core.
//! Re-exported to keep the `warren_wire::control::` paths stable; byte-
//! compatibility is pinned by the shared golden vectors and the engine tests.

pub use warrenguard_multihop::{
    CONTROL_FIRST_BYTE, CONTROL_VERSION_V3, ControlError, PopSignature, WarrenControlMessage,
    encode_control, try_decode_control,
};
