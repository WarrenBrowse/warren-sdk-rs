//! Shared handshake primitives (identity, DAITA config, protocol version): thin
//! re-exports of the engine's `warrenguard-wire` types, so the wire constants and
//! codecs are defined once and shared with warren-core. The re-export keeps the
//! `warren_wire::handshake::` (and `warren_wire::`) paths stable for SDK
//! consumers; byte-compatibility is pinned by the shared golden vectors and the
//! engine crate's round-trip tests.

pub use warrenguard_wire::{
    CLIENT_PUBKEY_LEN, DEVICE_ID_LEN, DaitaConfig, MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION,
    ProtocolError, features,
};
