//! Tunnel handshake frames (`Setup` / `SetupAck`), now sourced from the engine's
//! `warrenguard-wire` so a single postcard codec is shared with warren-core.
//!
//! Re-exported here to keep the `warren_wire::handshake::` (and `warren_wire::`)
//! paths stable for the SDK's consumers. Byte-compatibility is pinned by the
//! shared `vectors/handshake.json` golden vectors and the engine crate's own
//! round-trip tests; this module no longer carries a second implementation.

pub use warrenguard_wire::{
    DEVICE_ID_LEN, DaitaConfig, MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, ProtocolError, Setup,
    SetupAck, decode_setup, decode_setup_ack, encode_setup, encode_setup_ack, features,
};
