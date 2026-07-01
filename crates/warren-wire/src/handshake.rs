//! Tunnel handshake frames (`Setup` / `SetupAck`): thin re-exports of the
//! engine's `warrenguard-wire` types, so the postcard wire format is defined
//! once and shared with warren-core. The re-export keeps the
//! `warren_wire::handshake::` (and `warren_wire::`) paths stable for SDK
//! consumers; byte-compatibility is pinned by the shared
//! `vectors/handshake.json` golden vectors and the engine crate's round-trip
//! tests.

pub use warrenguard_wire::{
    AUTH_SIG_LEN, AuthSig, CLIENT_PUBKEY_LEN, DEVICE_ID_LEN, DaitaConfig, MAX_SETUP_FRAME_BYTES,
    PROTOCOL_VERSION, ProtocolError, Setup, SetupAck, decode_setup, decode_setup_ack, encode_setup,
    encode_setup_ack, features,
};
