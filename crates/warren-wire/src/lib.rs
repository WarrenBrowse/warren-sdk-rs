//! Pure Warren wire codecs.
//!
//! Implemented:
//! - the tunnel handshake frames ([`handshake::Setup`] / [`handshake::SetupAck`],
//!   postcard, wire-compatible with warren-core);
//! - the NAT-PMP codec ([`natpmp`], RFC 6886 plus the Warren rate-limit trailer).
//!
//! Landing with the transport multihop path: the multihop HPKE frame (X25519 +
//! HKDF-SHA256 + ChaCha20Poly1305, frame v1).

pub mod handshake;
pub mod natpmp;

pub use handshake::{
    DEVICE_ID_LEN, DaitaConfig, MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, ProtocolError, Setup,
    SetupAck, decode_setup, decode_setup_ack, encode_setup, encode_setup_ack, features,
};
