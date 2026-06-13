//! Pure Warren wire codecs.
//!
//! Implemented: the tunnel handshake frames ([`handshake::Setup`] /
//! [`handshake::SetupAck`], postcard, wire-compatible with warren-core).
//!
//! Landing with their consuming phases: the NAT-PMP codec (RFC 6886 plus the
//! Warren rate-limit trailer) with port forwarding (P7), and the multihop HPKE
//! frame (X25519 + HKDF-SHA256 + ChaCha20Poly1305, frame v1) with the transport
//! multihop path. All codecs are pinned by golden vectors under `vectors/`.

pub mod handshake;

pub use handshake::{
    DEVICE_ID_LEN, DaitaConfig, MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, ProtocolError, Setup,
    SetupAck, decode_setup, decode_setup_ack, encode_setup, encode_setup_ack, features,
};
