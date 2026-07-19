//! Pure Warren wire codecs.
//!
//! Implemented:
//! - the shared handshake primitives ([`handshake`]: identity, DAITA config and
//!   protocol version, wire-compatible with warren-core);
//! - the NAT-PMP codec ([`natpmp`], RFC 6886 plus the Warren rate-limit trailer);
//! - the multihop dispatch frame wire codec ([`multihop::WarrenMultihopFrame`]):
//!   the first frame every connection sends. HPKE sealing/opening and the exit
//!   X25519 descriptor PKI live in the multihop session layer;
//! - the multihop control messages ([`control::WarrenControlMessage`]): the
//!   sealed inner setup protocol (`IpRequest`/`IpAssign`/`Rejected`) carried as
//!   the plaintext inside a frame.

pub mod control;
pub mod handshake;
pub mod multihop;
pub mod natpmp;

pub use control::{
    CONTROL_FIRST_BYTE, CONTROL_VERSION_V3, ControlError, PopSignature, WarrenControlMessage,
    encode_control, try_decode_control,
};
pub use handshake::{
    CLIENT_PUBKEY_LEN, DEVICE_ID_LEN, DaitaConfig, MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION,
    ProtocolError, features,
};
pub use multihop::{
    MULTIHOP_FRAME_MAX_OVERHEAD, MultihopError, WARREN_HPKE_AAD_V1, WARREN_HPKE_VERSION_V1,
    WARREN_PKI_OPERATIONAL_EXIT_V1, WarrenMultihopFrame,
};
