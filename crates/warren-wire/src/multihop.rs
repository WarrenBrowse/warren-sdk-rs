//! Multihop dispatch frame (`WarrenMultihopFrame`, C1: client -> relay/exit).
//!
//! This is the FIRST frame the client sends on every connection: the exit reads
//! it (cleartext `exit_id` for routing, HPKE-sealed `ciphertext` for the inner
//! `Setup`/control) before anything else. A raw [`Setup`](crate::Setup) is
//! rejected by real exits with `malformed setup frame`. Byte-compatible with
//! warren-core `warren-multihop::wire_format` (postcard; `exit_id` is the raw
//! 16-byte form, matching warren-protocol `ExitId` in non-human-readable serde).
//!
//! This module is the pure wire codec only. HPKE sealing/opening (X25519 /
//! HKDF-SHA256 / ChaCha20Poly1305) and the operational-exit X25519 descriptor
//! PKI live in the multihop session layer (separate, follows).

use serde::{Deserialize, Serialize};

/// `/v1` HPKE wire version byte.
pub const WARREN_HPKE_VERSION_V1: u8 = 0x01;
/// AEAD additional-authenticated-data domain prefix:
/// `WARREN_HPKE_AAD_V1 || exit_id(16) || epoch_u32_be || seq_u64_be`.
pub const WARREN_HPKE_AAD_V1: &[u8] = b"warren/multihop/v1/aad";
/// PKI context binding an operational key's signature over an exit's X25519 key:
/// `WARREN_PKI_OPERATIONAL_EXIT_V1 || exit_id(16) || exit_x25519_pubkey(32)`.
pub const WARREN_PKI_OPERATIONAL_EXIT_V1: &[u8] = b"warren/multihop/v1/operational-signs-exit";

/// Largest accepted encoded frame (matches warren-core).
const MAX_FRAME_BYTES: usize = 65536;
/// Exit identifier length.
pub const EXIT_ID_LEN: usize = 16;

/// Worst-case bytes a sealed frame adds on top of its inner plaintext (the
/// detached AEAD keeps ciphertext == plaintext length). Breakdown, postcard
/// worst case: version(1) + exit_id(16) + epoch varint(5, `u32::MAX`) + seq
/// varint(10, `u64::MAX`) + encapsulated_key(32) + aead_tag(16) + ciphertext
/// length varint(3, up to `MAX_FRAME_BYTES`) = 83. Datapaths subtract this
/// from the path datagram size to size the inner MTU. Pinned by
/// `frame_overhead_never_exceeds_the_bound`.
pub const MULTIHOP_FRAME_MAX_OVERHEAD: usize = 83;

/// The C1 wire frame carried client -> relay -> exit. `exit_id` is cleartext for
/// routing; the payload is HPKE-sealed (`encapsulated_key` + `aead_tag` +
/// `ciphertext`), bound to `(exit_id, epoch, seq)` via the AEAD AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrenMultihopFrame {
    /// Wire version; MUST equal [`WARREN_HPKE_VERSION_V1`].
    pub version: u8,
    /// 16-byte exit identifier (bound into the HPKE AAD).
    pub exit_id: [u8; EXIT_ID_LEN],
    /// Rekey epoch counter (AAD + replay window).
    pub epoch: u32,
    /// Per-session monotonic sequence number (AAD + replay window).
    pub seq: u64,
    /// Serialized ephemeral X25519 public key from the HPKE KEM encap step.
    pub encapsulated_key: [u8; 32],
    /// Detached ChaCha20Poly1305 authentication tag.
    pub aead_tag: [u8; 16],
    /// AEAD ciphertext (same length as the sealed plaintext).
    pub ciphertext: Vec<u8>,
}

/// Errors encoding or decoding a [`WarrenMultihopFrame`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultihopFrameError {
    /// postcard encode/decode failure.
    #[error("multihop frame codec error: {0}")]
    Codec(#[from] postcard::Error),
    /// Encoded frame exceeds `MAX_FRAME_BYTES` (on encode or decode).
    #[error("multihop frame too large")]
    TooLarge,
    /// A valid frame was followed by unexpected trailing bytes. Rejected so the
    /// "exactly one frame per buffer" invariant matches the sibling codecs and
    /// warren-core (a frame must not smuggle extra bytes past the AAD binding).
    #[error("trailing bytes after a valid multihop frame")]
    TrailingBytes,
    /// `version` byte is not [`WARREN_HPKE_VERSION_V1`].
    #[error("unsupported multihop version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// Version received.
        got: u8,
        /// Version expected.
        expected: u8,
    },
}

impl WarrenMultihopFrame {
    /// Encodes the frame to postcard bytes.
    ///
    /// # Errors
    ///
    /// [`MultihopFrameError::Codec`] if postcard encoding fails, or
    /// [`MultihopFrameError::TooLarge`] if the encoded frame would exceed
    /// `MAX_FRAME_BYTES` (the cap is enforced symmetrically with [`Self::decode`]
    /// so an over-budget frame fails at the sender, not silently at the peer).
    pub fn encode(&self) -> Result<Vec<u8>, MultihopFrameError> {
        let bytes = postcard::to_stdvec(self)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(MultihopFrameError::TooLarge);
        }
        Ok(bytes)
    }

    /// Decodes a postcard frame, rejecting oversized input, trailing bytes and
    /// wrong versions.
    ///
    /// # Errors
    ///
    /// [`MultihopFrameError::TooLarge`] if longer than `MAX_FRAME_BYTES`,
    /// [`MultihopFrameError::Codec`] on malformed input,
    /// [`MultihopFrameError::TrailingBytes`] if extra bytes follow the frame, or
    /// [`MultihopFrameError::UnsupportedVersion`] on a wrong version byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, MultihopFrameError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(MultihopFrameError::TooLarge);
        }
        let (frame, rest): (Self, &[u8]) = postcard::take_from_bytes(bytes)?;
        if !rest.is_empty() {
            return Err(MultihopFrameError::TrailingBytes);
        }
        if frame.version != WARREN_HPKE_VERSION_V1 {
            return Err(MultihopFrameError::UnsupportedVersion {
                got: frame.version,
                expected: WARREN_HPKE_VERSION_V1,
            });
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WarrenMultihopFrame {
        WarrenMultihopFrame {
            version: WARREN_HPKE_VERSION_V1,
            exit_id: [0xa1; EXIT_ID_LEN],
            epoch: 7,
            seq: 42,
            encapsulated_key: [0x02; 32],
            aead_tag: [0x03; 16],
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    #[test]
    fn frame_roundtrips() {
        let f = sample();
        let bytes = f.encode().expect("encode");
        assert_eq!(WarrenMultihopFrame::decode(&bytes).expect("decode"), f);
    }

    #[test]
    fn frame_postcard_bytes_are_frozen() {
        // Golden vector pinning the exact postcard layout (cross-language
        // contract): version(1) exit_id(16) epoch(varint) seq(varint)
        // encap(32) tag(16) ciphertext(len-varint + bytes).
        let bytes = sample().encode().expect("encode");
        let mut expected = Vec::new();
        expected.push(0x01); // version
        expected.extend_from_slice(&[0xa1; 16]); // exit_id
        expected.push(0x07); // epoch varint
        expected.push(0x2a); // seq varint (42)
        expected.extend_from_slice(&[0x02; 32]); // encapsulated_key
        expected.extend_from_slice(&[0x03; 16]); // aead_tag
        expected.push(0x04); // ciphertext len varint
        expected.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(bytes, expected, "frozen multihop frame layout");
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut f = sample();
        f.version = 0x02;
        let bytes = f.encode().unwrap();
        assert!(matches!(
            WarrenMultihopFrame::decode(&bytes).unwrap_err(),
            MultihopFrameError::UnsupportedVersion {
                got: 0x02,
                expected: 0x01
            }
        ));
    }

    #[test]
    fn frame_overhead_never_exceeds_the_bound() {
        // Worst case for the varint-encoded fields: max epoch + max seq, and a
        // large ciphertext so its length varint is at its widest. The encoded
        // overhead (everything but the ciphertext bytes) must stay within
        // MULTIHOP_FRAME_MAX_OVERHEAD so datapaths never under-reserve the MTU.
        // The exact worst-case overhead for the frozen frame layout (see the
        // byte-pinned vector in multihop_vectors.rs). Re-derive only with a format
        // change, and keep it <= MULTIHOP_FRAME_MAX_OVERHEAD.
        const EXACT_WORST_CASE_OVERHEAD: usize = 83;
        let payload_len = MAX_FRAME_BYTES - 256;
        let frame = WarrenMultihopFrame {
            version: WARREN_HPKE_VERSION_V1,
            exit_id: [0xff; EXIT_ID_LEN],
            epoch: u32::MAX,
            seq: u64::MAX,
            encapsulated_key: [0xff; 32],
            aead_tag: [0xff; 16],
            ciphertext: vec![0u8; payload_len],
        };
        let encoded = frame.encode().expect("encode");
        let overhead = encoded.len() - payload_len;
        assert!(
            overhead <= MULTIHOP_FRAME_MAX_OVERHEAD,
            "frame overhead {overhead} exceeded the reserved bound {MULTIHOP_FRAME_MAX_OVERHEAD}"
        );
        // Pin the exact worst-case overhead so a wire-format change is noticed even
        // when it stays under the bound: the reserved constant must track the real
        // worst case, not just be an upper bound (which would silently over-reserve).
        assert_eq!(
            overhead, EXACT_WORST_CASE_OVERHEAD,
            "the worst-case frame overhead changed; re-derive MULTIHOP_FRAME_MAX_OVERHEAD"
        );
    }

    #[test]
    fn decode_rejects_oversized() {
        let big = vec![0u8; MAX_FRAME_BYTES + 1];
        assert!(matches!(
            WarrenMultihopFrame::decode(&big).unwrap_err(),
            MultihopFrameError::TooLarge
        ));
    }

    #[test]
    fn encode_rejects_oversized() {
        // The cap is enforced on encode too, so an over-budget frame fails at the
        // sender instead of being rejected as TooLarge by the peer's decode.
        let frame = WarrenMultihopFrame {
            ciphertext: vec![0u8; MAX_FRAME_BYTES],
            ..sample()
        };
        assert!(matches!(
            frame.encode().unwrap_err(),
            MultihopFrameError::TooLarge
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // Parity with decode_setup/try_decode_control: exactly one frame per
        // buffer, no trailing smuggled bytes.
        let mut bytes = sample().encode().expect("encode");
        bytes.push(0xff);
        assert!(matches!(
            WarrenMultihopFrame::decode(&bytes).unwrap_err(),
            MultihopFrameError::TrailingBytes
        ));
    }

    #[test]
    fn aad_and_pki_contexts_match_warren_core() {
        assert_eq!(WARREN_HPKE_AAD_V1, b"warren/multihop/v1/aad");
        assert_eq!(
            WARREN_PKI_OPERATIONAL_EXIT_V1,
            b"warren/multihop/v1/operational-signs-exit"
        );
        assert_eq!(WARREN_HPKE_VERSION_V1, 0x01);
    }
}
