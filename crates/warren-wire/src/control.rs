//! Warren multihop control messages (the sealed inner setup protocol).
//!
//! A control message is the **plaintext** carried inside a
//! [`WarrenMultihopFrame`](crate::multihop::WarrenMultihopFrame): the HPKE
//! seal/open layer is transparent to this module. A control plaintext is
//! identified by a reserved first byte ([`CONTROL_FIRST_BYTE`] = `0xC0`),
//! distinct from every value the exit-side dispatch already recognises:
//!
//! - `0x40 ..= 0x4F` an IPv4 packet (nibble `4`),
//! - `0x60 ..= 0x6F` an IPv6 packet (nibble `6`),
//! - `0xFF` a DAITA dummy.
//!
//! So on the datagram plane the exit routes a single first-byte compare:
//! control vs IP packet vs padding. Byte-compatible with warren-core
//! `warren-multihop::control` (postcard, `/v2`).
//!
//! ## Wire layout
//!
//! ```text
//! +--------+--------+----...---+
//! | 0xC0   | 0x02   | postcard(WarrenControlMessage)
//! +--------+--------+----...---+
//!   marker  version
//! ```
//!
//! Frozen for `/v2`. An incompatible change bumps [`CONTROL_VERSION_V2`]. The
//! `0x01` version is retired and MUST be rejected (`UnsupportedVersion`): its
//! payload schema was mutated in place pre-production, so `0x01` no longer
//! identifies one layout. Client and exits redeploy together, so there is no
//! dual-stack decode path: a version mismatch is a stale binary and fails loud.

use serde::{Deserialize, Serialize};

/// Reserved plaintext first byte that signals a Warren control message.
///
/// Chosen outside every value the exit-side IP / DAITA dispatch matches
/// (`0x40..=0x4F` IPv4, `0x60..=0x6F` IPv6, `0xFF` DAITA dummy), so a single
/// byte compare routes the plaintext.
pub const CONTROL_FIRST_BYTE: u8 = 0xC0;

/// Control protocol version byte. `0x02` is the current layout (proof of
/// possession on `IpRequest`, sealed `Rejected` reply). A breaking change bumps
/// this; forward-compatible additions go inside the postcard payload.
///
/// `0x01` is retired and never decoded (its payload schema was mutated in place
/// pre-production, so it no longer identifies one layout).
pub const CONTROL_VERSION_V2: u8 = 0x02;

/// Errors from [`encode_control`] and [`try_decode_control`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The plaintext started with [`CONTROL_FIRST_BYTE`] but was shorter than
    /// the 2-byte header (marker + version). A legitimate sender always emits at
    /// least these two bytes.
    #[error("control plaintext too short: got {got} bytes, need at least 2 for marker + version")]
    TooShort {
        /// Length of the plaintext passed to the decoder.
        got: usize,
    },

    /// The version byte did not match [`CONTROL_VERSION_V2`]. Receivers drop the
    /// frame; a stale peer build is the usual cause.
    #[error("unsupported control version: got 0x{got:02x}, expected 0x{expected:02x}")]
    UnsupportedVersion {
        /// Version byte read from the plaintext.
        got: u8,
        /// Version byte required by this build.
        expected: u8,
    },

    /// A valid message was followed by unexpected trailing bytes. Rejected to
    /// keep the encoding unambiguous (one plaintext is exactly one message),
    /// same rule as [`decode_setup`](crate::decode_setup).
    #[error("trailing bytes after a valid control message")]
    TrailingBytes,

    /// postcard rejected the payload (truncation, schema mismatch, or an
    /// over-budget field).
    #[error("control payload codec error: {0}")]
    Codec(#[from] postcard::Error),
}

/// Ed25519 proof-of-possession signature carried as 64 raw bytes (no length
/// prefix). Newtype because serde has no built-in `[u8; 64]` impls; the manual
/// impl serialises as a fixed 64-tuple so postcard emits exactly 64 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopSignature(
    /// The raw Ed25519 signature bytes.
    pub [u8; 64],
);

impl Serialize for PopSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(64)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for PopSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = PopSignature;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("64 raw Ed25519 signature bytes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(PopSignature(out))
            }
        }
        deserializer.deserialize_tuple(64, SigVisitor)
    }
}

/// Warren multihop control messages exchanged between client and exit over the
/// same HPKE-sealed channel that carries IP packets.
///
/// Single `/v2` format: client and exit redeploy together, so the message
/// carries every field directly instead of accumulating append-only variants. A
/// genuine wire break bumps [`CONTROL_VERSION_V2`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WarrenControlMessage {
    /// Client to exit. Asks the exit to allocate a tunnel IP.
    IpRequest {
        /// Optional client IPv4 preference. `None` means "anything".
        /// Advisory only; the exit MAY override.
        prefer_ipv4: Option<[u8; 4]>,
        /// 32-byte Ed25519 verifying-key bytes. When `Some`, the exit serves a
        /// sticky IP across reconnects (keyed on the pubkey) and the allowlist
        /// gate authorises the client by it. `None` means a fresh, non-sticky
        /// allocation (rejected in strict allowlist mode).
        client_pubkey: Option<[u8; 32]>,
        /// `true` asks for a dual-stack IPv6 alongside the IPv4. The exit MAY
        /// still answer with `ipv6: None` in [`Self::IpAssign`] (no v6 served);
        /// the presence of `ipv6` in the reply is the capability echo.
        wants_ipv6: bool,
        /// Proof of possession of `client_pubkey`'s private key: an Ed25519
        /// signature over the domain-separated message binding the account key
        /// to this session's HPKE `encapsulated_key` and the `exit_id`. Required
        /// (with `client_pubkey`) in strict allowlist mode.
        pop_sig: Option<PopSignature>,
    },

    /// Exit to client. Authoritative IP allocation. `ipv6` is `Some` iff the
    /// exit actually granted dual-stack v6 (the capability echo).
    IpAssign {
        /// Allocated host IPv4 address.
        ipv4: [u8; 4],
        /// IPv4 subnet prefix length (e.g. 24 for a `/24`).
        prefix_len: u8,
        /// IPv4 subnet gateway (also the exit-side TUN address).
        gateway_ipv4: [u8; 4],
        /// Allocated host IPv6, or `None` when the exit did not grant v6.
        ipv6: Option<[u8; 16]>,
        /// IPv6 subnet prefix length. Ignored when `ipv6` is `None`.
        prefix_len_v6: u8,
        /// IPv6 subnet gateway, or `None` when no v6.
        gateway_ipv6: Option<[u8; 16]>,
    },

    /// Exit to client. The pool is exhausted; the client SHOULD terminate and
    /// surface the error.
    IpExhausted,

    /// Exit to client. The setup was refused by policy (pubkey not allowlisted,
    /// or the proof of possession is missing or invalid). Sent sealed before the
    /// exit closes, so the client learns the cause while the relay (hostile by
    /// model) sees only one opaque close code (anti subscription-status oracle).
    Rejected,
}

/// Encode a control message into the wire layout (marker + version + postcard
/// payload). The result is suitable for sealing as the plaintext of a
/// [`WarrenMultihopFrame`](crate::multihop::WarrenMultihopFrame).
///
/// # Errors
///
/// [`ControlError::Codec`] if postcard fails to encode (out of memory in
/// practice; the bounded fields rule out the usual overflow paths).
pub fn encode_control(msg: &WarrenControlMessage) -> Result<Vec<u8>, ControlError> {
    let payload = postcard::to_stdvec(msg)?;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(CONTROL_FIRST_BYTE);
    out.push(CONTROL_VERSION_V2);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Try to decode a plaintext as a control message.
///
/// - `Ok(Some(msg))`: the plaintext starts with [`CONTROL_FIRST_BYTE`] and
///   parses cleanly. Consume it as control, do not forward to the netstack.
/// - `Ok(None)`: the plaintext does not start with the marker. Fall through to
///   the normal IP-packet dispatch (or the DAITA dummy filter).
/// - `Err(_)`: the plaintext starts with the marker but is malformed. Drop it.
///
/// # Errors
///
/// See [`ControlError`].
pub fn try_decode_control(plaintext: &[u8]) -> Result<Option<WarrenControlMessage>, ControlError> {
    let Some(&first) = plaintext.first() else {
        return Ok(None);
    };
    if first != CONTROL_FIRST_BYTE {
        return Ok(None);
    }
    if plaintext.len() < 2 {
        return Err(ControlError::TooShort {
            got: plaintext.len(),
        });
    }
    let version = plaintext[1];
    if version != CONTROL_VERSION_V2 {
        return Err(ControlError::UnsupportedVersion {
            got: version,
            expected: CONTROL_VERSION_V2,
        });
    }
    // take_from_bytes + an explicit rest check rejects trailing bytes after a
    // valid message: one plaintext is exactly one control message.
    let (msg, rest): (WarrenControlMessage, &[u8]) = postcard::take_from_bytes(&plaintext[2..])?;
    if !rest.is_empty() {
        return Err(ControlError::TrailingBytes);
    }
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ip_request_v4_only() {
        let msg = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
        };
        let encoded = encode_control(&msg).expect("encode");
        assert_eq!(encoded[0], CONTROL_FIRST_BYTE);
        assert_eq!(encoded[1], CONTROL_VERSION_V2);
        let decoded = try_decode_control(&encoded)
            .expect("decode result")
            .expect("control message present");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_ip_request_with_pubkey_pop_and_wants_ipv6() {
        for wants_ipv6 in [true, false] {
            let msg = WarrenControlMessage::IpRequest {
                prefer_ipv4: Some([10, 66, 0, 42]),
                client_pubkey: Some([0x42; 32]),
                wants_ipv6,
                pop_sig: Some(PopSignature([0xA5; 64])),
            };
            let decoded = try_decode_control(&encode_control(&msg).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(
                decoded, msg,
                "IpRequest must round-trip (wants_ipv6={wants_ipv6})"
            );
        }
    }

    #[test]
    fn round_trip_ip_assign_v4_only_and_dual_stack() {
        let v4_only = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 8],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
        };
        let decoded = try_decode_control(&encode_control(&v4_only).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(decoded, v4_only, "v4-only IpAssign must round-trip");

        let dual = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 7],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
            ]),
            prefix_len_v6: 64,
            gateway_ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
        };
        let decoded = try_decode_control(&encode_control(&dual).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(decoded, dual, "dual-stack IpAssign must round-trip");
    }

    #[test]
    fn round_trip_ip_exhausted_and_rejected() {
        for msg in [
            WarrenControlMessage::IpExhausted,
            WarrenControlMessage::Rejected,
        ] {
            let decoded = try_decode_control(&encode_control(&msg).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(decoded, msg);
        }
    }

    // ---- Frozen wire vectors (/v2), byte-exact with warren-core ----
    //
    // Every expected byte is a hard literal: a vector that re-derived its
    // expectation from the constants under test would pass through any drift.
    // A failure here means the wire layout moved: bump the version and freeze a
    // new vector, never edit the literal to make the test pass.

    #[test]
    fn ip_request_minimal_wire_layout_is_frozen() {
        let msg = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
        };
        assert_eq!(
            encode_control(&msg).unwrap(),
            vec![
                0xC0, // CONTROL_FIRST_BYTE
                0x02, // CONTROL_VERSION_V2
                0x00, // variant tag 0 (IpRequest)
                0x00, // prefer_ipv4 = None
                0x00, // client_pubkey = None
                0x00, // wants_ipv6 = false
                0x00, // pop_sig = None
            ],
            "minimal IpRequest wire layout drifted: bump the version + freeze a new vector"
        );
    }

    #[test]
    fn ip_request_full_wire_layout_is_frozen() {
        let msg = WarrenControlMessage::IpRequest {
            prefer_ipv4: Some([10, 66, 0, 42]),
            client_pubkey: Some([0x42; 32]),
            wants_ipv6: true,
            pop_sig: Some(PopSignature([0xA5; 64])),
        };
        let mut expected = vec![
            0xC0, // CONTROL_FIRST_BYTE
            0x02, // CONTROL_VERSION_V2
            0x00, // variant tag 0 (IpRequest)
            0x01, // prefer_ipv4 = Some
            10, 66, 0, 42,   // prefer_ipv4 bytes
            0x01, // client_pubkey = Some
        ];
        expected.extend_from_slice(&[0x42; 32]); // client_pubkey bytes
        expected.push(0x01); // wants_ipv6 = true
        expected.push(0x01); // pop_sig = Some
        expected.extend_from_slice(&[0xA5; 64]); // raw signature, no length prefix
        assert_eq!(
            encode_control(&msg).unwrap(),
            expected,
            "full IpRequest wire layout drifted: bump the version + freeze a new vector"
        );
    }

    #[test]
    fn ip_assign_wire_layout_is_frozen() {
        let msg = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 7],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
        };
        assert_eq!(
            encode_control(&msg).unwrap(),
            vec![
                0xC0, // CONTROL_FIRST_BYTE
                0x02, // CONTROL_VERSION_V2
                0x01, // variant tag 1 (IpAssign)
                10, 66, 0, 7,  // ipv4
                24, // prefix_len
                10, 66, 0, 1,    // gateway_ipv4
                0x00, // ipv6 = None
                0x00, // prefix_len_v6
                0x00, // gateway_ipv6 = None
            ],
            "IpAssign wire layout drifted: bump the version + freeze a new vector"
        );
    }

    #[test]
    fn ip_exhausted_and_rejected_wire_layouts_are_frozen() {
        assert_eq!(
            encode_control(&WarrenControlMessage::IpExhausted).unwrap(),
            vec![0xC0, 0x02, 0x02],
            "IpExhausted wire layout drifted: bump the version + freeze a new vector"
        );
        assert_eq!(
            encode_control(&WarrenControlMessage::Rejected).unwrap(),
            vec![0xC0, 0x02, 0x03],
            "Rejected wire layout drifted: bump the version + freeze a new vector"
        );
    }

    // ---- Decoder hygiene ----

    #[test]
    fn non_control_prefix_returns_none() {
        // IPv4 (nibble 4), IPv6 (nibble 6), DAITA dummy (0xFF): none is control.
        for first in [0x45u8, 0x60, 0xFF] {
            let plaintext = [first, 0x00, 0x00, 0x14];
            assert!(
                try_decode_control(&plaintext)
                    .expect("decode result")
                    .is_none(),
                "first byte 0x{first:02x} must not be classified as control"
            );
        }
        // Empty plaintext also falls through (no marker).
        assert!(try_decode_control(&[]).unwrap().is_none());
    }

    #[test]
    fn unknown_variant_tag_is_a_codec_error_not_a_panic() {
        let bogus = [CONTROL_FIRST_BYTE, CONTROL_VERSION_V2, 0x7F, 0x00];
        assert!(matches!(
            try_decode_control(&bogus),
            Err(ControlError::Codec(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_a_valid_message_are_rejected() {
        let mut encoded = encode_control(&WarrenControlMessage::IpExhausted).unwrap();
        encoded.push(0x00);
        assert!(
            matches!(
                try_decode_control(&encoded),
                Err(ControlError::TrailingBytes)
            ),
            "trailing bytes after a valid control message must be a codec error"
        );
    }

    #[test]
    fn retired_v1_version_byte_is_rejected_loudly() {
        let stale = [CONTROL_FIRST_BYTE, 0x01, 0x02];
        assert!(matches!(
            try_decode_control(&stale),
            Err(ControlError::UnsupportedVersion {
                got: 0x01,
                expected: 0x02
            })
        ));
    }

    #[test]
    fn too_short_and_unknown_version_are_errors() {
        assert!(matches!(
            try_decode_control(&[CONTROL_FIRST_BYTE]),
            Err(ControlError::TooShort { got: 1 })
        ));
        assert!(matches!(
            try_decode_control(&[CONTROL_FIRST_BYTE, 0x99, 0x00]),
            Err(ControlError::UnsupportedVersion {
                got: 0x99,
                expected: 0x02
            })
        ));
    }
}
