//! Wire-level stable exit identifier.
//!
//! [`ExitId`] is a 16-byte (UUID-shaped) opaque identifier minted once per exit
//! deployment. It survives Ed25519 key rotations, so clients pin observed
//! pubkeys against it. Serialization is format-aware (32-char lowercase hex in
//! JSON, 16 raw bytes in binary codecs), byte-compatible with warren-core.

use core::fmt;

use serde::{Deserialize, Serialize};

/// Length in bytes of an [`ExitId`].
pub const EXIT_ID_LEN: usize = 16;

/// 16-byte opaque exit identifier (UUID-shaped).
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ExitId([u8; EXIT_ID_LEN]);

/// Failure modes for [`ExitId::from_hex`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitIdError {
    /// Hex input length is not exactly 32 characters.
    #[error("expected 32 hex chars for a 16-byte exit_id, got {got}")]
    WrongHexLength {
        /// Length of the offending input.
        got: usize,
    },
    /// Hex input contains a non-hex character.
    #[error("invalid hex character in exit_id")]
    InvalidHex,
}

impl ExitId {
    /// All-zero sentinel ("no stable identifier assigned yet").
    pub const ZERO: Self = Self([0u8; EXIT_ID_LEN]);

    /// Wraps a raw 16-byte buffer.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EXIT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EXIT_ID_LEN] {
        &self.0
    }

    /// Returns the lower-case hex encoding (exactly 32 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a 32-character hex string.
    ///
    /// # Errors
    ///
    /// [`ExitIdError::WrongHexLength`] or [`ExitIdError::InvalidHex`].
    pub fn from_hex(s: &str) -> Result<Self, ExitIdError> {
        if s.len() != 32 {
            return Err(ExitIdError::WrongHexLength { got: s.len() });
        }
        let mut out = [0u8; EXIT_ID_LEN];
        hex::decode_to_slice(s, &mut out).map_err(|_| ExitIdError::InvalidHex)?;
        Ok(Self(out))
    }

    /// True when every byte is zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < EXIT_ID_LEN {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl Default for ExitId {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for ExitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ExitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExitId({self})")
    }
}

impl Serialize for ExitId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ExitId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; EXIT_ID_LEN]>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_against_known_vector() {
        let raw = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let id = ExitId::from_bytes(raw);
        assert_eq!(id.to_hex(), "123456789abcdef01122334455667788");
        assert_eq!(ExitId::from_hex(&id.to_hex()).expect("parse"), id);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert_eq!(
            ExitId::from_hex(&"ab".repeat(15)),
            Err(ExitIdError::WrongHexLength { got: 30 })
        );
    }

    #[test]
    fn from_hex_rejects_non_hex_of_correct_length() {
        // Right length (32 chars) but non-hex bytes: the length guard passes and
        // the decode must reject, distinct from WrongHexLength.
        assert_eq!(
            ExitId::from_hex(&"zz".repeat(16)),
            Err(ExitIdError::InvalidHex)
        );
    }

    #[test]
    fn json_serializes_as_hex_string() {
        let id = ExitId::from_bytes([0xaa; 16]);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{}\"", "aa".repeat(16))
        );
    }
}
