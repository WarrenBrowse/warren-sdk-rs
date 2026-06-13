//! Warren tunnel handshake frames: `Setup` (client) and `SetupAck` (exit).
//!
//! Encoding is `postcard`, byte-for-byte compatible with warren-core. The wire
//! layout is frozen by `PROTOCOL_VERSION`; any change requires bumping it and
//! shipping a new vector. The byte vectors are pinned in
//! `vectors/handshake.json`.

use serde::{Deserialize, Serialize};

/// Warren application protocol version. Bumped on every wire-incompatible
/// change to [`Setup`] / [`SetupAck`].
pub const PROTOCOL_VERSION: u8 = 4;

/// Length in bytes of a [`Setup::device_id`] (128-bit random).
pub const DEVICE_ID_LEN: usize = 16;

/// Heap allocation cap when reading a Setup or SetupAck frame.
pub const MAX_SETUP_FRAME_BYTES: usize = 16 * 1024;

/// Feature bitmask advertised by the client in [`Setup::features`].
pub mod features {
    /// Client supports QUIC multipath.
    pub const MULTIPATH: u32 = 1 << 0;
    /// Client requests a NAT-PMP external port at startup.
    pub const PORT_FORWARD: u32 = 1 << 1;
    /// Client supports IPv6 inside the tunnel.
    pub const IPV6: u32 = 1 << 2;
    /// Client requests MTU padding on all QUIC application datagrams.
    pub const PAD_TO_MTU: u32 = 1 << 3;
}

/// First frame sent by the client when opening the setup stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    /// Warren application protocol version.
    pub protocol_version: u8,
    /// Bitmask of features requested by the client (see [`features`]).
    pub features: u32,
    /// 0-based index of this connection within the client's multi-conn session.
    pub connection_index: u8,
    /// Total number of QUIC connections for this client session.
    pub total_connections: u8,
    /// Client advertises DAITA v2 support.
    pub daita_support: bool,
    /// Random, ephemeral per-run device identifier. All connections of one run
    /// carry the same value so the exit counts devices, not connections.
    pub device_id: [u8; DEVICE_ID_LEN],
}

impl Setup {
    /// Builds a single-connection [`Setup`] with DAITA off.
    #[must_use]
    pub fn single_conn(features: u32) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            features,
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
        }
    }

    /// Sets the per-run [`Self::device_id`].
    #[must_use]
    pub fn with_device_id(mut self, device_id: [u8; DEVICE_ID_LEN]) -> Self {
        self.device_id = device_id;
        self
    }

    /// Builds a single-connection [`Setup`] advertising DAITA v2 support.
    #[must_use]
    pub fn single_conn_with_daita(features: u32) -> Self {
        Self {
            daita_support: true,
            ..Self::single_conn(features)
        }
    }

    /// Builds a [`Setup`] for the `idx`-th of `total` multi-conn connections.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= total` or `total == 0` (protocol invariant).
    #[must_use]
    pub fn multi_conn(features: u32, idx: u8, total: u8) -> Self {
        assert!(total >= 1, "total_connections must be >= 1");
        assert!(
            idx < total,
            "connection_index ({idx}) must be < total_connections ({total})"
        );
        Self {
            protocol_version: PROTOCOL_VERSION,
            features,
            connection_index: idx,
            total_connections: total,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
        }
    }
}

/// Exit's response. Carries the client's assigned tunnel IP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupAck {
    /// Protocol version accepted by the exit.
    pub protocol_version: u8,
    /// Tunnel IPv4 (`10.66.x.y/32`) assigned to this session.
    pub tunnel_ipv4: [u8; 4],
    /// Optional tunnel IPv6.
    pub tunnel_ipv6: Option<[u8; 16]>,
    /// Confirmation of the exit's Ed25519 pubkey.
    pub exit_pubkey: [u8; 32],
    /// MTU negotiated for the session.
    pub max_mtu: u16,
    /// `true` if this connection attached to the client session.
    pub multiconn_attached: bool,
    /// DAITA v2 machine spec selected by the exit, or `None` if disabled.
    pub daita_spec: Option<DaitaConfig>,
}

/// Wire-transmissible DAITA v2 configuration negotiated at handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaitaConfig {
    /// Serialized maybenot machines, one entry per machine.
    pub machine_specs: Vec<String>,
    /// Hard cap on the fraction of total packets that may be padding (`0.0..=1.0`).
    pub max_padding_frac: f64,
    /// Hard cap on the fraction of total time that may be blocked (`0.0..=1.0`).
    pub max_blocking_frac: f64,
}

impl DaitaConfig {
    /// True if the config has at least one machine spec.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.machine_specs.is_empty()
    }

    /// True if both fractional caps are finite and within `[0.0, 1.0]`.
    #[must_use]
    pub fn fractions_valid(&self) -> bool {
        (0.0..=1.0).contains(&self.max_padding_frac)
            && (0.0..=1.0).contains(&self.max_blocking_frac)
    }
}

/// Errors raised when encoding or decoding a handshake frame.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// `postcard` encode / decode error.
    #[error("postcard codec error: {0}")]
    Codec(#[from] postcard::Error),
    /// The decoded frame was followed by unexpected trailing bytes.
    #[error("trailing bytes after valid frame")]
    TrailingBytes,
    /// `connection_index >= total_connections` or `total_connections == 0`.
    #[error("invalid multi-conn indices: index={index}, total={total}")]
    InvalidMultiConn {
        /// `connection_index` from the frame.
        index: u8,
        /// `total_connections` from the frame.
        total: u8,
    },
    /// The frame announces a version other than [`PROTOCOL_VERSION`].
    #[error("protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch {
        /// Expected version (= [`PROTOCOL_VERSION`]).
        expected: u8,
        /// Version announced by the peer.
        got: u8,
    },
}

/// Encodes a [`Setup`] frame to bytes (postcard).
///
/// # Errors
///
/// [`ProtocolError::Codec`] if postcard encoding fails.
pub fn encode_setup(setup: &Setup) -> Result<Vec<u8>, ProtocolError> {
    Ok(postcard::to_allocvec(setup)?)
}

/// Decodes a [`Setup`] frame, rejecting trailing bytes and wrong versions.
///
/// # Errors
///
/// [`ProtocolError::Codec`], [`ProtocolError::TrailingBytes`],
/// [`ProtocolError::VersionMismatch`] or [`ProtocolError::InvalidMultiConn`].
pub fn decode_setup(buf: &[u8]) -> Result<Setup, ProtocolError> {
    let (s, rest): (Setup, _) = postcard::take_from_bytes(buf)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }
    if s.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            got: s.protocol_version,
        });
    }
    if s.total_connections == 0 || s.connection_index >= s.total_connections {
        return Err(ProtocolError::InvalidMultiConn {
            index: s.connection_index,
            total: s.total_connections,
        });
    }
    Ok(s)
}

/// Encodes a [`SetupAck`] frame to bytes (postcard).
///
/// # Errors
///
/// See [`encode_setup`].
pub fn encode_setup_ack(ack: &SetupAck) -> Result<Vec<u8>, ProtocolError> {
    Ok(postcard::to_allocvec(ack)?)
}

/// Decodes a [`SetupAck`] frame, rejecting trailing bytes and wrong versions.
///
/// # Errors
///
/// See [`decode_setup`].
pub fn decode_setup_ack(buf: &[u8]) -> Result<SetupAck, ProtocolError> {
    let (a, rest): (SetupAck, _) = postcard::take_from_bytes(buf)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }
    if a.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            got: a.protocol_version,
        });
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack_no_daita(version: u8) -> SetupAck {
        SetupAck {
            protocol_version: version,
            tunnel_ipv4: [10, 66, 42, 7],
            tunnel_ipv6: None,
            exit_pubkey: [0xab; 32],
            max_mtu: 1350,
            multiconn_attached: true,
            daita_spec: None,
        }
    }

    #[test]
    fn roundtrip_setup() {
        let s = Setup::single_conn(features::MULTIPATH | features::PORT_FORWARD);
        assert_eq!(decode_setup(&encode_setup(&s).unwrap()).unwrap(), s);
    }

    #[test]
    fn roundtrip_setup_ack() {
        let a = ack_no_daita(PROTOCOL_VERSION);
        assert_eq!(decode_setup_ack(&encode_setup_ack(&a).unwrap()).unwrap(), a);
    }

    #[test]
    fn setup_wire_format_is_stable_v4() {
        let s = Setup {
            protocol_version: 4,
            features: 0x03,
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id: [0xAB; DEVICE_ID_LEN],
        };
        let mut expected = vec![0x04, 0x03, 0x00, 0x01, 0x00];
        expected.extend_from_slice(&[0xAB; DEVICE_ID_LEN]);
        assert_eq!(encode_setup(&s).unwrap(), expected);
    }

    #[test]
    fn setup_ack_wire_format_header_is_stable() {
        let a = SetupAck {
            protocol_version: 4,
            tunnel_ipv4: [10, 66, 42, 7],
            tunnel_ipv6: None,
            exit_pubkey: [0u8; 32],
            max_mtu: 1350,
            multiconn_attached: true,
            daita_spec: None,
        };
        let bytes = encode_setup_ack(&a).unwrap();
        assert_eq!(&bytes[..6], &[0x04, 0x0a, 0x42, 0x2a, 0x07, 0x00]);
        assert_eq!(&bytes[6..38], &[0u8; 32]);
        assert_eq!(&bytes[38..40], &[0xc6, 0x0a]);
        assert_eq!(&bytes[40..42], &[0x01, 0x00]);
    }

    #[test]
    fn feature_bits_are_distinct_powers_of_two() {
        let all =
            features::MULTIPATH | features::PORT_FORWARD | features::IPV6 | features::PAD_TO_MTU;
        assert_eq!(all.count_ones(), 4);
        assert_eq!(features::PAD_TO_MTU, 0x08);
    }

    #[test]
    fn version_mismatch_is_detected() {
        let bytes = postcard::to_allocvec(&Setup {
            protocol_version: 99,
            ..Setup::single_conn(0)
        })
        .unwrap();
        assert!(matches!(
            decode_setup(&bytes).unwrap_err(),
            ProtocolError::VersionMismatch { got: 99, .. }
        ));
    }

    #[test]
    fn decode_setup_rejects_trailing_bytes() {
        let mut payload = encode_setup(&Setup::single_conn(0)).unwrap();
        payload.extend_from_slice(&[0xFF; 8]);
        assert!(matches!(
            decode_setup(&payload).unwrap_err(),
            ProtocolError::TrailingBytes
        ));
    }

    #[test]
    fn decode_setup_rejects_empty_buffer() {
        assert!(matches!(
            decode_setup(&[]).unwrap_err(),
            ProtocolError::Codec(_)
        ));
    }

    #[test]
    fn decode_setup_rejects_invalid_multiconn() {
        // index >= total: encode a raw frame bypassing the checked builder.
        let bytes = postcard::to_allocvec(&Setup {
            protocol_version: PROTOCOL_VERSION,
            features: 0,
            connection_index: 4,
            total_connections: 4,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
        })
        .unwrap();
        assert!(matches!(
            decode_setup(&bytes).unwrap_err(),
            ProtocolError::InvalidMultiConn { index: 4, total: 4 }
        ));
    }

    #[test]
    fn setup_ack_with_daita_spec_roundtrips() {
        let spec = DaitaConfig {
            machine_specs: vec!["02eNpjYEAHjOgCAAA0AAI=".to_owned()],
            max_padding_frac: 0.05,
            max_blocking_frac: 0.1,
        };
        let a = SetupAck {
            daita_spec: Some(spec.clone()),
            ..ack_no_daita(PROTOCOL_VERSION)
        };
        let decoded = decode_setup_ack(&encode_setup_ack(&a).unwrap()).unwrap();
        let got = decoded.daita_spec.expect("daita_spec round-trips");
        assert_eq!(got.machine_specs, spec.machine_specs);
        assert!(got.is_enabled() && got.fractions_valid());
    }

    #[test]
    fn multi_conn_helper_panics_on_idx_eq_total() {
        let r = std::panic::catch_unwind(|| Setup::multi_conn(0, 4, 4));
        assert!(r.is_err());
    }
}
