//! Signed multi-hop directory (`GET /v1/multihop/directory`, v2) verification.
//!
//! Byte-compatible with warren-core `warren-relay-selector::multihop_directory`
//! and `warren-multihop` PKI. Trust chain, all Ed25519:
//!
//! 1. **server envelope**: the pinned server key signs the canonical directory
//!    bytes (freshness: `generation` / `signed_at` / `expires_at`).
//! 2. **operational certificate**: the root key signs the operational pubkey
//!    (`WARREN_PKI_ROOT_OPERATIONAL_V1 || operational_pubkey`). Root pinned by
//!    the embedder; empty pin set = TOFU (accept the carried operational key).
//! 3. **exit descriptor**: the operational key signs each exit's HPKE recipient
//!    key (`WARREN_PKI_OPERATIONAL_EXIT_V2 || exit_id || x25519 || dns_byte`,
//!    falling back to the `…_V1` payload without the dns byte).
//!
//! The canonical preimage is serialized from typed structs in frozen
//! declaration order (NOT a `serde_json::Value`, which would reorder keys), so
//! the envelope signature reproduces warren-core's bytes exactly.
//!
//! Node attestation (geo/AS diversity) and the relay descriptor are carried and
//! signed-over but not independently re-verified here yet (tracked); the exit
//! RPK TLS pin comes from the separately-signed `/v1/exits` list, cross-checked
//! by `exit_id`.

use std::net::SocketAddr;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Directory wire version this verifier accepts.
pub const MULTIHOP_DIRECTORY_VERSION: u32 = 2;
/// PKI context: root key signs the operational key.
pub const WARREN_PKI_ROOT_OPERATIONAL_V1: &[u8] = b"warren/multihop/v1/root-signs-operational";
/// PKI context: operational key signs an exit's x25519 key (`/v1`).
pub const WARREN_PKI_OPERATIONAL_EXIT_V1: &[u8] = b"warren/multihop/v1/operational-signs-exit";
/// PKI context: operational key signs an exit's x25519 key + dns byte (`/v2`).
pub const WARREN_PKI_OPERATIONAL_EXIT_V2: &[u8] = b"warren/multihop/v2/operational-signs-exit";

/// Hex-string serde for a fixed byte array (lowercase, matches warren-core).
mod hexn {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<S: Serializer, const N: usize>(
        v: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        v.try_into().map_err(|_| D::Error::custom("bad hex length"))
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// Relay (entry) descriptor. Field order frozen (warren-core `RelayDescriptorSigned`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct RelayDescriptorSigned {
    #[serde(with = "hexn")]
    relay_id: [u8; 16],
    #[serde(with = "hexn")]
    relay_ed25519_pubkey: [u8; 32],
    endpoint: SocketAddr,
    #[serde(with = "hexn")]
    signature: [u8; 64],
}

/// Exit descriptor. Field order frozen (warren-core `ExitDescriptorSigned`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct ExitDescriptorSigned {
    #[serde(with = "hexn")]
    exit_id: [u8; 16],
    #[serde(with = "hexn")]
    exit_ed25519_pubkey: [u8; 32],
    #[serde(with = "hexn")]
    exit_x25519_multihop_pubkey: [u8; 32],
    endpoint: SocketAddr,
    #[serde(with = "hexn")]
    signature: [u8; 64],
    #[serde(default, skip_serializing_if = "is_false")]
    dns_disabled: bool,
}

/// One fleet node. Field order frozen (warren-core `NodeEntry`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct NodeEntry {
    relay: RelayDescriptorSigned,
    exit: ExitDescriptorSigned,
    country: String,
    city: String,
    #[serde(default)]
    asn: u32,
    weight: u64,
    attestation_hex: String,
}

/// Full signed directory wire form (`GET /v1/multihop/directory`).
#[derive(Debug, Clone, Deserialize)]
struct SignedDirectory {
    version: u32,
    nodes: Vec<NodeEntry>,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    operational_pubkey_hex: String,
    operational_cert_hex: String,
    server_pubkey_hex: String,
    signature_hex: String,
}

/// Canonical server-envelope preimage. Field order frozen, must match
/// warren-core `UnsignedMultiHopDirectory`.
#[derive(Serialize)]
struct UnsignedDirectory<'a> {
    version: u32,
    nodes: &'a [NodeEntry],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    operational_pubkey_hex: &'a str,
    operational_cert_hex: &'a str,
    server_pubkey_hex: &'a str,
}

/// A verified exit usable as an HPKE recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExit {
    /// 16-byte exit identifier (cleartext routing key for the frame).
    pub exit_id: [u8; 16],
    /// The exit's Ed25519 identity (TLS RPK; cross-check with `/v1/exits`).
    pub exit_ed25519_pubkey: [u8; 32],
    /// The exit's long-lived X25519 HPKE recipient key.
    pub exit_x25519_multihop_pubkey: [u8; 32],
    /// QUIC endpoint to dial.
    pub endpoint: SocketAddr,
    /// ISO 3166-1 alpha-2 country.
    pub country: String,
    /// City.
    pub city: String,
    /// Selection weight.
    pub weight: u64,
}

/// Verified directory: trusted exits plus freshness metadata the caller enforces.
#[derive(Debug, Clone)]
pub struct VerifiedDirectory {
    /// Exits whose descriptor verified under the operational key.
    pub exits: Vec<VerifiedExit>,
    /// Monotonic content version (anti-rollback).
    pub generation: u64,
    /// Unix epoch seconds the directory was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which it is stale.
    pub expires_at: u64,
}

/// Errors verifying the multi-hop directory.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DirectoryError {
    /// Malformed JSON.
    #[error("invalid directory json: {0}")]
    Json(#[from] serde_json::Error),
    /// `version` is not [`MULTIHOP_DIRECTORY_VERSION`].
    #[error("unsupported directory version: {got}")]
    UnsupportedVersion {
        /// Version received.
        got: u32,
    },
    /// The declared server pubkey is not in the pinned set (key omitted, no-log).
    #[error("directory server pubkey not in the pinned set")]
    ServerPubkeyMismatch,
    /// Invalid hex for a pubkey or signature field.
    #[error("invalid hex encoding in directory")]
    InvalidHex,
    /// The server envelope signature did not verify.
    #[error("directory server envelope signature failed")]
    BadEnvelopeSignature,
    /// The operational certificate did not verify against any pinned root.
    #[error("directory operational certificate failed")]
    BadOperationalCert,
}

fn vkey(hex_str: &str) -> Result<VerifyingKey, DirectoryError> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DirectoryError::InvalidHex)
}

fn sig64(hex_str: &str) -> Result<Signature, DirectoryError> {
    let bytes: [u8; 64] = hex::decode(hex_str)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    Ok(Signature::from_bytes(&bytes))
}

/// Verifies the operational certificate: `root` signed
/// `WARREN_PKI_ROOT_OPERATIONAL_V1 || operational_pubkey`.
fn verify_operational_cert(
    root: &VerifyingKey,
    operational: &VerifyingKey,
    cert: &Signature,
) -> bool {
    let mut payload = Vec::with_capacity(WARREN_PKI_ROOT_OPERATIONAL_V1.len() + 32);
    payload.extend_from_slice(WARREN_PKI_ROOT_OPERATIONAL_V1);
    payload.extend_from_slice(operational.as_bytes());
    root.verify(&payload, cert).is_ok()
}

/// Verifies an exit descriptor under the operational key (`/v2` then `/v1`).
fn exit_descriptor_ok(operational: &VerifyingKey, d: &ExitDescriptorSigned) -> bool {
    let sig = Signature::from_bytes(&d.signature);
    let mut v2 = Vec::with_capacity(WARREN_PKI_OPERATIONAL_EXIT_V2.len() + 16 + 32 + 1);
    v2.extend_from_slice(WARREN_PKI_OPERATIONAL_EXIT_V2);
    v2.extend_from_slice(&d.exit_id);
    v2.extend_from_slice(&d.exit_x25519_multihop_pubkey);
    v2.push(u8::from(d.dns_disabled));
    if operational.verify(&v2, &sig).is_ok() {
        return true;
    }
    let mut v1 = Vec::with_capacity(WARREN_PKI_OPERATIONAL_EXIT_V1.len() + 16 + 32);
    v1.extend_from_slice(WARREN_PKI_OPERATIONAL_EXIT_V1);
    v1.extend_from_slice(&d.exit_id);
    v1.extend_from_slice(&d.exit_x25519_multihop_pubkey);
    operational.verify(&v1, &sig).is_ok()
}

/// Verifies the directory and returns the trusted exits.
///
/// `expected_server_pubkeys` pins the online server key (empty = TOFU);
/// `expected_root_pubkeys` pins the offline root key (empty = TOFU).
///
/// # Errors
///
/// See [`DirectoryError`]. Freshness (`generation`, `expires_at`) is enforced by
/// the caller via the returned metadata.
pub fn verify_multihop_directory(
    json: &str,
    expected_server_pubkeys: &[&str],
    expected_root_pubkeys: &[&str],
) -> Result<VerifiedDirectory, DirectoryError> {
    let signed: SignedDirectory = serde_json::from_str(json)?;
    if signed.version != MULTIHOP_DIRECTORY_VERSION {
        return Err(DirectoryError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !expected_server_pubkeys.is_empty()
        && !expected_server_pubkeys
            .iter()
            .any(|p| *p == signed.server_pubkey_hex)
    {
        return Err(DirectoryError::ServerPubkeyMismatch);
    }

    // (2) server envelope over the canonical preimage (typed, frozen order).
    let unsigned = UnsignedDirectory {
        version: signed.version,
        nodes: &signed.nodes,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        operational_pubkey_hex: &signed.operational_pubkey_hex,
        operational_cert_hex: &signed.operational_cert_hex,
        server_pubkey_hex: &signed.server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned)?;
    let server_pubkey = vkey(&signed.server_pubkey_hex)?;
    server_pubkey
        .verify(&canonical, &sig64(&signed.signature_hex)?)
        .map_err(|_| DirectoryError::BadEnvelopeSignature)?;

    // (3) operational certificate against the pinned root (empty = TOFU).
    let operational = vkey(&signed.operational_pubkey_hex)?;
    let cert = sig64(&signed.operational_cert_hex)?;
    if !expected_root_pubkeys.is_empty() {
        let ok = expected_root_pubkeys
            .iter()
            .filter_map(|h| vkey(h).ok())
            .any(|root| verify_operational_cert(&root, &operational, &cert));
        if !ok {
            return Err(DirectoryError::BadOperationalCert);
        }
    }

    // (4) per-exit descriptor under the operational key; drop unverifiable ones.
    let exits = signed
        .nodes
        .into_iter()
        .filter(|n| exit_descriptor_ok(&operational, &n.exit))
        .map(|n| VerifiedExit {
            exit_id: n.exit.exit_id,
            exit_ed25519_pubkey: n.exit.exit_ed25519_pubkey,
            exit_x25519_multihop_pubkey: n.exit.exit_x25519_multihop_pubkey,
            endpoint: n.exit.endpoint,
            country: n.country,
            city: n.city,
            weight: n.weight,
        })
        .collect();

    Ok(VerifiedDirectory {
        exits,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}
