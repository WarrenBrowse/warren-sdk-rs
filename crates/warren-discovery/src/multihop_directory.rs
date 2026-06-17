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
//! 4. **relay descriptor + node attestation**: the operational key also signs
//!    each node's relay (entry) descriptor and a geo+identity attestation
//!    (`WARREN_PKI_OPERATIONAL_NODE_V1 || relay_id || exit_ed25519_pubkey ||
//!    asn_be || country`). The attestation is the ONLY operational-key binding
//!    of `exit_ed25519_pubkey` (the exit descriptor signs the x25519 key, not
//!    the RPK identity), so it must be verified before the RPK is used as a TLS
//!    pin. A node failing any of the four checks is dropped (`node_fully_vouched`).

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
/// PKI context: operational key signs a relay (entry) descriptor.
pub const WARREN_PKI_OPERATIONAL_RELAY_V1: &[u8] = b"warren/multihop/v1/operational-signs-relay";
/// PKI context: operational key attests a node's geo + exit RPK identity.
pub const WARREN_PKI_OPERATIONAL_NODE_V1: &[u8] = b"warren/multihop/v1/operational-signs-node";

/// Largest accepted directory validity window (`expires_at - signed_at`).
/// Mirrors the signed relay list's anti-freeze cap: a compromised server cannot
/// mint a directory that outlives revocation.
const MAX_VALIDITY_SECS: u64 = 7 * 24 * 60 * 60;

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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    /// The exit runs no in-tunnel DNS forwarder: name resolution over the tunnel
    /// will fail unless the client points the netstack at another resolver.
    pub dns_disabled: bool,
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
    /// Nodes dropped because they were not fully vouched (bad relay/exit
    /// descriptor, bad attestation, or an unattested `dns_disabled = true`).
    /// Surfaced for diagnostics, matching warren-core; a non-zero value on an
    /// otherwise-valid directory signals a tampered or partially-stale fleet.
    pub dropped: usize,
}

impl VerifiedDirectory {
    /// True if `now_unix_secs` is at or past the signed expiry (anti-freeze).
    /// Mirrors [`VerifiedRelayList::is_expired`](crate::VerifiedRelayList::is_expired).
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }
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
    /// The validity window (`expires_at - signed_at`) exceeds the cap
    /// (`MAX_VALIDITY_SECS`): a compromised server cannot outrun revocation.
    #[error("directory validity window too long")]
    ValidityTooLong,
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

/// Outcome of verifying an exit descriptor under the operational key.
enum ExitAttestation {
    /// `/v2` verified: `dns_disabled` is bound under the signature, trustworthy.
    Attested {
        /// The signed value of the `dns_disabled` bit.
        dns_disabled: bool,
    },
    /// Only legacy `/v1` verified: `dns_disabled` is NOT covered by the
    /// signature (the `/v1` preimage omits the dns byte), so it is advisory.
    Unattested,
    /// Neither PKI context verified the descriptor.
    Rejected,
}

/// Verifies an exit descriptor under the operational key (`/v2` then `/v1`),
/// reporting whether `dns_disabled` was covered by the signature. The `/v2` and
/// `/v1` contexts use distinct domain-separation tags, so a `/v1` signature can
/// never satisfy the `/v2` verifier: a descriptor that only validates under
/// `/v1` carries an unauthenticated `dns_disabled` bit (mirrors warren-core
/// `verify_exit_descriptor_with_dns_attestation`).
fn exit_descriptor_attestation(
    operational: &VerifyingKey,
    d: &ExitDescriptorSigned,
) -> ExitAttestation {
    let sig = Signature::from_bytes(&d.signature);
    let mut v2 = Vec::with_capacity(WARREN_PKI_OPERATIONAL_EXIT_V2.len() + 16 + 32 + 1);
    v2.extend_from_slice(WARREN_PKI_OPERATIONAL_EXIT_V2);
    v2.extend_from_slice(&d.exit_id);
    v2.extend_from_slice(&d.exit_x25519_multihop_pubkey);
    v2.push(u8::from(d.dns_disabled));
    if operational.verify(&v2, &sig).is_ok() {
        return ExitAttestation::Attested {
            dns_disabled: d.dns_disabled,
        };
    }
    let mut v1 = Vec::with_capacity(WARREN_PKI_OPERATIONAL_EXIT_V1.len() + 16 + 32);
    v1.extend_from_slice(WARREN_PKI_OPERATIONAL_EXIT_V1);
    v1.extend_from_slice(&d.exit_id);
    v1.extend_from_slice(&d.exit_x25519_multihop_pubkey);
    if operational.verify(&v1, &sig).is_ok() {
        return ExitAttestation::Unattested;
    }
    ExitAttestation::Rejected
}

/// Verifies a relay (entry) descriptor under the operational key:
/// `WARREN_PKI_OPERATIONAL_RELAY_V1 || relay_id(16) || relay_ed25519_pubkey(32)`.
fn relay_descriptor_ok(operational: &VerifyingKey, d: &RelayDescriptorSigned) -> bool {
    let mut payload = Vec::with_capacity(WARREN_PKI_OPERATIONAL_RELAY_V1.len() + 16 + 32);
    payload.extend_from_slice(WARREN_PKI_OPERATIONAL_RELAY_V1);
    payload.extend_from_slice(&d.relay_id);
    payload.extend_from_slice(&d.relay_ed25519_pubkey);
    operational
        .verify(&payload, &Signature::from_bytes(&d.signature))
        .is_ok()
}

/// Verifies a node's geo + exit-RPK attestation under the operational key:
/// `WARREN_PKI_OPERATIONAL_NODE_V1 || node_id(16) || exit_ed25519_pubkey(32) ||
/// asn_u32_be(4) || country_bytes`. This is the only operational-key binding of
/// `exit_ed25519_pubkey` (the exit descriptor signs the x25519 key, not the RPK
/// identity), so without it the TLS pin would be server-trusted, not PKI-bound.
fn node_attestation_ok(operational: &VerifyingKey, n: &NodeEntry) -> bool {
    let Ok(att) = hex::decode(&n.attestation_hex) else {
        return false;
    };
    let Ok(att): Result<[u8; 64], _> = att.try_into() else {
        return false;
    };
    let mut payload =
        Vec::with_capacity(WARREN_PKI_OPERATIONAL_NODE_V1.len() + 16 + 32 + 4 + n.country.len());
    payload.extend_from_slice(WARREN_PKI_OPERATIONAL_NODE_V1);
    payload.extend_from_slice(&n.relay.relay_id);
    payload.extend_from_slice(&n.exit.exit_ed25519_pubkey);
    payload.extend_from_slice(&n.asn.to_be_bytes());
    payload.extend_from_slice(n.country.as_bytes());
    operational
        .verify(&payload, &Signature::from_bytes(&att))
        .is_ok()
}

/// Verifies every operational-signed part of `n` (relay descriptor, exit
/// descriptor, geo+identity attestation) and, when fully vouched, returns the
/// effective `dns_disabled` to trust. A node failing any check is dropped
/// (matches warren-core `node_fully_vouched`).
///
/// Downgrade-attack defense on `dns_disabled`: when only the legacy `/v1` exit
/// signature verifies, the bit is unauthenticated. A `/v1`-only descriptor
/// advertising `dns_disabled = true` is a suspected downgrade and is dropped
/// (warren-core refuses the dial); otherwise the bit is forced to `false`.
fn node_effective_dns_disabled(operational: &VerifyingKey, n: &NodeEntry) -> Option<bool> {
    if !relay_descriptor_ok(operational, &n.relay) || !node_attestation_ok(operational, n) {
        return None;
    }
    match exit_descriptor_attestation(operational, &n.exit) {
        ExitAttestation::Attested { dns_disabled } => Some(dns_disabled),
        ExitAttestation::Unattested if !n.exit.dns_disabled => Some(false),
        ExitAttestation::Unattested | ExitAttestation::Rejected => None,
    }
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

    // Anti-freeze: cap the validity window so a replayed/forged-but-signed
    // directory cannot outlive revocation (caller still enforces expires_at).
    // Checked only after the envelope signature so all anti-freeze decisions
    // are made on authenticated fields (matching `verify_signed_relay_list`).
    if signed.expires_at.saturating_sub(signed.signed_at) > MAX_VALIDITY_SECS {
        return Err(DirectoryError::ValidityTooLong);
    }

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

    // (4) every operational-signed part of each node (relay descriptor, exit
    // descriptor, geo+RPK attestation); drop any node not fully vouched.
    let node_count = signed.nodes.len();
    let exits: Vec<VerifiedExit> = signed
        .nodes
        .into_iter()
        .filter_map(|n| {
            let dns_disabled = node_effective_dns_disabled(&operational, &n)?;
            Some(VerifiedExit {
                exit_id: n.exit.exit_id,
                exit_ed25519_pubkey: n.exit.exit_ed25519_pubkey,
                exit_x25519_multihop_pubkey: n.exit.exit_x25519_multihop_pubkey,
                endpoint: n.exit.endpoint,
                country: n.country,
                city: n.city,
                weight: n.weight,
                dns_disabled,
            })
        })
        .collect();

    Ok(VerifiedDirectory {
        dropped: node_count - exits.len(),
        exits,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}

/// Server-side directory minting for tests. Gated so it never compiles into the
/// production surface: available to in-crate tests (`cfg(test)`) and to other
/// crates' tests through the `test-helpers` feature. It mirrors the operator's
/// signing exactly (canonical preimage order, full PKI chain) so a facade or
/// integration test can exercise [`verify_multihop_directory`] end to end.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::{
        ExitDescriptorSigned, MULTIHOP_DIRECTORY_VERSION, NodeEntry, RelayDescriptorSigned,
        SignedDirectory, UnsignedDirectory, WARREN_PKI_OPERATIONAL_EXIT_V2,
        WARREN_PKI_OPERATIONAL_NODE_V1, WARREN_PKI_OPERATIONAL_RELAY_V1,
        WARREN_PKI_ROOT_OPERATIONAL_V1,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn op_sign(op: &SigningKey, ctx: &[u8], parts: &[&[u8]]) -> [u8; 64] {
        let mut payload = ctx.to_vec();
        for p in parts {
            payload.extend_from_slice(p);
        }
        op.sign(&payload).to_bytes()
    }

    fn vouched_node(op: &SigningKey, tag: u8, country: &str, asn: u32) -> NodeEntry {
        let endpoint: std::net::SocketAddr = format!("198.51.100.{tag}:443").parse().unwrap();
        let relay_id = [tag; 16];
        let relay_ed = [tag.wrapping_add(1); 32];
        let exit_id = [tag.wrapping_add(2); 16];
        let exit_ed = [tag.wrapping_add(3); 32];
        let exit_x = [tag.wrapping_add(4); 32];
        let relay_sig = op_sign(op, WARREN_PKI_OPERATIONAL_RELAY_V1, &[&relay_id, &relay_ed]);
        let exit_sig = op_sign(
            op,
            WARREN_PKI_OPERATIONAL_EXIT_V2,
            &[&exit_id, &exit_x, &[0u8]],
        );
        let attestation = op_sign(
            op,
            WARREN_PKI_OPERATIONAL_NODE_V1,
            &[&relay_id, &exit_ed, &asn.to_be_bytes(), country.as_bytes()],
        );
        NodeEntry {
            relay: RelayDescriptorSigned {
                relay_id,
                relay_ed25519_pubkey: relay_ed,
                endpoint,
                signature: relay_sig,
            },
            exit: ExitDescriptorSigned {
                exit_id,
                exit_ed25519_pubkey: exit_ed,
                exit_x25519_multihop_pubkey: exit_x,
                endpoint,
                signature: exit_sig,
                dns_disabled: false,
            },
            country: country.to_owned(),
            city: "City".to_owned(),
            asn,
            weight: 100,
            attestation_hex: hex::encode(attestation),
        }
    }

    /// Mints the wire JSON the API serves at `GET /v1/multihop/directory`: two
    /// fully-vouched nodes, the operational key certified by `root`, the envelope
    /// signed by `server`. Pass a `root` the verifier does not pin to exercise the
    /// operational-cert rejection path.
    #[must_use]
    pub fn mint_directory_json(
        root: &SigningKey,
        op: &SigningKey,
        server: &SigningKey,
        generation: u64,
        signed_at: u64,
        expires_at: u64,
    ) -> String {
        let nodes = vec![
            vouched_node(op, 10, "RO", 100),
            vouched_node(op, 20, "NL", 200),
        ];
        let op_pub = op.verifying_key().to_bytes();
        let cert = op_sign(root, WARREN_PKI_ROOT_OPERATIONAL_V1, &[&op_pub]);
        let unsigned = UnsignedDirectory {
            version: MULTIHOP_DIRECTORY_VERSION,
            nodes: &nodes,
            generation,
            signed_at,
            expires_at,
            operational_pubkey_hex: &hex::encode(op_pub),
            operational_cert_hex: &hex::encode(cert),
            server_pubkey_hex: &hex::encode(server.verifying_key().to_bytes()),
        };
        let canonical = serde_json::to_vec(&unsigned).unwrap();
        let sig = server.sign(&canonical).to_bytes();
        let full = SignedDirectory {
            version: MULTIHOP_DIRECTORY_VERSION,
            nodes,
            generation,
            signed_at,
            expires_at,
            operational_pubkey_hex: hex::encode(op_pub),
            operational_cert_hex: hex::encode(cert),
            server_pubkey_hex: hex::encode(server.verifying_key().to_bytes()),
            signature_hex: hex::encode(sig),
        };
        serde_json::to_string(&full).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn op_sign(op: &SigningKey, ctx: &[u8], parts: &[&[u8]]) -> [u8; 64] {
        let mut payload = ctx.to_vec();
        for p in parts {
            payload.extend_from_slice(p);
        }
        op.sign(&payload).to_bytes()
    }

    /// Mints a fully-vouched node (relay desc + exit desc v2 + attestation all
    /// signed by `op`).
    fn signed_node(op: &SigningKey, tag: u8, country: &str, asn: u32) -> NodeEntry {
        let endpoint: SocketAddr = format!("198.51.100.{tag}:443").parse().unwrap();
        let relay_id = [tag; 16];
        let relay_ed = [tag.wrapping_add(1); 32];
        let exit_id = [tag.wrapping_add(2); 16];
        let exit_ed = [tag.wrapping_add(3); 32];
        let exit_x = [tag.wrapping_add(4); 32];
        let relay_sig = op_sign(op, WARREN_PKI_OPERATIONAL_RELAY_V1, &[&relay_id, &relay_ed]);
        let exit_sig = op_sign(
            op,
            WARREN_PKI_OPERATIONAL_EXIT_V2,
            &[&exit_id, &exit_x, &[0u8]],
        );
        let attestation = op_sign(
            op,
            WARREN_PKI_OPERATIONAL_NODE_V1,
            &[&relay_id, &exit_ed, &asn.to_be_bytes(), country.as_bytes()],
        );
        NodeEntry {
            relay: RelayDescriptorSigned {
                relay_id,
                relay_ed25519_pubkey: relay_ed,
                endpoint,
                signature: relay_sig,
            },
            exit: ExitDescriptorSigned {
                exit_id,
                exit_ed25519_pubkey: exit_ed,
                exit_x25519_multihop_pubkey: exit_x,
                endpoint,
                signature: exit_sig,
                dns_disabled: false,
            },
            country: country.to_owned(),
            city: "City".to_owned(),
            asn,
            weight: 100,
            attestation_hex: hex::encode(attestation),
        }
    }

    /// Builds a directory JSON signed by `server`, with `op` certified by `root`.
    fn signed_directory_json(
        root: &SigningKey,
        op: &SigningKey,
        server: &SigningKey,
        nodes: Vec<NodeEntry>,
        signed_at: u64,
        expires_at: u64,
    ) -> String {
        let op_pub = op.verifying_key().to_bytes();
        let cert = op_sign(root, WARREN_PKI_ROOT_OPERATIONAL_V1, &[&op_pub]);
        let unsigned = UnsignedDirectory {
            version: MULTIHOP_DIRECTORY_VERSION,
            nodes: &nodes,
            generation: 1,
            signed_at,
            expires_at,
            operational_pubkey_hex: &hex::encode(op_pub),
            operational_cert_hex: &hex::encode(cert),
            server_pubkey_hex: &hex::encode(server.verifying_key().to_bytes()),
        };
        let canonical = serde_json::to_vec(&unsigned).unwrap();
        let sig = server.sign(&canonical).to_bytes();
        let full = SignedDirectory {
            version: MULTIHOP_DIRECTORY_VERSION,
            nodes,
            generation: 1,
            signed_at,
            expires_at,
            operational_pubkey_hex: hex::encode(op_pub),
            operational_cert_hex: hex::encode(cert),
            server_pubkey_hex: hex::encode(server.verifying_key().to_bytes()),
            signature_hex: hex::encode(sig),
        };
        serde_json::to_string(&full).unwrap()
    }

    fn server_pin(server: &SigningKey) -> String {
        hex::encode(server.verifying_key().to_bytes())
    }

    #[test]
    fn happy_path_returns_all_fully_vouched_exits() {
        let (root, op, server) = (key(1), key(2), key(3));
        let nodes = vec![
            signed_node(&op, 10, "RO", 100),
            signed_node(&op, 20, "NL", 200),
        ];
        let json = signed_directory_json(&root, &op, &server, nodes, 1000, 1000 + 3600);
        let dir = verify_multihop_directory(
            &json,
            &[&server_pin(&server)],
            &[&hex::encode(root.verifying_key().to_bytes())],
        )
        .expect("verifies");
        assert_eq!(dir.exits.len(), 2, "both fully-vouched nodes returned");
        assert_eq!(dir.exits[0].country, "RO");
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(matches!(
            verify_multihop_directory("{not json", &[], &[]),
            Err(DirectoryError::Json(_))
        ));
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        // Parity with the signed relay list: the directory wire form is strict, so
        // a newer-schema (or tampered) directory is rejected rather than silently
        // accepted with fields ignored.
        let (root, op, server) = (key(1), key(2), key(3));
        let json = signed_directory_json(&root, &op, &server, vec![], 1000, 1000 + 3600);
        let tampered = json.replacen('{', "{\"surprise\":true,", 1);
        assert!(matches!(
            verify_multihop_directory(&tampered, &[], &[]),
            Err(DirectoryError::Json(_))
        ));
    }

    #[test]
    fn wrong_server_pin_is_server_pubkey_mismatch() {
        let (root, op, server) = (key(1), key(2), key(3));
        let json = signed_directory_json(
            &root,
            &op,
            &server,
            vec![signed_node(&op, 10, "RO", 100)],
            1000,
            1000 + 3600,
        );
        assert!(matches!(
            verify_multihop_directory(&json, &[&"00".repeat(32)], &[]),
            Err(DirectoryError::ServerPubkeyMismatch)
        ));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let (root, op, server) = (key(1), key(2), key(3));
        let json = signed_directory_json(&root, &op, &server, vec![], 1000, 1000 + 3600)
            .replace("\"version\":2", "\"version\":1");
        assert!(matches!(
            verify_multihop_directory(&json, &[&server_pin(&server)], &[]),
            Err(DirectoryError::UnsupportedVersion { got: 1 })
        ));
    }

    #[test]
    fn validity_window_too_long_is_rejected() {
        let (root, op, server) = (key(1), key(2), key(3));
        let json = signed_directory_json(
            &root,
            &op,
            &server,
            vec![],
            1000,
            1000 + MAX_VALIDITY_SECS + 1,
        );
        assert!(matches!(
            verify_multihop_directory(&json, &[&server_pin(&server)], &[]),
            Err(DirectoryError::ValidityTooLong)
        ));
    }

    #[test]
    fn tampered_envelope_is_bad_envelope_signature() {
        let (root, op, server) = (key(1), key(2), key(3));
        // Sign with `server` but pin (and present) a different server key by
        // re-signing the body with `other` while keeping `server`'s pin? Simpler:
        // flip the city, which is inside the signed `nodes`, invalidating the
        // envelope signature without changing the pinned server key.
        let mut json = signed_directory_json(
            &root,
            &op,
            &server,
            vec![signed_node(&op, 10, "RO", 100)],
            1000,
            1000 + 3600,
        );
        json = json.replacen("\"City\"", "\"Citx\"", 1);
        assert!(matches!(
            verify_multihop_directory(&json, &[&server_pin(&server)], &[]),
            Err(DirectoryError::BadEnvelopeSignature)
        ));
    }

    #[test]
    fn bad_operational_cert_against_pinned_root_is_rejected() {
        let (root, op, server) = (key(1), key(2), key(3));
        let json = signed_directory_json(
            &root,
            &op,
            &server,
            vec![signed_node(&op, 10, "RO", 100)],
            1000,
            1000 + 3600,
        );
        // Pin a DIFFERENT root that never certified this operational key.
        let wrong_root = key(9);
        assert!(matches!(
            verify_multihop_directory(
                &json,
                &[&server_pin(&server)],
                &[&hex::encode(wrong_root.verifying_key().to_bytes())]
            ),
            Err(DirectoryError::BadOperationalCert)
        ));
    }

    #[test]
    fn invalid_hex_field_is_rejected() {
        let (root, op, server) = (key(1), key(2), key(3));
        let json = signed_directory_json(&root, &op, &server, vec![], 1000, 1000 + 3600).replacen(
            &server_pin(&server),
            "zz",
            1,
        );
        // The server pin set is empty so the bad hex is hit at vkey() decode.
        assert!(matches!(
            verify_multihop_directory(&json, &[], &[]),
            Err(DirectoryError::InvalidHex)
        ));
    }

    #[test]
    fn forged_exit_descriptor_node_is_dropped_not_returned() {
        let (root, op, server) = (key(1), key(2), key(3));
        let good = signed_node(&op, 10, "RO", 100);
        // Forge: a node whose exit descriptor was signed by a NON-operational key.
        let mut bad = signed_node(&op, 20, "NL", 200);
        let forger = key(99);
        bad.exit.signature = op_sign(
            &forger,
            WARREN_PKI_OPERATIONAL_EXIT_V2,
            &[
                &bad.exit.exit_id,
                &bad.exit.exit_x25519_multihop_pubkey,
                &[0u8],
            ],
        );
        let json = signed_directory_json(&root, &op, &server, vec![good, bad], 1000, 1000 + 3600);
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert_eq!(dir.exits.len(), 1, "the forged-exit node must be dropped");
        assert_eq!(dir.exits[0].country, "RO");
        assert_eq!(
            dir.dropped, 1,
            "the dropped count surfaces the rejected node"
        );
    }

    #[test]
    fn directory_is_expired_at_the_expiry_boundary() {
        let (root, op, server) = (key(1), key(2), key(3));
        let nodes = vec![signed_node(&op, 10, "RO", 100)];
        let json = signed_directory_json(&root, &op, &server, nodes, 1000, 1000 + 3600);
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert!(
            !dir.is_expired(4599),
            "one second before expiry is still fresh"
        );
        assert!(dir.is_expired(4600), "at expires_at the directory is stale");
        assert_eq!(dir.dropped, 0, "a fully-vouched fleet drops nothing");
    }

    #[test]
    fn forged_attestation_node_is_dropped() {
        // The attestation binds exit_ed25519_pubkey: a node whose attestation was
        // not signed by the operational key must be dropped (this is the check
        // that makes the TLS RPK pin trustworthy).
        let (root, op, server) = (key(1), key(2), key(3));
        let mut bad = signed_node(&op, 30, "DE", 300);
        bad.attestation_hex = hex::encode([0xAAu8; 64]);
        let json = signed_directory_json(&root, &op, &server, vec![bad], 1000, 1000 + 3600);
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert!(dir.exits.is_empty(), "unattested node must be dropped");
    }

    #[test]
    fn attestation_over_relabeled_country_is_dropped() {
        // A compromised server relabeling the country (geo diversity attack) must
        // be dropped: the attestation covers `country`.
        let (root, op, server) = (key(1), key(2), key(3));
        let mut bad = signed_node(&op, 40, "RO", 400);
        bad.country = "DE".to_owned(); // attestation was signed over "RO"
        let json = signed_directory_json(&root, &op, &server, vec![bad], 1000, 1000 + 3600);
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert!(
            dir.exits.is_empty(),
            "relabeled-country node must be dropped"
        );
    }

    #[test]
    fn forged_relay_descriptor_node_is_dropped() {
        let (root, op, server) = (key(1), key(2), key(3));
        let mut bad = signed_node(&op, 50, "FR", 500);
        bad.relay.signature = [0u8; 64];
        let json = signed_directory_json(&root, &op, &server, vec![bad], 1000, 1000 + 3600);
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert!(
            dir.exits.is_empty(),
            "node with a bad relay descriptor must be dropped"
        );
    }

    #[test]
    fn directory_field_order_is_frozen() {
        // The server envelope signs the canonical JSON of these structs, so a
        // reordering of any field would silently break wire compatibility with
        // warren-core. Pin the canonical substring order (parity with the signed
        // relay list's field-order vector tests).
        let (root, op, server) = (key(1), key(2), key(3));
        let json = signed_directory_json(
            &root,
            &op,
            &server,
            vec![signed_node(&op, 10, "RO", 100)],
            7,
            99,
        );
        let order = [
            r#""version":"#,
            r#""nodes":["#,
            // NodeEntry -> relay (RelayDescriptorSigned) field order.
            r#""relay":{"#,
            r#""relay_id":"#,
            r#""relay_ed25519_pubkey":"#,
            r#""endpoint":"#,
            r#""signature":"#,
            // NodeEntry -> exit (ExitDescriptorSigned) field order.
            r#""exit":{"#,
            r#""exit_id":"#,
            r#""exit_ed25519_pubkey":"#,
            r#""exit_x25519_multihop_pubkey":"#,
            r#""endpoint":"#,
            r#""signature":"#,
            // NodeEntry tail.
            r#""country":"#,
            r#""city":"#,
            r#""asn":"#,
            r#""weight":"#,
            r#""attestation_hex":"#,
            // SignedDirectory tail.
            r#""generation":"#,
            r#""signed_at":"#,
            r#""expires_at":"#,
            r#""operational_pubkey_hex":"#,
            r#""operational_cert_hex":"#,
            r#""server_pubkey_hex":"#,
            r#""signature_hex":"#,
        ];
        let mut last = 0usize;
        for needle in order {
            let pos = json[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("missing {needle} in {json}"));
            last += pos + needle.len();
        }
    }

    /// Re-signs a node's exit descriptor under the legacy `/v1` payload (which
    /// does NOT cover `dns_disabled`), advertising `dns_disabled_advertised` on
    /// the wire. Models a directory served before the `/v2` dns attestation.
    fn signed_node_v1(
        op: &SigningKey,
        tag: u8,
        country: &str,
        asn: u32,
        dns_disabled_advertised: bool,
    ) -> NodeEntry {
        let mut n = signed_node(op, tag, country, asn);
        n.exit.dns_disabled = dns_disabled_advertised;
        n.exit.signature = op_sign(
            op,
            WARREN_PKI_OPERATIONAL_EXIT_V1,
            &[&n.exit.exit_id, &n.exit.exit_x25519_multihop_pubkey],
        );
        n
    }

    #[test]
    fn v1_only_descriptor_with_dns_disabled_false_verifies_as_false() {
        // A legacy /v1 descriptor (no dns attestation) advertising the default
        // dns_disabled=false is still accepted, surfacing dns_disabled=false.
        let (root, op, server) = (key(1), key(2), key(3));
        let node = signed_node_v1(&op, 10, "RO", 100, false);
        let json = signed_directory_json(&root, &op, &server, vec![node], 1000, 1000 + 3600);
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert_eq!(dir.exits.len(), 1, "legacy v1 descriptor is still accepted");
        assert!(!dir.exits[0].dns_disabled);
    }

    #[test]
    fn v1_only_descriptor_advertising_dns_disabled_true_is_dropped() {
        // Downgrade-attack defense: a /v1 signature does not cover dns_disabled,
        // so a descriptor that only validates under /v1 yet advertises
        // dns_disabled=true is a suspected downgrade and must be dropped (parity
        // with warren-core, which refuses the dial on an Unattested true bit).
        let (root, op, server) = (key(1), key(2), key(3));
        let node = signed_node_v1(&op, 10, "RO", 100, true);
        let json = signed_directory_json(&root, &op, &server, vec![node], 1000, 1000 + 3600);
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert!(
            dir.exits.is_empty(),
            "unattested dns_disabled=true node must be dropped"
        );
    }

    #[test]
    fn dns_disabled_round_trips_and_surfaces_on_the_verified_exit() {
        // dns_disabled is a security-relevant flag (it gates DNS-over-tunnel) and
        // is covered by the exit descriptor v2 preimage, so a `true` value must
        // both verify and surface on the VerifiedExit.
        let (root, op, server) = (key(1), key(2), key(3));
        let mut node = signed_node(&op, 10, "RO", 100);
        node.exit.dns_disabled = true;
        // Re-sign the exit descriptor over the dns_disabled=1 preimage.
        node.exit.signature = op_sign(
            &op,
            WARREN_PKI_OPERATIONAL_EXIT_V2,
            &[
                &node.exit.exit_id,
                &node.exit.exit_x25519_multihop_pubkey,
                &[1u8],
            ],
        );
        let json = signed_directory_json(&root, &op, &server, vec![node], 1000, 1000 + 3600);
        // When true, the byte is serialized; when false it is omitted (default).
        assert!(json.contains("\"dns_disabled\":true"));
        let dir = verify_multihop_directory(&json, &[&server_pin(&server)], &[]).unwrap();
        assert_eq!(dir.exits.len(), 1);
        assert!(dir.exits[0].dns_disabled);
    }
}
