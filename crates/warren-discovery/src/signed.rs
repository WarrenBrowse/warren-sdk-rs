//! Signed exit list (`warren-relays.json` v5) verification.
//!
//! An attacker who can intercept the HTTP fetch could substitute their own
//! exits. The warren-api server's Ed25519 signature binds the list to a
//! legitimate operator; the client verifies against a pinned `server_pubkey`
//! (or TOFU on first boot).
//!
//! Canonical format (frozen at v5, never modify without rotating the version):
//!
//! ```text
//! canonical_bytes = serde_json::to_vec(UnsignedRelayList {
//!     version, relays, generation, signed_at, expires_at, server_pubkey_hex,
//! })
//! signature = Ed25519::sign(server_secret_key, canonical_bytes)
//! ```
//!
//! Field order in the struct determines JSON order, which is part of the signed
//! preimage. `generation` is a monotonic content version (anti-rollback);
//! `expires_at` is a signed expiry (anti-freeze/replay). The crate stays
//! clock-free; the caller enforces both via [`VerifiedRelayList`].

use std::net::SocketAddr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::exit_id::ExitId;
use crate::relay::{Location, Relay, RelayList};

/// Current signed format version. Bumping is an incompatible rotation.
pub const SIGNED_VERSION: u32 = 5;

/// Wire representation of one relay in the signed JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRelay {
    /// 64-char hex of the Ed25519 endpoint pubkey.
    pub endpoint_id: String,
    /// Stable operator-assigned identifier (32-char hex in JSON).
    pub exit_id: ExitId,
    /// `host:port` addresses where the exit is reachable.
    pub ip_addrs: Vec<String>,
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// City name (free form).
    pub city: String,
    /// Relative weight for weighted selection.
    pub weight: u64,
    /// `false` disables the exit without removing it from the list.
    pub active: bool,
    /// `true` when the exit attests working IPv6 egress.
    #[serde(default)]
    pub ipv6_egress: bool,
}

/// Signed exit list (full wire format).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayList {
    /// Must equal [`SIGNED_VERSION`].
    pub version: u32,
    /// Exits announced by the server.
    pub relays: Vec<JsonRelay>,
    /// Monotonic content version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the list was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the list must not be trusted (anti-freeze).
    pub expires_at: u64,
    /// 64-char hex of the server's verifying key.
    pub server_pubkey_hex: String,
    /// 128-char hex Ed25519 signature over the canonical bytes.
    pub signature_hex: String,
}

/// Signature preimage. Field order must match [`SignedRelayList`].
#[derive(Debug, Serialize)]
struct UnsignedRelayList<'a> {
    version: u32,
    relays: &'a [JsonRelay],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    server_pubkey_hex: &'a str,
}

/// Result of a successful verification: resolved relays plus the
/// freshness/anti-rollback metadata the caller must enforce.
#[derive(Debug, Clone)]
pub struct VerifiedRelayList {
    /// Resolved relays.
    pub relays: RelayList,
    /// Monotonic content version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the list was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the list is stale.
    pub expires_at: u64,
    /// Hex Ed25519 pubkey that signed (and verified) this list. The facade
    /// persists this for trust-on-first-use pinning.
    pub server_pubkey_hex: String,
}

impl VerifiedRelayList {
    /// True if `now_unix_secs` is at or past the signed expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }
}

/// Errors from verifying a signed relay list.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignedError {
    /// Invalid JSON or unexpected structure.
    #[error("invalid signed relay list: {0}")]
    Json(#[from] serde_json::Error),
    /// `version != SIGNED_VERSION`.
    #[error("unsupported signed relay list version: {got} (expected {SIGNED_VERSION})")]
    UnsupportedVersion {
        /// Version actually received.
        got: u32,
    },
    /// The declared server pubkey is not in the pinned set. The keys are kept
    /// as fields for programmatic inspection but deliberately NOT rendered in
    /// the message (no-log discipline: a pubkey is identity material).
    #[error("server pubkey not in the pinned set")]
    ServerPubkeyMismatch {
        /// Pubkey hex announced in the JSON.
        got: String,
        /// Comma-joined pinned set.
        expected: String,
    },
    /// The signed validity window (`expires_at - signed_at`) is implausibly long.
    #[error("signed relay list validity window too long")]
    ValidityTooLong,
    /// Invalid hex for the pubkey or the signature.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// Received pubkey is not a valid Ed25519 point.
    #[error("server pubkey is not a valid Ed25519 point")]
    PubkeyNotOnCurve,
    /// Signature does not verify against the pubkey and canonical bytes.
    #[error("signature verification failed")]
    BadSignature,
    /// A relay entry has an invalid endpoint id or address.
    #[error("invalid relay entry: {0}")]
    Relay(String),
}

/// Signs a relay list (server side; used here for fixtures and tests).
///
/// # Panics
///
/// Panics only if JSON serialization of the scalar-only preimage fails, which
/// is infallible in practice.
#[must_use]
pub fn sign_relay_list(
    relays: Vec<JsonRelay>,
    server_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedRelayList {
    let server_pubkey_hex = hex::encode(server_key.verifying_key().as_bytes());
    let unsigned = UnsignedRelayList {
        version: SIGNED_VERSION,
        relays: &relays,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex: &server_pubkey_hex,
    };
    let canonical =
        serde_json::to_vec(&unsigned).expect("UnsignedRelayList JSON serialization is infallible");
    let signature = server_key.sign(&canonical);
    SignedRelayList {
        version: SIGNED_VERSION,
        relays,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Verifies a signed relay list, optionally pinning the server pubkey.
///
/// `expected_server_pubkey = None` is TOFU (any self-consistent signature).
///
/// # Errors
///
/// See [`SignedError`].
pub fn verify_signed_relay_list(
    s: &str,
    expected_server_pubkey: Option<&str>,
) -> Result<VerifiedRelayList, SignedError> {
    match expected_server_pubkey {
        Some(p) => verify_signed_relay_list_any(s, &[p]),
        None => verify_signed_relay_list_any(s, &[]),
    }
}

/// Multi-key variant for pinned-key rotation: accepts the list if signed by any
/// of `expected_server_pubkeys` (empty slice means TOFU).
///
/// # Errors
///
/// See [`SignedError`].
pub fn verify_signed_relay_list_any(
    s: &str,
    expected_server_pubkeys: &[&str],
) -> Result<VerifiedRelayList, SignedError> {
    let signed: SignedRelayList = serde_json::from_str(s)?;
    if signed.version != SIGNED_VERSION {
        return Err(SignedError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !expected_server_pubkeys.is_empty()
        && !expected_server_pubkeys
            .iter()
            .any(|p| *p == signed.server_pubkey_hex)
    {
        return Err(SignedError::ServerPubkeyMismatch {
            got: signed.server_pubkey_hex.clone(),
            expected: expected_server_pubkeys.join(","),
        });
    }

    let pubkey_bytes: [u8; 32] = hex::decode(&signed.server_pubkey_hex)
        .map_err(|_| SignedError::InvalidHex)?
        .try_into()
        .map_err(|_| SignedError::InvalidHex)?;
    let server_pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| SignedError::PubkeyNotOnCurve)?;

    let sig_bytes: [u8; 64] = hex::decode(&signed.signature_hex)
        .map_err(|_| SignedError::InvalidHex)?
        .try_into()
        .map_err(|_| SignedError::InvalidHex)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let unsigned = UnsignedRelayList {
        version: signed.version,
        relays: &signed.relays,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: &signed.server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(SignedError::Json)?;
    server_pubkey
        .verify(&canonical, &signature)
        .map_err(|_| SignedError::BadSignature)?;

    // Bound the authenticated validity window: a compromised signer cannot mint
    // a list that anti-rollback can never supersede by setting a decade-long
    // expiry. Clock-free (relationship between two signed fields).
    const MAX_VALIDITY_SECS: u64 = 7 * 24 * 60 * 60;
    if signed.expires_at.saturating_sub(signed.signed_at) > MAX_VALIDITY_SECS {
        return Err(SignedError::ValidityTooLong);
    }

    let relays: Result<Vec<_>, SignedError> =
        signed.relays.into_iter().map(json_relay_to_relay).collect();
    Ok(VerifiedRelayList {
        relays: RelayList::new(relays?),
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: signed.server_pubkey_hex,
    })
}

/// Decodes a relay `endpoint_id` into the 32-byte exit pubkey.
///
/// warren-api publishes it as a Warren SS58 (`wb…`) address since the SS58
/// migration; the 64-char hex form is accepted as a fallback for legacy or
/// locally-authored lists. A hex string is never a valid SS58 address and
/// vice-versa, so the dispatch is unambiguous (matches warren-core).
fn decode_endpoint_id(s: &str) -> Result<[u8; 32], SignedError> {
    if let Ok(bytes) = warren_identity::ss58::decode(s) {
        return Ok(bytes);
    }
    hex::decode(s)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| SignedError::Relay("invalid relay endpoint id".to_owned()))
}

fn json_relay_to_relay(r: JsonRelay) -> Result<Relay, SignedError> {
    let endpoint_id = decode_endpoint_id(&r.endpoint_id)?;
    let mut addrs: Vec<SocketAddr> = Vec::with_capacity(r.ip_addrs.len());
    for raw in &r.ip_addrs {
        addrs.push(
            raw.parse()
                .map_err(|_| SignedError::Relay("invalid relay socket address".to_owned()))?,
        );
    }
    Ok(Relay::new(
        endpoint_id,
        r.exit_id,
        addrs,
        Location::new(r.country, r.city),
        r.weight,
        r.active,
    )
    .with_ipv6_egress(r.ipv6_egress))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_server_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn sample_relay() -> JsonRelay {
        JsonRelay {
            endpoint_id: "00".repeat(32),
            exit_id: ExitId::from_bytes([0xaa; 16]),
            ip_addrs: vec!["127.0.0.1:1234".to_owned()],
            country: "RO".to_owned(),
            city: "Bucharest".to_owned(),
            weight: 100,
            active: true,
            ipv6_egress: false,
        }
    }

    #[test]
    fn round_trip_sign_then_verify_passes_with_matching_pubkey() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_relay()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let pin = hex::encode(key.verifying_key().as_bytes());
        let v = verify_signed_relay_list(&json, Some(&pin)).expect("verify");
        assert_eq!(v.relays.relays().len(), 1);
        assert_eq!(v.generation, 1);
        assert_eq!(v.expires_at, 1_700_086_400);
    }

    #[test]
    fn verify_rejects_unexpected_server_pubkey() {
        let signed = sign_relay_list(vec![sample_relay()], &fixed_server_key(), 1, 1, 2);
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_signed_relay_list(&json, Some(&hex::encode([0xff; 32]))).unwrap_err();
        assert!(matches!(err, SignedError::ServerPubkeyMismatch { .. }));
    }

    #[test]
    fn server_pubkey_mismatch_display_omits_the_key() {
        // No-log discipline: the pubkey must not appear in the Display.
        let signed = sign_relay_list(vec![sample_relay()], &fixed_server_key(), 1, 1, 2);
        let json = serde_json::to_string(&signed).unwrap();
        let pin = hex::encode([0xff; 32]);
        let err = verify_signed_relay_list(&json, Some(&pin)).unwrap_err();
        let rendered = err.to_string();
        let actual_key = hex::encode(fixed_server_key().verifying_key().as_bytes());
        assert!(
            !rendered.contains(&actual_key),
            "leaked server key: {rendered}"
        );
        assert!(!rendered.contains(&pin), "leaked pin: {rendered}");
    }

    #[test]
    fn verify_rejects_implausibly_long_validity_window() {
        // signed_at..expires_at spanning a year exceeds the 7-day cap.
        let signed = sign_relay_list(
            vec![sample_relay()],
            &fixed_server_key(),
            1,
            1_700_000_000,
            1_700_000_000 + 365 * 24 * 60 * 60,
        );
        let json = serde_json::to_string(&signed).unwrap();
        assert!(matches!(
            verify_signed_relay_list(&json, None).unwrap_err(),
            SignedError::ValidityTooLong
        ));
    }

    #[test]
    fn endpoint_id_accepts_ss58_and_hex() {
        // Legacy hex form.
        assert_eq!(
            decode_endpoint_id(&hex::encode([0xab; 32])).unwrap(),
            [0xab; 32]
        );
        // Production SS58 (`wb…`) form, as warren-api publishes since the SS58
        // migration. Without this the live exit list fails to parse.
        let ss58 = warren_identity::ss58::encode(&[0xcd; 32]);
        assert!(ss58.starts_with("wb"));
        assert_eq!(decode_endpoint_id(&ss58).unwrap(), [0xcd; 32]);
        // Neither form.
        assert!(decode_endpoint_id("not-an-id").is_err());
    }

    #[test]
    fn verify_rejects_unknown_fields() {
        // deny_unknown_fields: an injected field fails parsing (fail closed).
        let signed = sign_relay_list(vec![sample_relay()], &fixed_server_key(), 1, 1, 2);
        let mut value: serde_json::Value = serde_json::to_value(&signed).unwrap();
        value["surprise"] = serde_json::json!("x");
        let json = serde_json::to_string(&value).unwrap();
        assert!(matches!(
            verify_signed_relay_list(&json, None).unwrap_err(),
            SignedError::Json(_)
        ));
    }

    #[test]
    fn verify_rejects_tampered_relays() {
        let signed = sign_relay_list(vec![sample_relay()], &fixed_server_key(), 1, 1, 2);
        let mut tampered = signed.clone();
        tampered.relays[0].ip_addrs = vec!["127.0.0.1:1235".to_owned()];
        let json = serde_json::to_string(&tampered).unwrap();
        assert!(matches!(
            verify_signed_relay_list(&json, None).unwrap_err(),
            SignedError::BadSignature
        ));
    }

    #[test]
    fn verify_rejects_tampered_generation() {
        let signed = sign_relay_list(vec![sample_relay()], &fixed_server_key(), 9, 1, 2);
        let mut tampered = signed.clone();
        tampered.generation = 1;
        let json = serde_json::to_string(&tampered).unwrap();
        assert!(matches!(
            verify_signed_relay_list(&json, None).unwrap_err(),
            SignedError::BadSignature
        ));
    }

    #[test]
    fn verify_rejects_unsupported_version() {
        let json = r#"{"version":1,"relays":[],"generation":0,"signed_at":0,"expires_at":0,"server_pubkey_hex":"00","signature_hex":"00"}"#;
        assert!(matches!(
            verify_signed_relay_list(json, None).unwrap_err(),
            SignedError::UnsupportedVersion { got: 1 }
        ));
    }

    #[test]
    fn field_order_is_frozen() {
        let signed = sign_relay_list(vec![], &fixed_server_key(), 7, 42, 86442);
        let json = serde_json::to_string(&signed).unwrap();
        let order = [
            r#""version":5"#,
            r#""relays":[]"#,
            r#""generation":7"#,
            r#""signed_at":42"#,
            r#""expires_at":86442"#,
            r#""server_pubkey_hex":"#,
            r#""signature_hex":"#,
        ];
        let mut last = 0usize;
        for needle in order {
            let pos = json[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("missing {needle}"));
            last += pos + needle.len();
        }
    }

    #[test]
    fn is_expired_boundary() {
        let signed = sign_relay_list(
            vec![sample_relay()],
            &fixed_server_key(),
            1,
            1_700_000_000,
            1_700_086_400,
        );
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_signed_relay_list(&json, None).unwrap();
        assert!(!v.is_expired(1_700_086_399));
        assert!(v.is_expired(1_700_086_400));
    }
}
