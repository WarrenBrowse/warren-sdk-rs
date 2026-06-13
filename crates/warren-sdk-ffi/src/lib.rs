//! FFI-ready surface for the Warren SDK.
//!
//! Every function here uses plain, owned, generic-free types and a serializable
//! [`FfiError`], which is exactly the shape `uniffi` (Swift, Kotlin, Python,
//! Java) and `flutter_rust_bridge` (Dart) generate bindings from. The binding
//! codegen is wired in a later phase; annotating these functions with
//! `#[uniffi::export]` plus a `uniffi::setup_scaffolding!()` call is mechanical
//! once the per-language build harness is in place.
//!
//! This phase covers the pure, fully deterministic identity surface (the part
//! every sibling-language SDK shares and validates against `vectors/`). The
//! async tunnel surface (connect/disconnect/events) is added with the binding
//! runtime, since it needs an async executor bridge per language.

// FFI exports take owned arguments by value on purpose: uniffi and
// flutter_rust_bridge marshal owned values across the language boundary, so a
// borrowed signature would not match the generated bindings.
#![allow(clippy::needless_pass_by_value)]

use warren_sdk::identity::{WarrenIdentity, ss58};

/// A serializable error for the FFI boundary.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum FfiError {
    /// The mnemonic is not a valid BIP39 phrase.
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    /// A hex argument was malformed or the wrong length.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// The SS58 address was malformed.
    #[error("invalid address")]
    InvalidAddress,
}

/// A Warren identity in FFI-friendly form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiIdentity {
    /// The 12-word BIP39 mnemonic (secret).
    pub mnemonic: String,
    /// The canonical SS58 `wb…` address.
    pub address: String,
    /// The 32-byte Ed25519 public key as 64 hex chars.
    pub public_key_hex: String,
}

/// The four `X-Warren-*` header values for a signed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiSignedHeaders {
    /// `X-Warren-PubKey` (SS58 address).
    pub pubkey_ss58: String,
    /// `X-Warren-Sig` (128 hex chars).
    pub signature_hex: String,
    /// `X-Warren-Timestamp` (unix seconds).
    pub timestamp: u64,
    /// `X-Warren-Nonce` (32 hex chars).
    pub nonce_hex: String,
}

/// Generates a fresh identity.
#[must_use]
pub fn generate_identity() -> FfiIdentity {
    let (identity, mnemonic) = WarrenIdentity::generate();
    to_ffi(&identity, mnemonic)
}

/// Rebuilds an identity from a BIP39 mnemonic.
///
/// # Errors
///
/// [`FfiError::InvalidMnemonic`] if the phrase is not valid BIP39.
pub fn identity_from_mnemonic(mnemonic: String) -> Result<FfiIdentity, FfiError> {
    let identity =
        WarrenIdentity::from_mnemonic(&mnemonic).map_err(|_| FfiError::InvalidMnemonic)?;
    Ok(to_ffi(&identity, mnemonic))
}

/// Returns the SS58 `wb…` address for a mnemonic.
///
/// # Errors
///
/// [`FfiError::InvalidMnemonic`] if the phrase is not valid BIP39.
pub fn address_from_mnemonic(mnemonic: String) -> Result<String, FfiError> {
    Ok(WarrenIdentity::from_mnemonic(&mnemonic)
        .map_err(|_| FfiError::InvalidMnemonic)?
        .address())
}

/// Encodes a 32-byte pubkey (64 hex chars) as a Warren SS58 address.
///
/// # Errors
///
/// [`FfiError::InvalidHex`] if the input is not 32 bytes of hex.
pub fn ss58_encode(public_key_hex: String) -> Result<String, FfiError> {
    let pk = hex32(&public_key_hex)?;
    Ok(ss58::encode(&pk))
}

/// Decodes a Warren SS58 address into the 32-byte pubkey (64 hex chars).
///
/// # Errors
///
/// [`FfiError::InvalidAddress`] if the address is malformed.
pub fn ss58_decode(address: String) -> Result<String, FfiError> {
    ss58::decode(&address)
        .map(hex::encode)
        .map_err(|_| FfiError::InvalidAddress)
}

/// Signs a Warren API request, returning the four header values.
///
/// `nonce_hex` must be 32 hex chars (16 bytes). The caller supplies `timestamp`
/// and `nonce_hex` so the binding layer owns the clock and RNG.
///
/// # Errors
///
/// [`FfiError::InvalidMnemonic`] or [`FfiError::InvalidHex`].
pub fn sign_request(
    mnemonic: String,
    method: String,
    path: String,
    body_utf8: String,
    timestamp: u64,
    nonce_hex: String,
) -> Result<FfiSignedHeaders, FfiError> {
    let identity =
        WarrenIdentity::from_mnemonic(&mnemonic).map_err(|_| FfiError::InvalidMnemonic)?;
    let nonce = hex16(&nonce_hex)?;
    let sig = identity.sign_request(&method, &path, body_utf8.as_bytes(), timestamp, nonce);
    Ok(FfiSignedHeaders {
        pubkey_ss58: sig.pubkey_ss58,
        signature_hex: sig.signature_hex,
        timestamp: sig.timestamp,
        nonce_hex: sig.nonce_hex,
    })
}

fn to_ffi(identity: &WarrenIdentity, mnemonic: String) -> FfiIdentity {
    FfiIdentity {
        mnemonic,
        address: identity.address(),
        public_key_hex: hex::encode(identity.public_key()),
    }
}

fn hex32(s: &str) -> Result<[u8; 32], FfiError> {
    hex::decode(s)
        .map_err(|e| FfiError::InvalidHex(e.to_string()))?
        .try_into()
        .map_err(|_| FfiError::InvalidHex("expected 32 bytes".to_owned()))
}

fn hex16(s: &str) -> Result<[u8; 16], FfiError> {
    hex::decode(s)
        .map_err(|e| FfiError::InvalidHex(e.to_string()))?
        .try_into()
        .map_err(|_| FfiError::InvalidHex("expected 16 bytes".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_ENTROPY_24W: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn address_from_mnemonic_matches_frozen_vector() {
        let addr = address_from_mnemonic(ZERO_ENTROPY_24W.to_owned()).expect("valid");
        assert_eq!(addr, "wbDSf2fncAfyDQkNbkyqjuhi8kpg3z8kCHqL2TYDSM2F1nVED");
    }

    #[test]
    fn identity_roundtrips_through_ffi() {
        let id = generate_identity();
        let restored = identity_from_mnemonic(id.mnemonic.clone()).expect("valid");
        assert_eq!(id, restored);
        assert!(id.address.starts_with("wb"));
    }

    #[test]
    fn ss58_encode_decode_roundtrip() {
        let id = generate_identity();
        let decoded = ss58_decode(id.address.clone()).expect("decode");
        assert_eq!(decoded, id.public_key_hex);
        let encoded = ss58_encode(id.public_key_hex.clone()).expect("encode");
        assert_eq!(encoded, id.address);
    }

    #[test]
    fn sign_request_emits_four_header_values() {
        let id = generate_identity();
        let headers = sign_request(
            id.mnemonic,
            "GET".to_owned(),
            "/v1/subscription".to_owned(),
            String::new(),
            1_700_000_000,
            "00112233445566778899aabbccddeeff".to_owned(),
        )
        .expect("sign");
        assert_eq!(headers.pubkey_ss58, id.address);
        assert_eq!(headers.signature_hex.len(), 128);
        assert_eq!(headers.nonce_hex.len(), 32);
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        assert!(matches!(
            address_from_mnemonic("not a mnemonic".to_owned()),
            Err(FfiError::InvalidMnemonic)
        ));
    }

    #[test]
    fn bad_nonce_hex_is_rejected() {
        let id = generate_identity();
        assert!(matches!(
            sign_request(
                id.mnemonic,
                "GET".to_owned(),
                "/x".to_owned(),
                String::new(),
                1,
                "tooshort".to_owned(),
            ),
            Err(FfiError::InvalidHex(_))
        ));
    }
}
