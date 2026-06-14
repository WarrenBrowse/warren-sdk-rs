//! FFI surface for the Warren SDK, exported via `uniffi`.
//!
//! Every function uses plain, owned, generic-free types and a serializable
//! [`FfiError`], the shape `uniffi` generates Swift/Kotlin/Python/Ruby bindings
//! from (and that `flutter_rust_bridge` can consume for Dart). The bindings are
//! produced by the `uniffi-bindgen` binary in `src/bin/` against the built
//! `cdylib`; see the crate README for the generate commands.
//!
//! This phase covers the pure, fully deterministic identity surface (the part
//! every sibling-language SDK shares and validates against `vectors/`). The
//! async tunnel surface (connect/disconnect/events) is added later, since it
//! needs an async executor bridge per language.

// FFI exports take owned arguments by value on purpose: uniffi marshals owned
// values across the language boundary, so a borrowed signature would not match
// the generated bindings.
#![allow(clippy::needless_pass_by_value)]
// FFI BOUNDARY EXCEPTION: this is the one crate where `unsafe_code` is not
// `forbid` (the workspace forbids it everywhere else). uniffi generates the
// C-ABI scaffolding, which is unavoidably `unsafe`; we hand-write zero unsafe.
// The manifest keeps the lint at `deny`, and this single documented `allow`
// admits only the generated boundary code.
#![allow(unsafe_code)]

use std::sync::Arc;

use warren_sdk::api::ClientError;
use warren_sdk::identity::{WarrenIdentity, ss58};
use warren_sdk::{DefaultClient, WarrenClient};

uniffi::setup_scaffolding!();

/// A serializable error for the FFI boundary.
#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
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
    /// The server returned a non-2xx status. The body is intentionally dropped
    /// (it is server-controlled and may be noisy); only the code crosses the FFI.
    #[error("server returned status {status}")]
    ServerStatus {
        /// HTTP status code.
        status: u16,
    },
    /// A transport, build, or other client-side failure. The message is derived
    /// from a no-log-safe `Display` (no pubkey/address/IP/secret).
    #[error("client error: {message}")]
    Client {
        /// Human-readable, redaction-safe summary.
        message: String,
    },
}

/// A Warren identity in FFI-friendly form.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiIdentity {
    /// The 12-word BIP39 mnemonic (secret).
    pub mnemonic: String,
    /// The canonical SS58 `wb…` address.
    pub address: String,
    /// The 32-byte Ed25519 public key as 64 hex chars.
    pub public_key_hex: String,
}

// Manual Debug: the mnemonic is seed material and must never reach a log, so it
// is redacted while the public address and pubkey stay visible for debugging.
impl std::fmt::Debug for FfiIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiIdentity")
            .field("mnemonic", &"<redacted>")
            .field("address", &self.address)
            .field("public_key_hex", &self.public_key_hex)
            .finish()
    }
}

/// The four `X-Warren-*` header values for a signed request.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
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
#[uniffi::export]
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
#[uniffi::export]
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
#[uniffi::export]
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
#[uniffi::export]
pub fn ss58_encode(public_key_hex: String) -> Result<String, FfiError> {
    let pk = hex32(&public_key_hex)?;
    Ok(ss58::encode(&pk))
}

/// Decodes a Warren SS58 address into the 32-byte pubkey (64 hex chars).
///
/// # Errors
///
/// [`FfiError::InvalidAddress`] if the address is malformed.
#[uniffi::export]
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
#[uniffi::export]
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

/// A live Warren SDK client exposed across the FFI boundary.
///
/// Wraps the default reqwest-backed [`DefaultClient`]. Async methods run on the
/// tokio runtime the host app drives (uniffi `async_runtime = "tokio"`). Held by
/// the foreign side as an opaque handle; drop it to release the client.
#[derive(uniffi::Object)]
pub struct WarrenFfiClient {
    inner: DefaultClient,
}

#[uniffi::export(async_runtime = "tokio")]
impl WarrenFfiClient {
    /// Builds a client from a BIP39 mnemonic, the API base URL (no trailing
    /// slash), and the server's 64-hex Ed25519 pin.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidMnemonic`] if the phrase is not valid BIP39. (The pin
    /// is validated lazily on the first signed fetch, not here.)
    #[uniffi::constructor]
    pub fn new(
        mnemonic: String,
        api_base: String,
        server_pubkey_pin: String,
    ) -> Result<Arc<Self>, FfiError> {
        let identity =
            WarrenIdentity::from_mnemonic(&mnemonic).map_err(|_| FfiError::InvalidMnemonic)?;
        let inner = WarrenClient::builder()
            .identity(identity)
            .api_base(api_base)
            .server_pubkey_pin(server_pubkey_pin)
            .build()
            // Unreachable in practice (identity and pin are both set above), but
            // surfaced rather than unwrapped to keep the boundary panic-free.
            .map_err(|e| FfiError::Client {
                message: e.to_string(),
            })?;
        Ok(Arc::new(Self { inner }))
    }

    /// The wallet SS58 `wb…` address of this client.
    #[must_use]
    pub fn address(&self) -> String {
        self.inner.api().address()
    }

    /// Fetches the subscription expiry (unix epoch seconds) for this account.
    ///
    /// # Errors
    ///
    /// [`FfiError::ServerStatus`] on a non-2xx reply (e.g. no subscription),
    /// [`FfiError::Client`] on a transport or other client-side failure.
    pub async fn subscription_expiry(&self) -> Result<u64, FfiError> {
        let sub = self
            .inner
            .api()
            .subscription()
            .await
            .map_err(map_client_error)?;
        Ok(sub.expires_at)
    }
}

/// Maps a [`ClientError`] to the FFI error, keeping the no-log discipline: the
/// server-status body is dropped and only redaction-safe `Display` text crosses.
fn map_client_error(e: ClientError) -> FfiError {
    match e {
        ClientError::ServerStatus { status, .. } => FfiError::ServerStatus { status },
        other => FfiError::Client {
            message: other.to_string(),
        },
    }
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
    fn ffi_identity_debug_redacts_the_mnemonic() {
        let id = generate_identity();
        let rendered = format!("{id:?}");
        assert!(
            !rendered.contains(&id.mnemonic),
            "the seed mnemonic must never appear in Debug output"
        );
        assert!(rendered.contains("<redacted>"));
        // The public address stays visible for debugging.
        assert!(rendered.contains(&id.address));
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        assert!(matches!(
            address_from_mnemonic("not a mnemonic".to_owned()),
            Err(FfiError::InvalidMnemonic)
        ));
    }

    #[test]
    fn client_new_rejects_bad_mnemonic() {
        let r = WarrenFfiClient::new(
            "not a mnemonic".to_owned(),
            "https://api.example.test".to_owned(),
            "ab".repeat(32),
        );
        assert!(matches!(r, Err(FfiError::InvalidMnemonic)));
    }

    #[test]
    fn client_new_accepts_valid_inputs_and_exposes_address() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic.clone(),
            "https://api.example.test".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        assert_eq!(client.address(), id.address);
    }

    #[tokio::test]
    async fn subscription_expiry_surfaces_a_client_error_on_unroutable_host() {
        // Port 1 on loopback refuses fast, so this exercises the full async FFI
        // bridge and ClientError -> FfiError mapping without a live server.
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client.subscription_expiry().await;
        assert!(
            matches!(
                r,
                Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
            ),
            "an unroutable host must surface as a client/server error, not panic"
        );
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
