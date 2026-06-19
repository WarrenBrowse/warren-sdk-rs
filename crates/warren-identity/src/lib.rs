//! Warren non-custodial Ed25519 identity.
//!
//! This is the foundational, fully portable layer of the Warren SDK. It maps
//! 1:1 to every sibling-language SDK (TypeScript, Dart, Python, Kotlin, Swift,
//! Java) and its outputs are pinned by the shared golden vectors in
//! `vectors/identity.json`.
//!
//! Pipeline:
//!
//! ```text
//! 12-word BIP39 mnemonic
//!   -> PBKDF2-SHA512 (passphrase "")  -> 64-byte seed, keep first 32
//!   -> HKDF-SHA256 (salt warren/identity/v1, info vpn-node-key) -> 32 bytes
//!   -> Ed25519 SigningKey
//!   -> public key -> SS58 `wb…` address
//! ```
//!
//! The mnemonic is the sole secret (non-custodial). Every buffer holding secret
//! material is zeroized on drop.

pub mod mnemonic;
pub mod signing;
pub mod ss58;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Re-export of the exact `ed25519-dalek` the SDK builds against, so dependent
/// crates can name `SigningKey`/`VerifyingKey` without pinning the version
/// themselves.
pub use ed25519_dalek;

/// The byte-locked seed -> Ed25519 derivation primitive is the engine's, shared
/// with warren-core (one implementation of the frozen identity pipeline).
pub use warrenguard_identity::derive_node_key;

pub use mnemonic::{MnemonicError, generate as generate_mnemonic, seed_from_mnemonic};
pub use signing::{
    HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, RequestSignature,
    canonical_message,
};

/// HKDF-SHA256 salt for Warren identity derivation. Frozen: never modify
/// without bumping the version (`identity/v2`).
pub const HKDF_SALT_IDENTITY_V1: &[u8] = b"warren/identity/v1";

/// HKDF-SHA256 info for the node key. Frozen alongside [`HKDF_SALT_IDENTITY_V1`].
pub const HKDF_INFO_NODEKEY: &[u8] = b"vpn-node-key";

/// Errors building a [`WarrenIdentity`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// The supplied mnemonic is not a valid BIP39 phrase.
    #[error(transparent)]
    Mnemonic(#[from] MnemonicError),
}

/// A Warren wallet identity: an Ed25519 keypair derived from a BIP39 mnemonic,
/// with its canonical SS58 `wb…` address and the ability to sign API requests.
///
/// The secret key is zeroized on drop. `Debug` prints only the public address.
///
/// # Examples
///
/// ```
/// use warren_identity::WarrenIdentity;
///
/// // Generate a new identity and recover the same one from its mnemonic.
/// let (identity, mnemonic) = WarrenIdentity::generate();
/// let restored = WarrenIdentity::from_mnemonic(&mnemonic)?;
/// assert_eq!(identity.address(), restored.address());
/// assert!(identity.address().starts_with("wb"));
///
/// // Sign an API request (the SDK facade supplies the clock and a random nonce).
/// let signed = identity.sign_request("GET", "/v1/subscription", b"", 1_700_000_000, [0u8; 16]);
/// for (name, value) in signed.headers() {
///     // attach each X-Warren-* header to the outgoing HTTP request
///     let _ = (name, value);
/// }
/// # Ok::<(), warren_identity::IdentityError>(())
/// ```
pub struct WarrenIdentity {
    signing: SigningKey,
}

impl WarrenIdentity {
    /// Generates a brand-new identity, returning it together with the 12-word
    /// mnemonic that reproduces it. Persist the mnemonic securely: it is the
    /// only way to recover the identity.
    #[must_use]
    pub fn generate() -> (Self, String) {
        let phrase = mnemonic::generate();
        let identity =
            Self::from_mnemonic(&phrase).expect("a freshly generated BIP39 mnemonic always parses");
        (identity, phrase)
    }

    /// Rebuilds an identity from an existing BIP39 mnemonic.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Mnemonic`] if the phrase is not valid BIP39.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, IdentityError> {
        let seed = seed_from_mnemonic(phrase)?;
        Ok(Self::from_seed(&seed))
    }

    /// Builds an identity directly from a 32-byte seed (the first 32 bytes of a
    /// BIP39 seed). Mainly useful for tests and golden-vector replay.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: derive_node_key(seed),
        }
    }

    /// The 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The verifying (public) key, for callers that need the typed form.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Clones the underlying Ed25519 signing key.
    ///
    /// The Warren wallet key doubles as the QUIC tunnel client identity (RPK
    /// handshake), so the transport layer needs it. The returned key zeroizes on
    /// drop; treat it as secret.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        self.signing.clone()
    }

    /// The canonical Warren SS58 address (`wb…`).
    #[must_use]
    pub fn address(&self) -> String {
        ss58::encode(&self.public_key())
    }

    /// Signs an arbitrary message, returning the 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Produces the authentication material for a signed Warren API request.
    ///
    /// `timestamp` and `nonce` are taken as inputs to keep this deterministic
    /// and FFI-friendly; the SDK facade supplies a system clock and a random
    /// nonce. `nonce` is 16 random bytes (rendered as 32 hex chars).
    #[must_use]
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp: u64,
        nonce: [u8; 16],
    ) -> RequestSignature {
        let nonce_hex = hex::encode(nonce);
        let body_hash_hex = hex::encode(Sha256::digest(body));
        let canonical = canonical_message(method, path, timestamp, &nonce_hex, &body_hash_hex);
        let signature_hex = hex::encode(self.signing.sign(canonical.as_bytes()).to_bytes());
        RequestSignature {
            pubkey_ss58: self.address(),
            signature_hex,
            timestamp,
            nonce_hex,
        }
    }
}

impl std::fmt::Debug for WarrenIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret key. The public address is the safe handle.
        f.debug_struct("WarrenIdentity")
            .field("address", &self.address())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn derivation_is_deterministic() {
        let seed = [0xab; 32];
        assert_eq!(
            derive_node_key(&seed).to_bytes(),
            derive_node_key(&seed).to_bytes()
        );
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        assert_ne!(
            derive_node_key(&[0xab; 32]).to_bytes(),
            derive_node_key(&[0xcd; 32]).to_bytes()
        );
    }

    #[test]
    fn seed_ab_produces_known_pubkey() {
        let id = WarrenIdentity::from_seed(&[0xab; 32]);
        assert_eq!(
            hex::encode(id.public_key()),
            "21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b",
            "WARREN identity schema changed - bump to identity/v2 if intentional"
        );
        assert_eq!(
            id.address(),
            "wb8X9ovjY66mreUk8qVtmRX5DGP4mkTqoYkUFjU6gbtjp1mUr"
        );
    }

    #[test]
    fn seed_zero_produces_known_pubkey() {
        let id = WarrenIdentity::from_seed(&[0u8; 32]);
        assert_eq!(
            hex::encode(id.public_key()),
            "d9d24d24f77550ec46914c30d83dc973063c759967d03af4efe508fb34ed5308",
            "WARREN identity schema changed - bump to identity/v2 if intentional"
        );
        assert_eq!(
            id.address(),
            "wbCgHqDAE3CKBuAeSDCC4r9TZtjXveuXNd934zzm7ncceJa6q"
        );
    }

    #[test]
    fn full_chain_from_zero_entropy_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let seed = seed_from_mnemonic(phrase).expect("valid mnemonic");
        assert_eq!(
            hex::encode(*seed),
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"
        );
        let id = WarrenIdentity::from_mnemonic(phrase).expect("valid mnemonic");
        assert_eq!(
            hex::encode(id.public_key()),
            "fba874de8721df35921c9999a036c03bb098df35fc21fcbeac98af880ababdb9",
            "WARREN identity/BIP39 pipeline changed - bump to identity/v2 if intentional"
        );
        assert_eq!(
            id.address(),
            "wbDSf2fncAfyDQkNbkyqjuhi8kpg3z8kCHqL2TYDSM2F1nVED"
        );
    }

    #[test]
    fn generate_roundtrips_through_mnemonic() {
        let (id, phrase) = WarrenIdentity::generate();
        let restored = WarrenIdentity::from_mnemonic(&phrase).expect("valid mnemonic");
        assert_eq!(id.public_key(), restored.public_key());
        assert!(id.address().starts_with("wb"));
    }

    #[test]
    fn signature_roundtrips_through_verify() {
        let id = WarrenIdentity::from_seed(&[0xab; 32]);
        let msg = b"warren-vpn-handshake-challenge";
        let sig = Signature::from_bytes(&id.sign(msg));
        id.verifying_key()
            .verify(msg, &sig)
            .expect("signature must verify with its own pubkey");
    }

    #[test]
    fn signature_does_not_verify_with_wrong_key() {
        let alice = WarrenIdentity::from_seed(&[0xaa; 32]);
        let bob = WarrenIdentity::from_seed(&[0xbb; 32]);
        let msg = b"only-alice-should-sign-this";
        let sig = Signature::from_bytes(&alice.sign(msg));
        bob.verifying_key()
            .verify(msg, &sig)
            .expect_err("bob's pubkey must NOT verify alice's signature");
    }

    #[test]
    fn sign_request_verifies_against_canonical_message() {
        let id = WarrenIdentity::from_seed(&[0x42; 32]);
        let body = b"{\"voucher\":\"abc\"}";
        let req = id.sign_request("POST", "/v1/register", body, 1_700_000_000, [9u8; 16]);

        assert_eq!(req.pubkey_ss58, id.address());
        assert_eq!(req.nonce_hex, hex::encode([9u8; 16]));
        assert_eq!(req.signature_hex.len(), 128);

        let body_hash_hex = hex::encode(Sha256::digest(body));
        let canonical = canonical_message(
            "POST",
            "/v1/register",
            1_700_000_000,
            &req.nonce_hex,
            &body_hash_hex,
        );
        let sig_bytes: [u8; 64] = hex::decode(&req.signature_hex)
            .expect("hex")
            .try_into()
            .expect("64 bytes");
        id.verifying_key()
            .verify(canonical.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .expect("server-side canonical rebuild must verify");
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let id = WarrenIdentity::from_seed(&[0x11; 32]);
        let rendered = format!("{id:?}");
        assert!(rendered.contains(&id.address()));
        assert!(!rendered.contains("signing"));
    }
}
