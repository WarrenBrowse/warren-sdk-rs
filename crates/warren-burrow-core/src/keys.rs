//! Key material of the gateway and its peers.
//!
//! Every type here is a newtype over exactly 32 bytes in the base64 spelling
//! the WireGuard configuration format uses, so a key never travels as a bare
//! string. Nothing renders key material through `Debug`: a gateway key, a
//! preshared key and a peer public key are all identity material, and the
//! operator label is the handle logs and health routes use instead.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::{Zeroize, Zeroizing};

/// Length of every key this gateway handles.
pub const KEY_LEN: usize = 32;

/// Why a key could not be read.
///
/// Displays name the rule that refused, never the value that broke it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The value is not valid base64.
    #[error("key is not valid base64")]
    BadEncoding,
    /// The value decodes to something other than 32 bytes.
    #[error("key is not 32 bytes")]
    BadLength,
}

fn decode(value: &str) -> Result<[u8; KEY_LEN], KeyError> {
    let mut bytes = BASE64
        .decode(value.trim())
        .map_err(|_| KeyError::BadEncoding)?;
    let out = <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| KeyError::BadLength);
    // The decoded buffer holds the secret on every path, including the refusal.
    bytes.zeroize();
    out
}

/// The gateway's own static key pair.
///
/// Also the type provisioning mints a peer's key pair with: a peer key is the
/// same x25519 static secret, and the client configuration carries its base64.
pub struct GatewayKey {
    secret: x25519_dalek::StaticSecret,
    // Cached rather than derived per use: it is needed on every handshake, and
    // the derivation is a scalar multiplication.
    public: PeerPublicKey,
}

impl GatewayKey {
    /// Draws a fresh key pair from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self::from_secret(x25519_dalek::StaticSecret::random_from_rng(
            rand::rngs::OsRng,
        ))
    }

    /// Reads a key from its base64 spelling.
    ///
    /// # Errors
    ///
    /// [`KeyError::BadEncoding`] when the value is not base64,
    /// [`KeyError::BadLength`] when it does not decode to 32 bytes.
    pub fn from_base64(value: &str) -> Result<Self, KeyError> {
        let bytes = decode(value)?;
        Ok(Self::from_secret(x25519_dalek::StaticSecret::from(bytes)))
    }

    fn from_secret(secret: x25519_dalek::StaticSecret) -> Self {
        let public = PeerPublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes());
        Self { secret, public }
    }

    /// The public key peers encrypt to.
    #[must_use]
    pub fn public(&self) -> PeerPublicKey {
        self.public
    }

    // The secret itself, which only the responder needs: boringtun clones it
    // into every peer tunnel. Deliberately not public: nothing outside this
    // crate has a reason to hold the gateway's private key.
    pub(crate) fn secret(&self) -> &x25519_dalek::StaticSecret {
        &self.secret
    }

    /// The base64 spelling of the private key, wiped when the caller drops it.
    #[must_use]
    pub fn to_base64_zeroizing(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new(self.secret.to_bytes());
        let encoded = Zeroizing::new(BASE64.encode(bytes.as_ref()));
        bytes.zeroize();
        encoded
    }
}

impl Clone for GatewayKey {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            public: self.public,
        }
    }
}

impl std::fmt::Debug for GatewayKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatewayKey")
    }
}

/// A peer's static public key, which is also how the gateway names a peer on
/// the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerPublicKey([u8; KEY_LEN]);

impl PeerPublicKey {
    /// Wraps 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Reads a public key from its base64 spelling.
    ///
    /// # Errors
    ///
    /// [`KeyError::BadEncoding`] or [`KeyError::BadLength`].
    pub fn from_base64(value: &str) -> Result<Self, KeyError> {
        decode(value).map(Self)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The base64 spelling written into configuration files.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }
}

impl std::fmt::Debug for PeerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerPublicKey")
    }
}

/// The optional symmetric key mixed into a peer's handshake.
pub struct PresharedKey(Zeroizing<[u8; KEY_LEN]>);

impl PresharedKey {
    /// Draws a fresh preshared key from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        use rand::RngCore as _;
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rand::rngs::OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// Wraps 32 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Reads a preshared key from its base64 spelling.
    ///
    /// # Errors
    ///
    /// [`KeyError::BadEncoding`] or [`KeyError::BadLength`].
    pub fn from_base64(value: &str) -> Result<Self, KeyError> {
        decode(value).map(Self::from_bytes)
    }

    /// The raw bytes, as boringtun wants them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The base64 spelling, wiped when the caller drops it.
    #[must_use]
    pub fn to_base64_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(self.0.as_ref()))
    }
}

impl Clone for PresharedKey {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

impl PartialEq for PresharedKey {
    fn eq(&self, other: &Self) -> bool {
        // Configuration comparison only (has this peer's key material changed
        // since the last reload), never an authentication decision.
        *self.0 == *other.0
    }
}

impl Eq for PresharedKey {}

impl Zeroize for PresharedKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PresharedKey")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn round_trips_a_gateway_key_through_base64() {
        let key = GatewayKey::generate();
        let encoded = key.to_base64_zeroizing();
        let restored = GatewayKey::from_base64(&encoded).expect("a key we just rendered");
        assert_eq!(restored.public(), key.public());
        assert_eq!(*restored.to_base64_zeroizing(), *encoded);
    }

    #[test]
    fn renders_a_wireguard_sized_base64_key() {
        let key = GatewayKey::generate();
        assert_eq!(key.to_base64_zeroizing().len(), 44);
        assert_eq!(key.public().to_base64().len(), 44);
    }

    #[test]
    fn refuses_a_key_that_is_not_thirty_two_bytes() {
        assert_eq!(
            GatewayKey::from_base64("YWJj").unwrap_err(),
            KeyError::BadLength
        );
        assert_eq!(
            PeerPublicKey::from_base64("YWJj").unwrap_err(),
            KeyError::BadLength
        );
        assert_eq!(
            PresharedKey::from_base64("YWJj").unwrap_err(),
            KeyError::BadLength
        );
    }

    #[test]
    fn refuses_a_key_that_is_not_base64() {
        assert_eq!(
            GatewayKey::from_base64("not a key at all!!!!").unwrap_err(),
            KeyError::BadEncoding
        );
    }

    #[test]
    fn round_trips_a_peer_public_key_and_a_preshared_key() {
        let public = PeerPublicKey::from_bytes([9u8; 32]);
        assert_eq!(PeerPublicKey::from_base64(&public.to_base64()), Ok(public));

        let psk = PresharedKey::generate();
        let restored = PresharedKey::from_base64(&psk.to_base64_zeroizing()).expect("round trip");
        assert_eq!(restored.as_bytes(), psk.as_bytes());
        assert_ne!(psk.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn renders_no_key_material_when_key_types_are_printed() {
        let key = GatewayKey::generate();
        let private = key.to_base64_zeroizing();
        let public = key.public().to_base64();
        let psk = PresharedKey::generate();
        let secret = psk.to_base64_zeroizing();

        for rendered in [
            format!("{key:?}"),
            format!("{:?}", key.public()),
            format!("{psk:?}"),
        ] {
            assert!(!rendered.contains(private.as_str()), "{rendered}");
            assert!(!rendered.contains(public.as_str()), "{rendered}");
            assert!(!rendered.contains(secret.as_str()), "{rendered}");
        }
    }

    #[test]
    fn wipes_a_preshared_key_when_it_is_zeroized() {
        let mut psk = PresharedKey::from_bytes([7u8; 32]);
        psk.zeroize();
        assert_eq!(psk.as_bytes(), &[0u8; 32]);
    }
}
