//! Warren TLS 1.3 configuration backed by raw Ed25519 public keys (RFC 7250).
//!
//! Turns an `ed25519_dalek::SigningKey` into the quinn client/server configs the
//! tunnel uses. There is no PKI: the peer pubkey is encoded in the TLS server
//! name (SNI) and the verifier checks the presented raw key against it. 0-RTT is
//! disabled, TLS 1.2 is rejected. Ported wire-compatibly from warren-core
//! (`warren-tls`).

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use rustls::pki_types::{
    CertificateDer, ServerName, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, UnixTime,
    alg_id,
};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme,
    SupportedProtocolVersion,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};

/// First 12 bytes of an Ed25519 SPKI (ASN.1 DER) emitted by rustls.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Length of an Ed25519 SubjectPublicKeyInfo blob.
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Errors raised while building a TLS config.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WarrenTlsError {
    /// The crypto provider lacks the QUIC initial-packet cipher.
    #[error("crypto provider lacks the QUIC initial-packet cipher (TLS_AES_128_GCM_SHA256)")]
    NoInitialCipherSuite,
    /// rustls rejected the configuration.
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}

impl From<quinn::crypto::rustls::NoInitialCipherSuite> for WarrenTlsError {
    fn from(_: quinn::crypto::rustls::NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite
    }
}

/// The ring-backed crypto provider used by Warren by default.
#[must_use]
pub fn default_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// SNI codec: a peer pubkey encoded as `<base32>.exits.warrenbrowse.com`.
pub mod name {
    use data_encoding::BASE32_DNSSEC;

    /// SNI suffix, mimicking a casual HTTP/3 endpoint on the Warren domain.
    pub(crate) const SUFFIX: &str = ".exits.warrenbrowse.com";

    /// Encodes a 32-byte pubkey as the canonical TLS server name.
    #[must_use]
    pub fn encode(pubkey: &[u8; 32]) -> String {
        format!("{}{SUFFIX}", BASE32_DNSSEC.encode(pubkey))
    }

    /// Decodes a TLS server name back into a 32-byte pubkey, or `None`.
    #[must_use]
    pub fn decode(name: &str) -> Option<[u8; 32]> {
        let label = name.strip_suffix(SUFFIX)?;
        if label.is_empty() || label.contains('.') {
            return None;
        }
        let decoded = BASE32_DNSSEC.decode(label.as_bytes()).ok()?;
        decoded.try_into().ok()
    }
}

const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
const ED25519_DALEK: Ed25519Dalek = Ed25519Dalek;
const SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&ED25519_DALEK],
    mapping: &[(SignatureScheme::ED25519, &[&ED25519_DALEK])],
};

/// Builds the quinn client config used to dial an exit.
///
/// # Errors
///
/// [`WarrenTlsError`] if the provider lacks the QUIC initial cipher or rustls
/// rejects the configuration.
pub fn make_client_config(
    secret: &SigningKey,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ClientConfig, WarrenTlsError> {
    let cert_resolver = Arc::new(RpkResolver::new(secret));
    let mut crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ServerVerifier))
        .with_client_cert_resolver(cert_resolver);
    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.resumption = rustls::client::Resumption::disabled();
    crypto.enable_early_data = false;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

/// Builds the quinn server config an exit serves to clients.
///
/// # Errors
///
/// Same as [`make_client_config`].
pub fn make_server_config(
    secret: &SigningKey,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ServerConfig, WarrenTlsError> {
    let cert_resolver = Arc::new(RpkResolver::new(secret));
    let mut crypto = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_client_cert_verifier(Arc::new(ClientVerifier))
        .with_cert_resolver(cert_resolver);
    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.send_tls13_tickets = 0;
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    // Disable active path migration: Warren is single-path in v1 and migration
    // aids timing correlation against the user's outbound IP.
    server_cfg.migration(false);
    Ok(server_cfg)
}

/// Extracts the peer's authenticated 32-byte pubkey from a live connection.
#[must_use]
pub fn peer_pubkey(conn: &quinn::Connection) -> Option<[u8; 32]> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    pubkey_from_certs(&certs)
}

fn pubkey_from_certs(certs: &[CertificateDer<'_>]) -> Option<[u8; 32]> {
    let bytes = certs.first()?.as_ref();
    if bytes.len() != ED25519_SPKI_LEN || bytes[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX
    {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[ED25519_SPKI_PREFIX.len()..]);
    Some(pk)
}

#[derive(Debug)]
struct RpkResolver {
    key: Arc<rustls::sign::CertifiedKey>,
}

impl RpkResolver {
    fn new(secret: &SigningKey) -> Self {
        let signer = Arc::new(RpkSigner {
            key: secret.clone(),
        });
        let end_entity = CertificateDer::from(signer.spki().to_vec());
        Self {
            key: Arc::new(rustls::sign::CertifiedKey::new(vec![end_entity], signer)),
        }
    }
}

impl rustls::client::ResolvesClientCert for RpkResolver {
    fn resolve(
        &self,
        _hints: &[&[u8]],
        _schemes: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
    fn has_certs(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for RpkResolver {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct RpkSigner {
    key: SigningKey,
}

impl RpkSigner {
    fn spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        rustls::sign::public_key_to_spki(&alg_id::ED25519, self.key.verifying_key().as_bytes())
    }
}

impl rustls::sign::SigningKey for RpkSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(self.clone()) as Box<dyn rustls::sign::Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki())
    }
}

impl rustls::sign::Signer for RpkSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[derive(Debug)]
struct ServerVerifier;

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ServerName::DnsName(dns_name) = server_name else {
            return Err(rustls::Error::UnsupportedNameType);
        };
        let Some(remote_pubkey) = name::decode(dns_name.as_ref()) else {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ));
        };
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        let expected = rustls::sign::public_key_to_spki(&alg_id::ED25519, remote_pubkey);
        if expected != SubjectPublicKeyInfoDer::from(end_entity.as_ref()) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &SUPPORTED_SIG_ALGS,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct ClientVerifier;

impl ClientCertVerifier for ClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &SUPPORTED_SIG_ALGS,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct Ed25519Dalek;

impl SignatureVerificationAlgorithm for Ed25519Dalek {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), rustls::pki_types::InvalidSignature> {
        let pk_bytes: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| rustls::pki_types::InvalidSignature)?;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes)
            .map_err(|_| rustls::pki_types::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| rustls::pki_types::InvalidSignature)?;
        pk.verify_strict(message, &sig)
            .map_err(|_| rustls::pki_types::InvalidSignature)
    }
    fn public_key_alg_id(&self) -> rustls::pki_types::AlgorithmIdentifier {
        alg_id::ED25519
    }
    fn signature_alg_id(&self) -> rustls::pki_types::AlgorithmIdentifier {
        alg_id::ED25519
    }
    fn fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_roundtrips() {
        let pk = [0xde; 32];
        assert_eq!(name::decode(&name::encode(&pk)), Some(pk));
    }

    #[test]
    fn sni_decode_rejects_wrong_suffix() {
        let pk = [0u8; 32];
        let bad = name::encode(&pk).replace(".com", ".net");
        assert!(name::decode(&bad).is_none());
    }

    #[test]
    fn configs_build_with_default_provider() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        make_client_config(&key, default_crypto_provider(), &[b"h3"]).expect("client config");
        make_server_config(&key, default_crypto_provider(), &[b"h3"]).expect("server config");
    }
}
