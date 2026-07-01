//! Client-side signing of Warren API requests (`X-Warren-*` headers).
//!
//! The header names and the canonical message live in `warren-contract`, shared
//! with the server verifier so they cannot drift. This module adds the
//! client-side [`RequestSignature`] header bundle.

pub use warren_contract::auth::{
    HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, canonical_message,
};

/// A signed request's authentication material, ready to be attached as the four
/// `X-Warren-*` headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSignature {
    /// Signer pubkey as a Warren SS58 address (`wb…`).
    pub pubkey_ss58: String,
    /// Ed25519 signature of the canonical message, 128 hex chars (64 bytes).
    pub signature_hex: String,
    /// Unix epoch-seconds timestamp the canonical message was built with.
    pub timestamp: u64,
    /// Random 32-hex-char nonce (16 bytes).
    pub nonce_hex: String,
}

impl RequestSignature {
    /// Returns the four `X-Warren-*` headers as `(name, value)` pairs, in a
    /// stable order, ready to be added to an HTTP request.
    #[must_use]
    pub fn headers(&self) -> [(&'static str, String); 4] {
        [
            (HEADER_PUBKEY, self.pubkey_ss58.clone()),
            (HEADER_SIGNATURE, self.signature_hex.clone()),
            (HEADER_TIMESTAMP, self.timestamp.to_string()),
            (HEADER_NONCE, self.nonce_hex.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_carry_all_four_fields() {
        let sig = RequestSignature {
            pubkey_ss58: "wbXXXX".to_owned(),
            signature_hex: "aa".repeat(64),
            timestamp: 1_700_000_000,
            nonce_hex: "00".repeat(16),
        };
        let h = sig.headers();
        assert_eq!(h[0], (HEADER_PUBKEY, "wbXXXX".to_owned()));
        assert_eq!(h[2], (HEADER_TIMESTAMP, "1700000000".to_owned()));
        assert_eq!(h[3].1.len(), 32);
    }
}
