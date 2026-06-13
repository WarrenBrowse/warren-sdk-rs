//! Canonical signing of Warren API requests (`X-Warren-*` headers).
//!
//! Canonical format (frozen, never change without rotating to `/v2`):
//!
//! ```text
//! message = METHOD || "\n" || path || "\n" || timestamp || "\n" || nonce_hex || "\n" || sha256_hex(body)
//! sig     = Ed25519::sign(secret_key, message)
//! ```
//!
//! The server verifier (warren-core `warren-identity::auth`) rebuilds the exact
//! same string, so any drift here breaks every signature. The format is pinned
//! by `vectors/identity.json`.

/// Canonical name of the pubkey header (value: Warren SS58 `wb…` address).
pub const HEADER_PUBKEY: &str = "X-Warren-PubKey";
/// Canonical name of the signature header (value: 128 hex chars).
pub const HEADER_SIGNATURE: &str = "X-Warren-Sig";
/// Canonical name of the epoch-seconds timestamp header.
pub const HEADER_TIMESTAMP: &str = "X-Warren-Timestamp";
/// Canonical name of the 32-char hex nonce header.
pub const HEADER_NONCE: &str = "X-Warren-Nonce";

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

/// Builds the canonical message that is signed and verified.
///
/// Format frozen: never change without rotating to `/v2`. Must stay strictly
/// identical to the server-side verifier, otherwise no signature verifies.
#[must_use]
pub fn canonical_message(
    method: &str,
    path: &str,
    timestamp: u64,
    nonce_hex: &str,
    body_hash_hex: &str,
) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(
        method.len() + path.len() + 20 + nonce_hex.len() + body_hash_hex.len() + 4,
    );
    s.push_str(method);
    s.push('\n');
    s.push_str(path);
    s.push('\n');
    write!(&mut s, "{timestamp}").expect("write to String is infallible");
    s.push('\n');
    s.push_str(nonce_hex);
    s.push('\n');
    s.push_str(body_hash_hex);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_format_is_byte_stable() {
        let actual = canonical_message("GET", "/v1/exits", 42, "abcd1234", "ff00");
        assert_eq!(
            actual, "GET\n/v1/exits\n42\nabcd1234\nff00",
            "wire format change - bump auth schema version"
        );
    }

    #[test]
    fn canonical_message_uses_unix_newline_separator() {
        let actual = canonical_message("GET", "/x", 1, "a", "b");
        assert!(!actual.contains('\r'), "canonical must never contain CR");
        assert_eq!(actual.matches('\n').count(), 4, "exactly 4 LF separators");
    }

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
