//! Client-side signing of Warren API requests (`X-Warren-*` headers).
//!
//! The header names, the canonical message, the [`RequestSignature`] bundle and
//! the [`sign_request`] procedure all live in `warren-contract`, the single
//! definition shared with the server verifier and the backend's own client so
//! nothing can drift. This module just re-exports them.

pub use warren_contract::auth::{
    HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, RequestSignature,
    canonical_message, sign_request,
};

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
