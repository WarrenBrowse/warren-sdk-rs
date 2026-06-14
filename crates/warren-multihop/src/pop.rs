//! Proof of possession (PoP) of the multihop account key.
//!
//! On a multihop connection the exit's TLS peer is the relay, not the client,
//! so the account pubkey asserted in the setup `IpRequest` is otherwise
//! self-declared: anyone who merely KNOWS an allowlisted pubkey (they are not
//! secret, they appear in allowlist snapshots and API headers) could obtain
//! egress. The PoP closes that hole: the client signs a domain-separated
//! message binding its account key to this session's HPKE `encapsulated_key`
//! and the destination `exit_id`, and the exit verifies the signature against
//! the asserted pubkey before consulting the allowlist.
//!
//! Freshness: the `encapsulated_key` is chosen by the client per session, so a
//! captured PoP is useless on any other session. Intra-session replay of the
//! whole setup frame is rejected by the exit's session-scoped anti-replay
//! window.
//!
//! The signed message is deterministic raw-byte concatenation (no serde):
//! `context || exit_id (16) || encapsulated_key (32)`. All three parts are
//! fixed-length, so the encoding is unambiguous without length prefixes.
//! Byte-compatible with warren-core `warren-multihop::pop`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use warren_wire::PopSignature;
use warren_wire::multihop::EXIT_ID_LEN;

/// Domain-separation context for the multihop PoP signature. Versioned with the
/// control wire (`/v2`): a future change to the signed-message layout mints a
/// new context string, never mutating this one.
pub const POP_CONTEXT_V2: &[u8] = b"warren/multihop/pop/v2";

/// Build the exact byte string the PoP signature covers:
/// [`POP_CONTEXT_V2`] || `exit_id` (16 raw bytes) || `encapsulated_key`
/// (32 raw bytes).
#[must_use]
pub fn pop_signing_message(exit_id: &[u8; EXIT_ID_LEN], encapsulated_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(POP_CONTEXT_V2.len() + EXIT_ID_LEN + 32);
    msg.extend_from_slice(POP_CONTEXT_V2);
    msg.extend_from_slice(exit_id);
    msg.extend_from_slice(encapsulated_key);
    msg
}

/// Sign the proof of possession with the account signing key. The result goes
/// into the `IpRequest::pop_sig` field alongside the matching `client_pubkey`.
#[must_use]
pub fn sign_pop(
    key: &SigningKey,
    exit_id: &[u8; EXIT_ID_LEN],
    encapsulated_key: &[u8; 32],
) -> PopSignature {
    PopSignature(
        key.sign(&pop_signing_message(exit_id, encapsulated_key))
            .to_bytes(),
    )
}

/// Verify a proof of possession against the asserted account pubkey. Returns
/// `false` on a malformed pubkey (not a valid Ed25519 point) or a signature
/// that does not cover exactly this `(exit_id, encapsulated_key)` pair.
#[must_use]
pub fn verify_pop(
    client_pubkey: &[u8; 32],
    exit_id: &[u8; EXIT_ID_LEN],
    encapsulated_key: &[u8; 32],
    sig: &PopSignature,
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(client_pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig.0);
    verifying_key
        .verify(&pop_signing_message(exit_id, encapsulated_key), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const EXIT_ID: [u8; EXIT_ID_LEN] = [0xAA; EXIT_ID_LEN];
    const ENCAP: [u8; 32] = [0x5C; 32];

    #[test]
    fn valid_pop_verifies_against_the_signing_pubkey() {
        let key = det_key(0x11);
        let sig = sign_pop(&key, &EXIT_ID, &ENCAP);
        assert!(
            verify_pop(&key.verifying_key().to_bytes(), &EXIT_ID, &ENCAP, &sig),
            "a signature by the key owner over the exact session binding must verify"
        );
    }

    #[test]
    fn pop_signed_by_another_key_is_rejected() {
        // The attack the PoP exists to stop: asserting someone else's
        // allowlisted pubkey without holding its private key.
        let owner = det_key(0x11);
        let attacker = det_key(0x22);
        let sig = sign_pop(&attacker, &EXIT_ID, &ENCAP);
        assert!(
            !verify_pop(&owner.verifying_key().to_bytes(), &EXIT_ID, &ENCAP, &sig),
            "a signature by a different key must NOT verify against the asserted pubkey"
        );
    }

    #[test]
    fn pop_is_bound_to_the_exit_id_and_the_encapsulated_key() {
        // Cross-session / cross-exit replay: a PoP captured on one session must
        // be invalid for any other (exit_id, encap) pair.
        let key = det_key(0x11);
        let pubkey = key.verifying_key().to_bytes();
        let sig = sign_pop(&key, &EXIT_ID, &ENCAP);

        let other_exit = [0xBB; EXIT_ID_LEN];
        assert!(
            !verify_pop(&pubkey, &other_exit, &ENCAP, &sig),
            "a PoP for one exit must not verify for another"
        );
        let other_encap = [0x5D; 32];
        assert!(
            !verify_pop(&pubkey, &EXIT_ID, &other_encap, &sig),
            "a PoP for one session's encapsulated key must not verify for another"
        );
    }

    #[test]
    fn tampered_signature_and_malformed_pubkey_are_rejected() {
        let key = det_key(0x11);
        let pubkey = key.verifying_key().to_bytes();
        let mut sig = sign_pop(&key, &EXIT_ID, &ENCAP);
        sig.0[0] ^= 0x01;
        assert!(
            !verify_pop(&pubkey, &EXIT_ID, &ENCAP, &sig),
            "a single flipped signature bit must fail verification"
        );

        // A 32-byte blob that is not a valid Ed25519 point must fail closed.
        let good_sig = sign_pop(&key, &EXIT_ID, &ENCAP);
        let bogus_pubkey = [0xFF; 32];
        assert!(!verify_pop(&bogus_pubkey, &EXIT_ID, &ENCAP, &good_sig));
    }

    #[test]
    fn pop_message_layout_is_frozen() {
        // The signed message is part of the wire contract: context || exit_id ||
        // encapsulated_key, raw bytes, no length prefixes.
        let msg = pop_signing_message(&EXIT_ID, &ENCAP);
        let mut expected = b"warren/multihop/pop/v2".to_vec();
        expected.extend_from_slice(&EXIT_ID);
        expected.extend_from_slice(&ENCAP);
        assert_eq!(
            msg, expected,
            "PoP signing message layout drifted: mint a new context string"
        );
    }
}
