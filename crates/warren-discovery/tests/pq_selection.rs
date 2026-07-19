//! The SDK's directory-verify facade is PQ-aware with classical fallback.
//!
//! A classical (non-PQ) signed directory verifies and surfaces exits carrying
//! NO ML-KEM key, so the multihop dial stays on the byte-unchanged classical
//! `/v1` seal. This is the SDK side of "verify accepts a classical exit" and
//! "no PQ key advertised -> classical wire unchanged". PQ-signed directory
//! population is pinned by the neutral `warren-discovery-core` verifier tests;
//! here we lock that the SDK facade neither rejects a classical exit nor
//! invents PQ material for one.
#![cfg(feature = "test-helpers")]

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use warren_discovery::multihop_directory::test_helpers::mint_directory_json;
use warren_discovery::verify_multihop_directory;

fn pin(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

#[test]
fn classical_directory_verifies_and_surfaces_no_pq_key() {
    let root = SigningKey::from_bytes(&[1; 32]);
    let op = SigningKey::from_bytes(&[2; 32]);
    let server = SigningKey::from_bytes(&[3; 32]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    let json = mint_directory_json(&root, &op, &server, 1, now - 3600, now + 3600);

    let dir = verify_multihop_directory(&json, &[&pin(&server)], &[&pin(&root)])
        .expect("a classical signed directory must still verify");

    assert!(
        !dir.exits.is_empty(),
        "the fixture mints classical exits; the facade must not drop them",
    );
    for exit in &dir.exits {
        assert!(
            exit.exit_mlkem768_pubkey.is_none(),
            "a classical exit must surface no PQ key, so the dial keeps the \
             byte-unchanged classical seal",
        );
    }
}
