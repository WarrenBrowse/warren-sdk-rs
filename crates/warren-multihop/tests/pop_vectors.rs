//! Replays the shared multihop proof-of-possession golden vector in
//! `vectors/pop.json`. The PoP preimage (`context || exit_id || encap`) is the
//! Warren-specific cross-language contract; every sibling SDK must build the
//! same bytes and a signature over them that verifies. The Ed25519 signature is
//! RFC 8032 deterministic, so we also pin that the signed preimage round-trips
//! through `sign_pop`/`verify_pop`.

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use warren_multihop::{ExitId, POP_CONTEXT_V2, pop_signing_message, sign_pop, verify_pop};

#[derive(Deserialize)]
struct PopFile {
    context_hex: String,
    vectors: Vec<PopVec>,
}

#[derive(Deserialize)]
struct PopVec {
    exit_id_hex: String,
    encapsulated_key_hex: String,
    preimage_hex: String,
    signing_key_seed_hex: String,
    signature_hex: String,
}

fn b16(s: &str) -> [u8; 16] {
    hex::decode(s).expect("hex").try_into().expect("16 bytes")
}

fn b32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

#[test]
fn pop_preimage_and_signature_match_the_vector() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/pop.json");
    let f: PopFile = serde_json::from_str(&std::fs::read_to_string(path).expect("read pop.json"))
        .expect("parse pop.json");

    // The pinned context hex must equal the crate's domain-separation constant.
    assert_eq!(
        hex::encode(POP_CONTEXT_V2),
        f.context_hex,
        "POP_CONTEXT_V2 drifted from the frozen vector"
    );
    assert!(!f.vectors.is_empty(), "vector file must carry a case");

    for v in &f.vectors {
        let exit_id = ExitId::from_bytes(b16(&v.exit_id_hex));
        let encap = b32(&v.encapsulated_key_hex);

        // The preimage is the frozen cross-language contract.
        assert_eq!(
            hex::encode(pop_signing_message(&exit_id, &encap)),
            v.preimage_hex,
            "PoP signing preimage drifted from the frozen vector"
        );

        // A signature over the preimage must verify against the seed's pubkey,
        // and reject when bound to a different exit_id (domain separation).
        let key = SigningKey::from_bytes(&b32(&v.signing_key_seed_hex));
        let pubkey = key.verifying_key().to_bytes();
        let sig = sign_pop(&key, &exit_id, &encap);
        // Ed25519 (RFC 8032) is deterministic, so the signature bytes are a
        // frozen cross-language value a sibling SDK must reproduce exactly.
        assert_eq!(
            hex::encode(sig.0),
            v.signature_hex,
            "PoP signature drifted from the frozen vector"
        );
        assert!(
            verify_pop(&pubkey, &exit_id, &encap, &sig),
            "freshly signed PoP must verify"
        );
        let mut other_raw = *exit_id.as_bytes();
        other_raw[0] ^= 0x01;
        let other_exit = ExitId::from_bytes(other_raw);
        assert!(
            !verify_pop(&pubkey, &other_exit, &encap, &sig),
            "a PoP bound to one exit_id must not verify for another"
        );
    }
}
