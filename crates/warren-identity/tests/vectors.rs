//! Replays the shared cross-implementation golden vectors in
//! `vectors/identity.json`. These pin the wire contract that every
//! sibling-language SDK must reproduce byte-for-byte.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use warren_identity::{WarrenIdentity, canonical_message, seed_from_mnemonic, ss58};

#[derive(Deserialize)]
struct Vectors {
    ss58: Ss58Section,
    derivation: DerivationSection,
    bip39: Bip39Section,
    canonical_message: CanonicalSection,
    request_signature: RequestSignatureSection,
}

#[derive(Deserialize)]
struct Ss58Section {
    prefix: u16,
    vectors: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct DerivationSection {
    hkdf_salt: String,
    hkdf_info: String,
    vectors: Vec<DerivationVec>,
}

#[derive(Deserialize)]
struct DerivationVec {
    seed_hex: String,
    pubkey_hex: String,
    address: String,
}

#[derive(Deserialize)]
struct Bip39Section {
    vectors: Vec<Bip39Vec>,
}

#[derive(Deserialize)]
struct Bip39Vec {
    mnemonic: String,
    seed_hex: String,
    pubkey_hex: String,
    address: String,
}

#[derive(Deserialize)]
struct CanonicalSection {
    vectors: Vec<CanonicalVec>,
}

#[derive(Deserialize)]
struct CanonicalVec {
    method: String,
    path: String,
    timestamp: u64,
    nonce_hex: String,
    body_hash_hex: String,
    expected: String,
}

#[derive(Deserialize)]
struct RequestSignatureSection {
    vectors: Vec<RequestSignatureVec>,
}

#[derive(Deserialize)]
struct RequestSignatureVec {
    seed_hex: String,
    method: String,
    path: String,
    body_utf8: String,
    timestamp: u64,
    nonce_hex: String,
    pubkey_ss58: String,
    signature_hex: String,
}

fn load() -> Vectors {
    // CARGO_MANIFEST_DIR is crates/warren-identity; vectors live at repo root.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/identity.json");
    let raw = std::fs::read_to_string(path).expect("read vectors/identity.json");
    serde_json::from_str(&raw).expect("parse vectors/identity.json")
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

#[test]
fn ss58_vectors_match() {
    let v = load();
    assert_eq!(v.ss58.prefix, ss58::WARREN_SS58_PREFIX);
    for (pubkey_hex, expected) in &v.ss58.vectors {
        let addr = ss58::encode(&hex32(pubkey_hex));
        assert_eq!(&addr, expected, "ss58 encode for {pubkey_hex}");
        assert_eq!(
            ss58::decode(expected).expect("decode"),
            hex32(pubkey_hex),
            "ss58 decode for {expected}"
        );
    }
}

#[test]
fn derivation_vectors_match() {
    let v = load();
    assert_eq!(
        v.derivation.hkdf_salt.as_bytes(),
        warren_identity::HKDF_SALT_IDENTITY_V1
    );
    assert_eq!(
        v.derivation.hkdf_info.as_bytes(),
        warren_identity::HKDF_INFO_NODEKEY
    );
    for vec in &v.derivation.vectors {
        let id = WarrenIdentity::from_seed(&hex32(&vec.seed_hex));
        assert_eq!(
            hex::encode(id.public_key()),
            vec.pubkey_hex,
            "pubkey for seed {}",
            vec.seed_hex
        );
        assert_eq!(
            id.address(),
            vec.address,
            "address for seed {}",
            vec.seed_hex
        );
    }
}

#[test]
fn bip39_vectors_match() {
    let v = load();
    for vec in &v.bip39.vectors {
        let seed = seed_from_mnemonic(&vec.mnemonic).expect("valid mnemonic");
        assert_eq!(hex::encode(*seed), vec.seed_hex, "seed for mnemonic");
        let id = WarrenIdentity::from_mnemonic(&vec.mnemonic).expect("valid mnemonic");
        assert_eq!(
            hex::encode(id.public_key()),
            vec.pubkey_hex,
            "pubkey for mnemonic"
        );
        assert_eq!(id.address(), vec.address, "address for mnemonic");
    }
}

#[test]
fn canonical_message_vectors_match() {
    let v = load();
    for vec in &v.canonical_message.vectors {
        let actual = canonical_message(
            &vec.method,
            &vec.path,
            vec.timestamp,
            &vec.nonce_hex,
            &vec.body_hash_hex,
        );
        assert_eq!(
            actual, vec.expected,
            "canonical for {} {}",
            vec.method, vec.path
        );
    }
}

#[test]
fn request_signature_vectors_match() {
    let v = load();
    for vec in &v.request_signature.vectors {
        let id = WarrenIdentity::from_seed(&hex32(&vec.seed_hex));
        let nonce: [u8; 16] = hex::decode(&vec.nonce_hex)
            .expect("nonce hex")
            .try_into()
            .expect("16 bytes");
        let req = id.sign_request(
            &vec.method,
            &vec.path,
            vec.body_utf8.as_bytes(),
            vec.timestamp,
            nonce,
        );

        assert_eq!(req.pubkey_ss58, vec.pubkey_ss58, "pubkey_ss58");
        assert_eq!(
            req.signature_hex, vec.signature_hex,
            "signature_hex (Ed25519 is deterministic)"
        );

        // Independent sanity: the produced signature must verify against the
        // server-side canonical rebuild.
        use ed25519_dalek::{Signature, Verifier};
        let body_hash_hex = hex::encode(Sha256::digest(vec.body_utf8.as_bytes()));
        let canonical = canonical_message(
            &vec.method,
            &vec.path,
            vec.timestamp,
            &req.nonce_hex,
            &body_hash_hex,
        );
        let sig_bytes: [u8; 64] = hex::decode(&req.signature_hex)
            .expect("hex")
            .try_into()
            .expect("64 bytes");
        id.verifying_key()
            .verify(canonical.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .expect("signature must verify");
    }
}
