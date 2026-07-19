//! Frozen `/v2` post-quantum golden vectors replayed through the SDK's
//! re-exported engine types (X-Wing hybrid seal: X25519 + ML-KEM-768).
//!
//! Replays the shared `vectors/xwing_kem.json` (official
//! draft-connolly-cfrg-xwing-kem KATs) and `vectors/pq_hpke_seal_v2.json`
//! (the Warren `/v2` seal + signed PQ exit descriptor) using ONLY the types the
//! SDK re-exports from `warren_multihop`, proving the SDK reproduces the exact
//! post-quantum wire bytes and drives the same anti-downgrade negotiation the
//! engine does. Compiled only with the (default) `pq-hpke` feature.
#![cfg(feature = "pq-hpke")]

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use warren_multihop::test_support::xwing_reference_flow;
use warren_multihop::{
    ExitDescriptorSigned, ExitId, ExitPkiError, PqAvailability, PqClientSession, PqExitSession,
    XWingRecipientSecretKey, encode_frame_v2, exit_descriptor_signing_payload_pq, negotiate_pq,
    verify_exit_descriptor_pq, xwing_combiner,
};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}
fn h16(s: &str) -> [u8; 16] {
    h(s).try_into().expect("16 bytes")
}
fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().expect("32 bytes")
}
fn h64(s: &str) -> [u8; 64] {
    h(s).try_into().expect("64 bytes")
}

fn read(rel: &str) -> String {
    let path = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {rel}: {e}; run `git submodule update --init`"))
}

#[derive(Deserialize)]
struct XWingFile {
    vectors: Vec<XWingVector>,
}

#[derive(Deserialize)]
struct XWingVector {
    seed_hex: String,
    eseed_hex: String,
    ss_hex: String,
    sk_hex: String,
    pk_hex: String,
    ct_hex: String,
}

/// The re-exported X-Wing KEM reproduces the official draft KATs byte for byte
/// (keygen -> encaps -> decaps), proving the SDK's PQ half is the exact X-Wing
/// construction and not a home-grown combiner.
#[test]
fn official_xwing_draft_vectors_replay_through_the_sdk() {
    let file: XWingFile = serde_json::from_str(&read("vectors/xwing_kem.json")).expect("parse");
    assert_eq!(
        file.vectors.len(),
        3,
        "expected the 3 official draft vectors"
    );
    for (i, v) in file.vectors.iter().enumerate() {
        let seed = h32(&v.seed_hex);
        assert_eq!(h32(&v.sk_hex), seed, "vector {i}: sk must equal the seed");
        let out = xwing_reference_flow(&seed, &h64(&v.eseed_hex)).expect("reference flow");
        assert_eq!(
            out.public_key,
            h(&v.pk_hex),
            "vector {i}: public key drifted"
        );
        assert_eq!(
            out.ciphertext,
            h(&v.ct_hex),
            "vector {i}: ciphertext drifted"
        );
        assert_eq!(
            out.shared_secret_encaps,
            h32(&v.ss_hex),
            "vector {i}: encaps shared secret drifted"
        );
        assert_eq!(
            out.shared_secret_decaps,
            h32(&v.ss_hex),
            "vector {i}: decaps did not recover the shared secret"
        );
    }
}

/// Independent SHA3-256 cross-check of the re-exported combiner byte layout.
#[test]
fn xwing_combiner_layout_is_frozen() {
    let a = xwing_combiner(&[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32]);
    assert_eq!(
        a.as_bytes(),
        &h32("5c6bfaf8c3ec48ab3cee7c12129b39913b8a7fa1234115da7e1c55608ad19fb6")
    );
}

#[derive(Deserialize)]
struct Vectors {
    recipient: Recipient,
    encaps: Encaps,
    forward_setup: ForwardSetup,
    reverse_reply: ReverseReply,
    exit_descriptor_pq: DescriptorPq,
}

#[derive(Deserialize)]
struct Recipient {
    mlkem768_d_seed_hex: String,
    mlkem768_z_seed_hex: String,
    x25519_sk_seed_hex: String,
    mlkem768_ek_hex: String,
    x25519_pubkey_hex: String,
}

#[derive(Deserialize)]
struct Encaps {
    mlkem768_m_seed_hex: String,
    x25519_ephemeral_seed_hex: String,
}

#[derive(Deserialize)]
struct ForwardSetup {
    exit_id_hex: String,
    epoch: u32,
    seq: u64,
    payload_hex: String,
    encapsulated_key_hex: String,
    pq_ct_hex: String,
    aead_tag_hex: String,
    ciphertext_hex: String,
    frame_bytes_hex: String,
}

#[derive(Deserialize)]
struct ReverseReply {
    epoch: u32,
    seq: u64,
    payload_hex: String,
    aead_tag_hex: String,
    ciphertext_hex: String,
    frame_bytes_hex: String,
}

#[derive(Deserialize)]
struct DescriptorPq {
    operational_pubkey_hex: String,
    descriptor_json: String,
}

fn load() -> Vectors {
    serde_json::from_str(&read("vectors/pq_hpke_seal_v2.json")).expect("parse pq vectors")
}

/// The re-exported `PqClientSession` seals the forward setup frame to the exact
/// frozen `/v2` bytes (encapsulated key, ML-KEM ciphertext, AEAD tag, ciphertext
/// and encoded frame).
#[test]
fn forward_setup_frame_is_byte_for_byte_frozen() {
    let v = load();
    let (_sk, pk) = XWingRecipientSecretKey::derive_deterministic(
        &h32(&v.recipient.mlkem768_d_seed_hex),
        &h32(&v.recipient.mlkem768_z_seed_hex),
        &h32(&v.recipient.x25519_sk_seed_hex),
    );
    assert_eq!(pk.mlkem768_ek_bytes(), h(&v.recipient.mlkem768_ek_hex));
    assert_eq!(pk.x25519_pubkey(), &h32(&v.recipient.x25519_pubkey_hex));

    let exit_id = ExitId::from_bytes(h16(&v.forward_setup.exit_id_hex));
    let client = PqClientSession::new_deterministic(
        &pk,
        exit_id,
        &h32(&v.encaps.mlkem768_m_seed_hex),
        &h32(&v.encaps.x25519_ephemeral_seed_hex),
    )
    .expect("client session");
    let frame = client
        .seal_setup(
            &h(&v.forward_setup.payload_hex),
            v.forward_setup.epoch,
            v.forward_setup.seq,
        )
        .expect("seal_setup");

    assert_eq!(
        frame.encapsulated_key.as_slice(),
        h(&v.forward_setup.encapsulated_key_hex),
        "ct_X drifted"
    );
    assert_eq!(frame.pq_ct, h(&v.forward_setup.pq_ct_hex), "ct_M drifted");
    assert_eq!(frame.aead_tag.as_slice(), h(&v.forward_setup.aead_tag_hex));
    assert_eq!(frame.ciphertext, h(&v.forward_setup.ciphertext_hex));
    assert_eq!(
        encode_frame_v2(&frame).expect("encode"),
        h(&v.forward_setup.frame_bytes_hex),
        "encoded /v2 frame bytes drifted from the frozen vector"
    );
}

/// The re-exported `PqExitSession` decapsulates the client material and seals
/// the reverse reply to the exact frozen `/v2` bytes.
#[test]
fn reverse_reply_frame_is_byte_for_byte_frozen() {
    let v = load();
    let (sk, _pk) = XWingRecipientSecretKey::derive_deterministic(
        &h32(&v.recipient.mlkem768_d_seed_hex),
        &h32(&v.recipient.mlkem768_z_seed_hex),
        &h32(&v.recipient.x25519_sk_seed_hex),
    );
    let exit_id = ExitId::from_bytes(h16(&v.forward_setup.exit_id_hex));
    let exit = PqExitSession::new(
        &sk,
        &h32(&v.forward_setup.encapsulated_key_hex),
        &h(&v.forward_setup.pq_ct_hex),
        exit_id,
    )
    .expect("exit session");
    let reply = exit
        .seal_response(
            &h(&v.reverse_reply.payload_hex),
            v.reverse_reply.epoch,
            v.reverse_reply.seq,
        )
        .expect("seal_response");
    assert_eq!(reply.aead_tag.as_slice(), h(&v.reverse_reply.aead_tag_hex));
    assert_eq!(reply.ciphertext, h(&v.reverse_reply.ciphertext_hex));
    assert_eq!(
        encode_frame_v2(&reply).expect("encode"),
        h(&v.reverse_reply.frame_bytes_hex),
        "reverse /v2 frame bytes drifted"
    );
}

/// A PQ-advertising exit (validly signed ML-KEM key) negotiates to the
/// post-quantum seal, while the SAME exit with its ML-KEM key stripped falls
/// back to the classical seal, and a `require_pq` client refuses the stripped
/// descriptor rather than being silently downgraded. This is the exact decision
/// the SDK dial consumes to pick the `/v2` vs classical `/v1` session.
#[test]
fn pq_advertising_exit_negotiates_pq_and_classical_falls_back() {
    let v = load();
    let op = VerifyingKey::from_bytes(&h32(&v.exit_descriptor_pq.operational_pubkey_hex))
        .expect("op pubkey");
    let descriptor: ExitDescriptorSigned =
        serde_json::from_str(&v.exit_descriptor_pq.descriptor_json).expect("descriptor json");

    verify_exit_descriptor_pq(&op, &descriptor).expect("pq descriptor verifies");
    assert_eq!(
        negotiate_pq(&op, &descriptor, false).expect("negotiate"),
        PqAvailability::Available,
        "a signed ML-KEM key must select the PQ seal",
    );

    let mut classical = descriptor.clone();
    classical.exit_mlkem768_pubkey = None;
    assert_eq!(
        negotiate_pq(&op, &classical, false).expect("negotiate"),
        PqAvailability::ClassicalFallback,
        "no signed ML-KEM key must fall back to the classical seal",
    );
    assert!(
        matches!(
            negotiate_pq(&op, &classical, true),
            Err(ExitPkiError::PqDowngrade)
        ),
        "require_pq must refuse a stripped descriptor, never downgrade",
    );
}

/// The re-exported `exit_descriptor_signing_payload_pq` reproduces the frozen
/// PQ signing-payload layout: the vector's signature verifies against the
/// payload rebuilt from the descriptor fields, pinning the exact bytes the SDK
/// verifies a PQ exit over.
#[test]
fn pq_descriptor_signing_payload_is_frozen() {
    let v = load();
    let descriptor: ExitDescriptorSigned =
        serde_json::from_str(&v.exit_descriptor_pq.descriptor_json).expect("descriptor json");
    let ek = descriptor
        .exit_mlkem768_pubkey
        .as_deref()
        .expect("vector descriptor carries a signed ML-KEM key");
    let payload = exit_descriptor_signing_payload_pq(
        descriptor.exit_id,
        &descriptor.exit_x25519_multihop_pubkey,
        descriptor.dns_disabled,
        ek,
    );
    let op = VerifyingKey::from_bytes(&h32(&v.exit_descriptor_pq.operational_pubkey_hex))
        .expect("op pubkey");
    op.verify_strict(
        &payload,
        &ed25519_dalek::Signature::from_bytes(&descriptor.signature),
    )
    .expect("frozen signature verifies over the reproduced payload");
}
