//! Verifies a REAL signed multi-hop directory captured from the production API
//! (`GET https://api.warrenbrowse.com/v1/multihop/directory`). Because the
//! Ed25519 signatures are clock-free, the captured fixture is a deterministic,
//! byte-exact proof that the SDK's canonical preimage and PKI chain match
//! warren-core: if the envelope signature verified against the production server
//! key, the bytes are right.

use warren_discovery::verify_multihop_directory;

/// Production warren-api server key (warren-config `WARREN_SERVER_PUBKEY_HEX`).
const SERVER_PUBKEY: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";

#[test]
fn verifies_real_production_directory() {
    let json = include_str!("fixtures/multihop_directory.json");

    // Server-pinned; root via TOFU (the root pin is operator config). Envelope
    // signature + per-exit operational signatures must all verify.
    let dir = verify_multihop_directory(json, &[SERVER_PUBKEY], &[])
        .expect("production directory must verify against the pinned server key");

    assert!(
        !dir.exits.is_empty(),
        "at least one exit descriptor must verify under the operational key"
    );
    // Every returned exit carries a 32-byte HPKE recipient key.
    for exit in &dir.exits {
        assert_eq!(exit.exit_x25519_multihop_pubkey.len(), 32);
        assert!(!exit.country.is_empty());
    }

    // A wrong server pin must be rejected.
    assert!(verify_multihop_directory(json, &[&"00".repeat(32)], &[]).is_err());
}

#[test]
fn production_directory_yields_entry_distinct_circuits() {
    let json = include_str!("fixtures/multihop_directory.json");
    let dir = verify_multihop_directory(json, &[SERVER_PUBKEY], &[]).expect("verify");

    // Unified dual-role fleet: every vouched node is both an entry and an exit.
    assert_eq!(dir.entries.len(), dir.exits.len());

    let exit = &dir.exits[0];
    let entry = dir
        .entries
        .iter()
        .find(|e| e.exit_id != exit.exit_id)
        .expect("the production fleet has at least two nodes");
    let dialed = exit
        .via_entry(entry)
        .expect("distinct nodes form a circuit");
    assert_eq!(dialed.endpoint, entry.endpoint, "dial target is the entry");
    assert_eq!(
        dialed.exit_id, exit.exit_id,
        "sealed frame still routes to the exit"
    );

    let same = dir
        .entries
        .iter()
        .find(|e| e.exit_id == exit.exit_id)
        .expect("the exit's own node is an entry too");
    assert!(exit.via_entry(same).is_none(), "entry == exit node refused");
}
