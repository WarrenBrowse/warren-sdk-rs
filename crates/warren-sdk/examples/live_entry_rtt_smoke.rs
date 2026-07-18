//! Live smoke of the CLIENT-MEASURED half of the path-aware selection.
//!
//! Run: `cargo run -p warren-sdk --example live_entry_rtt_smoke`
//!
//! No wallet: the directory and the advisory are unauthenticated GETs and
//! the identity is a throwaway, selection-only (no tunnel is opened).
//!
//! 1. Fetches and verifies the production multihop directory + advisory.
//! 2. Finds an exit with at least two policy-legal entries.
//! 3. Baseline pick with an EMPTY RTT store, then plants a synthetic
//!    measured RTT (1 ms on a losing entry, 500 ms on the baseline
//!    winner) and re-selects: the pick must move onto the measured-fast
//!    entry, proving the store's signal reaches the shared selection
//!    against real production data.

use warren_sdk::WarrenClient;
use warren_sdk::discovery::{
    DEFAULT_RTT_TTL_SECS, PathAwareParams, RttCache, entry_rtt_from, select_entry_path_aware,
};
use warren_sdk::identity::WarrenIdentity;

const API_BASE: &str = "https://api.warrenbrowse.com";
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (identity, _mnemonic) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(API_BASE)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;

    let dir = client.fetch_multihop_directory_full().await?;
    println!(
        "directory: generation {} / {} nodes ({} dropped)",
        dir.generation,
        dir.exits.len(),
        dir.dropped
    );
    let advisory = client.fetch_path_quality().await;
    match &advisory {
        Some(a) => println!("advisory: {} entries", a.entries.len()),
        None => println!("advisory: none"),
    }

    let now = now_secs();
    let params = PathAwareParams::default();
    for exit in &dir.exits {
        let legal: Vec<_> = dir
            .entries
            .iter()
            .filter(|e| dir.policy.permits(e, exit))
            .collect();
        if legal.len() < 2 {
            continue;
        }
        println!(
            "exit {} / {}: {} policy-legal entries",
            exit.country,
            exit.city,
            legal.len()
        );

        let empty = RttCache::new();
        let baseline = select_entry_path_aware(
            &dir.entries,
            exit,
            &dir.policy,
            advisory.as_ref(),
            entry_rtt_from(&empty, now, DEFAULT_RTT_TTL_SECS),
            now,
            None,
            &params,
        )
        .ok_or("no baseline entry")?;
        println!(
            "  baseline (empty store): {} / {}  {}",
            baseline.country, baseline.city, baseline.endpoint
        );

        let target = legal
            .iter()
            .find(|e| e.exit_id != baseline.exit_id)
            .ok_or("no alternative legal entry")?;
        let mut store = RttCache::new();
        store.record(target.relay_ed25519_pubkey, 1, now);
        store.record(baseline.relay_ed25519_pubkey, 500, now);
        let biased = select_entry_path_aware(
            &dir.entries,
            exit,
            &dir.policy,
            advisory.as_ref(),
            entry_rtt_from(&store, now, DEFAULT_RTT_TTL_SECS),
            now,
            None,
            &params,
        )
        .ok_or("no biased entry")?;
        println!(
            "  with synthetic store (1 ms -> {} {}, 500 ms -> baseline): picked {} / {}  {}",
            target.country, target.city, biased.country, biased.city, biased.endpoint
        );

        assert_eq!(
            biased.exit_id, target.exit_id,
            "the measured-fast entry must win the selection"
        );
        assert_ne!(
            biased.exit_id, baseline.exit_id,
            "the pick must have moved off the empty-store baseline"
        );
        println!("SMOKE PASSED: the client RTT store steers the live selection");
        return Ok(());
    }
    Err("no exit with two policy-legal entries in the live directory".into())
}
