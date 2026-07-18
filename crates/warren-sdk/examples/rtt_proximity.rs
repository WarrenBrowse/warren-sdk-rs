//! Live validation of client RTT proximity scoring (doc 52 §6.2 client).
//!
//! Run with a SUBSCRIBED wallet (routing requires it):
//!   `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example rtt_proximity`
//!
//! What it validates against real exits:
//!   1. A real multihop handshake yields a real, sane path RTT
//!      (`MultihopSession::path_rtt`), recorded into the
//!      client's [`RttCache`] keyed by the exit's Ed25519 endpoint pubkey.
//!   2. `select_exit_by_proximity` biases weighted selection toward the
//!      lower-RTT exit at comparable weight (doc 52 §6.2 client: selection
//!      prefers a nearby exit).
//!
//! Without `WARREN_MNEMONIC` the exit refuses routing after the handshake,
//! so no session (and no RTT) is returned; the example says so and exits.

use std::time::{SystemTime, UNIX_EPOCH};

use warren_sdk::WarrenClient;
use warren_sdk::discovery::{DEFAULT_RTT_TTL_SECS, ExitQuery, ExitSelector, VerifiedExit};
use warren_sdk::identity::WarrenIdentity;

const API_BASE: &str = "https://api.warrenbrowse.com";
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
/// How many distinct real exits to probe (each costs one handshake).
const MAX_PROBES: usize = 3;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (identity, subscribed) = match std::env::var("WARREN_MNEMONIC") {
        Ok(phrase) if !phrase.trim().is_empty() => {
            (WarrenIdentity::from_mnemonic(phrase.trim())?, true)
        }
        _ => (WarrenIdentity::generate().0, false),
    };
    println!(
        "client identity: {} (subscribed={subscribed})",
        identity.address()
    );
    if !subscribed {
        println!(
            "no WARREN_MNEMONIC: real exits refuse routing after the handshake, so no RTT \
             can be measured. Re-run with a subscribed mnemonic to validate proximity \
             scoring end-to-end."
        );
    }

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(API_BASE)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;

    let selector = client.fetch_exits().await?;
    println!(
        "signed exit list verified: {} relays.",
        selector.relays().len()
    );

    let dir_exits = match client.fetch_multihop_directory().await {
        Ok(e) => e,
        Err(warren_sdk::SdkError::NoMultihopDirectory) => {
            println!("multihop directory disabled server-side; cannot probe. Stopping.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    // Only probe exits whose identity is in the pinned relay list.
    let probes: Vec<VerifiedExit> = dir_exits
        .into_iter()
        .filter(|e| relay_list_has(&selector, e))
        .take(MAX_PROBES)
        .collect();
    println!("probing {} exit(s) for real RTT ...", probes.len());

    for exit in &probes {
        match client.connect_multihop(exit).await {
            Ok(_sink) => println!(
                "  connected {} / {} ({})",
                exit.country, exit.city, exit.endpoint
            ),
            Err(e) => println!(
                "  {} / {}: no session ({e}); RTT not measured{}",
                exit.country,
                exit.city,
                if subscribed {
                    ""
                } else {
                    " (expected without subscription)"
                }
            ),
        }
    }

    // Read back the measured RTTs from the client's cache.
    let snapshot = client.rtt_cache_snapshot();
    let now = now_secs();
    let mut measured: Vec<(&VerifiedExit, u32)> = Vec::new();
    println!("\nmeasured RTTs:");
    for exit in &probes {
        match snapshot.fresh_rtt_ms(exit.exit_ed25519_pubkey, now, DEFAULT_RTT_TTL_SECS) {
            Some(rtt) => {
                println!("  {} / {}: {rtt} ms", exit.country, exit.city);
                measured.push((exit, rtt));
            }
            None => println!("  {} / {}: (unmeasured)", exit.country, exit.city),
        }
    }

    if measured.len() < 2 {
        println!(
            "\nfewer than 2 real measurements: RTT probe {}. Proximity ordering is proven by \
             the unit tests; re-run subscribed against >=2 exits to see the live distribution.",
            if measured.is_empty() {
                "did not fire"
            } else {
                "fired once"
            }
        );
        return Ok(());
    }

    // Demonstrate the bias: run the proximity selector many times over the
    // full relay list and tally how often the nearer vs the farther measured
    // exit is chosen. At comparable weight the lower-RTT one must win.
    let (near_exit, near_rtt) = measured.iter().min_by_key(|(_, r)| *r).unwrap();
    let (far_exit, far_rtt) = measured.iter().max_by_key(|(_, r)| *r).unwrap();
    let query = ExitQuery::any();
    let (mut near_hits, mut far_hits) = (0usize, 0usize);
    for _ in 0..1000 {
        if let Ok(relay) = client.select_exit_by_proximity(&selector, &query) {
            if relay.endpoint_id() == near_exit.exit_ed25519_pubkey {
                near_hits += 1;
            } else if relay.endpoint_id() == far_exit.exit_ed25519_pubkey {
                far_hits += 1;
            }
        }
    }
    println!("\n1000 proximity selections over the full relay list:");
    println!(
        "  near {} / {} ({near_rtt} ms): {near_hits} picks",
        near_exit.country, near_exit.city
    );
    println!(
        "  far  {} / {} ({far_rtt} ms): {far_hits} picks",
        far_exit.country, far_exit.city
    );
    if near_hits > far_hits {
        println!("PASS: proximity selection favoured the lower-RTT exit (doc 52 §6.2 client).");
    } else {
        println!(
            "NOTE: near did not out-pick far; their RTTs may be too close, or their server \
             weights differ enough to dominate the proximity factor."
        );
    }
    Ok(())
}

/// True if the directory exit's Ed25519 identity is in the pinned relay list.
fn relay_list_has(selector: &ExitSelector, exit: &VerifiedExit) -> bool {
    selector
        .relays()
        .iter()
        .any(|r| r.endpoint_id() == exit.exit_ed25519_pubkey)
}
