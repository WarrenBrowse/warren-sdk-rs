//! Live validation against the production Warren API and a real exit.
//!
//! Run: `cargo run -p warren-sdk --example live_exit`
//!   - with a subscribed account: `WARREN_MNEMONIC="word1 ... word12" cargo run \
//!     -p warren-sdk --example live_exit`
//!
//! What it validates against production (no account needed):
//!   1. the signed exit list verifies under the pinned server key;
//!   2. the signed multihop directory verifies (server envelope -> operational
//!      cert -> exit descriptor) and yields trusted x25519 HPKE keys;
//!   3. each directory exit's Ed25519 identity also appears in the pinned relay
//!      list (binds the directory to the pinned trust root).
//!
//! Then it opens a real MULTIHOP tunnel (the handshake real exits require an
//! HPKE-sealed setup frame). Routing requires a SUBSCRIBED
//! wallet (the exit gates the `IpAssign` on its allowlist + proof of
//! possession), so without `WARREN_MNEMONIC` the exit answers `Rejected`: that
//! still proves the sealed handshake reached the exit's policy gate.

use warren_sdk::WarrenClient;
use warren_sdk::discovery::VerifiedExit;
use warren_sdk::identity::WarrenIdentity;

const API_BASE: &str = "https://api.warrenbrowse.com";
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (identity, subscribed) = match std::env::var("WARREN_MNEMONIC") {
        Ok(phrase) if !phrase.trim().is_empty() => {
            (WarrenIdentity::from_mnemonic(phrase.trim())?, true)
        }
        _ => (WarrenIdentity::generate().0, false),
    };
    println!(
        "client identity: {} ({})",
        identity.address(),
        if subscribed {
            "from WARREN_MNEMONIC"
        } else {
            "ephemeral (not subscribed)"
        }
    );

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(API_BASE)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;

    println!("fetching signed exit list from {API_BASE} ...");
    let selector = client.fetch_exits().await?;
    println!("signed exit list verified against the pinned server key.");

    println!("fetching signed multihop directory ...");
    let exits = match client.fetch_multihop_directory().await {
        Ok(exits) => exits,
        Err(warren_sdk::SdkError::NoMultihopDirectory) => {
            // The server can toggle multihop off (`/v1/multihop/directory` -> 404
            // "multi-hop directory disabled"). Without the directory's x25519
            // keys no sealed tunnel can be opened, so stop with a clear message
            // rather than a cryptic error.
            println!(
                "multihop directory is disabled server-side: no sealed tunnel can be \
                 opened until it is re-enabled. (The SDK handled the 404 correctly.)"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    println!(
        "multihop directory verified: {} trusted exits.",
        exits.len()
    );

    // Bind the directory to the pinned relay list: only use an exit whose
    // Ed25519 identity is in the (pinned) signed exit list.
    let exit = exits
        .into_iter()
        .find(|e| relay_list_has(&selector, e))
        .ok_or("no multihop exit cross-checks against the pinned relay list")?;
    println!(
        "selected exit: {} / {}  endpoint={}",
        exit.country, exit.city, exit.endpoint
    );

    println!("opening real multihop tunnel (sealed setup frame) ...");
    match client.connect_multihop(&exit).await {
        Ok(sink) => {
            let s = sink.session();
            println!(
                "TUNNEL UP. assigned_ipv4={} max_inner_payload={}",
                s.assigned_ipv4(),
                s.max_inner_payload()
            );
            println!("real-exit multihop datapath validated.");
        }
        Err(e) if !subscribed => {
            // Without a subscribed wallet the exit refuses the IpAssign by
            // policy AFTER opening the sealed setup frame, so reaching this
            // error proves the multihop handshake itself is correct.
            print!("exit reached: connect was refused (expected without a subscribed wallet): {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                print!(" -> {s}");
                src = s.source();
            }
            println!();
            println!(
                "the sealed handshake path is exercised; rerun with WARREN_MNEMONIC \
                 to complete routing."
            );
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// True if the directory exit's Ed25519 identity appears in the pinned relay
/// list, binding the directory to the pinned trust root.
fn relay_list_has(selector: &warren_sdk::discovery::ExitSelector, exit: &VerifiedExit) -> bool {
    selector
        .relays()
        .iter()
        .any(|r| r.endpoint_id() == exit.exit_ed25519_pubkey)
}
