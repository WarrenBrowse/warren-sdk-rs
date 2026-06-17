//! PRIVILEGED TUN datapath validation harness (P6). EXPERIMENTAL.
//!
//! This is the runnable end-to-end check for the privileged TUN backend. It
//! cannot run from a headless CI/dev sandbox: it needs root / `CAP_NET_ADMIN`, a
//! real kernel TUN device, AND a subscribed account against the live exit. Per
//! CLAUDE.md, the TUN backend is only "done" once this passes against a real
//! exit; everything it calls is otherwise unit-tested and cross-compiled.
//!
//! Run on a rooted Linux host with the production exit reachable:
//!   sudo -E WARREN_MNEMONIC="word1 ... word12" \
//!     cargo run -p warren-sdk --example live_tun --features experimental-tun
//!
//! What it does:
//!   1. Opens a real multihop tunnel to a cross-checked production exit.
//!   2. `start_tun_multihop`: opens a kernel TUN device (`warren0`), applies the
//!      split-default routing + the killswitch, and forwards raw IP packets
//!      between the device and the sealed tunnel.
//!   3. Leaves the datapath up for a few seconds so the operator can verify
//!      egress (e.g. `curl https://checkip.amazonaws.com` should show the exit's
//!      IP, and `ip route` should show the split-default capture).
//!
//! Dropping the returned handle tears the datapath down and reverts the routing
//! and killswitch (the handle restores them on drop, and `start_tun_multihop`
//! itself fail-safe reverts a partial setup).
//!
//! The privileged datapath (`start_tun_multihop`) is Unix-only and behind the
//! `experimental-tun` feature, so this example is a no-op stub elsewhere (it must
//! still compile under `--all-targets --all-features` on every target).

#[cfg(all(unix, feature = "experimental-tun"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use warren_sdk::WarrenClient;
    use warren_sdk::identity::WarrenIdentity;

    const API_BASE: &str = "https://api.warrenbrowse.com";
    const SERVER_PUBKEY_PIN: &str =
        "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
    const TUN_NAME: &str = "warren0";

    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;
    println!("client identity: {}", identity.address());

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(API_BASE)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;

    // Cross-check the multihop exit against the signed relay list (same as the
    // other live examples).
    let selector = client.fetch_exits().await?;
    let exits = client.fetch_multihop_directory().await?;
    let exit = exits
        .into_iter()
        .find(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .ok_or("no cross-checked multihop exit")?;
    println!("exit: {} / {}  {}", exit.country, exit.city, exit.endpoint);

    println!("opening TUN device {TUN_NAME} + applying routing/killswitch (needs root)...");
    let handle = client.start_tun_multihop(&exit, TUN_NAME).await?;
    println!("TUN datapath up on {TUN_NAME}. Verify egress now, e.g.:");
    println!("  curl -s https://checkip.amazonaws.com   # should show the exit IP");
    println!("  ip route                                # split-default via {TUN_NAME}");

    tokio::time::sleep(std::time::Duration::from_secs(20)).await;

    drop(handle);
    println!("datapath torn down.");
    Ok(())
}

#[cfg(not(all(unix, feature = "experimental-tun")))]
fn main() {
    eprintln!(
        "live_tun requires a Unix host built with --features experimental-tun \
         (the privileged TUN datapath is Unix-only)"
    );
}
