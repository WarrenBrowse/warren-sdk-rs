//! Live proof of the PATH-AWARE multihop entry selection.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_path_aware`
//!
//! 1. Fetches and verifies the production multihop directory (full view).
//! 2. Best-effort fetches the unsigned path-quality advisory; on an API
//!    without the endpoint this prints the fallback (`no advisory`), which
//!    is exactly the deployed-clients-safe degradation path.
//! 3. Runs `select_multihop_entry` for an exit and shows the chosen entry.
//! 4. PROOF: opens the userland SOCKS5 proxy over the SELECTED circuit and
//!    completes a TCP CONNECT to a public host through it, so the
//!    path-aware circuit demonstrably carries traffic end to end.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warren_sdk::WarrenClient;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;

const API_BASE: &str = "https://api.warrenbrowse.com";
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;
    println!("client identity: {}", identity.address());

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

    // A/B knob: force the no-advisory fallback path for comparison runs.
    let advisory = if std::env::var("WARREN_NO_ADVISORY").is_ok() {
        println!("advisory: DISABLED by WARREN_NO_ADVISORY -> weight-order fallback");
        None
    } else {
        let a = client.fetch_path_quality().await;
        match &a {
            Some(a) => println!(
                "advisory: {} entries (generated_at {})",
                a.entries.len(),
                a.generated_at
            ),
            None => println!("advisory: none (older API or unavailable) -> weight-order fallback"),
        }
        a
    };

    let wanted = std::env::var("WARREN_EXIT_COUNTRY").unwrap_or_else(|_| "NL".into());
    let exit = dir
        .exits
        .iter()
        .find(|e| e.country == wanted)
        .or_else(|| dir.exits.first())
        .ok_or("empty directory")?
        .clone();
    println!("exit: {} / {}", exit.country, exit.city);

    let circuit = client
        .select_multihop_entry(&dir, &exit, advisory.as_ref(), None)
        .ok_or("no policy-legal entry for this exit")?;
    let entry = dir
        .entries
        .iter()
        .find(|e| e.endpoint == circuit.endpoint)
        .ok_or("selected entry not in the directory")?;
    println!(
        "selected entry: {} / {}  {} (path-aware)",
        entry.country, entry.city, entry.endpoint
    );

    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client.start_proxy_multihop(&circuit, &cfg).await?;
    println!("SOCKS5 proxy up on {}", handle.local_addr());

    let attempt_budget = std::time::Duration::from_millis(2500);
    let probe: std::net::SocketAddr = "1.1.1.1:443".parse()?;
    for attempt in 1..=15 {
        if let Ok(Ok(())) =
            tokio::time::timeout(attempt_budget, socks5_connect(handle.local_addr(), probe)).await
        {
            println!(
                "EGRESS CONFIRMED via the path-aware circuit (SYN-ACK through the \
                 sealed tunnel, attempt {attempt})"
            );
            // Optional hold so the relay leg spans heartbeat ticks (lets an
            // operator watch the fleet's path-quality advisory populate).
            if let Some(secs) = std::env::var("WARREN_HOLD_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
            {
                println!("holding the circuit open for {secs}s...");
                tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            }
            handle.shutdown();
            return Ok(());
        }
    }
    Err("egress probe never succeeded through the selected circuit".into())
}

/// Minimal SOCKS5 CONNECT to `target` through the proxy at `proxy`.
async fn socks5_connect(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    let std::net::SocketAddr::V4(v4) = target else {
        return Err("ipv4 target expected".into());
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT refused: 0x{:02x}", reply[1]).into());
    }
    Ok(())
}
