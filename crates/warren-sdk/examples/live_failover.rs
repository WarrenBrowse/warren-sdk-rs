//! Live validation of supervised exit FAILOVER against production exits.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_failover`
//!
//! Builds a candidate list with a KNOWN-BROKEN exit first (Singapore, which
//! consistently fails the multihop setup in prod) followed by the others, then
//! calls `start_proxy_supervised_failover`. The supervisor must rotate
//! past the broken exit, reach `Connected` on a working one, and egress through
//! the stable address. This proves failover routes around a real broken exit.
//! If prod has no broken exit (Singapore was fixed), it still validates that
//! failover connects through the first working candidate.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warren_sdk::discovery::VerifiedExit;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_sdk::transport::ConnectionState;
use warren_sdk::{Circuit, WarrenClient};

const API_BASE: &str = warren_sdk::product::API_URL;
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

    let selector = client.fetch_exits().await?;
    let exits = client.fetch_multihop_directory().await?;
    // Only consider exits cross-checked against the pinned relay list.
    let mut candidates: Vec<VerifiedExit> = exits
        .into_iter()
        .filter(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .collect();
    // Put Singapore first if present (the known-broken exit), so failover must
    // rotate past it to prove it routes around a real failure.
    candidates.sort_by_key(|e| if e.city.starts_with("Sing") { 0 } else { 1 });
    if candidates.len() < 2 {
        return Err("need at least two cross-checked exits to exercise failover".into());
    }
    println!("candidate order (first is tried first):");
    for e in &candidates {
        println!("  - {} / {}  {}", e.country, e.city, e.endpoint);
    }

    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let circuits: Vec<Circuit> = candidates.iter().cloned().map(Circuit::SingleHop).collect();
    let handle = client
        .start_proxy_supervised_failover(&circuits, &cfg)
        .await?;
    let proxy = handle.local_addr();
    println!(
        "failover proxy bound on {proxy} (initial state: {:?})",
        handle.state()
    );

    // Await Connected: the supervisor rotates past any failing candidate.
    let mut state_rx = handle.watch_state();
    let connected = tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            if *state_rx.borrow_and_update() == ConnectionState::Connected {
                return;
            }
            if state_rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await;
    if connected.is_err() || handle.state() != ConnectionState::Connected {
        return Err(format!(
            "failover never reached Connected (state: {:?})",
            handle.state()
        )
        .into());
    }
    println!(
        "state: {:?} (reached a working exit via failover)",
        handle.state()
    );

    // Egress proof through the stable failover address.
    let probe: SocketAddr = "1.1.1.1:443".parse()?;
    let budget = std::time::Duration::from_millis(2500);
    let mut ok = false;
    for attempt in 1..=15 {
        if let Ok(Ok(())) = tokio::time::timeout(budget, socks5_connect(proxy, probe)).await {
            println!("egress proof: CONNECT 1.1.1.1:443 ok (attempt {attempt})");
            ok = true;
            break;
        }
    }
    handle.shutdown();
    if ok {
        println!(
            "FAILOVER VALIDATED: rotated to a working exit and egressed through the stable address."
        );
        Ok(())
    } else {
        Err("egress never succeeded after failover".into())
    }
}

/// SOCKS5 greeting + CONNECT to `target`; Ok(()) iff the proxy replied success.
async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    let std::net::IpAddr::V4(ip) = target.ip() else {
        return Err("ipv4 only".into());
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(format!("rep={}", reply[1]).into());
    }
    Ok(())
}
