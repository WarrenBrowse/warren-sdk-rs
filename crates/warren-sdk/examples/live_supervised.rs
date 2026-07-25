//! Live validation of the self-healing supervised proxy against a production exit.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_supervised`
//!
//! Starts `start_proxy_supervised`, awaits the `Connected` state on the
//! state watch, proves egress through the stable SOCKS5 address, and shuts down.
//! This validates the supervised happy path (bind-once listener, background
//! establish, `ConnectionState` reporting, egress) against real infrastructure.
//! The drop-triggered automatic reconnect needs a forced mid-session tunnel drop
//! (not reproducible here); the rebuild-from-fresh-IpAssign path it reuses is
//! validated by `live_reconnect`.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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

    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client
        .start_proxy_supervised(&Circuit::SingleHop(exit.clone()), &cfg)
        .await?;
    let proxy_addr = handle.local_addr();
    println!(
        "supervised proxy bound on {proxy_addr} (initial state: {:?})",
        handle.state()
    );

    // Await Connected on the state watch (the supervisor establishes in the
    // background, so the handle returns before the first tunnel is up).
    let mut state_rx = handle.watch_state();
    let connected = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if state_rx.borrow_and_update().eq(&ConnectionState::Connected) {
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
            "supervisor did not reach Connected (state: {:?})",
            handle.state()
        )
        .into());
    }
    println!("state: {:?}", handle.state());

    // Egress proof through the stable supervised address.
    let probe: SocketAddr = "1.1.1.1:443".parse()?;
    let budget = std::time::Duration::from_millis(2500);
    let mut ok = false;
    for attempt in 1..=15 {
        if let Ok(Ok(())) = tokio::time::timeout(budget, socks5_connect(proxy_addr, probe)).await {
            println!("egress proof: CONNECT 1.1.1.1:443 ok (attempt {attempt})");
            ok = true;
            break;
        }
    }
    if !ok {
        return Err("egress never succeeded through the supervised proxy".into());
    }

    println!("SUPERVISED PROXY VALIDATED: stable address, reached Connected, egress confirmed.");
    handle.shutdown();
    Ok(())
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
