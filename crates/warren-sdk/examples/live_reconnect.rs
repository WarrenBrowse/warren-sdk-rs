//! Live validation of the reconnect path against a production exit.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_reconnect`
//!
//! A reconnect rebuilds the whole datapath from a freshly fetched `IpAssign`:
//! the exit may hand out a different tunnel address, gateway or MTU on the next
//! session, so the netstack must be rebuilt from the new assignment rather than
//! reused. This example runs two connect/egress/teardown cycles and proves egress
//! each time, exercising exactly that rebuild (the second cycle re-reads the
//! assignment and re-establishes the sealed tunnel from scratch).
//!
//! This is the app-driven reconnect pattern: observe `ProxyHandle::state`, and on
//! `TunnelState::Disconnected` drop the handle and call `start_proxy`
//! again. For a hands-off equivalent, `start_proxy_supervised` keeps the
//! tunnel up automatically behind a stable proxy address. It needs a subscribed
//! wallet (the exit gates the `IpAssign`).

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_sdk::{Circuit, WarrenClient};

const API_BASE: &str = warren_sdk::product::API_URL;
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
const CYCLES: usize = 2;

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

    for cycle in 1..=CYCLES {
        println!("\n=== cycle {cycle}/{CYCLES} ===");
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

        let cfg = ProxyConfig {
            socks5: "127.0.0.1:0".parse()?,
            http: None,
            ..ProxyConfig::default()
        };
        let handle = client
            .start_proxy(&Circuit::SingleHop(exit.clone()), &cfg)
            .await?;
        println!(
            "tunnel up on {} (state: {:?}) via {} / {}",
            handle.local_addr(),
            handle.state(),
            exit.country,
            exit.city
        );

        // Egress proof: a SOCKS5 CONNECT to a public host completing through the
        // freshly rebuilt tunnel means this cycle's datapath egresses at the exit.
        let probe: SocketAddr = "1.1.1.1:443".parse()?;
        let budget = std::time::Duration::from_millis(2500);
        let mut ok = false;
        for attempt in 1..=15 {
            if let Ok(Ok(())) =
                tokio::time::timeout(budget, socks5_connect(handle.local_addr(), probe)).await
            {
                println!("egress proof: CONNECT 1.1.1.1:443 ok (attempt {attempt})");
                ok = true;
                break;
            }
        }
        if !ok {
            return Err(format!("cycle {cycle}: egress never succeeded").into());
        }

        handle.shutdown();
        println!("cycle {cycle}: tunnel torn down");
    }

    println!(
        "\nRECONNECT VALIDATED: {CYCLES} independent sessions each rebuilt from a fresh IpAssign and egressed."
    );
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
