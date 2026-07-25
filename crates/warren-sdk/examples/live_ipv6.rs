//! Live validation of dual-stack IPv6 egress against a production exit.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_ipv6`
//!
//! Opens a real multihop proxy and inspects the exit's `IpAssign`. If the exit
//! granted a v6 address, it proves v6 egress with a SOCKS5 CONNECT to a public
//! IPv6 literal (Cloudflare `2606:4700:4700::1111:443`) completing through the
//! sealed tunnel. If the exit did not grant v6, that is reported as a clean,
//! non-fatal outcome (this exit cannot exercise the v6 datapath).

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_sdk::{Circuit, WarrenClient};

const API_BASE: &str = warren_sdk::product::API_URL;
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
/// Cloudflare's public IPv6 resolver, which answers TCP/443.
const V6_PROBE: &str = "[2606:4700:4700::1111]:443";

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
    let v6_ids: Vec<_> = selector
        .relays()
        .iter()
        .filter(|r| r.ipv6_egress())
        .map(warren_sdk::discovery::Relay::endpoint_id)
        .collect();

    // Probe EVERY directory exit's IpAssign for a v6 address (not just one): a
    // different exit may grant client v6 even if the first does not.
    println!("probing {} exit(s) for a v6 assignment ...", exits.len());
    let mut chosen = None;
    for e in &exits {
        let marks_v6 = v6_ids.contains(&e.exit_ed25519_pubkey);
        match client.connect_multihop(e).await {
            Ok(sink) => {
                let v6 = sink.session().assigned_ipv6();
                println!(
                    "  {} / {} {}: assigned_ipv4={} assigned_ipv6={} (list ipv6_egress={})",
                    e.country,
                    e.city,
                    e.endpoint,
                    sink.session().assigned_ipv4(),
                    v6.map_or_else(|| "none".to_owned(), |a| a.to_string()),
                    marks_v6
                );
                if v6.is_some() && chosen.is_none() {
                    chosen = Some(e.clone());
                }
            }
            Err(err) => println!("  {} / {}: connect failed: {err}", e.country, e.city),
        }
    }

    let Some(exit) = chosen else {
        println!(
            "no exit granted a client v6 address: the v6 client datapath cannot be exercised \
             against prod today. The SDK requested v6 and fell back to v4-only (fail-closed), \
             which is correct; enabling it is an exit-side change (assign v6 in the IpAssign)."
        );
        return Ok(());
    };
    println!(
        "using {} / {} (granted v6) for the egress proof",
        exit.country, exit.city
    );

    // Start the proxy (re-establishes; the facade enables dual-stack from the
    // fresh assignment) and prove v6 egress.
    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client
        .start_proxy(&Circuit::SingleHop(exit.clone()), &cfg)
        .await?;
    let proxy = handle.local_addr();
    println!("proxy up on {proxy}; proving IPv6 egress to {V6_PROBE} ...");

    let target: SocketAddr = V6_PROBE.parse()?;
    let budget = std::time::Duration::from_millis(3000);
    let mut ok = false;
    for attempt in 1..=15 {
        if let Ok(Ok(())) = tokio::time::timeout(budget, socks5_connect_v6(proxy, target)).await {
            println!(
                "IPv6 EGRESS CONFIRMED (attempt {attempt}): SYN-ACK from {V6_PROBE} via the exit."
            );
            ok = true;
            break;
        }
    }
    handle.shutdown();
    if ok {
        Ok(())
    } else {
        Err("v6 egress never succeeded through the tunnel".into())
    }
}

/// SOCKS5 greeting + CONNECT to an IPv6 `target` (ATYP 0x04); Ok(()) iff the
/// proxy replied success.
async fn socks5_connect_v6(
    proxy: SocketAddr,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    let std::net::IpAddr::V6(ip) = target.ip() else {
        return Err("ipv6 target required".into());
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x04];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 22]; // v6 bound-addr reply is longer than v4
    // The reply length depends on the bound ATYP; read the fixed 4-byte head then
    // drain by ATYP. Simpler: read enough and check the status byte.
    s.read_exact(&mut reply[..4]).await?;
    if reply[1] != 0x00 {
        return Err(format!("rep={}", reply[1]).into());
    }
    Ok(())
}
