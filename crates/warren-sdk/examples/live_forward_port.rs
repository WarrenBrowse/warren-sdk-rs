//! Live probe of the NAT-PMP port-forwarding path against a production exit.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_forward_port`
//!
//! Opens a real multihop proxy datapath, then asks the exit to map a tunnel-side
//! TCP port via NAT-PMP (`ProxyHandle::forward_port`). What this validates against
//! real infrastructure:
//!   - whether the production exit runs a NAT-PMP gateway at all;
//!   - if it does, that the full map exchange (request, retransmission, parse)
//!     completes and yields an allocated external port.
//!
//! It does NOT exercise an inbound dial-in (that needs an external internet peer
//! reaching the granted external port); a successful grant is still conclusive
//! that the gateway path works end to end. A clean "gateway disabled / no reply"
//! is reported as a non-fatal outcome, not a crash.

use std::net::SocketAddr;

use tokio::net::TcpListener;
use warren_sdk::WarrenClient;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{MapProto, ProxyConfig};

const API_BASE: &str = "https://api.warrenbrowse.com";
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
/// Tunnel-side internal port to request a mapping for (arbitrary).
const INTERNAL_PORT: u16 = 8080;

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
    let handle = client.start_proxy_multihop(&exit, &cfg).await?;
    println!("tunnel up (state: {:?})", handle.state());

    // A local server the forwarded port would relay inbound connections to.
    let local = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr: SocketAddr = local.local_addr()?;
    tokio::spawn(async move {
        // Accept-and-echo, so a real inbound dial-in (if one existed) round-trips.
        while let Ok((mut s, _)) = local.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    println!("requesting NAT-PMP TCP mapping for internal port {INTERNAL_PORT} ...");
    match handle
        .forward_port(MapProto::Tcp, INTERNAL_PORT, local_addr)
        .await
    {
        Ok(forwarded) => {
            println!(
                "MAPPING GRANTED: external_port={} -> internal_port={} (the exit runs a NAT-PMP \
                 gateway and the map exchange completed end to end).",
                forwarded.external_port(),
                forwarded.internal_port()
            );
            println!(
                "(An external peer dialing the exit on port {} would be relayed to the local \
                 server; that leg needs an internet peer and is not exercised here.)",
                forwarded.external_port()
            );
            forwarded.shutdown().await;
            println!("mapping released.");
        }
        Err(e) => {
            // Not a crash: many exits do not run a NAT-PMP gateway. Report the
            // protocol-level reason (no identity material) and exit cleanly.
            print!("no mapping: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                print!(" -> {s}");
                src = s.source();
            }
            println!();
            println!(
                "(This is expected if the exit does not run a NAT-PMP gateway; the client path \
                 itself handled the outcome cleanly.)"
            );
        }
    }

    handle.shutdown();
    Ok(())
}
