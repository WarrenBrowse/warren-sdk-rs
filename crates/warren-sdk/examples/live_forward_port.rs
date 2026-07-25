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
//!     completes and yields an allocated external port;
//!   - the INBOUND leg end to end: this host doubles as the external internet
//!     peer by dialing the exit's public `ip:external_port` directly (a distinct
//!     network path from the in-process tunnel client), and the payload must
//!     round-trip through the tunnel to the local server.
//!
//! A clean "gateway disabled / no reply" is reported as a non-fatal outcome, not
//! a crash; if the grant succeeds but the inbound dial does not round-trip, that
//! is reported too (the grant itself is still validated).

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{MapProto, ProxyConfig};
use warren_sdk::{Circuit, WarrenClient};

const API_BASE: &str = warren_sdk::product::API_URL;
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
    let handle = client
        .start_proxy(&Circuit::SingleHop(exit.clone()), &cfg)
        .await?;
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

            // Full inbound leg: this host doubles as the "external internet peer"
            // by dialing the exit's PUBLIC ip:external_port DIRECTLY (not through
            // the tunnel). If the exit forwards it through the tunnel to our
            // internal port, serve_inbound relays it to the local echo and the
            // payload round-trips. This is a distinct network path from the
            // in-process tunnel client, so a single host can exercise both ends.
            let exit_ip = exit.endpoint.ip();
            let inbound_target = SocketAddr::new(exit_ip, forwarded.external_port());
            println!("dialing the exit's public {inbound_target} as an external peer ...");
            let probe = b"inbound-roundtrip";
            let mut relayed = false;
            for attempt in 1..=10 {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    inbound_roundtrip(inbound_target, probe),
                )
                .await
                {
                    Ok(Ok(echo)) if echo == probe => {
                        println!(
                            "INBOUND CONFIRMED (attempt {attempt}): a connection to the exit's \
                             public port was forwarded through the tunnel to the local server and \
                             the payload round-tripped."
                        );
                        relayed = true;
                        break;
                    }
                    Ok(Ok(_)) => {}           // connected but wrong/short echo: retry
                    Ok(Err(_)) | Err(_) => {} // connect/timeout: warm-up, retry
                }
            }
            if !relayed {
                println!(
                    "(Mapping was granted, but a direct dial to {inbound_target} did not \
                     round-trip: the exit may not actually relay inbound forwarded ports, or the \
                     port is filtered on the path. The grant itself is validated.)"
                );
            }

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

/// Connects directly to `target` (the exit's public ip:external_port), sends
/// `probe`, and returns the bytes echoed back through the forwarded tunnel.
async fn inbound_roundtrip(
    target: SocketAddr,
    probe: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(target).await?;
    s.write_all(probe).await?;
    s.flush().await?;
    let mut buf = vec![0u8; probe.len()];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}
