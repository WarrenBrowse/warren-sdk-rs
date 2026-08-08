//! Live attribution of every tunnel death against a PRODUCTION exit.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! live_epoch_causes -- <minutes>`
//!
//! Holds one supervised session for the requested duration and prints every
//! state transition with the supervisor's own verdict on WHY the epoch ended
//! (`EpochEnd`), plus the QUIC close reason. This is the real-network half of
//! the epoch-attribution work: the in-process tests prove the supervisor
//! publishes the right cause for each of its four epoch enders, and this proves
//! what a real path actually produces.
//!
//! It is also the harness for the path-stall experiment. Injecting a stall on
//! the box (dropping the client's outbound UDP for N seconds) and reading the
//! cause printed here is what separates the two hypotheses:
//!
//! - `cause=EgressDead close=None` means a live QUIC connection was torn down
//!   by the in-tunnel probe: a working tunnel convicted on a transient.
//! - `cause=SessionClosed close=Some("timed_out")` means the transport itself
//!   gave up, which is the honest outcome for a path that really stopped.
//!
//! The session is otherwise idle on purpose: an idle tunnel is what the fleet
//! spends most of its life being, and it is the shape every observed death had.

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
    let minutes: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(10);
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;

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
        .start_proxy_supervised(&Circuit::SingleHop(exit), &cfg)
        .await?;
    let proxy_addr = handle.local_addr();
    println!("proxy: {proxy_addr}");

    let started = std::time::Instant::now();
    let mut state_rx = handle.watch_state();
    let epoch_rx = handle.watch_epoch_end();
    let mut previous = ConnectionState::Connecting;
    let mut deaths = 0usize;

    let watcher = tokio::spawn(async move {
        loop {
            let state = *state_rx.borrow_and_update();
            if state != previous {
                let left_connected =
                    previous == ConnectionState::Connected && state != ConnectionState::Connected;
                let report = epoch_rx.borrow().filter(|_| left_connected);
                if left_connected {
                    deaths += 1;
                }
                match report {
                    Some(r) => println!(
                        "[{:>6.1}s] {previous:?} -> {state:?}   DEATH #{deaths}  \
                         cause={:?} close={:?} epoch={}s",
                        started.elapsed().as_secs_f64(),
                        r.cause,
                        r.close,
                        r.up_s
                    ),
                    None => println!(
                        "[{:>6.1}s] {previous:?} -> {state:?}",
                        started.elapsed().as_secs_f64()
                    ),
                }
                previous = state;
            }
            if state_rx.changed().await.is_err() {
                return deaths;
            }
        }
    });

    // Keep the session honest: one CONNECT a minute proves the proxy is still
    // usable, without turning an idle tunnel into a loaded one.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(minutes * 60);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let reachable = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            socks5_connect(proxy_addr, "1.1.1.1:443".parse()?),
        )
        .await;
        println!(
            "[{:>6.1}s] egress check: {}",
            started.elapsed().as_secs_f64(),
            match reachable {
                Ok(Ok(())) => "ok".to_owned(),
                Ok(Err(e)) => format!("refused ({e})"),
                Err(_) => "timeout".to_owned(),
            }
        );
    }

    watcher.abort();
    println!("done after {minutes} minutes");
    handle.shutdown();
    Ok(())
}

/// SOCKS5 greeting + CONNECT to `target`; Ok(()) iff the proxy replied success.
async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err("socks5 greeting refused".into());
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => return Err("ipv4 target only".into()),
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(format!("socks5 connect failed (rep {})", reply[1]).into());
    }
    Ok(())
}
