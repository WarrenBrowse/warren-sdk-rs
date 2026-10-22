//! Real-exit probe: a client that comes back with another session token
//! serial gets its pinned forwarded port back, and how long that takes.
//!
//! Run (beta): `WARREN_MNEMONIC="word1 ... word12" PIN_EXIT=RO
//! cargo run -p warren-sdk --example live_pinned_port_continuity`
//!
//! 1. Client A (token rotation 0) opens a single-hop tunnel to `PIN_EXIT`
//!    and maps a TCP port it pins (random in the forwarding range).
//! 2. A closes its tunnel and its process dies without releasing the
//!    mapping, as a daemon stopped for an update does (A runs as a child
//!    process: a mapping kept alive in-process keeps its tunnel alive too).
//!    With `PIN_CRASH=1`, A is killed with SIGKILL instead, so its tunnel is
//!    never closed and the exit learns of it only from its idle timeout.
//! 3. Client B of the same wallet (token rotation 1, so another serial of the
//!    same batch and a stranger to the exit's session placement) opens a new
//!    tunnel to the same exit and asks for the same port every
//!    `PIN_RETRY_SECS` (default 5) until it is granted or `PIN_MAX_SECS`
//!    (default 420) runs out.
//!
//! An exit that recognises the entitlement B presents as the one A spent
//! grants the port once A's session reads as departed (about 40 s); an exit
//! that does not keeps it behind the reaper and the release cooldown (about
//! five and a half minutes). Nothing printed names a token, a serial or the
//! wallet.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use warren_sdk::api::ReqwestTransport;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{MapProto, ProxyConfig};
use warren_sdk::{Circuit, WarrenClient};

const API_BASE: &str = warren_sdk::product::API_URL;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn client(
    phrase: &str,
    rotation: u64,
) -> Result<WarrenClient<ReqwestTransport>, Box<dyn std::error::Error>> {
    Ok(WarrenClient::builder()
        .identity(WarrenIdentity::from_mnemonic(phrase.trim())?)
        .api_base(API_BASE)
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .token_rotation(rotation)
        .session_admission(warren_sdk::SessionAdmission::TokensOnly)
        .build()?)
}

async fn exit_of(
    client: &WarrenClient<ReqwestTransport>,
    country: &str,
) -> Result<warren_sdk::discovery::VerifiedExit, Box<dyn std::error::Error>> {
    client
        .fetch_multihop_directory()
        .await?
        .into_iter()
        .find(|e| e.country.eq_ignore_ascii_case(country))
        .ok_or_else(|| format!("no exit in {country}").into())
}

/// Client A, run as its own process: pin `port`, close the tunnel the way a
/// daemon stopped for an update does, then die without releasing the mapping
/// (`process::exit` runs no destructor), leaving the exit to find out.
async fn hold(phrase: &str, country: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let first = client(phrase, 0)?;
    let exit = exit_of(&first, country).await?;
    let handle = first
        .start_proxy(&Circuit::SingleHop(exit), &proxy_config()?)
        .await?;
    let granted = handle
        .forwarder()
        .forward_port_with_suggested(MapProto::Tcp, port, "127.0.0.1:9".parse()?, port)
        .await?;
    println!(
        "[A] pinned port granted: {} (asked {port})",
        granted.external_port()
    );
    if std::env::var("PIN_CRASH").is_ok() {
        // Wait to be killed: a crash closes nothing, and the exit learns of
        // it only from its own idle timeout.
        std::future::pending::<()>().await;
    }
    handle.shutdown();
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("[A] tunnel closed, mapping left behind");
    std::process::exit(0);
}

fn proxy_config() -> Result<ProxyConfig, Box<dyn std::error::Error>> {
    Ok(ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let country = std::env::var("PIN_EXIT").unwrap_or_else(|_| "RO".to_owned());
    if let Ok(port) = std::env::var("PIN_HOLD_PORT") {
        return hold(&phrase, &country, port.parse()?).await;
    }
    let retry = Duration::from_secs(env_u64("PIN_RETRY_SECS", 5));
    let budget = Duration::from_secs(env_u64("PIN_MAX_SECS", 420));
    let port: u16 = 50_000 + (rand::random::<u16>() % 15_000);

    let mut holder = std::process::Command::new(std::env::current_exe()?)
        .env("PIN_HOLD_PORT", port.to_string())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let stdout = holder.stdout.take().ok_or("client A has no stdout")?;
    for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
        let line = line?;
        println!("{line}");
        if line.starts_with("[A] pinned port granted") && std::env::var("PIN_CRASH").is_ok() {
            holder.kill()?;
            println!("[A] killed (SIGKILL), mapping and tunnel left behind");
            break;
        }
    }
    if !holder.wait()?.success() && std::env::var("PIN_CRASH").is_err() {
        return Err("client A failed".into());
    }
    let left = Instant::now();

    let second = client(&phrase, 1)?;
    let exit = exit_of(&second, &country).await?;
    println!("exit: {} / {}", exit.country, exit.city);
    let handle = second
        .start_proxy(&Circuit::SingleHop(exit), &proxy_config()?)
        .await?;
    println!(
        "[B] tunnel up {:.1}s after A left",
        left.elapsed().as_secs_f64()
    );
    let local: SocketAddr = "127.0.0.1:9".parse()?;
    loop {
        match handle
            .forwarder()
            .forward_port_with_suggested(MapProto::Tcp, port, local, port)
            .await
        {
            Ok(forwarded) => {
                println!(
                    "[B] RESULT granted {} after {:.1}s",
                    forwarded.external_port(),
                    left.elapsed().as_secs_f64()
                );
                break;
            }
            Err(e) if left.elapsed() < budget => {
                println!("[B] refused at {:.1}s: {e}", left.elapsed().as_secs_f64());
                tokio::time::sleep(retry).await;
            }
            Err(e) => {
                println!(
                    "[B] RESULT still refused after {:.1}s: {e}",
                    left.elapsed().as_secs_f64()
                );
                break;
            }
        }
    }
    handle.shutdown();
    Ok(())
}
