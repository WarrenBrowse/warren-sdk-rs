//! Real-exit probe: two live devices of one wallet that lead with the same
//! session token serial on the same exit both come up, each on its own
//! session, and the first one keeps working once the second arrives.
//!
//! Run (beta): `WARREN_MNEMONIC="word1 ... word12" PIN_EXIT=SG
//! cargo run -p warren-sdk --example live_one_serial_two_devices`
//!
//! Each device is its own process (two clients in one process share the
//! wallet's batch and never lead with the same serial), both on token
//! rotation 0. The exit must refuse the second one's lead serial as in use,
//! so it walks to its next token, instead of merging it into the first one's
//! session. Every device fetches an HTTPS IP echo through its own SOCKS5
//! listener; the first one fetches again after the second came up.
//!
//! Nothing printed names a token, a serial or the wallet.

use std::time::Duration;

use warren_sdk::api::ReqwestTransport;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_sdk::{Circuit, SessionAdmission, WarrenClient};

const ECHO_URL: &str = "https://api.ipify.org";

fn client(phrase: &str) -> Result<WarrenClient<ReqwestTransport>, Box<dyn std::error::Error>> {
    Ok(WarrenClient::builder()
        .identity(WarrenIdentity::from_mnemonic(phrase.trim())?)
        .api_base(warren_sdk::product::API_URL)
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .token_rotation(0)
        .session_admission(SessionAdmission::TokensOnly)
        .build()?)
}

/// The exit's address as seen through `proxy` (a SOCKS5 URL carrying the
/// listener's credentials), or why the fetch failed.
fn echo_through(proxy: &str) -> String {
    let out = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "15", "--proxy", proxy])
        .arg(ECHO_URL)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        Ok(o) => format!("FAILED: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => format!("FAILED: {e}"),
    }
}

async fn device(name: &str, hold: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let country = std::env::var("PIN_EXIT").unwrap_or_else(|_| "SG".to_owned());
    let client = client(&phrase)?;
    let exit = client
        .fetch_multihop_directory()
        .await?
        .into_iter()
        .find(|e| e.country.eq_ignore_ascii_case(&country))
        .ok_or_else(|| format!("no exit in {country}"))?;
    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client.start_proxy(&Circuit::SingleHop(exit), &cfg).await?;
    let proxy = handle
        .credentials()
        .proxy_url("socks5h", handle.local_addr());
    let socks = proxy.as_str();
    println!("[{name}] up, echo: {}", echo_through(socks));
    if name == "A" {
        let status = std::process::Command::new(std::env::current_exe()?)
            .env("ONE_SERIAL_ROLE", "B")
            .status()?;
        println!("[A] device B exited: {status}");
        println!("[A] after B, echo: {}", echo_through(socks));
    } else {
        tokio::time::sleep(hold).await;
        println!(
            "[{name}] after {}s, echo: {}",
            hold.as_secs(),
            echo_through(socks)
        );
    }
    handle.shutdown();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::var("ONE_SERIAL_ROLE").as_deref() {
        Ok("B") => device("B", Duration::from_secs(20)).await,
        _ => device("A", Duration::ZERO).await,
    }
}
