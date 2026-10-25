//! Real-exit probe: a client that changes country keeps its forwarded port,
//! and how many requests that costs.
//!
//! Run (beta): `WARREN_MNEMONIC="word1 ... word12" PIN_EXIT_A=DE PIN_EXIT_B=FI
//! WARREN_PRODUCT_ENV=beta cargo run -p warren-sdk --example live_port_country_switch`
//!
//! One client maps a port it pins on exit A, deletes it and leaves (the way
//! the app tears a tunnel down to change country), maps the same port on exit
//! B, then goes back to A and maps it again. Each leg prints how long the
//! grant took and how many requests were refused first. An exit that hands the
//! entitlement's lease back when the client deletes its forward grants every
//! leg at the first request; one that keeps it until it reaps the session
//! refuses the entitlement on the next exit.
//!
//! `PIN_RELEASE=0` leaves the forward without deleting it, as a client that
//! loses its tunnel does. Nothing printed names a token, a serial or the
//! wallet.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use warren_sdk::api::ReqwestTransport;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{MapProto, ProxyConfig};
use warren_sdk::{Circuit, SessionAdmission, WarrenClient};

const BUDGET: Duration = Duration::from_secs(120);

fn client(phrase: &str) -> Result<WarrenClient<ReqwestTransport>, Box<dyn std::error::Error>> {
    Ok(WarrenClient::builder()
        .identity(WarrenIdentity::from_mnemonic(phrase.trim())?)
        .api_base(warren_sdk::product::API_URL)
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .token_rotation(0)
        .session_admission(SessionAdmission::TokensOnly)
        .build()?)
}

/// Opens a tunnel to `country`, maps `port` until it is granted or the budget
/// runs out, then deletes it (or not) and closes the tunnel.
async fn leg(
    client: &WarrenClient<ReqwestTransport>,
    name: &str,
    country: &str,
    port: u16,
    release: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let exit = client
        .fetch_multihop_directory()
        .await?
        .into_iter()
        .find(|e| e.country.eq_ignore_ascii_case(country))
        .ok_or_else(|| format!("no exit in {country}"))?;
    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client.start_proxy(&Circuit::SingleHop(exit), &cfg).await?;
    let local: SocketAddr = "127.0.0.1:9".parse()?;
    let asked = Instant::now();
    let mut refused = 0u32;
    let forwarded = loop {
        match handle
            .forwarder()
            .forward_port_with_suggested(MapProto::Tcp, port, local, port)
            .await
        {
            Ok(forwarded) => break forwarded,
            Err(e) if asked.elapsed() < BUDGET => {
                refused += 1;
                println!(
                    "[{name}] refused after {:.2}s: {e}",
                    asked.elapsed().as_secs_f64()
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                println!("[{name}] RESULT still refused after {refused} tries: {e}");
                handle.shutdown();
                return Ok(());
            }
        }
    };
    println!(
        "[{name}] RESULT {country}: port {} granted in {:.2}s after {refused} refusal(s)",
        forwarded.external_port(),
        asked.elapsed().as_secs_f64()
    );
    if release {
        let deleted = Instant::now();
        forwarded.shutdown().await;
        println!(
            "[{name}] forward deleted at the exit in {:.2}s",
            deleted.elapsed().as_secs_f64()
        );
    } else {
        drop(forwarded);
    }
    handle.shutdown();
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let a = std::env::var("PIN_EXIT_A").unwrap_or_else(|_| "DE".to_owned());
    let b = std::env::var("PIN_EXIT_B").unwrap_or_else(|_| "FI".to_owned());
    let release = std::env::var("PIN_RELEASE").map_or(true, |v| v != "0");
    let port: u16 = 50_000 + (rand::random::<u16>() % 15_000);
    let client = client(&phrase)?;

    leg(&client, "1 first", &a, port, release).await?;
    leg(&client, "2 switch", &b, port, release).await?;
    leg(&client, "3 back", &a, port, release).await?;
    Ok(())
}
