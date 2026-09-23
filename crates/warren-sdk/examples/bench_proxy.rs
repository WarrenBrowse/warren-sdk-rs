//! Bench client for the userland proxy datapath on a shaped uplink.
//!
//! Brings up the supervised single-hop proxy exactly as wclaude does, prints
//! `PROXY <socks5 addr>` once it is up, then prints one `METRICS ...` line per
//! second from the live counters until stdin closes. The measurement itself (a
//! large upload through the SOCKS5 listener, the shape of one Claude Code turn)
//! is driven from outside by `scripts/bench/proxy-upload-shaped.sh`, so what is
//! under test is the shipped datapath and nothing written for the bench.
//!
//! Run: `WARREN_MNEMONIC="word1 ... word12" cargo run -p warren-sdk --example
//! bench_proxy`. `WARREN_EXIT_COUNTRY` picks the exit (default `NL`) and
//! `WARREN_API_BASE` the control plane (default: this build's channel; the beta
//! fleet the members run on answers at `https://api.beta.warrenbrowse.com`).
//!
//! Every `METRICS` line carries the offered counters (`tx_p`, `tx_b`: what the
//! inner stack handed the datagram queue, retransmissions included), the wire
//! counters (`sent`, `lost`) and the queue's own drops (`dg_drop_aqm`,
//! `dg_drop_full`), which is the split the 2026-09-13 investigation lacked.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_sdk::{Circuit, WarrenClient};

const API_BASE: &str = warren_sdk::product::API_URL;
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;
    let country = std::env::var("WARREN_EXIT_COUNTRY").unwrap_or_else(|_| "NL".to_owned());
    let api_base = std::env::var("WARREN_API_BASE").unwrap_or_else(|_| API_BASE.to_owned());

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(api_base)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;
    let selector = client.fetch_exits().await?;
    let exits = client.fetch_multihop_directory().await?;
    let exit = exits
        .into_iter()
        .filter(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .find(|e| e.country.eq_ignore_ascii_case(&country))
        .ok_or_else(|| format!("no cross-checked exit in {country}"))?;
    eprintln!("exit: {} / {}", exit.country, exit.city);

    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse()?,
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client
        .start_proxy_supervised(&Circuit::SingleHop(exit), &cfg)
        .await?;
    // The line carries the session's proxy credentials: the bench reads it
    // inside its own single-tenant container and hands it to curl on stdin.
    println!(
        "PROXY {}",
        &*handle
            .credentials()
            .proxy_url("socks5h", handle.local_addr())
    );

    let reader = handle.metrics_reader();
    let mut stdin = tokio::io::stdin();
    let mut sink = [0u8; 64];
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Some(m) = reader.read() {
                    let mut line = format!(
                        "METRICS state={:?} up_s={} tx_b={} tx_p={} rx_b={} rx_p={}",
                        handle.state(), m.uptime_secs, m.bytes_sent, m.packets_sent,
                        m.bytes_recv, m.packets_recv
                    );
                    if let Some(p) = m.path {
                        line.push_str(&format!(
                            " carrier={} rtt_ms={} mtu={} inner_mtu={} holes={} sent={} \
                             lost={} cong={} dg_drop_aqm={} dg_drop_full={} \
                             mtu_probes={} mtu_probes_lost={}",
                            p.carrier.as_str(), p.rtt_ms, p.path_mtu, p.max_inner_payload,
                            p.black_holes, p.sent_packets, p.lost_packets,
                            p.congestion_events, p.dg_dropped_aqm, p.dg_dropped_overflow,
                            p.plpmtud_probes_sent, p.plpmtud_probes_lost
                        ));
                    }
                    println!("{line}");
                } else {
                    println!("METRICS state={:?} datapath=none", handle.state());
                }
            }
            read = stdin.read(&mut sink) => {
                if matches!(read, Ok(0) | Err(_)) {
                    break;
                }
            }
        }
    }
    handle.shutdown();
    Ok(())
}
