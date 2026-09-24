//! Live check that multihop sessions left idle after their setup still carry
//! traffic, against a real exit.
//!
//! An exit that refreshes a `/v2` session only from the connection's own
//! traffic forgets a session that stays silent for five seconds after its
//! setup, and drops every later uplink frame of it until the client's next
//! rekey. This opens `WARREN_LEGS` sessions (default 4) to one exit and bonds
//! them, leaves them idle for `WARREN_IDLE_SECS` (default 8), then stripes DNS
//! queries across them and counts the answers. A healthy client gets every
//! answer; a client whose idle sessions were forgotten loses the share of
//! queries striped onto them.
//!
//! Run (the mnemonic is read from a file, never from the command line):
//! `WARREN_PRODUCT_ENV=beta WARREN_MNEMONIC_FILE=<path> cargo run -p warren-sdk
//! --example live_idle_legs`, optionally with `WARREN_EXIT_COUNTRY=<cc>`.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use warren_sdk::WarrenClient;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{BondedPacketSink, PacketSink, RecordType, build_udp_packet, encode_query};

const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
const QUERIES_PER_LEG: u16 = 10;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var("WARREN_MNEMONIC_FILE")?;
    let identity = WarrenIdentity::from_mnemonic(std::fs::read_to_string(path)?.trim())?;
    let legs: u16 = env_or("WARREN_LEGS", 4);
    let idle = Duration::from_secs(env_or("WARREN_IDLE_SECS", 8));
    let country = std::env::var("WARREN_EXIT_COUNTRY").ok();

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(warren_sdk::product::API_URL)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;
    let selector = client.fetch_exits().await?;
    let exit = client
        .fetch_multihop_directory()
        .await?
        .into_iter()
        .filter(|e| {
            country
                .as_deref()
                .is_none_or(|c| e.country.eq_ignore_ascii_case(c))
        })
        .find(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .ok_or("no cross-checked multihop exit matches")?;
    println!("exit {} / {}", exit.country, exit.city);

    let mut sinks = Vec::new();
    for _ in 0..legs.max(1) {
        sinks.push(client.connect_multihop(&exit).await?);
    }
    let source = sinks[0].session().assigned_ipv4();
    let bond = BondedPacketSink::new(sinks);
    println!("{} leg(s) up; idle for {}s", bond.len(), idle.as_secs());
    tokio::time::sleep(idle).await;

    let resolver = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
    let total = legs.max(1) * QUERIES_PER_LEG;
    let mut sent = HashSet::new();
    for i in 0..total {
        let id = 0x5000 + i;
        let query = encode_query("example.com", id, RecordType::A)?;
        let packet = build_udp_packet(SocketAddr::from((source, id)), resolver, &query)
            .ok_or("query does not fit a packet")?;
        bond.send_packet(&packet).await?;
        sent.insert(id);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut answered = HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while let Ok(Ok(packet)) = tokio::time::timeout_at(deadline, bond.recv_packet()).await {
        if let Some(id) = dns_answer_id(&packet).filter(|id| sent.contains(id)) {
            answered.insert(id);
        }
    }
    let lost = usize::from(total) - answered.len();
    println!("queries {total}, answered {}, lost {lost}", answered.len());
    if lost == 0 {
        println!("PASS: every idle leg carried its share");
        Ok(())
    } else {
        Err(format!(
            "FAIL: {lost} of {total} queries lost after {}s idle",
            idle.as_secs()
        )
        .into())
    }
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The DNS id of a UDP datagram from port 53 over IPv4, if `packet` is one.
fn dns_answer_id(packet: &[u8]) -> Option<u16> {
    if packet.first()? >> 4 != 4 || *packet.get(9)? != 17 {
        return None;
    }
    let udp = packet.get(usize::from(packet.first()? & 0x0f) * 4..)?;
    if u16::from_be_bytes([*udp.first()?, *udp.get(1)?]) != 53 {
        return None;
    }
    let dns = udp.get(8..)?;
    Some(u16::from_be_bytes([*dns.first()?, *dns.get(1)?]))
}
