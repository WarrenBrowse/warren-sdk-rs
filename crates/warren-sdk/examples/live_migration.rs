//! Live validation that a PRODUCTION exit accepts a QUIC path migration.
//!
//! Run (beta stack): `WARREN_PRODUCT_ENV=beta WARREN_MNEMONIC="word1 ... word12"
//! cargo run -p warren-sdk --example live_migration`
//!
//! This is the real-network half of the migration watchdog: the decision loop
//! and the fallback are unit-tested against loopback exits, but whether a real
//! relay revalidates a moved path (rather than dropping it, which its generic
//! engine server config would do) can only be observed against real
//! infrastructure.
//!
//! It dials one multihop session, proves egress through it, rebinds the session
//! onto a fresh socket exactly as the watchdog does on a network change, and
//! proves egress again on the SAME session. A second success is the proof: no
//! re-handshake happens here, so the exit revalidated the new 4-tuple.

use std::sync::Arc;
use std::time::Duration;

use warren_sdk::identity::WarrenIdentity;
use warren_sdk::transport::RebindPolicy;
use warren_sdk::{WarrenClient, discovery::VerifiedExit};

/// Public resolver queried through the tunnel; any UDP answer proves the exit
/// forwarded and NATed the flow.
const PROBE_RESOLVER: &str = "1.1.1.1:53";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's 12 words")?;
    let identity = WarrenIdentity::from_mnemonic(phrase.trim())?;
    println!(
        "channel: {} ({})",
        warren_sdk::product::CHANNEL_NAME,
        warren_sdk::product::API_URL
    );

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(warren_sdk::product::API_URL)
        .server_pubkey_pin(warren_sdk::product::SERVER_PUBKEY_HEX)
        .build()?;

    let selector = client.fetch_exits().await?;
    let exits = client.fetch_multihop_directory().await?;
    let exit: VerifiedExit = exits
        .into_iter()
        .find(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .ok_or("no cross-checked multihop exit")?;
    println!("exit: {} / {}  {}", exit.country, exit.city, exit.endpoint);

    let sink = client.connect_multihop(&exit).await?;
    let session = warren_sdk::net::PacketSink::multihop_session(&sink)
        .ok_or("the multihop sink must expose its session")?;
    let assignment = session.assignment().clone();
    let mtu = warren_sdk::net::PacketSink::max_payload(&sink);
    println!(
        "tunnel up: assigned {} mtu {mtu} carrier {:?}",
        session.assigned_ipv4(),
        session.carrier()
    );

    let config = warren_sdk::net::NetstackConfig::new(
        session.assigned_ipv4(),
        assignment.prefix_len,
        std::net::Ipv4Addr::from(assignment.gateway_ipv4),
        mtu,
    );
    let (connector, _alive) = warren_sdk::net::spawn_over_sink(Arc::new(sink), config);

    let before = probe_egress(&connector).await?;
    println!("egress before the migration: {before} bytes of DNS answer");

    let old_addr = session.local_addr()?;
    session.rebind_wildcard(RebindPolicy::Plain)?;
    let new_addr = session.local_addr()?;
    assert_ne!(
        old_addr.port(),
        new_addr.port(),
        "the rebind must move the session onto a fresh socket"
    );
    println!("rebound the session onto a fresh socket (local port moved)");

    let after = probe_egress(&connector).await?;
    println!("egress after the migration: {after} bytes of DNS answer");
    println!("path after the migration: {:?}", session.path_quality());
    println!("MIGRATION VALIDATED: the exit revalidated the moved path, no re-handshake.");
    Ok(())
}

/// Sends one DNS query through the tunnel and returns the answer size. Fails
/// when the tunnel carries nothing, which is what a refused migration looks
/// like from the client.
async fn probe_egress(connector: &warren_sdk::net::TunnelConnector) -> Result<usize, String> {
    let socket = connector
        .open_udp()
        .await
        .map_err(|e| format!("open the in-tunnel UDP flow: {e}"))?;
    let mut socket = socket;
    let target: std::net::SocketAddr = PROBE_RESOLVER.parse().expect("literal resolver address");
    socket
        .send_to(dns_query().into(), target)
        .await
        .map_err(|e| format!("send the probe query: {e}"))?;
    let answer = tokio::time::timeout(Duration::from_secs(8), socket.recv_from())
        .await
        .map_err(|_| "no DNS answer through the tunnel within 8s".to_owned())?
        .ok_or_else(|| "the in-tunnel UDP flow closed".to_owned())?;
    Ok(answer.0.len())
}

/// A minimal DNS `A` query for `example.com`, built by hand so this example
/// needs no resolver crate.
fn dns_query() -> Vec<u8> {
    let mut q = vec![
        0x42, 0x42, // transaction id
        0x01, 0x00, // standard query, recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answer/authority/additional
    ];
    for label in ["example", "com"] {
        q.push(u8::try_from(label.len()).expect("short label"));
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    q
}
