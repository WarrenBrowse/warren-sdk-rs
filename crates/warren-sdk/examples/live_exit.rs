//! Live validation against the production Warren API and a real exit.
//!
//! Run: `cargo run -p warren-sdk --example live_exit`
//!
//! Fetches and verifies the production signed exit list (pinned server key),
//! then opens a real QUIC tunnel (RFC 7250 raw-public-key handshake +
//! Setup/SetupAck) to a selected exit. This is the real-exit validation that
//! in-process fake-device tests cannot provide.

use warren_sdk::WarrenClient;
use warren_sdk::discovery::ExitQuery;
use warren_sdk::identity::WarrenIdentity;

const API_BASE: &str = "https://api.warrenbrowse.com";
const SERVER_PUBKEY_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (identity, _mnemonic) = WarrenIdentity::generate();
    println!("client identity: {}", identity.address());

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base(API_BASE)
        .server_pubkey_pin(SERVER_PUBKEY_PIN)
        .build()?;

    println!("fetching signed exit list from {API_BASE} ...");
    let selector = client.fetch_exits().await?;
    println!("signed list verified against the pinned server key.");

    let exit = selector.select_weighted(&ExitQuery::any())?.clone();
    let ep = exit.endpoint_id();
    println!(
        "selected exit: {} / {}  endpoint={:02x}{:02x}..  addrs={:?}",
        exit.location().country_code(),
        exit.location().city(),
        ep[0],
        ep[1],
        exit.addrs(),
    );

    println!("opening QUIC tunnel (RPK handshake + Setup/SetupAck) ...");
    let sink = client.connect_tunnel(&exit).await?;
    let session = sink.session();
    println!(
        "TUNNEL UP. assigned_ipv4={} max_mtu={} max_payload={}",
        session.assigned_ipv4(),
        session.assigned_max_mtu(),
        warren_sdk::net::PacketSink::max_payload(&sink),
    );
    println!("real-exit handshake validated.");
    Ok(())
}
