//! End-to-end facade test: `WarrenClient::connect_tunnel` establishes the QUIC
//! tunnel to an in-process exit and yields a working packet plane. The account
//! API transport is a stub (connect does not touch it).

use ed25519_dalek::SigningKey;
use warren_sdk::WarrenClient;
use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_sdk::discovery::{ExitId, Location, Relay};
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::PacketSink;
use warren_test_support::spawn_fake_exit;

/// A transport that is never used (connect_tunnel does not call the API).
struct UnusedTransport;

impl HttpTransport for UnusedTransport {
    async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Io("transport must not be called".into()))
    }
}

#[tokio::test]
async fn facade_connects_tunnel_to_exit_and_passes_a_packet() {
    let (addr, exit_pubkey) = spawn_fake_exit(SigningKey::from_bytes(&[9u8; 32])).await;

    let (identity, _mnemonic) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build_with_transport(UnusedTransport)
        .expect("build");

    // A resolved exit pointing at the in-process server.
    let exit = Relay::new(
        exit_pubkey,
        ExitId::from_bytes([0xa1; 16]),
        vec![addr],
        Location::new("RO", "Bucharest"),
        100,
        true,
    );

    let sink = client.connect_tunnel(&exit).await.expect("tunnel connects");
    sink.send_packet(&[0x45, 0, 0, 0]).await.expect("send");
    let echoed = sink.recv_packet().await.expect("recv");
    assert_eq!(echoed, vec![0x45, 0, 0, 0]);
}
