//! End-to-end facade test: `WarrenClient::connect_tunnel` establishes the QUIC
//! tunnel to an in-process exit and yields a working packet plane. The account
//! API transport is a stub (connect does not touch it).

use ed25519_dalek::SigningKey;
use warren_sdk::WarrenClient;
use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_sdk::discovery::{ExitId, Location, Relay};
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::PacketSink;
use warren_sdk::transport::tls::{default_crypto_provider, make_server_config};
use warren_wire::{
    MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, SetupAck, decode_setup, encode_setup_ack,
};

const ALPN_H3: &[u8] = b"h3";

/// A transport that is never used (connect_tunnel does not call the API).
struct UnusedTransport;

impl HttpTransport for UnusedTransport {
    async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Io("transport must not be called".into()))
    }
}

async fn spawn_fake_exit(exit_key: SigningKey) -> (std::net::SocketAddr, [u8; 32]) {
    let exit_pubkey = exit_key.verifying_key().to_bytes();
    let cfg = make_server_config(&exit_key, default_crypto_provider(), &[ALPN_H3]).expect("cfg");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("ep");
    let addr = endpoint.local_addr().expect("addr");
    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let _ = decode_setup(
            &recv
                .read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .expect("setup"),
        );
        let ack = SetupAck {
            protocol_version: PROTOCOL_VERSION,
            tunnel_ipv4: [10, 66, 0, 5],
            tunnel_ipv6: None,
            exit_pubkey,
            max_mtu: 1280,
            multiconn_attached: true,
            daita_spec: None,
        };
        send.write_all(&encode_setup_ack(&ack).expect("enc"))
            .await
            .expect("write");
        send.finish().expect("finish");
        while let Ok(dg) = conn.read_datagram().await {
            if conn.send_datagram(dg).is_err() {
                break;
            }
        }
        drop(endpoint);
    });
    (addr, exit_pubkey)
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
