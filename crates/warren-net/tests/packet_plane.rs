//! Validates the QUIC packet plane ([`QuicPacketSink`]) end-to-end against an
//! in-process exit: a packet sent through the sink is echoed back as a datagram.

use ed25519_dalek::SigningKey;
use warren_net::{PacketSink, QuicPacketSink};
use warren_transport::ClientTunnel;
use warren_transport::tls::{default_crypto_provider, make_server_config};
use warren_wire::{
    MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, SetupAck, decode_setup, encode_setup_ack,
};

const ALPN_H3: &[u8] = b"h3";

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
            tunnel_ipv4: [10, 66, 0, 9],
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
        // Echo datagrams until the client closes.
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
async fn quic_packet_sink_round_trips_a_packet() {
    let (addr, exit_pubkey) = spawn_fake_exit(SigningKey::from_bytes(&[9u8; 32])).await;
    let session = ClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]))
        .connect(exit_pubkey, addr)
        .await
        .expect("connect");

    let sink = QuicPacketSink::new(session);
    assert!(sink.max_payload() >= 1200, "path MTU floor");

    // A minimal fake IP packet; the exit echoes it verbatim.
    let packet = vec![0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef];
    sink.send_packet(&packet).await.expect("send");
    let got = sink.recv_packet().await.expect("recv");
    assert_eq!(got, packet);
}
