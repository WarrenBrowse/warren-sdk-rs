//! Validates the QUIC packet plane ([`QuicPacketSink`]) end-to-end against an
//! in-process exit: a packet sent through the sink is echoed back as a datagram.

use ed25519_dalek::SigningKey;
use warren_net::{PacketSink, QuicPacketSink};
use warren_test_support::spawn_fake_exit;
use warren_transport::ClientTunnel;

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

#[tokio::test]
async fn quic_packet_sink_batch_default_round_trips() {
    let (addr, exit_pubkey) = spawn_fake_exit(SigningKey::from_bytes(&[9u8; 32])).await;
    let session = ClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]))
        .connect(exit_pubkey, addr)
        .await
        .expect("connect");
    let sink = QuicPacketSink::new(session);

    // The default send_batch/recv_batch forward to the per-packet path; the
    // exit echoes each datagram, so a one-packet batch round-trips.
    let p = vec![0x45u8, 0, 0, 0x10, 0x01, 0x02, 0x03, 0x04];
    sink.send_batch(&[p.as_slice()]).await.expect("send_batch");
    let got = sink.recv_batch(8).await.expect("recv_batch");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0], p);
}
