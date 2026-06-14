//! The multihop packet sink moves inner IP packets over an HPKE-sealed tunnel.
//! Drives [`MultihopPacketSink`] against the in-process fake multihop exit: a
//! packet sent through the sink comes back through it, sealed both ways, and the
//! reported MTU leaves room for the per-packet frame overhead.

use ed25519_dalek::SigningKey;
use warren_net::{MultihopPacketSink, PacketSink};
use warren_test_support::spawn_fake_multihop_exit;
use warren_transport::MultihopClientTunnel;

#[tokio::test(flavor = "multi_thread")]
async fn sink_round_trips_a_sealed_packet_and_reserves_mtu() {
    let exit_key = SigningKey::from_bytes(&[5u8; 32]);
    let (exit_addr, keys) = spawn_fake_multihop_exit(exit_key).await;

    let session = MultihopClientTunnel::new(SigningKey::from_bytes(&[2u8; 32]))
        .connect(
            keys.ed25519_pubkey,
            keys.x25519_pubkey,
            keys.exit_id,
            exit_addr,
        )
        .await
        .expect("multihop connect");
    let sink = MultihopPacketSink::new(session);

    // The sink reserves the per-packet sealed-frame overhead from the path
    // datagram size, so the reported inner MTU is a sane positive value strictly
    // below it (the exact overhead bound is unit-tested in warren-wire).
    let path = sink
        .session()
        .max_datagram_size()
        .expect("path datagram size known on loopback");
    assert!(
        sink.max_payload() < path && sink.max_payload() >= path - 128,
        "max_payload {} must reserve the frame overhead under the path size {path}",
        sink.max_payload()
    );

    let mut packet = vec![0x45u8, 0, 0, 21];
    packet.extend_from_slice(b"sealed-sink-roundtrip");
    sink.send_packet(&packet).await.expect("send through sink");
    let echoed = sink.recv_packet().await.expect("recv through sink");
    assert_eq!(
        &echoed[..],
        &packet[..],
        "the sink must preserve the packet"
    );
}
