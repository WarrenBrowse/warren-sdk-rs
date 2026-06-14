//! Data-plane anti-replay: an exit that replays each sealed reply (same epoch+seq
//! twice) must not cause the client to deliver a packet twice. Regression test
//! for the verify-then-record ordering in `MultihopSession::recv_packet`.

use ed25519_dalek::SigningKey;
use warren_test_support::spawn_replaying_multihop_exit;
use warren_transport::MultihopClientTunnel;

#[tokio::test(flavor = "multi_thread")]
async fn replayed_data_frames_are_dropped_exactly_once() {
    let (exit_addr, keys) = spawn_replaying_multihop_exit(SigningKey::from_bytes(&[9u8; 32])).await;

    let session = MultihopClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]))
        .connect(
            keys.ed25519_pubkey,
            keys.x25519_pubkey,
            keys.exit_id,
            exit_addr,
        )
        .await
        .expect("multihop connect");

    // Packet A: the exit replies (and replays the reply). The client must return
    // A exactly once; the duplicate is dropped by the reverse anti-replay window.
    let mut a = vec![0x45u8, 0, 0, 20];
    a.extend_from_slice(b"packet-A-aaaaaaaaaaaa");
    session.send_packet(&a).expect("send A");
    let got_a = session.recv_packet().await.expect("recv A");
    assert_eq!(got_a, a);

    // Packet B at the next reverse seq. If the duplicate of A had NOT been
    // dropped, this recv would return A again instead of B.
    let mut b = vec![0x45u8, 0, 0, 20];
    b.extend_from_slice(b"packet-B-bbbbbbbbbbbb");
    session.send_packet(&b).expect("send B");
    let got_b = session.recv_packet().await.expect("recv B");
    assert_eq!(
        got_b, b,
        "the replayed A must have been dropped, not delivered"
    );

    session.disconnect();
}
