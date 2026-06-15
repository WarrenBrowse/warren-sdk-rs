//! In-process end-to-end test of the multihop datapath: a client completes the
//! HPKE-sealed setup exchange (inner `IpRequest`/`IpAssign`) against a fake exit
//! that re-derives the per-frame crypto independently, then exchanges a sealed
//! data datagram. This validates the handshake real exits require (a sealed
//! `WarrenMultihopFrame` first, not a bare `Setup`) without any real network.

use std::net::Ipv4Addr;

use ed25519_dalek::SigningKey;
use warren_test_support::spawn_fake_multihop_exit;
use warren_transport::{MultihopClientTunnel, MultihopError};

#[tokio::test(flavor = "multi_thread")]
async fn multihop_setup_assigns_ip_and_sealed_datagram_echoes() {
    let exit_key = SigningKey::from_bytes(&[9u8; 32]);
    let (exit_addr, keys) = spawn_fake_multihop_exit(exit_key).await;

    let tunnel = MultihopClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]));
    let session = tunnel
        .connect(
            keys.ed25519_pubkey,
            keys.x25519_pubkey,
            keys.exit_id,
            exit_addr,
        )
        .await
        .expect("multihop setup must succeed");

    assert_eq!(session.assigned_ipv4(), Ipv4Addr::new(10, 66, 0, 2));
    assert_eq!(session.assignment().prefix_len, 24);
    assert_eq!(session.assigned_ipv6(), None);

    // A minimal IPv4-shaped packet (first nibble 4): the exit opens it, re-seals
    // it in the reverse direction, and the client decrypts the echo.
    let packet = {
        let mut p = vec![0x45u8, 0, 0, 20];
        p.extend_from_slice(b"warren-multihop-data");
        p
    };
    session.send_packet(&packet).expect("send sealed packet");
    let echoed = session.recv_packet().await.expect("recv sealed echo");
    assert_eq!(
        echoed, packet,
        "the sealed round-trip must preserve the packet"
    );

    session.disconnect();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_exit_pubkey_is_rejected() {
    // The TLS peer cannot present a cert matching the wrong pinned identity, so
    // the connect must fail rather than seal traffic to an impostor.
    let exit_key = SigningKey::from_bytes(&[9u8; 32]);
    let (exit_addr, keys) = spawn_fake_multihop_exit(exit_key).await;

    let wrong = SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes();
    let tunnel = MultihopClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]));
    // MultihopSession is intentionally not Debug (it holds secret key material),
    // so assert on the Result shape directly instead of `expect_err`.
    match tunnel
        .connect(wrong, keys.x25519_pubkey, keys.exit_id, exit_addr)
        .await
    {
        Ok(_) => panic!("a mismatched pin must be rejected"),
        // The rejection must come from the identity defense specifically: the TLS
        // raw-public-key pin mismatch fails the QUIC connect, or (had TLS passed)
        // the post-handshake key check trips. Anything else (bind, setup, frame)
        // would mean the impostor was not caught for the right reason.
        Err(err @ (MultihopError::Quic { .. } | MultihopError::ExitIdentityMismatch)) => {
            assert!(
                !err.to_string().is_empty(),
                "the error stays redacted but non-empty"
            );
        }
        Err(other) => panic!("expected an identity-defense rejection, got {other:?}"),
    }
}
