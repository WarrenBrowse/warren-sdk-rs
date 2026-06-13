//! In-process end-to-end test: a client tunnel handshakes with a minimal exit
//! built from the same TLS RPK layer, then exchanges a datagram. This validates
//! the full P5 stack (RPK handshake, Setup/SetupAck, datagram plane) without any
//! real network or privilege.

use std::net::Ipv4Addr;

use ed25519_dalek::SigningKey;
use warren_test_support::spawn_fake_exit;
use warren_transport::{ClientTunnel, TunnelError};

#[tokio::test]
async fn handshake_assigns_ip_and_datagram_echoes() {
    let exit_key = SigningKey::from_bytes(&[9u8; 32]);
    let (exit_addr, exit_pubkey) = spawn_fake_exit(exit_key).await;

    let tunnel = ClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]))
        .with_features(warren_wire::features::PORT_FORWARD);
    let session = tunnel
        .connect(exit_pubkey, exit_addr)
        .await
        .expect("handshake must succeed");

    assert_eq!(session.assigned_ipv4(), Ipv4Addr::new(10, 66, 0, 2));
    assert_eq!(session.assigned_max_mtu(), 1280);
    assert_eq!(session.exit_pubkey(), exit_pubkey);

    session
        .send_datagram(b"warren-hello".to_vec())
        .expect("send");
    let echoed = session.read_datagram().await.expect("read echo");
    assert_eq!(echoed[..], b"warren-hello"[..]);

    session.disconnect();
}

#[tokio::test]
async fn wrong_exit_pubkey_is_rejected() {
    // The SNI encodes the wrong identity, so the server's RPK does not match
    // what the client pinned: the handshake must fail rather than connect to an
    // impostor.
    let exit_key = SigningKey::from_bytes(&[9u8; 32]);
    let (exit_addr, _real) = spawn_fake_exit(exit_key).await;

    let wrong_pubkey = SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes();
    let tunnel = ClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]));
    let err = tunnel
        .connect(wrong_pubkey, exit_addr)
        .await
        .expect_err("must reject a pubkey the exit cannot present");
    // The exit cannot present a cert matching the wrong SNI, so the TLS
    // handshake fails during the connect await (a quinn ConnectionError) or the
    // peer key check rejects it.
    assert!(matches!(
        err,
        TunnelError::Quic {
            context: "connect",
            ..
        } | TunnelError::ExitIdentityMismatch
    ));
}
