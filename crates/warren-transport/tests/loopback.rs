//! In-process end-to-end test: a client tunnel handshakes with a minimal exit
//! built from the same TLS RPK layer, then exchanges a datagram. This validates
//! the full P5 stack (RPK handshake, Setup/SetupAck, datagram plane) without any
//! real network or privilege.

use std::net::Ipv4Addr;

use ed25519_dalek::SigningKey;
use warren_transport::tls::{default_crypto_provider, make_server_config};
use warren_transport::{ClientTunnel, TunnelError};
use warren_wire::{
    MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, SetupAck, decode_setup, encode_setup_ack,
};

const ALPN_H3: &[u8] = b"h3";

/// Spawns a minimal in-process exit that accepts one connection, completes the
/// handshake assigning `10.66.0.2`, and echoes the first datagram. Returns the
/// exit's address and its pubkey.
async fn spawn_fake_exit(exit_key: SigningKey) -> (std::net::SocketAddr, [u8; 32]) {
    let exit_pubkey = exit_key.verifying_key().to_bytes();
    let cfg = make_server_config(&exit_key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap())
        .expect("server endpoint binds");
    let addr = endpoint.local_addr().expect("local addr");

    tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming connection");
        let conn = incoming.await.expect("connection established");

        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let setup_bytes = recv
            .read_to_end(MAX_SETUP_FRAME_BYTES)
            .await
            .expect("read setup");
        let _setup = decode_setup(&setup_bytes).expect("decode setup");

        let ack = SetupAck {
            protocol_version: PROTOCOL_VERSION,
            tunnel_ipv4: [10, 66, 0, 2],
            tunnel_ipv6: None,
            exit_pubkey,
            max_mtu: 1280,
            multiconn_attached: true,
            daita_spec: None,
        };
        send.write_all(&encode_setup_ack(&ack).expect("encode ack"))
            .await
            .expect("write ack");
        send.finish().expect("finish");

        // Echo one datagram, then wait for the client to close.
        if let Ok(dg) = conn.read_datagram().await {
            let _ = conn.send_datagram(dg);
        }
        conn.closed().await;
        // Keep the endpoint alive until the connection is done.
        drop(endpoint);
    });

    (addr, exit_pubkey)
}

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
