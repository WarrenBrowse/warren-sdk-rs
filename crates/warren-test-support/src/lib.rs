//! Test-only helpers shared across the Warren SDK workspace.
//!
//! This crate is `publish = false` and is only ever a dev-dependency. It exists
//! so the in-process fake exit lives in one place instead of being copy-pasted
//! into every crate's integration tests.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use warren_transport::{default_crypto_provider, make_server_config};
use warren_wire::{
    MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, SetupAck, decode_setup, encode_setup_ack,
};

/// ALPN the fake exit accepts, matching the client.
const ALPN_H3: &[u8] = b"h3";

/// Spawns an in-process QUIC "exit" bound to `127.0.0.1:0` that completes the
/// Warren handshake (raw-public-key TLS, Setup/SetupAck) for `exit_key` and then
/// echoes every datagram back until the client disconnects.
///
/// Returns the bound address and the exit's 32-byte public key, which the client
/// pins as the expected identity. The assigned tunnel IPv4 is `10.66.0.2`.
///
/// # Panics
///
/// Panics on any setup failure: it is a test helper, so a broken server is a
/// test bug, not a runtime condition.
pub async fn spawn_fake_exit(exit_key: SigningKey) -> (SocketAddr, [u8; 32]) {
    let exit_pubkey = exit_key.verifying_key().to_bytes();
    let cfg = make_server_config(&exit_key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap())
        .expect("server endpoint binds");
    let addr = endpoint.local_addr().expect("local addr");

    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming connection")
            .await
            .expect("connection established");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let _setup = decode_setup(
            &recv
                .read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .expect("read setup"),
        )
        .expect("decode setup");

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

        while let Ok(dg) = conn.read_datagram().await {
            if conn.send_datagram(dg).is_err() {
                break;
            }
        }
        drop(endpoint);
    });

    (addr, exit_pubkey)
}
