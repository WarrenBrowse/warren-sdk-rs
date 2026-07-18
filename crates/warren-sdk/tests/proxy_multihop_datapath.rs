//! Full non-root datapath through the facade over a MULTIHOP tunnel:
//! `WarrenClient::start_proxy` completes the HPKE-sealed setup exchange
//! against an in-process netstack-terminating multihop exit, runs the userspace
//! netstack over the sealed packet plane, and serves a local SOCKS5 proxy. A
//! SOCKS5 client reaches the exit's echo service through the whole chain, every
//! inner packet sealed and opened.
//!
//! Fake-device test (necessary, not sufficient per CLAUDE.md): the same path
//! must still be validated against a real Warren exit (needs a subscribed wallet
//! because the exit gates the IpAssign on its allowlist).

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warren_sdk::discovery::VerifiedExit;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_sdk::{Circuit, WarrenClient};
use warren_test_support::{NETSTACK_EXIT_IP, NETSTACK_EXIT_PORT, spawn_netstack_multihop_exit};

#[tokio::test(flavor = "multi_thread")]
async fn start_proxy_routes_socks5_through_a_sealed_tunnel() {
    let (exit_addr, keys) = spawn_netstack_multihop_exit(SigningKey::from_bytes(&[9u8; 32])).await;

    let (identity, _m) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build()
        .expect("build");

    let exit = VerifiedExit {
        exit_id: keys.exit_id,
        exit_ed25519_pubkey: keys.ed25519_pubkey,
        exit_x25519_multihop_pubkey: keys.x25519_pubkey,
        endpoint: exit_addr,
        country: "RO".to_owned(),
        asn: 0,
        city: "Bucharest".to_owned(),
        weight: 100,
        dns_disabled: false,
        cover_domain: None,
        tcp_fallback: false,
        edge_cert_sha256: None,
        exit_mlkem768_pubkey: None,
    };

    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse().unwrap(),
        http: None,
        ..ProxyConfig::default()
    };
    let handle = client
        .start_proxy(&Circuit::SingleHop(exit), &cfg)
        .await
        .expect("multihop proxy starts");

    let mut sock = TcpStream::connect(handle.local_addr())
        .await
        .expect("connect proxy");
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    sock.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&NETSTACK_EXIT_IP);
    req.extend_from_slice(&NETSTACK_EXIT_PORT.to_be_bytes());
    sock.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply[1], 0x00,
        "CONNECT through the sealed tunnel succeeded"
    );

    sock.write_all(b"sealed-e2e!").await.unwrap();
    let mut got = [0u8; 11];
    sock.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"sealed-e2e!");
}
