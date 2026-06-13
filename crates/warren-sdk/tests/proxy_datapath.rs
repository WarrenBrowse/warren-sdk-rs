//! Full non-root datapath through the facade: `WarrenClient::start_proxy`
//! connects a real QUIC tunnel to an in-process netstack-terminating exit, runs
//! the userspace netstack over it, and serves a local SOCKS5 proxy. A SOCKS5
//! client then reaches the exit's echo service through the whole chain.
//!
//! Fake-device test (necessary, not sufficient per CLAUDE.md): the same path
//! must still be validated against a real Warren exit.

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use warren_sdk::WarrenClient;
use warren_sdk::discovery::{ExitId, Location, Relay};
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_test_support::{NETSTACK_EXIT_IP, NETSTACK_EXIT_PORT, spawn_netstack_exit};

#[tokio::test(flavor = "multi_thread")]
async fn start_proxy_routes_socks5_through_the_tunnel() {
    let (exit_addr, exit_pubkey) = spawn_netstack_exit(SigningKey::from_bytes(&[9u8; 32])).await;

    let (identity, _m) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build()
        .expect("build");

    let exit = Relay::new(
        exit_pubkey,
        ExitId::from_bytes([0xa1; 16]),
        vec![exit_addr],
        Location::new("RO", "Bucharest"),
        100,
        true,
    );

    let cfg = ProxyConfig {
        socks5: "127.0.0.1:0".parse().unwrap(),
        http: None,
    };
    let handle = client.start_proxy(&exit, &cfg).await.expect("proxy starts");

    let mut sock = TcpStream::connect(handle.local_addr())
        .await
        .expect("connect proxy");
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    sock.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    // CONNECT to the exit-side echo service through the tunnel.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&NETSTACK_EXIT_IP);
    req.extend_from_slice(&NETSTACK_EXIT_PORT.to_be_bytes());
    sock.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT through the tunnel succeeded");

    sock.write_all(b"end-to-end").await.unwrap();
    let mut got = [0u8; 10];
    sock.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"end-to-end");
}
