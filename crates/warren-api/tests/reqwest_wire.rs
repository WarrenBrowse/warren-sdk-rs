//! Wire-level proof that the bundled reqwest transport actually emits the
//! headers the pure builder attaches (the unit tests pin the builder; this
//! pins the forwarding). Loopback only, no external network.

#![cfg(feature = "reqwest-transport")]

use std::io::{Read, Write};
use std::net::TcpListener;

use warren_api::{ReqwestTransport, WarrenApiClient};
use warren_identity::WarrenIdentity;

#[tokio::test]
async fn the_product_user_agent_reaches_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).expect("read request head");
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n[]")
            .expect("write response");
        head
    });

    let client = WarrenApiClient::new(
        format!("http://{addr}"),
        WarrenIdentity::from_seed(&[0x11; 32]),
        ReqwestTransport::try_new().expect("transport"),
    );
    let body = client.list_exits().await.expect("loopback exchange");
    assert_eq!(body, "[]");

    let head = server.join().expect("server thread").to_lowercase();
    assert!(
        head.contains("user-agent: warren-app"),
        "the product UA must reach the wire, got request head: {head}"
    );
}
