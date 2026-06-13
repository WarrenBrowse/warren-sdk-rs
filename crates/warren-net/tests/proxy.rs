//! End-to-end test of the SOCKS5 proxy front end with a direct connector: a
//! client speaks SOCKS5 to the proxy, the proxy relays to a local echo server,
//! and bytes round-trip. No tunnel is involved; the connector seam stands in for
//! it, which is exactly what makes the accept/handshake/relay loop testable.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use warren_net::{DirectConnector, Socks5Proxy};

/// Accepts one connection and echoes everything until EOF.
async fn spawn_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });
    addr
}

async fn spawn_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let proxy = Socks5Proxy::new(DirectConnector);
        let _ = proxy.serve(listener).await;
    });
    addr
}

/// Builds a SOCKS5 CONNECT request for an IPv4 target.
fn connect_request_v4(addr: std::net::SocketAddrV4) -> Vec<u8> {
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&addr.ip().octets());
    req.extend_from_slice(&addr.port().to_be_bytes());
    req
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_connect_relays_bytes_to_upstream() {
    let echo = spawn_echo().await;
    let proxy = spawn_proxy().await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");

    // Greeting: VER=5, 1 method, NO_AUTH.
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00], "server selects NO_AUTH");

    // CONNECT to the echo server.
    let std::net::SocketAddr::V4(echo_v4) = echo else {
        panic!("echo is v4")
    };
    client
        .write_all(&connect_request_v4(echo_v4))
        .await
        .unwrap();
    let mut reply = [0u8; 10]; // VER REP RSV ATYP=1 IP(4) PORT(2)
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT succeeded");

    // Relayed payload round-trips through the proxy to the echo server.
    client.write_all(b"warren-proxy").await.unwrap();
    let mut got = [0u8; 12];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"warren-proxy");
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_rejects_unsupported_command() {
    let proxy = spawn_proxy().await;
    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();

    // BIND (0x02) to an arbitrary IPv4 target.
    let mut req = vec![0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x07, "command not supported");
}
