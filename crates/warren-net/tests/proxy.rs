//! End-to-end test of the SOCKS5 proxy front end with a direct connector: a
//! client speaks SOCKS5 to the proxy, the proxy relays to a local echo server,
//! and bytes round-trip. No tunnel is involved; the connector seam stands in for
//! it, which is exactly what makes the accept/handshake/relay loop testable.

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use warren_net::socks5::Target;
use warren_net::{
    Connector, DirectConnector, HttpConnectProxy, NetError, Socks5Proxy, UdpConnector, UdpFlow,
};

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

async fn spawn_http_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let proxy = HttpConnectProxy::new(DirectConnector);
        let _ = proxy.serve(listener).await;
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn http_connect_relays_bytes_to_upstream() {
    let echo = spawn_echo().await;
    let proxy = spawn_http_proxy().await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    let req = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();

    // Read the status line up to the blank line.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "tunnel established: {head:?}"
    );

    client.write_all(b"warren-http").await.unwrap();
    let mut got = [0u8; 11];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"warren-http");
}

/// A UDP flow backed by a real local UDP socket, standing in for the netstack
/// flow so the relay loop is testable without a tunnel.
struct LocalUdpFlow {
    sock: UdpSocket,
    buf: Vec<u8>,
}

impl UdpFlow for LocalUdpFlow {
    async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
        self.sock
            .send_to(&data, dst)
            .await
            .map(|_| ())
            .map_err(NetError::Io)
    }

    async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
        let (n, src) = self.sock.recv_from(&mut self.buf).await.ok()?;
        Some((Bytes::copy_from_slice(&self.buf[..n]), src))
    }
}

/// A connector whose UDP flows use the local OS UDP stack (test seam). Its TCP
/// `connect` is unused here.
#[derive(Clone, Copy)]
struct LocalUdpConnector;

impl Connector for LocalUdpConnector {
    type Stream = TcpStream;
    async fn connect(&self, _target: Target) -> Result<Self::Stream, NetError> {
        Err(NetError::Unsupported("tcp not used in the udp test"))
    }
}

impl UdpConnector for LocalUdpConnector {
    type Flow = LocalUdpFlow;
    async fn open_udp(&self) -> Result<Self::Flow, NetError> {
        let sock = UdpSocket::bind("127.0.0.1:0").await.map_err(NetError::Io)?;
        Ok(LocalUdpFlow {
            sock,
            buf: vec![0u8; 64 * 1024],
        })
    }
    async fn resolve_host(&self, _host: &str) -> Result<std::net::IpAddr, NetError> {
        Err(NetError::Unsupported("no name resolution in the udp test"))
    }

    fn supports_ipv6(&self) -> bool {
        false
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_udp_associate_relays_datagrams() {
    // A UDP echo server stands in for the target.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, src)) = echo.recv_from(&mut buf).await else {
                break;
            };
            let _ = echo.send_to(&buf[..n], src).await;
        }
    });

    // The SOCKS5 proxy with UDP support.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let proxy = Socks5Proxy::new(LocalUdpConnector);
        let _ = proxy.serve_with_udp(listener).await;
    });

    // Control connection: greeting then UDP ASSOCIATE.
    let mut ctrl = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    ctrl.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);
    // UDP ASSOCIATE (0x03) with a 0.0.0.0:0 placeholder client address.
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10]; // VER REP RSV ATYP=1 IP(4) PORT(2)
    ctrl.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE succeeded");
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr: SocketAddr = (
        std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        relay_port,
    )
        .into();

    // The client's UDP socket sends a wrapped datagram targeting the echo.
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::SocketAddr::V4(echo_v4) = echo_addr else {
        panic!("v4")
    };
    let mut dgram = vec![0x00, 0x00, 0x00, 0x01];
    dgram.extend_from_slice(&echo_v4.ip().octets());
    dgram.extend_from_slice(&echo_v4.port().to_be_bytes());
    dgram.extend_from_slice(b"ping");
    client_udp.send_to(&dgram, relay_addr).await.unwrap();

    // The echoed datagram comes back wrapped with the SOCKS5 UDP header.
    let mut buf = [0u8; 2048];
    let (n, _from) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_udp.recv_from(&mut buf),
    )
    .await
    .expect("a reply arrived")
    .unwrap();
    // header is RSV(2) FRAG(1) ATYP(1) IPv4(4) PORT(2) = 10 bytes, then payload.
    assert!(n >= 10, "header present");
    assert_eq!(&buf[0..3], &[0x00, 0x00, 0x00], "RSV and FRAG are zero");
    assert_eq!(buf[3], 0x01, "ATYP is IPv4");
    assert_eq!(
        &buf[4..8],
        &echo_v4.ip().octets(),
        "the reply header carries the echo source address"
    );
    assert_eq!(
        u16::from_be_bytes([buf[8], buf[9]]),
        echo_v4.port(),
        "the reply header carries the echo source port"
    );
    assert_eq!(&buf[10..n], b"ping", "the echo payload round-trips");
    // Keep the control connection alive until here so the association persists.
    drop(ctrl);
}

#[tokio::test(flavor = "multi_thread")]
async fn http_rejects_non_connect_method() {
    let proxy = spawn_http_proxy().await;
    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if client.read_exact(&mut byte).await.is_err() {
            break;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 405"),
        "non-CONNECT refused: {head:?}"
    );
}
