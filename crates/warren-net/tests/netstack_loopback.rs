//! Validates the client userspace netstack end to end against a second smoltcp
//! stack that stands in for the exit's TCP termination. The two stacks are wired
//! by channels carrying bare IP packets, exactly as the QUIC datagram plane would
//! carry them. A real TCP handshake and a bidirectional echo prove the client
//! engine (`TunnelConnector` + `NetstackStream`) drives smoltcp correctly.
//!
//! This is a fake-device test: necessary but, per CLAUDE.md, not sufficient. The
//! same client stack must still be validated against a real Warren exit.

use std::collections::VecDeque;

use bytes::Bytes;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use warren_net::socks5::Target;
use warren_net::{Connector, Socks5Proxy, spawn_engine};

const MTU: usize = 1500;

/// A channel-backed smoltcp device for the test-side echo server.
struct ChanDevice {
    rx: VecDeque<Bytes>,
    tx: mpsc::Sender<Bytes>,
}

struct Rx(Bytes);
struct Tx(mpsc::Sender<Bytes>);

impl smoltcp::phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl smoltcp::phy::TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.try_send(Bytes::from(buf));
        r
    }
}

impl Device for ChanDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;
    fn receive(&mut self, _t: SmolInstant) -> Option<(Rx, Tx)> {
        let f = self.rx.pop_front()?;
        Some((Rx(f), Tx(self.tx.clone())))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Tx> {
        Some(Tx(self.tx.clone()))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps.checksum.ipv4 = Checksum::Both;
        caps.checksum.tcp = Checksum::Both;
        caps
    }
}

/// A smoltcp echo server listening on `:9` at `ip/prefix` with a default route
/// via `gateway`; accepts one connection and echoes.
async fn echo_server(
    ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    mut inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
) {
    let mut device = ChanDevice {
        rx: VecDeque::new(),
        tx: outbound,
    };
    let base = tokio::time::Instant::now();
    let now =
        || SmolInstant::from_micros(i64::try_from(base.elapsed().as_micros()).unwrap_or(i64::MAX));

    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x5345_5256_0002;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(ip), prefix));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(gateway);

    let mut sockets = SocketSet::new(Vec::new());
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
    );
    let handle = sockets.add(socket);
    sockets
        .get_mut::<tcp::Socket<'_>>(handle)
        .listen(9)
        .expect("listen");

    loop {
        while let Ok(f) = inbound.try_recv() {
            device.rx.push_back(f);
        }
        let _ = iface.poll(now(), &mut device, &mut sockets);

        let sock = sockets.get_mut::<tcp::Socket<'_>>(handle);
        let mut buf = [0u8; 4096];
        while sock.can_recv() && sock.can_send() {
            match sock.recv_slice(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = sock.send_slice(&buf[..n]);
                }
            }
        }

        let delay = iface
            .poll_delay(now(), &sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros()))
            .unwrap_or_else(|| std::time::Duration::from_millis(5));
        tokio::select! {
            f = inbound.recv() => match f {
                Some(f) => device.rx.push_back(f),
                None => return,
            },
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// Builds a minimal DNS response for `query` answering with a single A record
/// for `addr`. The exit forwarder does not need a full parser: it echoes the
/// query id and question and appends one compressed A answer.
fn dns_response(query: &[u8], addr: std::net::Ipv4Addr) -> Vec<u8> {
    let mut r = Vec::with_capacity(query.len() + 16);
    r.extend_from_slice(&query[0..2]); // transaction id, echoed
    r.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA, RCODE 0
    r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    r.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT
    r.extend_from_slice(&query[12..]); // echo the question section verbatim
    r.extend_from_slice(&[0xC0, 0x0C]); // name pointer to the question
    r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE A, CLASS IN
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60s
    r.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    r.extend_from_slice(&addr.octets()); // RDATA
    r
}

/// A smoltcp "exit" that both answers DNS `A` queries on UDP `:53` (always
/// returning its own address) and echoes TCP on `:9`. Lets a `Target::Domain`
/// resolve over the tunnel and then connect to the resolved address.
async fn dns_and_echo_server(
    ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    mut inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
) {
    let mut device = ChanDevice {
        rx: VecDeque::new(),
        tx: outbound,
    };
    let base = tokio::time::Instant::now();
    let now =
        || SmolInstant::from_micros(i64::try_from(base.elapsed().as_micros()).unwrap_or(i64::MAX));

    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x5345_5256_0003;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(ip), prefix));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(gateway);

    let mut sockets = SocketSet::new(Vec::new());
    let tcp_handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
    ));
    sockets
        .get_mut::<tcp::Socket<'_>>(tcp_handle)
        .listen(9)
        .expect("listen");
    let udp_handle = sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 2048]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 2048]),
    ));
    sockets
        .get_mut::<udp::Socket<'_>>(udp_handle)
        .bind(53)
        .expect("bind 53");

    loop {
        while let Ok(f) = inbound.try_recv() {
            device.rx.push_back(f);
        }
        let _ = iface.poll(now(), &mut device, &mut sockets);

        // DNS: answer any query with this exit's own address.
        let request = {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            match sock.recv() {
                Ok((data, meta)) if data.len() >= 12 => Some((data.to_vec(), meta.endpoint)),
                _ => None,
            }
        };
        if let Some((query, endpoint)) = request {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            let _ = sock.send_slice(&dns_response(&query, ip), endpoint);
        }

        // TCP echo.
        let sock = sockets.get_mut::<tcp::Socket<'_>>(tcp_handle);
        let mut buf = [0u8; 4096];
        while sock.can_recv() && sock.can_send() {
            match sock.recv_slice(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = sock.send_slice(&buf[..n]);
                }
            }
        }

        let delay = iface
            .poll_delay(now(), &sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros()))
            .unwrap_or_else(|| std::time::Duration::from_millis(5));
        tokio::select! {
            f = inbound.recv() => match f {
                Some(f) => device.rx.push_back(f),
                None => return,
            },
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_resolves_a_domain_over_the_tunnel_then_connects() {
    // A domain CONNECT: the engine sends a DNS query over the tunnel to the
    // gateway (10.66.0.1:53), the exit answers A = 10.66.0.1, then the engine
    // connects to 10.66.0.1:9 and echoes. No host resolver is consulted.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let connector = spawn_engine(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
        s2c_rx,
        c2s_tx,
    );
    tokio::spawn(dns_and_echo_server(
        "10.66.0.1".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Domain("example.com".to_owned(), 9))
        .await
        .expect("domain resolves over the tunnel and connects");
    stream.write_all(b"resolved").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 8];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"resolved");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_tcp_connect_and_echo() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024); // client -> server
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024); // server -> client

    let connector = spawn_engine(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
        s2c_rx,
        c2s_tx,
    );
    tokio::spawn(echo_server(
        "10.66.0.1".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Ip("10.66.0.1:9".parse().unwrap()))
        .await
        .expect("netstack TCP connect succeeds");

    stream.write_all(b"warren-netstack").await.expect("write");
    stream.flush().await.expect("flush");

    let mut got = [0u8; 15];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"warren-netstack");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_routes_out_of_subnet_target_via_default_route() {
    // The client is 10.66.0.2/16; the target 93.184.216.34 is OFF that subnet,
    // so reaching it MUST go through the installed default route. The exit stack
    // answers on that public address. This exercises the default route, which
    // the same-subnet tests never touch.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let connector = spawn_engine(
        "10.66.0.2".parse().unwrap(),
        16,
        "10.66.0.1".parse().unwrap(),
        MTU,
        s2c_rx,
        c2s_tx,
    );
    // The "exit" terminates the public target address and routes its replies
    // back out via its own default route.
    tokio::spawn(echo_server(
        "93.184.216.34".parse().unwrap(),
        24,
        "93.184.216.1".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Ip("93.184.216.34:9".parse().unwrap()))
        .await
        .expect("out-of-subnet connect via default route succeeds");
    stream.write_all(b"routed").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 6];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"routed");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_connect_to_unlistened_port_is_refused() {
    // The exit stack is up but nothing listens on :7, so the SYN gets a RST and
    // the connect fails fast (not a hang).
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);
    let connector = spawn_engine(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
        s2c_rx,
        c2s_tx,
    );
    tokio::spawn(echo_server(
        "10.66.0.1".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    // Port 7, not the listened :9.
    let result = connector
        .connect(Target::Ip("10.66.0.1:7".parse().unwrap()))
        .await;
    assert!(
        matches!(
            result,
            Err(warren_net::NetError::ConnectionRefused | warren_net::NetError::ConnectTimeout)
        ),
        "connect to a closed port must fail fast"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_proxy_over_netstack_reaches_the_exit() {
    // Full non-root datapath: a SOCKS5 client -> Socks5Proxy -> TunnelConnector
    // -> userspace netstack -> (channels = tunnel) -> smoltcp "exit" echo.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let connector = spawn_engine(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
        s2c_rx,
        c2s_tx,
    );
    tokio::spawn(echo_server(
        "10.66.0.1".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let proxy = Socks5Proxy::new(connector);
        let _ = proxy.serve(listener).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    // CONNECT to the exit-side address 10.66.0.1:9.
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 10, 66, 0, 1];
    req.extend_from_slice(&9u16.to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT through the tunnel succeeded");

    client.write_all(b"through-proxy").await.unwrap();
    let mut got = [0u8; 13];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"through-proxy");
}
