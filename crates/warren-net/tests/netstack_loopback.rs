//! Validates the client userspace netstack end to end against a second smoltcp
//! stack that stands in for the exit's TCP termination. The two stacks are wired
//! by channels carrying bare IP packets, exactly as the QUIC datagram plane would
//! carry them. A real TCP handshake and a bidirectional echo prove the client
//! engine (`TunnelConnector` + `NetstackStream`) drives smoltcp correctly.
//!
//! This is a fake-device test: necessary but, per CLAUDE.md, not sufficient. The
//! same client stack must still be validated against a real Warren exit.

use std::collections::VecDeque;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
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
    rx: VecDeque<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx(mpsc::UnboundedSender<Vec<u8>>);

impl smoltcp::phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl smoltcp::phy::TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf);
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

/// A smoltcp echo server at `10.66.0.1:9`: accepts one connection and echoes.
async fn echo_server(
    mut inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound: mpsc::UnboundedSender<Vec<u8>>,
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
        let _ = a.push(IpCidr::new(IpAddress::v4(10, 66, 0, 1), 24));
    });

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

#[tokio::test(flavor = "multi_thread")]
async fn netstack_tcp_connect_and_echo() {
    let (c2s_tx, c2s_rx) = mpsc::unbounded_channel(); // client -> server
    let (s2c_tx, s2c_rx) = mpsc::unbounded_channel(); // server -> client

    let connector = spawn_engine("10.66.0.2".parse().unwrap(), 24, MTU, s2c_rx, c2s_tx);
    tokio::spawn(echo_server(c2s_rx, s2c_tx));

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
async fn socks5_proxy_over_netstack_reaches_the_exit() {
    // Full non-root datapath: a SOCKS5 client -> Socks5Proxy -> TunnelConnector
    // -> userspace netstack -> (channels = tunnel) -> smoltcp "exit" echo.
    let (c2s_tx, c2s_rx) = mpsc::unbounded_channel();
    let (s2c_tx, s2c_rx) = mpsc::unbounded_channel();

    let connector = spawn_engine("10.66.0.2".parse().unwrap(), 24, MTU, s2c_rx, c2s_tx);
    tokio::spawn(echo_server(c2s_rx, s2c_tx));

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
