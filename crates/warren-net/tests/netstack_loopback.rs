//! Validates the client userspace netstack end to end against a second smoltcp
//! stack that stands in for the exit's TCP termination. The two stacks are wired
//! by channels carrying bare IP packets, exactly as the QUIC datagram plane would
//! carry them. A real TCP handshake and a bidirectional echo prove the client
//! engine (`TunnelConnector` + `NetstackStream`) drives smoltcp correctly.
//!
//! This is a fake-device test: necessary but, per CLAUDE.md, not sufficient. The
//! same client stack must still be validated against a real Warren exit.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
use warren_net::{Connector, NetstackConfig, Socks5Proxy, spawn_engine};

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

/// An IPv6 smoltcp "exit" echo server: owns `ip/prefix`, listens TCP on `:9`,
/// echoes, and installs a default v6 route via `gateway` so it can reply to a
/// client on a different v6 subnet.
async fn echo_server_v6(
    ip: std::net::Ipv6Addr,
    prefix: u8,
    gateway: std::net::Ipv6Addr,
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
    config.random_seed = 0x5345_5256_0005;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(ip), prefix));
    });
    let _ = iface.routes_mut().add_default_ipv6_route(gateway);

    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
    ));
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

/// A smoltcp "exit" that actively connects to `target`, sends `probe`, reads the
/// echo, and reports whether it matched. Models the exit forwarding an inbound
/// connection to the client's tunnel-side listen port.
#[allow(clippy::too_many_arguments)]
async fn exit_connect_and_check(
    exit_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    target: (std::net::Ipv4Addr, u16),
    probe: &'static [u8],
    result_tx: tokio::sync::oneshot::Sender<bool>,
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
    config.random_seed = 0x5345_5256_0009;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(exit_ip), prefix));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(gateway);

    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
    ));
    sockets
        .get_mut::<tcp::Socket<'_>>(handle)
        .connect(
            iface.context(),
            (IpAddress::from(target.0), target.1),
            49000,
        )
        .expect("connect");

    let mut sent = false;
    let mut result_tx = Some(result_tx);
    loop {
        while let Ok(f) = inbound.try_recv() {
            device.rx.push_back(f);
        }
        let _ = iface.poll(now(), &mut device, &mut sockets);

        let sock = sockets.get_mut::<tcp::Socket<'_>>(handle);
        if !sent && sock.can_send() {
            let _ = sock.send_slice(probe);
            sent = true;
        }
        if sock.can_recv() {
            let mut buf = [0u8; 64];
            if let Ok(n) = sock.recv_slice(&mut buf) {
                if let Some(tx) = result_tx.take() {
                    let _ = tx.send(&buf[..n] == probe);
                }
                return;
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

/// Builds a minimal DNS response for `query` answering with a single AAAA record
/// for `addr`, echoing the query id and question and appending one compressed
/// AAAA answer.
fn dns_aaaa_response(query: &[u8], addr: std::net::Ipv6Addr) -> Vec<u8> {
    let mut r = Vec::with_capacity(query.len() + 28);
    r.extend_from_slice(&query[0..2]); // transaction id, echoed
    r.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA, RCODE 0
    r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    r.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT
    r.extend_from_slice(&query[12..]); // echo the question section verbatim
    r.extend_from_slice(&[0xC0, 0x0C]); // name pointer to the question
    r.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]); // TYPE AAAA, CLASS IN
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60s
    r.extend_from_slice(&[0x00, 0x10]); // RDLENGTH 16
    r.extend_from_slice(&addr.octets()); // RDATA
    r
}

/// A dual-stack smoltcp "exit": answers `AAAA` queries on the v4 DNS address
/// `dns_ip:53` with `answer6` (an IPv6 address it also owns) and echoes TCP on
/// `:9` at that v6 address. Proves a domain target resolves AAAA over the tunnel
/// (v4 DNS transport) and then connects over IPv6.
async fn dns_aaaa_and_echo_server_v6(
    dns_ip: std::net::Ipv4Addr,
    prefix4: u8,
    answer6: std::net::Ipv6Addr,
    prefix6: u8,
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
    config.random_seed = 0x5345_5256_0006;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(dns_ip), prefix4));
        let _ = a.push(IpCidr::new(IpAddress::from(answer6), prefix6));
    });

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

        // Answer AAAA queries with the v6 echo address.
        let request = {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            match sock.recv() {
                Ok((data, meta)) if data.len() >= 12 => Some((data.to_vec(), meta.endpoint)),
                _ => None,
            }
        };
        if let Some((query, endpoint)) = request {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            let _ = sock.send_slice(&dns_aaaa_response(&query, answer6), endpoint);
        }

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

/// Like the DNS+echo exit but it records whether it ever received an `AAAA`
/// query (QTYPE `0x001c`) and answers every query with an `A` record. Lets a
/// fallback test prove the engine actually attempted AAAA before using A.
async fn dns_a_only_recording_aaaa(
    ip: std::net::Ipv4Addr,
    answer: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    saw_aaaa: Arc<AtomicBool>,
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
    config.random_seed = 0x5345_5256_0007;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(ip), prefix));
        let _ = a.push(IpCidr::new(IpAddress::from(answer), prefix));
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

        let request = {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            match sock.recv() {
                Ok((data, meta)) if data.len() >= 16 => Some((data.to_vec(), meta.endpoint)),
                _ => None,
            }
        };
        if let Some((query, endpoint)) = request {
            // QTYPE is the 2 bytes before the trailing QCLASS.
            let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            if qtype == 0x001c {
                saw_aaaa.store(true, Ordering::SeqCst);
            }
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            // Always answer A, so an AAAA query yields no AAAA and forces fallback.
            let _ = sock.send_slice(&dns_response(&query, answer), endpoint);
        }

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

/// A smoltcp "exit" that answers DNS `A` queries on UDP `:53` with `answer`
/// (deliberately distinct from `ip`, so the test proves the connect target came
/// from the parsed RDATA, not from the query destination) and echoes TCP on
/// `:9`. The exit owns both `ip` and `answer` so the resolved connect lands.
async fn dns_and_echo_server(
    ip: std::net::Ipv4Addr,
    answer: std::net::Ipv4Addr,
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
        // The exit also owns the resolved address so the connect to it lands.
        let _ = a.push(IpCidr::new(IpAddress::from(answer), prefix));
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
            let _ = sock.send_slice(&dns_response(&query, answer), endpoint);
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

/// A smoltcp "exit" that echoes UDP datagrams on `port` back to their source.
async fn udp_echo_server(
    ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    port: u16,
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
    config.random_seed = 0x5345_5256_0004;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(ip), prefix));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(gateway);

    let mut sockets = SocketSet::new(Vec::new());
    let udp_handle = sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8192]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8192]),
    ));
    sockets
        .get_mut::<udp::Socket<'_>>(udp_handle)
        .bind(port)
        .expect("bind udp");

    loop {
        while let Ok(f) = inbound.try_recv() {
            device.rx.push_back(f);
        }
        let _ = iface.poll(now(), &mut device, &mut sockets);

        let echo = {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            match sock.recv() {
                Ok((data, meta)) => Some((data.to_vec(), meta.endpoint)),
                Err(_) => None,
            }
        };
        if let Some((data, endpoint)) = echo {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            let _ = sock.send_slice(&data, endpoint);
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

/// An IPv6 UDP echo "exit": owns `ip/prefix`, binds UDP `port`, echoes.
async fn udp_echo_server_v6(
    ip: std::net::Ipv6Addr,
    prefix: u8,
    port: u16,
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
    config.random_seed = 0x5345_5256_0008;
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(ip), prefix));
    });

    let mut sockets = SocketSet::new(Vec::new());
    let udp_handle = sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8192]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8192]),
    ));
    sockets
        .get_mut::<udp::Socket<'_>>(udp_handle)
        .bind(port)
        .expect("bind udp");

    loop {
        while let Ok(f) = inbound.try_recv() {
            device.rx.push_back(f);
        }
        let _ = iface.poll(now(), &mut device, &mut sockets);

        let echo = {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            match sock.recv() {
                Ok((data, meta)) => Some((data.to_vec(), meta.endpoint)),
                Err(_) => None,
            }
        };
        if let Some((data, endpoint)) = echo {
            let sock = sockets.get_mut::<udp::Socket<'_>>(udp_handle);
            let _ = sock.send_slice(&data, endpoint);
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
async fn netstack_udp_flow_reaches_an_ipv6_target() {
    // A dual-stack engine opens a UDP flow and exchanges a datagram with a v6 UDP
    // echo exit ([fd66::1]:7) over the tunnel: proves v6 UDP egress through the
    // netstack (the SOCKS5 UDP-associate egress for v6 targets).
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let config = NetstackConfig::new(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
    )
    .with_ipv6("fd66::2".parse().unwrap(), 64, "fd66::1".parse().unwrap());
    let connector = spawn_engine(config, s2c_rx, c2s_tx);
    tokio::spawn(udp_echo_server_v6(
        "fd66::1".parse().unwrap(),
        64,
        7,
        c2s_rx,
        s2c_tx,
    ));

    let target: std::net::SocketAddr = "[fd66::1]:7".parse().unwrap();
    let mut udp = connector.open_udp().await.expect("open udp flow");
    udp.send_to(Bytes::from_static(b"ping6"), target)
        .await
        .expect("send");
    let (data, src) = tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv_from())
        .await
        .expect("recv did not time out")
        .expect("a datagram arrived");
    assert_eq!(&data[..], b"ping6", "the exit echoed the v6 datagram");
    assert_eq!(src, target, "the source is the v6 echo server");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_udp_flow_sends_and_receives_through_the_tunnel() {
    // A UDP flow: the engine binds a netstack UDP socket, sends a datagram to
    // the exit's UDP echo (10.66.0.1:7) through the tunnel, and receives the
    // echo back tagged with its source. This is the SOCKS5 UDP-associate egress.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let connector = spawn_engine(
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
        s2c_rx,
        c2s_tx,
    );
    tokio::spawn(udp_echo_server(
        "10.66.0.1".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        7,
        c2s_rx,
        s2c_tx,
    ));

    let target: std::net::SocketAddr = "10.66.0.1:7".parse().unwrap();
    let mut udp = connector.open_udp().await.expect("open udp flow");
    udp.send_to(Bytes::from_static(b"ping"), target)
        .await
        .expect("send");
    let (data, src) = tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv_from())
        .await
        .expect("recv did not time out")
        .expect("a datagram arrived");
    assert_eq!(&data[..], b"ping", "the exit echoed the datagram");
    assert_eq!(src, target, "the source is the echo server");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_resolves_a_domain_over_the_tunnel_then_connects() {
    // A domain CONNECT: the engine sends a DNS query over the tunnel to the
    // gateway (10.66.0.1:53), the exit answers A = 10.66.0.5 (distinct from the
    // gateway, proving the connect target is the parsed RDATA), then the engine
    // connects to 10.66.0.5:9 and echoes. No host resolver is consulted.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let connector = spawn_engine(
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
        s2c_rx,
        c2s_tx,
    );
    tokio::spawn(dns_and_echo_server(
        "10.66.0.1".parse().unwrap(),
        "10.66.0.5".parse().unwrap(),
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
async fn netstack_resolves_via_a_configured_non_gateway_resolver() {
    // dns_disabled fallback: the exit runs no gateway forwarder, so the resolver
    // is configured to a distinct in-tunnel address (10.66.0.9). The exit answers
    // DNS only at .9 and deliberately does NOT own the gateway .1, so resolution
    // succeeds ONLY if the engine queried the configured resolver rather than the
    // gateway. Everything is on the /24, so no default route is exercised.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let config = NetstackConfig::new(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
    )
    .with_dns_server("10.66.0.9".parse().unwrap());
    let connector = spawn_engine(config, s2c_rx, c2s_tx);

    tokio::spawn(dns_and_echo_server(
        "10.66.0.9".parse().unwrap(),
        "10.66.0.5".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Domain("example.com".to_owned(), 9))
        .await
        .expect("domain resolves via the configured resolver and connects");
    stream.write_all(b"viadns99").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 8];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"viadns99");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_resolves_aaaa_over_the_tunnel_then_connects_v6() {
    // A dual-stack client resolves a domain over the tunnel: with a v6 assignment
    // it prefers AAAA, gets fd66::5 (v4 DNS transport to the gateway), and then
    // connects to it over IPv6. No host resolver is consulted.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let config = NetstackConfig::new(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
    )
    .with_ipv6("fd66::2".parse().unwrap(), 64, "fd66::1".parse().unwrap());
    let connector = spawn_engine(config, s2c_rx, c2s_tx);

    tokio::spawn(dns_aaaa_and_echo_server_v6(
        "10.66.0.1".parse().unwrap(),
        24,
        "fd66::5".parse().unwrap(),
        64,
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Domain("example.com".to_owned(), 9))
        .await
        .expect("domain resolves AAAA over the tunnel and connects over v6");
    stream.write_all(b"aaaa-ok").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 7];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"aaaa-ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_falls_back_to_a_when_the_name_has_no_aaaa() {
    // Dual-stack client, but the name has no AAAA: the AAAA lookup yields no
    // record, so the engine falls back to A and connects over IPv4. The exit
    // answers every query with an A record (so the AAAA query is unsatisfied).
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let config = NetstackConfig::new(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
    )
    .with_ipv6("fd66::2".parse().unwrap(), 64, "fd66::1".parse().unwrap());
    let connector = spawn_engine(config, s2c_rx, c2s_tx);

    // Answers A (not AAAA) for any query and records whether an AAAA query was
    // attempted, so the test fails if the engine skipped AAAA (an A-only policy).
    let saw_aaaa = Arc::new(AtomicBool::new(false));
    tokio::spawn(dns_a_only_recording_aaaa(
        "10.66.0.1".parse().unwrap(),
        "10.66.0.5".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        Arc::clone(&saw_aaaa),
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Domain("example.com".to_owned(), 9))
        .await
        .expect("falls back to A and connects over v4");
    stream.write_all(b"a-fallback").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 10];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"a-fallback");
    // Pins the AAAA-first policy: the engine must have tried AAAA before A.
    assert!(
        saw_aaaa.load(Ordering::SeqCst),
        "engine attempted AAAA before falling back to A"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_connects_to_an_ipv6_target_over_the_tunnel() {
    // Dual-stack: the engine is assigned both a v4 and a v6 tunnel address, and a
    // literal IPv6 target is routed over the tunnel to a v6-only echo exit. Proves
    // the v6 interface address + default route are installed and v6 TCP egresses.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let config = NetstackConfig::new(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
    )
    .with_ipv6("fd66::2".parse().unwrap(), 64, "fd66::1".parse().unwrap());
    let connector = spawn_engine(config, s2c_rx, c2s_tx);

    tokio::spawn(echo_server_v6(
        "fd66::1".parse().unwrap(),
        64,
        "fd66::2".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Ip("[fd66::1]:9".parse().unwrap()))
        .await
        .expect("ipv6 connect over the tunnel succeeds");
    stream.write_all(b"v6-routed").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 9];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"v6-routed");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_routes_out_of_subnet_ipv6_target_via_default_route() {
    // The client is fd66::2/64; the target 2001:db8::1 is OFF that subnet, so
    // reaching it MUST go through the installed default v6 route. This is the v6
    // analogue of the v4 default-route test: without `add_default_ipv6_route` the
    // connect cannot route and the test fails.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let config = NetstackConfig::new(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        MTU,
    )
    .with_ipv6("fd66::2".parse().unwrap(), 64, "fd66::1".parse().unwrap());
    let connector = spawn_engine(config, s2c_rx, c2s_tx);

    // The exit terminates the off-subnet target and routes replies back out via
    // its own default v6 route (on its own /64).
    tokio::spawn(echo_server_v6(
        "2001:db8::1".parse().unwrap(),
        64,
        "2001:db8::ffff".parse().unwrap(),
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = connector
        .connect(Target::Ip("[2001:db8::1]:9".parse().unwrap()))
        .await
        .expect("out-of-subnet v6 connect via default route succeeds");
    stream.write_all(b"v6-default").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 10];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"v6-default");
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_rejects_ipv6_target_when_v6_not_assigned() {
    // Without a v6 assignment the connector must refuse a v6 target rather than
    // black-hole it (fail fast, fail closed).
    let (c2s_tx, _c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (_s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);
    let connector = spawn_engine(
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
        s2c_rx,
        c2s_tx,
    );
    let result = connector
        .connect(Target::Ip("[fd66::1]:9".parse().unwrap()))
        .await;
    assert!(
        matches!(result, Err(warren_net::NetError::Unsupported(_))),
        "a v6 target without a v6 assignment must be refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_accepts_an_inbound_connection_and_echoes() {
    // The port-forwarding accept side: the engine listens on a tunnel-side port,
    // the exit forwards an inbound connection to it, the app accepts the stream
    // and echoes. This exercises the netstack listen/accept path (inbound), the
    // mirror of the outbound connect path.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);

    let connector = spawn_engine(
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
        s2c_rx,
        c2s_tx,
    );

    // Bind the listener before the exit dials in, so the SYN has somewhere to land.
    let mut listener = connector.listen(8080).await.expect("listen on 8080");

    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(exit_connect_and_check(
        "10.66.0.1".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        ("10.66.0.2".parse().unwrap(), 8080),
        b"inbound!",
        result_tx,
        c2s_rx,
        s2c_tx,
    ));

    let mut stream = listener
        .accept()
        .await
        .expect("accept an inbound connection");
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).await.expect("read probe");
    stream.write_all(&buf).await.expect("echo");
    stream.flush().await.expect("flush");

    let matched = result_rx.await.expect("exit reported a result");
    assert!(
        matched,
        "the inbound connection round-tripped through the tunnel"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_serves_a_forwarded_port_to_a_local_listener() {
    // Full P7 inbound bridge: a local app server (host side) echoes; the engine
    // listens on a tunnel-side port and `serve_inbound` relays each inbound
    // connection to that local server. The exit dials in and round-trips.
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = local.accept().await {
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });

    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024);
    let connector = spawn_engine(
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
        s2c_rx,
        c2s_tx,
    );

    let listener = connector.listen(8080).await.expect("listen on 8080");
    tokio::spawn(warren_net::serve_inbound(listener, local_addr));

    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(exit_connect_and_check(
        "10.66.0.1".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        ("10.66.0.2".parse().unwrap(), 8080),
        b"fwd-port",
        result_tx,
        c2s_rx,
        s2c_tx,
    ));

    let matched = result_rx.await.expect("exit reported a result");
    assert!(
        matched,
        "the inbound connection was relayed to the local listener and echoed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn netstack_tcp_connect_and_echo() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Bytes>(1024); // client -> server
    let (s2c_tx, s2c_rx) = mpsc::channel::<Bytes>(1024); // server -> client

    let connector = spawn_engine(
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
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
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            16,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
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
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
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
        NetstackConfig::new(
            "10.66.0.2".parse().unwrap(),
            24,
            "10.66.0.1".parse().unwrap(),
            MTU,
        ),
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
