//! Userspace TCP/IP for the non-root proxy datapath.
//!
//! A single-threaded smoltcp engine runs on its own task. It owns a [`smoltcp`]
//! interface over a `TunnelDevice` whose frames are bare IP packets (no
//! Ethernet: `Medium::Ip`) carried in and out over channels. Application TCP
//! flows accepted by the SOCKS5 proxy become smoltcp TCP sockets; their bytes
//! are bridged to tokio through per-connection bounded channels exposed as a
//! [`NetstackStream`] (`AsyncRead`/`AsyncWrite`).
//!
//! Flow control is real, not just buffered: the write side uses a bounded
//! [`PollSender`] so a fast app blocks when the engine is behind, and the read
//! side only drains a socket's receive buffer when the app channel has capacity,
//! so the TCP window actually closes. Per-connection state is keyed by a bounded
//! per-connection channel, never by a recyclable smoltcp handle.
//!
//! The same client-side stack runs whether the peer is a real Warren exit or an
//! in-process test exit: only the frame transport differs. Per CLAUDE.md, the
//! end-to-end behavior must still be validated against a real exit before this
//! is relied on in production.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio_util::sync::PollSender;

use crate::dns;
use crate::error::NetError;
use crate::proxy::Connector;
use crate::socks5::Target;

/// Per-direction smoltcp TCP buffer (64 KiB), matching a typical socket window.
const TCP_BUFFER: usize = 64 * 1024;
/// First ephemeral local port handed to outbound connects.
const EPHEMERAL_BASE: u16 = 49152;
/// Per-connection app<->engine channel depth (chunks); the backpressure point.
const CONN_CHANNEL_DEPTH: usize = 32;
/// Frame-channel depth toward/from the tunnel.
const FRAME_CHANNEL_DEPTH: usize = 1024;
/// Max buffered app->net bytes per connection before the writer is throttled.
const PENDING_OUT_CAP: usize = 256 * 1024;
/// How long to wait for a SYN to complete before failing the connect.
const CONNECT_TIMEOUT: SmolDuration = SmolDuration::from_secs(10);
/// How long to wait for a DNS response before failing resolution.
const DNS_TIMEOUT: SmolDuration = SmolDuration::from_secs(5);
/// Standard DNS service port (queried on the tunnel gateway / exit forwarder).
const DNS_PORT: u16 = 53;
/// UDP buffer for one in-flight DNS query/response (fits an EDNS-sized reply).
const DNS_BUFFER: usize = 2048;
/// Per-direction UDP payload buffer for a relayed UDP flow (64 KiB).
const UDP_FLOW_BUFFER: usize = 64 * 1024;
/// Datagrams buffered per direction for a UDP flow before drops (lossy by design).
const UDP_CHANNEL_DEPTH: usize = 64;
/// Number of sockets kept in `LISTEN` state per listening port (accept backlog).
const LISTEN_BACKLOG: usize = 8;
/// Accepted-connection queue depth per listener before inbound SYNs are refused.
const ACCEPT_CHANNEL_DEPTH: usize = 32;

/// A smoltcp [`Device`] over IP-packet channels. Frames are zero-copy [`Bytes`].
struct TunnelDevice {
    rx: VecDeque<Bytes>,
    tx: mpsc::Sender<Bytes>,
    mtu: usize,
}

/// Receives one queued inbound frame.
struct RxToken(Bytes);
/// Emits one outbound frame to the tunnel.
struct TxToken(mpsc::Sender<Bytes>);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // try_send, not send: if the tunnel writer is behind, drop this IP
        // packet rather than block the engine; TCP will retransmit.
        let _ = self.0.try_send(Bytes::from(buf));
        r
    }
}

impl Device for TunnelDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((RxToken(frame), TxToken(self.tx.clone())))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // The exit verifies checksums; the client fills them.
        caps.checksum.ipv4 = Checksum::Both;
        caps.checksum.tcp = Checksum::Both;
        caps
    }
}

/// A request from a [`TunnelConnector`] to the engine.
enum Command {
    /// Open a TCP connection to `addr`.
    Open(OpenCommand),
    /// Resolve a host name to an address over the tunnel (DNS to the configured
    /// resolver), for the requested record type.
    Resolve(ResolveCommand),
    /// Open a UDP flow (an ephemeral local port) for datagrams to arbitrary
    /// targets through the tunnel (the SOCKS5 UDP-associate egress).
    OpenUdp(UdpOpenCommand),
    /// Listen on a tunnel-side TCP port and deliver inbound connections (the
    /// port-forwarding accept side).
    Listen(ListenCommand),
}

/// Listen on `port`, replying with a [`NetstackListener`] of accepted streams.
struct ListenCommand {
    port: u16,
    reply: oneshot::Sender<Result<NetstackListener, NetError>>,
}

/// Engine-side state for one listening port: a pool of sockets in `LISTEN` state
/// (the accept backlog) and the channel that delivers accepted streams.
struct Listener {
    port: u16,
    pending: Vec<SocketHandle>,
    accept_tx: mpsc::Sender<NetstackStream>,
}

/// Open a UDP flow, replying with a [`NetstackUdpSocket`] handle.
struct UdpOpenCommand {
    reply: oneshot::Sender<Result<NetstackUdpSocket, NetError>>,
}

/// Engine-side state for one UDP flow. Datagrams are lossy by design: when a
/// bounded channel or the socket buffer is full the datagram is dropped rather
/// than blocking the single-threaded engine, matching UDP semantics.
struct UdpFlow {
    handle: SocketHandle,
    local_port: u16,
    /// net->app: datagrams received from the tunnel, tagged with their source.
    to_app: mpsc::Sender<(Bytes, SocketAddr)>,
    /// app->net: datagrams to send, tagged with their destination.
    from_app: mpsc::Receiver<(Bytes, SocketAddr)>,
}

/// Open a TCP connection to `addr`, replying with the bridged stream or an error.
struct OpenCommand {
    addr: SocketAddr,
    reply: oneshot::Sender<Result<NetstackStream, NetError>>,
}

/// Resolve `name` over the tunnel for `rtype`, replying with the address.
struct ResolveCommand {
    name: String,
    rtype: dns::RecordType,
    reply: oneshot::Sender<Result<IpAddr, NetError>>,
}

/// Engine-side state for one in-flight DNS resolution.
struct PendingResolve {
    handle: SocketHandle,
    local_port: u16,
    /// Transaction id the response must echo (off-path spoof resistance).
    id: u16,
    /// The record type queried, so the reply is parsed for the matching answer.
    rtype: dns::RecordType,
    reply: oneshot::Sender<Result<IpAddr, NetError>>,
    deadline: SmolInstant,
}

/// An app->net write for one connection.
enum WriteOp {
    Data(Bytes),
    Shutdown,
}

/// Engine-side state for one connection.
struct Conn {
    handle: SocketHandle,
    local_port: u16,
    /// net->app (bounded; the read-side backpressure point).
    to_app: mpsc::Sender<Bytes>,
    /// app->net (bounded; the write-side backpressure point).
    from_app: mpsc::Receiver<WriteOp>,
    pending_out: VecDeque<Bytes>,
    pending_out_len: usize,
    want_close: bool,
    /// Deadline for the connect handshake to complete.
    deadline: SmolInstant,
    /// Set until the socket reaches `Established` (or fails/times out).
    connect: Option<(
        oneshot::Sender<Result<NetstackStream, NetError>>,
        NetstackStream,
    )>,
}

/// Handle used to drive a userspace-netstack TCP connection from tokio.
pub struct NetstackStream {
    writes: PollSender<WriteOp>,
    incoming: mpsc::Receiver<Bytes>,
    leftover: Bytes,
    read_pos: usize,
    wake: Arc<Notify>,
}

/// A tunnel-side listening port. Each [`accept`](Self::accept) yields the next
/// inbound connection (the port-forwarding accept side).
pub struct NetstackListener {
    accept_rx: mpsc::Receiver<NetstackStream>,
}

impl NetstackListener {
    /// Returns the next accepted inbound connection, or `None` when the engine
    /// has stopped (the tunnel is gone).
    pub async fn accept(&mut self) -> Option<NetstackStream> {
        self.accept_rx.recv().await
    }
}

impl AsyncRead for NetstackStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos >= self.leftover.len() {
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    self.leftover = data;
                    self.read_pos = 0;
                }
                // Sender dropped: the connection closed. EOF.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let start = self.read_pos;
        let n = (self.leftover.len() - start).min(buf.remaining());
        buf.put_slice(&self.leftover[start..start + n]);
        self.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for NetstackStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Real backpressure: park the writer until the bounded channel has room.
        ready!(self.writes.poll_reserve(cx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack engine stopped"))?;
        self.writes
            .send_item(WriteOp::Data(Bytes::copy_from_slice(buf)))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack engine stopped"))?;
        self.wake.notify_one();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.writes.poll_reserve(cx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack engine stopped"))?;
        let _ = self.writes.send_item(WriteOp::Shutdown);
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

/// A UDP socket on the userspace netstack, driven from tokio. One socket serves
/// a whole flow: send to many destinations, receive from many sources.
/// Datagrams are lossy (UDP), so a full buffer drops rather than blocks.
pub struct NetstackUdpSocket {
    outgoing: mpsc::Sender<(Bytes, SocketAddr)>,
    incoming: mpsc::Receiver<(Bytes, SocketAddr)>,
    wake: Arc<Notify>,
}

impl NetstackUdpSocket {
    /// Queues `data` for delivery to `dst` through the tunnel.
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] if the netstack engine has stopped.
    pub async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
        self.outgoing
            .send((data, dst))
            .await
            .map_err(|_| NetError::EngineStopped)?;
        self.wake.notify_one();
        Ok(())
    }

    /// Receives the next datagram and its source, or `None` once the engine has
    /// stopped.
    pub async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
        self.incoming.recv().await
    }
}

impl Drop for NetstackUdpSocket {
    fn drop(&mut self) {
        // Wake the engine so it reaps this flow's smoltcp socket and ephemeral
        // port promptly, rather than waiting out the poll-delay fallback.
        self.wake.notify_one();
    }
}

/// A [`Connector`] backed by the userspace netstack engine.
#[derive(Clone)]
pub struct TunnelConnector {
    commands: mpsc::UnboundedSender<Command>,
    wake: Arc<Notify>,
    /// Whether the engine was assigned a v6 address, so v6 targets are routable.
    has_ipv6: bool,
}

impl TunnelConnector {
    /// Resolves `host` to an address of `rtype` by sending a DNS query over the
    /// tunnel to the configured resolver (the gateway forwarder by default,
    /// never the host resolver, so the lookup cannot leak outside the VPN).
    async fn resolve(&self, host: &str, rtype: dns::RecordType) -> Result<IpAddr, NetError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Resolve(ResolveCommand {
                name: host.to_owned(),
                rtype,
                reply: reply_tx,
            }))
            .map_err(|_| NetError::EngineStopped)?;
        self.wake.notify_one();
        reply_rx.await.map_err(|_| NetError::EngineStopped)?
    }

    /// Opens a UDP flow (an ephemeral local port) for datagrams to arbitrary
    /// targets through the tunnel. The returned socket serves a whole SOCKS5 UDP
    /// association: it can send to and receive from many peers.
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] if the engine has stopped, or
    /// [`NetError::ConnectFailed`] if the UDP port could not be bound.
    pub async fn open_udp(&self) -> Result<NetstackUdpSocket, NetError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::OpenUdp(UdpOpenCommand { reply: reply_tx }))
            .map_err(|_| NetError::EngineStopped)?;
        self.wake.notify_one();
        reply_rx.await.map_err(|_| NetError::EngineStopped)?
    }

    /// Resolves `host` over the tunnel, preferring `AAAA` when a v6 assignment
    /// exists and falling back to `A` only when the name genuinely has no `AAAA`
    /// record (never on a timeout or transport error, which would just double the
    /// wait). The query egresses at the exit, so the lookup never leaks to the
    /// host resolver. Shared by the TCP `connect` and the UDP `resolve_host` paths.
    async fn resolve_dualstack(&self, host: &str) -> Result<IpAddr, NetError> {
        if self.has_ipv6 {
            match self.resolve(host, dns::RecordType::Aaaa).await {
                Ok(ip) => Ok(ip),
                Err(NetError::NoDnsRecord) => self.resolve(host, dns::RecordType::A).await,
                Err(e) => Err(e),
            }
        } else {
            self.resolve(host, dns::RecordType::A).await
        }
    }

    /// Opens a TCP connection to an already-resolved IPv4 or IPv6 socket address.
    async fn open(&self, addr: SocketAddr) -> Result<NetstackStream, NetError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Open(OpenCommand {
                addr,
                reply: reply_tx,
            }))
            .map_err(|_| NetError::EngineStopped)?;
        self.wake.notify_one();
        reply_rx.await.map_err(|_| NetError::EngineStopped)?
    }

    /// Listens on tunnel-side TCP `port`, returning a [`NetstackListener`] over
    /// inbound connections (the port-forwarding accept side). Inbound packets
    /// only reach `port` once the exit forwards them (for example via a NAT-PMP
    /// mapping created with [`crate::portforward`]).
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] if the engine has stopped, or
    /// [`NetError::ConnectFailed`] if the port cannot be bound.
    pub async fn listen(&self, port: u16) -> Result<NetstackListener, NetError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Listen(ListenCommand {
                port,
                reply: reply_tx,
            }))
            .map_err(|_| NetError::EngineStopped)?;
        self.wake.notify_one();
        reply_rx.await.map_err(|_| NetError::EngineStopped)?
    }
}

impl Connector for TunnelConnector {
    type Stream = NetstackStream;

    async fn connect(&self, target: Target) -> Result<Self::Stream, NetError> {
        let addr = match target {
            Target::Ip(addr @ SocketAddr::V4(_)) => addr,
            // Route v6 only when the exit granted a v6 address; otherwise refuse
            // rather than silently black-hole a v6 target.
            Target::Ip(addr @ SocketAddr::V6(_)) => {
                if !self.has_ipv6 {
                    return Err(NetError::Unsupported("IPv6 target but no v6 assignment"));
                }
                addr
            }
            // Resolve the name over the tunnel. With a v6 assignment, prefer
            // AAAA and fall back to A only when the name genuinely has no AAAA
            // record (not on a timeout or transport error, which would just
            // double the wait). The query egresses at the exit, so the lookup
            // never leaks to the host resolver.
            Target::Domain(host, port) => {
                let ip = self.resolve_dualstack(&host).await?;
                SocketAddr::from((ip, port))
            }
        };
        self.open(addr).await
    }
}

/// Addressing for the netstack engine: the client's tunnel IP, the routing
/// gateway, the DNS resolver to query over the tunnel, and the inner MTU.
///
/// `local_ip`/`prefix` is the tunnel-assigned client address (for example
/// `10.66.0.2/16`) and `gateway` the exit-side tunnel gateway (for example
/// `10.66.0.1`), installed as the default route so traffic to public targets is
/// sent to the exit. `mtu` is the inner IP MTU and MUST fit one tunnel frame
/// (derive it from `PacketSink::max_payload`, never the raw policy MTU).
///
/// `dns_server` is the resolver queried for `A` lookups, reached over the
/// tunnel. It defaults to `gateway` (the exit's DNS forwarder, the common case).
/// For a `dns_disabled` exit that runs no forwarder, override it with
/// [`with_dns_server`](Self::with_dns_server) to a public resolver: the query
/// still egresses through the tunnel, so the lookup never leaks to the host
/// resolver.
///
/// A plain value type with no generics, so it maps cleanly to the sibling SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetstackConfig {
    /// Tunnel-assigned client IPv4 address.
    pub local_ip: Ipv4Addr,
    /// IPv4 subnet prefix length for `local_ip`.
    pub prefix: u8,
    /// Exit-side tunnel gateway, installed as the default route.
    pub gateway: Ipv4Addr,
    /// Resolver queried for DNS `A` lookups over the tunnel.
    pub dns_server: Ipv4Addr,
    /// Dual-stack IPv6 addressing, set iff the exit granted v6. `None` keeps the
    /// datapath v4-only and v6 targets are refused.
    pub ipv6: Option<Ipv6Addressing>,
    /// Inner IP MTU; MUST fit one tunnel frame.
    pub mtu: usize,
}

/// The IPv6 half of a dual-stack tunnel assignment (the v6 client address, its
/// prefix, and the v6 gateway installed as the default v6 route).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Addressing {
    /// Tunnel-assigned client IPv6 address.
    pub local_ip: Ipv6Addr,
    /// IPv6 subnet prefix length.
    pub prefix: u8,
    /// Exit-side v6 gateway, installed as the default v6 route.
    pub gateway: Ipv6Addr,
}

impl NetstackConfig {
    /// Builds a v4-only config with `dns_server` defaulted to the gateway
    /// forwarder and no IPv6.
    #[must_use]
    pub fn new(local_ip: Ipv4Addr, prefix: u8, gateway: Ipv4Addr, mtu: usize) -> Self {
        Self {
            local_ip,
            prefix,
            gateway,
            dns_server: gateway,
            ipv6: None,
            mtu,
        }
    }

    /// Overrides the DNS resolver (for `dns_disabled` exits). The resolver is
    /// still reached over the tunnel, never via the host resolver.
    #[must_use]
    pub fn with_dns_server(mut self, dns_server: Ipv4Addr) -> Self {
        self.dns_server = dns_server;
        self
    }

    /// Enables the dual-stack IPv6 datapath with the exit-granted v6 address,
    /// prefix and gateway. Without this, v6 targets are refused.
    #[must_use]
    pub fn with_ipv6(mut self, local_ip: Ipv6Addr, prefix: u8, gateway: Ipv6Addr) -> Self {
        self.ipv6 = Some(Ipv6Addressing {
            local_ip,
            prefix,
            gateway,
        });
        self
    }
}

/// Spawns the netstack engine over IP-frame channels and returns a connector.
///
/// `config` carries the client addressing, routing gateway, DNS resolver and
/// MTU (see [`NetstackConfig`]). `inbound` delivers IP packets arriving from the
/// tunnel; `outbound` receives IP packets the stack wants to send.
#[must_use]
pub fn spawn_engine(
    config: NetstackConfig,
    inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
) -> TunnelConnector {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let wake = Arc::new(Notify::new());

    let engine = Engine {
        device: TunnelDevice {
            rx: VecDeque::new(),
            tx: outbound,
            mtu: config.mtu,
        },
        conns: HashMap::new(),
        resolvers: Vec::new(),
        udp_flows: Vec::new(),
        listeners: Vec::new(),
        next_conn_id: 0,
        next_port: EPHEMERAL_BASE,
        used_ports: HashSet::new(),
        local_ip: config.local_ip,
        prefix: config.prefix,
        gateway: config.gateway,
        dns_server: config.dns_server,
        ipv6: config.ipv6,
        cmd_rx,
        inbound,
        wake: Arc::clone(&wake),
    };
    tokio::spawn(engine.run());

    TunnelConnector {
        commands: cmd_tx,
        wake,
        has_ipv6: config.ipv6.is_some(),
    }
}

struct Engine {
    device: TunnelDevice,
    conns: HashMap<u64, Conn>,
    resolvers: Vec<PendingResolve>,
    udp_flows: Vec<UdpFlow>,
    listeners: Vec<Listener>,
    next_conn_id: u64,
    next_port: u16,
    used_ports: HashSet<u16>,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    dns_server: std::net::Ipv4Addr,
    ipv6: Option<Ipv6Addressing>,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    inbound: mpsc::Receiver<Bytes>,
    wake: Arc<Notify>,
}

impl Engine {
    async fn run(mut self) {
        let base = tokio::time::Instant::now();
        let now = |b: tokio::time::Instant| {
            SmolInstant::from_micros(i64::try_from(b.elapsed().as_micros()).unwrap_or(i64::MAX))
        };

        let mut config = Config::new(HardwareAddress::Ip);
        // Randomize the TCP ISN seed (RFC 6528) rather than a fixed constant.
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut self.device, now(base));
        let v6 = self.ipv6;
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::from(self.local_ip), self.prefix));
            // Dual-stack: add the v6 client address iff the exit granted v6.
            if let Some(v6) = v6 {
                let _ = addrs.push(IpCidr::new(IpAddress::from(v6.local_ip), v6.prefix));
            }
        });
        // Default route to the exit gateway so out-of-subnet (public) targets
        // egress through the tunnel rather than being unroutable.
        let _ = iface.routes_mut().add_default_ipv4_route(self.gateway);
        if let Some(v6) = v6 {
            let _ = iface.routes_mut().add_default_ipv6_route(v6.gateway);
        }
        let mut sockets = SocketSet::new(Vec::new());

        loop {
            while let Ok(cmd) = self.cmd_rx.try_recv() {
                match cmd {
                    Command::Open(c) => self.open(&mut iface, &mut sockets, c, now(base)),
                    Command::Resolve(c) => self.start_resolve(&mut sockets, c, now(base)),
                    Command::OpenUdp(c) => self.start_udp(&mut sockets, c),
                    Command::Listen(c) => self.start_listen(&mut sockets, c),
                }
            }
            self.ingest_writes();
            self.pump_udp(&mut sockets);

            // Inbound frames from the tunnel into the device.
            loop {
                match self.inbound.try_recv() {
                    Ok(frame) => self.device.rx.push_back(frame),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return, // tunnel closed
                }
            }

            self.pump_sockets(&mut sockets);
            // Drain smoltcp completely before yielding (canonical poll pattern).
            while iface.poll(now(base), &mut self.device, &mut sockets) != PollResult::None {}
            self.drain_sockets(&mut sockets, now(base));
            self.accept_listeners(&mut sockets, now(base));
            self.drain_resolvers(&mut sockets, now(base));
            self.drain_udp(&mut sockets);

            let mut delay = iface
                .poll_delay(now(base), &sockets)
                .map_or(std::time::Duration::from_secs(30), |d| {
                    std::time::Duration::from_micros(d.total_micros())
                });
            // A single-shot DNS query has no smoltcp retransmit timer to wake the
            // loop, so bound the sleep by the nearest resolver deadline.
            if let Some(nearest) = self.resolvers.iter().map(|r| r.deadline).min() {
                let now_i = now(base);
                let remaining = if nearest > now_i {
                    std::time::Duration::from_micros((nearest - now_i).total_micros())
                } else {
                    std::time::Duration::ZERO
                };
                delay = delay.min(remaining);
            }

            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
                frame = self.inbound.recv() => {
                    match frame {
                        Some(f) => self.device.rx.push_back(f),
                        None => return, // tunnel closed
                    }
                }
            }
        }
    }

    /// Picks a free ephemeral local port, skipping ones already in use.
    fn alloc_port(&mut self) -> u16 {
        for _ in 0..=(u16::MAX - EPHEMERAL_BASE) {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                EPHEMERAL_BASE
            } else {
                port + 1
            };
            if self.used_ports.insert(port) {
                return port;
            }
        }
        // All ephemeral ports busy (>16k live conns): reuse anyway.
        self.next_port
    }

    fn open(
        &mut self,
        iface: &mut Interface,
        sockets: &mut SocketSet<'_>,
        cmd: OpenCommand,
        now: SmolInstant,
    ) {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        let handle = sockets.add(socket);
        let local_port = self.alloc_port();

        let sock = sockets.get_mut::<tcp::Socket<'_>>(handle);
        let remote = (to_smol_ip(cmd.addr.ip()), cmd.addr.port());
        if sock.connect(iface.context(), remote, local_port).is_err() {
            sockets.remove(handle);
            self.used_ports.remove(&local_port);
            let _ = cmd.reply.send(Err(NetError::ConnectFailed));
            return;
        }

        let (to_app_tx, to_app_rx) = mpsc::channel(CONN_CHANNEL_DEPTH);
        let (from_app_tx, from_app_rx) = mpsc::channel(CONN_CHANNEL_DEPTH);
        let stream = NetstackStream {
            writes: PollSender::new(from_app_tx),
            incoming: to_app_rx,
            leftover: Bytes::new(),
            read_pos: 0,
            wake: Arc::clone(&self.wake),
        };
        let id = self.next_conn_id;
        self.next_conn_id += 1;
        self.conns.insert(
            id,
            Conn {
                handle,
                local_port,
                to_app: to_app_tx,
                from_app: from_app_rx,
                pending_out: VecDeque::new(),
                pending_out_len: 0,
                want_close: false,
                deadline: now + CONNECT_TIMEOUT,
                connect: Some((cmd.reply, stream)),
            },
        );
    }

    /// Creates a fresh socket in `LISTEN` state on `port`.
    fn new_listen_socket(sockets: &mut SocketSet<'_>, port: u16) -> Option<SocketHandle> {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        let handle = sockets.add(socket);
        if sockets
            .get_mut::<tcp::Socket<'_>>(handle)
            .listen(port)
            .is_err()
        {
            sockets.remove(handle);
            return None;
        }
        Some(handle)
    }

    /// Binds a pool of listening sockets on `cmd.port` (the accept backlog) and
    /// returns a [`NetstackListener`] over accepted streams.
    fn start_listen(&mut self, sockets: &mut SocketSet<'_>, cmd: ListenCommand) {
        let mut pending = Vec::with_capacity(LISTEN_BACKLOG);
        for _ in 0..LISTEN_BACKLOG {
            match Self::new_listen_socket(sockets, cmd.port) {
                Some(h) => pending.push(h),
                None => {
                    for h in pending {
                        sockets.remove(h);
                    }
                    let _ = cmd.reply.send(Err(NetError::ConnectFailed));
                    return;
                }
            }
        }
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_CHANNEL_DEPTH);
        self.listeners.push(Listener {
            port: cmd.port,
            pending,
            accept_tx,
        });
        let _ = cmd.reply.send(Ok(NetstackListener { accept_rx }));
    }

    /// Converts listening sockets that received a connection into tracked conns,
    /// delivers their streams to the app, refills the backlog, and reaps
    /// listeners whose [`NetstackListener`] was dropped.
    fn accept_listeners(&mut self, sockets: &mut SocketSet<'_>, now: SmolInstant) {
        let mut accepted: Vec<(SocketHandle, mpsc::Sender<NetstackStream>)> = Vec::new();
        let mut to_remove: Vec<SocketHandle> = Vec::new();
        let mut refill: Vec<(u16, usize)> = Vec::new();
        let mut dead: Vec<usize> = Vec::new();

        for (li, listener) in self.listeners.iter_mut().enumerate() {
            // The app dropped its listener: tear the whole thing down.
            if listener.accept_tx.is_closed() {
                dead.push(li);
                continue;
            }
            // Only convert a backlog socket once it is fully `Established`, so the
            // app sees connections with `accept(2)` semantics (not mid-handshake).
            // A socket still in `SynReceived` stays in the pool (it establishes or
            // smoltcp times it out); one that reached a terminal state without
            // establishing is reclaimed and the slot refilled.
            let mut engaged = 0usize;
            listener
                .pending
                .retain(|&h| match sockets.get::<tcp::Socket<'_>>(h).state() {
                    tcp::State::Listen | tcp::State::SynReceived => true,
                    tcp::State::Established => {
                        accepted.push((h, listener.accept_tx.clone()));
                        engaged += 1;
                        false
                    }
                    _ => {
                        to_remove.push(h);
                        engaged += 1;
                        false
                    }
                });
            if engaged > 0 {
                refill.push((listener.port, engaged));
            }
        }

        // Reclaim sockets that died before establishing.
        for handle in to_remove {
            sockets.remove(handle);
        }

        for (handle, accept_tx) in accepted {
            let (to_app_tx, to_app_rx) = mpsc::channel(CONN_CHANNEL_DEPTH);
            let (from_app_tx, from_app_rx) = mpsc::channel(CONN_CHANNEL_DEPTH);
            let stream = NetstackStream {
                writes: PollSender::new(from_app_tx),
                incoming: to_app_rx,
                leftover: Bytes::new(),
                read_pos: 0,
                wake: Arc::clone(&self.wake),
            };
            // Deliver to the app; if the accept queue is full or gone, drop the
            // connection rather than block the engine (backlog backpressure).
            if accept_tx.try_send(stream).is_err() {
                let sock = sockets.get_mut::<tcp::Socket<'_>>(handle);
                sock.abort();
                sockets.remove(handle);
                continue;
            }
            let id = self.next_conn_id;
            self.next_conn_id += 1;
            self.conns.insert(
                id,
                Conn {
                    handle,
                    // Inbound: the local port is the listen port, not an
                    // allocated ephemeral, so it is not tracked in `used_ports`.
                    local_port: 0,
                    to_app: to_app_tx,
                    from_app: from_app_rx,
                    pending_out: VecDeque::new(),
                    pending_out_len: 0,
                    want_close: false,
                    // Unused for accepted conns (`connect` is `None`).
                    deadline: now,
                    connect: None,
                },
            );
        }

        // Refill each backlog that lost sockets so the port keeps accepting.
        for (port, count) in refill {
            for _ in 0..count {
                let Some(h) = Self::new_listen_socket(sockets, port) else {
                    break;
                };
                if let Some(listener) = self.listeners.iter_mut().find(|l| l.port == port) {
                    listener.pending.push(h);
                } else {
                    sockets.remove(h);
                }
            }
        }

        for li in dead.into_iter().rev() {
            let listener = self.listeners.swap_remove(li);
            for h in listener.pending {
                sockets.remove(h);
            }
        }
    }

    /// Starts a DNS `A` resolution: bind a UDP socket, send the query to the
    /// configured resolver, and track it until a reply or the deadline.
    fn start_resolve(
        &mut self,
        sockets: &mut SocketSet<'_>,
        cmd: ResolveCommand,
        now: SmolInstant,
    ) {
        // A per-query transaction id the response must echo (spoof resistance).
        let id: u16 = rand::random();
        let query = match dns::encode_query(&cmd.name, id, cmd.rtype) {
            Ok(q) => q,
            Err(_) => {
                let _ = cmd.reply.send(Err(NetError::ConnectFailed));
                return;
            }
        };
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; DNS_BUFFER]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; DNS_BUFFER]);
        let handle = sockets.add(udp::Socket::new(rx, tx));
        let local_port = self.alloc_port();
        let sock = sockets.get_mut::<udp::Socket<'_>>(handle);
        let dst = IpEndpoint::new(IpAddress::from(self.dns_server), DNS_PORT);
        if sock.bind(local_port).is_err() || sock.send_slice(&query, dst).is_err() {
            sockets.remove(handle);
            self.used_ports.remove(&local_port);
            let _ = cmd.reply.send(Err(NetError::ConnectFailed));
            return;
        }
        self.resolvers.push(PendingResolve {
            handle,
            local_port,
            id,
            rtype: cmd.rtype,
            reply: cmd.reply,
            deadline: now + DNS_TIMEOUT,
        });
    }

    /// Delivers DNS responses (first matching record), times out stalled lookups,
    /// and reaps the UDP sockets of finished resolutions.
    fn drain_resolvers(&mut self, sockets: &mut SocketSet<'_>, now: SmolInstant) {
        let mut finished: Vec<(usize, Result<IpAddr, NetError>)> = Vec::new();
        for (i, r) in self.resolvers.iter().enumerate() {
            let sock = sockets.get_mut::<udp::Socket<'_>>(r.handle);
            if sock.can_recv() {
                if let Ok((data, _meta)) = sock.recv() {
                    let res = match dns::parse_response(data, r.id, r.rtype) {
                        Ok(addrs) => addrs.into_iter().next().ok_or(NetError::NoDnsRecord),
                        // "No such record" is distinct from a transport/parse
                        // failure so a dual-stack lookup falls back on it alone.
                        Err(dns::DnsError::NoAddress) => Err(NetError::NoDnsRecord),
                        Err(_) => Err(NetError::ConnectFailed),
                    };
                    finished.push((i, res));
                }
            } else if now >= r.deadline {
                finished.push((i, Err(NetError::ConnectTimeout)));
            }
        }
        // Remove highest indices first so the earlier ones stay valid.
        finished.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (i, res) in finished {
            let r = self.resolvers.swap_remove(i);
            sockets.remove(r.handle);
            self.used_ports.remove(&r.local_port);
            let _ = r.reply.send(res);
        }
    }

    /// Binds a UDP socket for a new flow and hands back a [`NetstackUdpSocket`].
    fn start_udp(&mut self, sockets: &mut SocketSet<'_>, cmd: UdpOpenCommand) {
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 16],
            vec![0u8; UDP_FLOW_BUFFER],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 16],
            vec![0u8; UDP_FLOW_BUFFER],
        );
        let handle = sockets.add(udp::Socket::new(rx, tx));
        let local_port = self.alloc_port();
        let sock = sockets.get_mut::<udp::Socket<'_>>(handle);
        if sock.bind(local_port).is_err() {
            sockets.remove(handle);
            self.used_ports.remove(&local_port);
            let _ = cmd.reply.send(Err(NetError::ConnectFailed));
            return;
        }
        let (to_app_tx, to_app_rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
        let (from_app_tx, from_app_rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
        self.udp_flows.push(UdpFlow {
            handle,
            local_port,
            to_app: to_app_tx,
            from_app: from_app_rx,
        });
        let _ = cmd.reply.send(Ok(NetstackUdpSocket {
            outgoing: from_app_tx,
            incoming: to_app_rx,
            wake: Arc::clone(&self.wake),
        }));
    }

    /// Sends queued app datagrams out each UDP flow and reaps flows whose app
    /// handle was dropped.
    fn pump_udp(&mut self, sockets: &mut SocketSet<'_>) {
        let mut closed: Vec<usize> = Vec::new();
        for (i, flow) in self.udp_flows.iter_mut().enumerate() {
            loop {
                match flow.from_app.try_recv() {
                    Ok((data, dst)) => {
                        let sock = sockets.get_mut::<udp::Socket<'_>>(flow.handle);
                        // Lossy: a full tx buffer drops this datagram (UDP).
                        let _ = sock.send_slice(&data, to_smol_endpoint(dst));
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        closed.push(i);
                        break;
                    }
                }
            }
        }
        closed.sort_unstable_by(|a, b| b.cmp(a));
        for i in closed {
            let flow = self.udp_flows.swap_remove(i);
            sockets.remove(flow.handle);
            self.used_ports.remove(&flow.local_port);
        }
    }

    /// Delivers received datagrams (with their source) to each UDP flow's app.
    fn drain_udp(&mut self, sockets: &mut SocketSet<'_>) {
        for flow in &self.udp_flows {
            let sock = sockets.get_mut::<udp::Socket<'_>>(flow.handle);
            while sock.can_recv() {
                match sock.recv() {
                    Ok((data, meta)) => {
                        if let Some(src) = from_smol_endpoint(meta.endpoint) {
                            // Lossy: a full app channel drops this datagram (UDP).
                            let _ = flow.to_app.try_send((Bytes::copy_from_slice(data), src));
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    /// Moves app->net writes into per-conn buffers, bounded by `PENDING_OUT_CAP`
    /// so a slow tunnel exerts backpressure through the bounded `from_app`
    /// channel rather than growing memory without bound.
    fn ingest_writes(&mut self) {
        for conn in self.conns.values_mut() {
            while conn.pending_out_len < PENDING_OUT_CAP {
                match conn.from_app.try_recv() {
                    Ok(WriteOp::Data(bytes)) => {
                        conn.pending_out_len += bytes.len();
                        conn.pending_out.push_back(bytes);
                    }
                    Ok(WriteOp::Shutdown) => conn.want_close = true,
                    Err(_) => break,
                }
            }
        }
    }

    /// Pushes buffered app bytes into socket send buffers and applies closes.
    fn pump_sockets(&mut self, sockets: &mut SocketSet<'_>) {
        for conn in self.conns.values_mut() {
            let sock = sockets.get_mut::<tcp::Socket<'_>>(conn.handle);
            while sock.can_send() {
                let Some(chunk) = conn.pending_out.front().cloned() else {
                    break;
                };
                match sock.send_slice(&chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.pending_out_len -= n;
                        if n == chunk.len() {
                            conn.pending_out.pop_front();
                        } else {
                            conn.pending_out[0] = chunk.slice(n..);
                        }
                    }
                    Err(_) => break,
                }
            }
            if conn.want_close && conn.pending_out.is_empty() && sock.can_send() {
                sock.close();
            }
        }
    }

    /// Delivers established streams, fails timed-out/refused connects, drains
    /// socket recv buffers to apps (only while the app channel has room, so the
    /// TCP window closes under a slow reader), and reaps closed connections.
    fn drain_sockets(&mut self, sockets: &mut SocketSet<'_>, now: SmolInstant) {
        for conn in self.conns.values_mut() {
            let sock = sockets.get_mut::<tcp::Socket<'_>>(conn.handle);

            if let Some((reply, stream)) = conn.connect.take() {
                match sock.state() {
                    tcp::State::Established => {
                        let _ = reply.send(Ok(stream));
                    }
                    tcp::State::Closed => {
                        let _ = reply.send(Err(NetError::ConnectionRefused));
                    }
                    _ if now >= conn.deadline => {
                        sock.abort();
                        let _ = reply.send(Err(NetError::ConnectTimeout));
                    }
                    // Still handshaking, within deadline: put it back.
                    _ => conn.connect = Some((reply, stream)),
                }
            }

            // Read backpressure: only pull from smoltcp when the app can take it.
            while sock.can_recv() {
                match conn.to_app.try_reserve() {
                    Ok(permit) => {
                        let mut buf = [0u8; 4096];
                        match sock.recv_slice(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => permit.send(Bytes::copy_from_slice(&buf[..n])),
                        }
                    }
                    // App is behind: leave bytes in smoltcp so the window closes.
                    Err(_) => break,
                }
            }
        }

        // Reap fully-closed connections (not still mid-connect); dropping
        // `to_app` signals EOF to the reader.
        let reapable: Vec<u64> = self
            .conns
            .iter()
            .filter(|(_, conn)| {
                let sock = sockets.get::<tcp::Socket<'_>>(conn.handle);
                conn.connect.is_none() && !sock.is_active() && sock.state() == tcp::State::Closed
            })
            .map(|(id, _)| *id)
            .collect();
        for id in reapable {
            if let Some(conn) = self.conns.remove(&id) {
                sockets.remove(conn.handle);
                self.used_ports.remove(&conn.local_port);
            }
        }
    }
}

/// Bridges a [`PacketSink`] to the netstack engine: a reader task feeds inbound
/// frames and a writer task drains outbound frames. A transient send failure
/// (for example a PMTU `TooLarge`) drops that one packet and continues; the
/// whole datapath only tears down when the tunnel read side closes.
///
/// Returns the connector and a liveness watch that flips to `false` when the
/// tunnel read side closes (the datapath is dead): a caller can surface that as
/// a disconnect so an app reacts to the leak window.
///
/// [`PacketSink`]: crate::PacketSink
#[must_use]
pub fn spawn_over_sink<S>(
    sink: Arc<S>,
    config: NetstackConfig,
) -> (TunnelConnector, watch::Receiver<bool>)
where
    S: crate::PacketSink + 'static,
{
    let (inbound_tx, inbound_rx) = mpsc::channel(FRAME_CHANNEL_DEPTH);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(FRAME_CHANNEL_DEPTH);
    let (alive_tx, alive_rx) = watch::channel(true);

    let reader = Arc::clone(&sink);
    tokio::spawn(async move {
        while let Ok(packet) = reader.recv_packet().await {
            if inbound_tx.send(packet).await.is_err() {
                break;
            }
        }
        // The tunnel read side closed (or the engine is gone): signal down.
        let _ = alive_tx.send(false);
    });
    tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            // Drop-and-continue on a per-packet send error; tunnel teardown is
            // detected by the reader task closing `inbound`.
            let _ = sink.send_packet(&frame).await;
        }
    });

    (spawn_engine(config, inbound_rx, outbound_tx), alive_rx)
}

impl crate::proxy::UdpFlow for NetstackUdpSocket {
    async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
        NetstackUdpSocket::send_to(self, data, dst).await
    }

    async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
        NetstackUdpSocket::recv_from(self).await
    }
}

impl crate::proxy::UdpConnector for TunnelConnector {
    type Flow = NetstackUdpSocket;

    async fn open_udp(&self) -> Result<NetstackUdpSocket, NetError> {
        TunnelConnector::open_udp(self).await
    }

    async fn resolve_host(&self, host: &str) -> Result<std::net::IpAddr, NetError> {
        // Same dual-stack policy as TCP: prefer AAAA when v6 is assigned, else A.
        // The lookup egresses over the tunnel (no host-resolver leak).
        self.resolve_dualstack(host).await
    }

    fn supports_ipv6(&self) -> bool {
        self.has_ipv6
    }
}

/// Converts a std IP address to smoltcp's wire type.
fn to_smol_ip(ip: std::net::IpAddr) -> IpAddress {
    match ip {
        std::net::IpAddr::V4(a) => IpAddress::from(a),
        std::net::IpAddr::V6(a) => IpAddress::from(a),
    }
}

/// Converts a std socket address to a smoltcp UDP endpoint.
fn to_smol_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(to_smol_ip(addr.ip()), addr.port())
}

/// Converts a smoltcp endpoint back to a std socket address.
fn from_smol_endpoint(ep: IpEndpoint) -> Option<SocketAddr> {
    let ip = match ep.addr {
        IpAddress::Ipv4(a) => std::net::IpAddr::V4(a),
        IpAddress::Ipv6(a) => std::net::IpAddr::V6(a),
    };
    Some(SocketAddr::new(ip, ep.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_dns_to_the_gateway() {
        // The default resolver MUST be the gateway forwarder: that is what keeps
        // lookups inside the tunnel by default. A regression to any other default
        // would be a DNS-leak vector, so pin it explicitly.
        let gw: Ipv4Addr = "10.66.0.1".parse().unwrap();
        let config = NetstackConfig::new("10.66.0.2".parse().unwrap(), 16, gw, 1280);
        assert_eq!(config.dns_server, gw);
    }

    #[test]
    fn with_dns_server_overrides_only_the_resolver() {
        let gw: Ipv4Addr = "10.66.0.1".parse().unwrap();
        let resolver: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let base = NetstackConfig::new("10.66.0.2".parse().unwrap(), 16, gw, 1280);
        let overridden = base.with_dns_server(resolver);
        assert_eq!(overridden.dns_server, resolver);
        // Every other field is untouched by the override.
        assert_eq!(overridden.local_ip, base.local_ip);
        assert_eq!(overridden.prefix, base.prefix);
        assert_eq!(overridden.gateway, base.gateway);
        assert_eq!(overridden.mtu, base.mtu);
    }

    #[test]
    fn config_is_v4_only_until_with_ipv6() {
        let gw: Ipv4Addr = "10.66.0.1".parse().unwrap();
        let base = NetstackConfig::new("10.66.0.2".parse().unwrap(), 16, gw, 1280);
        assert_eq!(base.ipv6, None, "v4-only by default");

        let local6: Ipv6Addr = "fd66::2".parse().unwrap();
        let gw6: Ipv6Addr = "fd66::1".parse().unwrap();
        let dual = base.with_ipv6(local6, 64, gw6);
        assert_eq!(
            dual.ipv6,
            Some(Ipv6Addressing {
                local_ip: local6,
                prefix: 64,
                gateway: gw6,
            })
        );
        // The v4 half is untouched by enabling v6.
        assert_eq!(dual.local_ip, base.local_ip);
        assert_eq!(dual.gateway, base.gateway);
    }
}
