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
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Per-direction smoltcp TCP buffer. This bounds the receive window, so a
/// single connection's throughput is capped at TCP_BUFFER / RTT: 64 KiB over a
/// 23 ms WAN path plateaus at ~22 Mbps, which starved the proxy datapath. 1 MiB
/// saturates links past 300 Mbps at that RTT (window scaling carries it); the
/// cost is 2 MiB per connection, fine for a client with a handful of them.
const TCP_BUFFER: usize = 1024 * 1024;
/// First ephemeral local port handed to outbound connects.
const EPHEMERAL_BASE: u16 = 49152;

/// A random start point in the ephemeral range `[EPHEMERAL_BASE, u16::MAX]`,
/// used to seed a fresh engine's port allocator (see the call site for why two
/// independent sessions must not share a port sequence). Allocation still
/// increments and wraps within the same range, so a single session's ports stay
/// unique; only the starting offset differs per instance.
fn random_ephemeral_start() -> u16 {
    let span = u16::MAX - EPHEMERAL_BASE;
    EPHEMERAL_BASE + (rand::random::<u16>() % span)
}
/// Per-connection app<->engine channel depth (chunks); the backpressure point.
const CONN_CHANNEL_DEPTH: usize = 32;
/// Frame-channel depth toward/from the tunnel. Kept shallow so queueing adds at
/// most a few ms of latency under load (a deeper queue buffers jitter the VPN
/// datapath should shed); the writer applies backpressure once it fills.
const FRAME_CHANNEL_DEPTH: usize = 256;
/// Max buffered app->net bytes per connection before the writer is throttled.
const PENDING_OUT_CAP: usize = 256 * 1024;
/// How long to wait for a SYN to complete before failing the connect.
const CONNECT_TIMEOUT: SmolDuration = SmolDuration::from_secs(10);
/// How long to wait for a DNS response before failing resolution.
const DNS_TIMEOUT: SmolDuration = SmolDuration::from_secs(5);
/// First DNS retransmit delay; doubles after each subsequent retransmit. A
/// single-shot query on the unreliable QUIC datagram plane has no retransmit
/// timer of its own (unlike TCP), so this recovers from one lost query or
/// reply well before `DNS_TIMEOUT` gives up.
const DNS_RETX_INITIAL: SmolDuration = SmolDuration::from_secs(1);
/// Standard DNS service port (queried on the tunnel gateway / exit forwarder).
const DNS_PORT: u16 = 53;
/// UDP buffer for one in-flight DNS query/response (fits an EDNS-sized reply).
const DNS_BUFFER: usize = 2048;
/// Cap on a cached DNS entry's lifetime, regardless of the record TTL: bounds how
/// stale a cached answer can get while still absorbing bursts of repeat lookups.
const DNS_CACHE_MAX_TTL: SmolDuration = SmolDuration::from_secs(300);
/// Max distinct cached names before the cache is pruned, bounding memory.
const DNS_CACHE_CAP: usize = 512;
/// Per-direction UDP payload buffer for a relayed UDP flow (64 KiB).
const UDP_FLOW_BUFFER: usize = 64 * 1024;
/// Datagrams buffered per direction for a UDP flow before drops (lossy by design).
const UDP_CHANNEL_DEPTH: usize = 64;
/// Number of sockets kept in `LISTEN` state per listening port (accept backlog).
const LISTEN_BACKLOG: usize = 8;
/// Accepted-connection queue depth per listener before inbound SYNs are refused.
const ACCEPT_CHANNEL_DEPTH: usize = 32;
/// Smallest inner MTU the engine will ever apply to the device. smoltcp derives
/// each TCP segment's MSS as `ip_mtu - ip_header_len - TCP_HEADER_LEN` (20 or 40
/// bytes of header); below this floor that subtraction can underflow. Matches
/// the classic IPv4 minimum-required-support MTU, the same floor rationale as
/// `warrenguard_transport_core::inner_mtu`'s `MSS_FLOOR`.
const MIN_NETSTACK_MTU: usize = 576;

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

/// Decides whether the device's MTU must change: clamps `candidate` (the
/// sink's live transmit budget) to [`MIN_NETSTACK_MTU`] and reports the new
/// value only when it actually differs from `current`, so a caller only pays
/// for a smoltcp interface rebuild on a genuine change (see
/// [`Engine::refresh_mtu`]).
#[must_use]
fn next_device_mtu(current: usize, candidate: usize) -> Option<usize> {
    let clamped = candidate.max(MIN_NETSTACK_MTU);
    (clamped != current).then_some(clamped)
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
    /// The queried name, kept so a successful answer can be cached by name.
    name: String,
    /// The record type queried, so the reply is parsed for the matching answer.
    rtype: dns::RecordType,
    reply: oneshot::Sender<Result<IpAddr, NetError>>,
    deadline: SmolInstant,
    /// The encoded query, kept to retransmit verbatim (same transaction id)
    /// without re-encoding.
    query: Vec<u8>,
    /// Next time to re-send the query if no answer has arrived yet. The
    /// unreliable QUIC datagram plane has no transport-level retransmission,
    /// unlike TCP, so a lost query or response would otherwise stall the whole
    /// `DNS_TIMEOUT` window for nothing.
    next_retx: SmolInstant,
    /// Current retransmit backoff, doubled after each retransmission.
    retx_interval: SmolDuration,
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

#[cfg(test)]
impl NetstackStream {
    /// An already-closed stream (its peers dropped), for tests that only need a
    /// stream value: reads hit EOF and writes fail. Used to exercise paths that
    /// never touch the stream (for example a relay whose local connect refuses).
    pub(crate) fn closed_for_test() -> Self {
        let (write_tx, write_rx) = mpsc::channel(1);
        drop(write_rx); // writer side has no receiver: writes fail
        let (incoming_tx, incoming) = mpsc::channel(1);
        drop(incoming_tx); // no sender: reads hit EOF
        Self {
            writes: PollSender::new(write_tx),
            incoming,
            leftover: Bytes::new(),
            read_pos: 0,
            wake: Arc::new(Notify::new()),
        }
    }
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

    /// Resolves `host` over the tunnel. With a v6 assignment it prefers `AAAA`
    /// and falls back to `A` only when the name genuinely has no `AAAA` record.
    ///
    /// IPv6 is preferred because the exit's tunnelled IPv4 egress is unreliable
    /// (it black-holes connects intermittently, stalling each one for the full
    /// `CONNECT_TIMEOUT`) while its tunnelled IPv6 egress is stable, so a v6
    /// assignment routes real traffic reliably. The query egresses at the exit,
    /// so the lookup never leaks to the host resolver. Shared by the TCP
    /// `connect` and the UDP `resolve_host` paths.
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
            // Resolve the name over the tunnel, preferring AAAA under a v6
            // assignment and falling back to A only for names with no AAAA (see
            // `resolve_dualstack`). The query egresses at the exit, so the
            // lookup never leaks to the host resolver.
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
    /// Per-direction smoltcp TCP buffer, in bytes (see [`TCP_BUFFER`] for the
    /// default and the throughput-vs-memory tradeoff it encodes).
    pub tcp_buffer_bytes: usize,
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
            tcp_buffer_bytes: TCP_BUFFER,
        }
    }

    /// Overrides the per-direction TCP buffer size (default: [`TCP_BUFFER`]).
    /// A larger buffer raises the throughput ceiling on high-RTT paths at the
    /// cost of memory per connection; a smaller one trades throughput for a
    /// tighter memory budget.
    #[must_use]
    pub fn with_tcp_buffer_bytes(mut self, tcp_buffer_bytes: usize) -> Self {
        self.tcp_buffer_bytes = tcp_buffer_bytes;
        self
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
/// tunnel; `outbound` receives IP packets the stack wants to send. The device
/// MTU is fixed at `config.mtu` for the connector's lifetime; use
/// [`spawn_over_sink`] when the path budget can change mid-session.
#[must_use]
pub fn spawn_engine(
    config: NetstackConfig,
    inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
) -> TunnelConnector {
    spawn_engine_inner(config, inbound, outbound, None)
}

/// Shared implementation behind [`spawn_engine`] and [`spawn_over_sink`].
/// `live_mtu`, when set, is polled once per engine loop iteration
/// ([`Engine::refresh_mtu`]) so a mid-session PMTU shrink or growth reaches
/// smoltcp's device capabilities.
fn spawn_engine_inner(
    config: NetstackConfig,
    inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
    live_mtu: Option<Arc<AtomicUsize>>,
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
        dns_cache: HashMap::new(),
        udp_flows: Vec::new(),
        listeners: Vec::new(),
        next_conn_id: 0,
        // Randomize the first ephemeral port per engine instance. The exit
        // gives one sticky inner IP to all connections of an account, so two
        // INDEPENDENT sessions of the same account (e.g. two machines on a
        // shared wallet) share that inner IP. If both started at a fixed
        // base they would allocate identical (inner ip, port) tuples to the
        // same destination, which the exit's NAT collapses into one flow and
        // no downlink demux can separate. A random start makes the two
        // sessions' 5-tuples disjoint with overwhelming probability, so the
        // exit's per-flow routing keeps their return traffic apart.
        next_port: random_ephemeral_start(),
        used_ports: HashSet::new(),
        local_ip: config.local_ip,
        prefix: config.prefix,
        gateway: config.gateway,
        dns_server: config.dns_server,
        ipv6: config.ipv6,
        tcp_buffer_bytes: config.tcp_buffer_bytes,
        cmd_rx,
        inbound,
        wake: Arc::clone(&wake),
        live_mtu,
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
    /// TTL-bounded cache of resolved names, so repeat connects to the same host
    /// skip a DNS round-trip over the tunnel. Single-threaded engine, so no lock.
    dns_cache: HashMap<(String, dns::RecordType), (IpAddr, SmolInstant)>,
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
    /// Per-direction TCP socket buffer size, from [`NetstackConfig::tcp_buffer_bytes`].
    tcp_buffer_bytes: usize,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    inbound: mpsc::Receiver<Bytes>,
    wake: Arc<Notify>,
    /// Tracks the sink's live transmit budget (see [`crate::PacketSink::max_payload`]);
    /// `None` for a fixed-MTU connector ([`spawn_engine`] called directly).
    live_mtu: Option<Arc<AtomicUsize>>,
}

impl Engine {
    /// Builds a fresh smoltcp interface over the current device (whose `mtu`
    /// reflects the latest live budget), re-adding this engine's addressing and
    /// default routes. Needed both at startup and on a live MTU change: smoltcp
    /// bakes `DeviceCapabilities` into the interface once at construction and
    /// never re-reads them (`capabilities()` is called only from `Interface::new`),
    /// so applying a runtime MTU change needs a fresh `Interface`. Existing TCP
    /// sockets are unaffected: they live in the separate `SocketSet`, not here.
    fn build_interface(&mut self, now: SmolInstant) -> Interface {
        let mut config = Config::new(HardwareAddress::Ip);
        // Randomize the TCP ISN seed (RFC 6528) rather than a fixed constant.
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut self.device, now);
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
        iface
    }

    /// Reads the sink's live transmit budget (if tracked) and, on a genuine
    /// change, applies it to the device and rebuilds `iface` so smoltcp's
    /// baked-in capabilities follow a mid-session PMTU shrink or growth (see
    /// `93-REDUCED-MTU-ADAPTATION.md`). A no-op when nothing changed or no live
    /// cell is tracked (a fixed-MTU connector).
    fn refresh_mtu(&mut self, iface: &mut Interface, now: SmolInstant) {
        let Some(live) = &self.live_mtu else {
            return;
        };
        if let Some(mtu) = next_device_mtu(self.device.mtu, live.load(Ordering::Relaxed)) {
            self.device.mtu = mtu;
            *iface = self.build_interface(now);
        }
    }

    async fn run(mut self) {
        let base = tokio::time::Instant::now();
        let now = |b: tokio::time::Instant| {
            SmolInstant::from_micros(i64::try_from(b.elapsed().as_micros()).unwrap_or(i64::MAX))
        };

        let mut iface = self.build_interface(now(base));
        let mut sockets = SocketSet::new(Vec::new());

        loop {
            self.refresh_mtu(&mut iface, now(base));
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
            self.retransmit_resolvers(&mut sockets, now(base));
            self.drain_udp(&mut sockets);

            let mut delay = iface
                .poll_delay(now(base), &sockets)
                .map_or(std::time::Duration::from_secs(30), |d| {
                    std::time::Duration::from_micros(d.total_micros())
                });
            // DNS queries have no smoltcp retransmit timer of their own to wake
            // the loop, so bound the sleep by the nearest resolver deadline or
            // retransmit time, whichever comes first.
            if let Some(nearest) = self
                .resolvers
                .iter()
                .map(|r| r.deadline.min(r.next_retx))
                .min()
            {
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

    /// Picks a free ephemeral local port, skipping ones already in use, or
    /// `None` if the entire ephemeral range is exhausted (>16k live flows).
    /// Failing closed here is correct: reusing a live port would alias two flows
    /// onto one 4-tuple and corrupt both when either is reaped.
    fn alloc_port(&mut self) -> Option<u16> {
        for _ in 0..=(u16::MAX - EPHEMERAL_BASE) {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                EPHEMERAL_BASE
            } else {
                port + 1
            };
            if self.used_ports.insert(port) {
                return Some(port);
            }
        }
        None
    }

    fn open(
        &mut self,
        iface: &mut Interface,
        sockets: &mut SocketSet<'_>,
        cmd: OpenCommand,
        now: SmolInstant,
    ) {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; self.tcp_buffer_bytes]),
            tcp::SocketBuffer::new(vec![0u8; self.tcp_buffer_bytes]),
        );
        let handle = sockets.add(socket);
        let Some(local_port) = self.alloc_port() else {
            sockets.remove(handle);
            let _ = cmd.reply.send(Err(NetError::ConnectFailed));
            return;
        };

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
    fn new_listen_socket(
        sockets: &mut SocketSet<'_>,
        port: u16,
        tcp_buffer_bytes: usize,
    ) -> Option<SocketHandle> {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; tcp_buffer_bytes]),
            tcp::SocketBuffer::new(vec![0u8; tcp_buffer_bytes]),
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
            match Self::new_listen_socket(sockets, cmd.port, self.tcp_buffer_bytes) {
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
        let tcp_buffer_bytes = self.tcp_buffer_bytes;
        for (port, count) in refill {
            for _ in 0..count {
                let Some(h) = Self::new_listen_socket(sockets, port, tcp_buffer_bytes) else {
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
        // Serve from the TTL-bounded cache when fresh: a repeat connect to the same
        // host skips the DNS round-trip over the tunnel entirely.
        if let Some((ip, expiry)) = self.dns_cache.get(&(cmd.name.clone(), cmd.rtype))
            && *expiry > now
        {
            let _ = cmd.reply.send(Ok(*ip));
            return;
        }
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
        let Some(local_port) = self.alloc_port() else {
            sockets.remove(handle);
            let _ = cmd.reply.send(Err(NetError::ConnectFailed));
            return;
        };
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
            name: cmd.name,
            rtype: cmd.rtype,
            reply: cmd.reply,
            deadline: now + DNS_TIMEOUT,
            query,
            next_retx: now + DNS_RETX_INITIAL,
            retx_interval: DNS_RETX_INITIAL,
        });
    }

    /// Delivers DNS responses (first matching record), times out stalled lookups,
    /// and reaps the UDP sockets of finished resolutions.
    fn drain_resolvers(&mut self, sockets: &mut SocketSet<'_>, now: SmolInstant) {
        // (resolver index, result, optional cache entry to store on success).
        type CacheEntry = (String, dns::RecordType, IpAddr, SmolInstant);
        let mut finished: Vec<(usize, Result<IpAddr, NetError>, Option<CacheEntry>)> = Vec::new();
        for (i, r) in self.resolvers.iter().enumerate() {
            let sock = sockets.get_mut::<udp::Socket<'_>>(r.handle);
            if sock.can_recv() {
                if let Ok((data, _meta)) = sock.recv() {
                    let (res, cache) = match dns::parse_response_ttl(data, r.id, r.rtype) {
                        Ok((addrs, ttl)) => match addrs.into_iter().next() {
                            Some(ip) => {
                                // Cache only when the answer carried a TTL, clamped
                                // to a ceiling to bound staleness.
                                let entry = (ttl > 0).then(|| {
                                    let live = SmolDuration::from_secs(u64::from(ttl))
                                        .min(DNS_CACHE_MAX_TTL);
                                    (r.name.clone(), r.rtype, ip, now + live)
                                });
                                (Ok(ip), entry)
                            }
                            None => (Err(NetError::NoDnsRecord), None),
                        },
                        // "No such record" is distinct from a transport/parse
                        // failure so a dual-stack lookup falls back on it alone.
                        Err(dns::DnsError::NoAddress) => (Err(NetError::NoDnsRecord), None),
                        Err(_) => (Err(NetError::ConnectFailed), None),
                    };
                    finished.push((i, res, cache));
                }
            } else if now >= r.deadline {
                finished.push((i, Err(NetError::ConnectTimeout), None));
            }
        }
        // Remove highest indices first so the earlier ones stay valid.
        finished.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (i, res, cache) in finished {
            let r = self.resolvers.swap_remove(i);
            sockets.remove(r.handle);
            self.used_ports.remove(&r.local_port);
            if let Some((name, rtype, ip, expiry)) = cache {
                self.cache_dns(name, rtype, ip, expiry, now);
            }
            let _ = r.reply.send(res);
        }
    }

    /// Re-sends the query for any pending resolution whose retransmit timer has
    /// elapsed and doubles its backoff. Keeps the same transaction id and
    /// socket, so a delayed original response still matches.
    fn retransmit_resolvers(&mut self, sockets: &mut SocketSet<'_>, now: SmolInstant) {
        let dst = IpEndpoint::new(IpAddress::from(self.dns_server), DNS_PORT);
        for r in &mut self.resolvers {
            if now < r.next_retx {
                continue;
            }
            let sock = sockets.get_mut::<udp::Socket<'_>>(r.handle);
            let _ = sock.send_slice(&r.query, dst);
            r.retx_interval = SmolDuration::from_micros(r.retx_interval.total_micros() * 2);
            r.next_retx = now + r.retx_interval;
        }
    }

    /// Inserts a resolved name into the DNS cache, pruning to stay under the cap:
    /// drop expired entries first, then, if still full, clear (a coarse but bounded
    /// eviction; the cache is a latency optimization, not a correctness store).
    fn cache_dns(
        &mut self,
        name: String,
        rtype: dns::RecordType,
        ip: IpAddr,
        expiry: SmolInstant,
        now: SmolInstant,
    ) {
        if self.dns_cache.len() >= DNS_CACHE_CAP {
            self.dns_cache.retain(|_, (_, exp)| *exp > now);
            if self.dns_cache.len() >= DNS_CACHE_CAP {
                self.dns_cache.clear();
            }
        }
        self.dns_cache.insert((name, rtype), (ip, expiry));
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
        let Some(local_port) = self.alloc_port() else {
            sockets.remove(handle);
            let _ = cmd.reply.send(Err(NetError::ConnectFailed));
            return;
        };
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
/// The engine's device MTU tracks `sink.max_payload()` for the life of the
/// connector (not just at connect time): both tasks below refresh a shared
/// cell on every frame they handle, and the engine polls it once per loop
/// iteration ([`Engine::refresh_mtu`]). This is what heals the reduced-MTU
/// black-hole (`93-REDUCED-MTU-ADAPTATION.md`): a multihop session's transmit
/// budget can shrink mid-session (a fresh PMTU probe on the path) or recover,
/// and smoltcp otherwise bakes in the connect-time MTU forever.
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
    let live_mtu = Arc::new(AtomicUsize::new(config.mtu));

    let reader = Arc::clone(&sink);
    let reader_mtu = Arc::clone(&live_mtu);
    tokio::spawn(async move {
        while let Ok(packet) = reader.recv_packet().await {
            reader_mtu.store(reader.max_payload(), Ordering::Relaxed);
            if inbound_tx.send(packet).await.is_err() {
                break;
            }
        }
        // The tunnel read side closed (or the engine is gone): signal down.
        let _ = alive_tx.send(false);
    });
    let writer_mtu = Arc::clone(&live_mtu);
    tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            writer_mtu.store(sink.max_payload(), Ordering::Relaxed);
            // Drop-and-continue on a per-packet send error; tunnel teardown is
            // detected by the reader task closing `inbound`.
            let _ = sink.send_packet(&frame).await;
        }
    });

    (
        spawn_engine_inner(config, inbound_rx, outbound_tx, Some(live_mtu)),
        alive_rx,
    )
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
    fn random_ephemeral_start_stays_in_the_ephemeral_range() {
        // Every start must be a valid ephemeral port at or above the base, so
        // the allocator never hands out a reserved low port. Sampled across
        // many draws to catch an off-by-one in the modulus range.
        for _ in 0..10_000 {
            let p = random_ephemeral_start();
            assert!(
                p >= EPHEMERAL_BASE,
                "start {p} fell below the ephemeral base {EPHEMERAL_BASE}"
            );
        }
    }

    #[test]
    fn config_defaults_tcp_buffer_to_the_1mib_constant() {
        // Pin the default so a config built with no override keeps the
        // existing throughput characteristics (see TCP_BUFFER's doc comment).
        let gw: Ipv4Addr = "10.66.0.1".parse().unwrap();
        let config = NetstackConfig::new("10.66.0.2".parse().unwrap(), 16, gw, 1280);
        assert_eq!(config.tcp_buffer_bytes, TCP_BUFFER);
    }

    #[test]
    fn with_tcp_buffer_bytes_overrides_only_that_field() {
        let gw: Ipv4Addr = "10.66.0.1".parse().unwrap();
        let base = NetstackConfig::new("10.66.0.2".parse().unwrap(), 16, gw, 1280);
        let overridden = base.with_tcp_buffer_bytes(64 * 1024);
        assert_eq!(overridden.tcp_buffer_bytes, 64 * 1024);
        assert_eq!(overridden.local_ip, base.local_ip);
        assert_eq!(overridden.dns_server, base.dns_server);
    }

    #[tokio::test]
    async fn open_allocates_sockets_sized_to_the_configured_tcp_buffer() {
        // Exercises the real `Engine::open` path (not a stub) with a
        // non-default buffer size, proving the config knob actually reaches
        // the smoltcp socket rather than being ignored in favor of the const.
        let (outbound_tx, _outbound_rx) = mpsc::channel(8);
        let (_inbound_tx, inbound_rx) = mpsc::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let mut engine = Engine {
            device: TunnelDevice {
                rx: VecDeque::new(),
                tx: outbound_tx,
                mtu: 1280,
            },
            conns: HashMap::new(),
            resolvers: Vec::new(),
            dns_cache: HashMap::new(),
            udp_flows: Vec::new(),
            listeners: Vec::new(),
            next_conn_id: 0,
            next_port: EPHEMERAL_BASE,
            used_ports: HashSet::new(),
            local_ip: "10.0.0.2".parse().unwrap(),
            prefix: 24,
            gateway: "10.0.0.1".parse().unwrap(),
            dns_server: "10.0.0.1".parse().unwrap(),
            ipv6: None,
            tcp_buffer_bytes: 4096,
            cmd_rx,
            inbound: inbound_rx,
            wake: Arc::new(Notify::new()),
            live_mtu: None,
        };
        let config = Config::new(HardwareAddress::Ip);
        let start = SmolInstant::from_millis(0);
        let mut iface = Interface::new(config, &mut engine.device, start);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::from(engine.local_ip), engine.prefix));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(engine.gateway);
        let mut sockets = SocketSet::new(Vec::new());
        let (reply_tx, _reply_rx) = oneshot::channel();
        engine.open(
            &mut iface,
            &mut sockets,
            OpenCommand {
                addr: "1.2.3.4:80".parse().unwrap(),
                reply: reply_tx,
            },
            start,
        );

        let conn = engine.conns.values().next().expect("open tracked one conn");
        let sock = sockets.get::<tcp::Socket<'_>>(conn.handle);
        assert_eq!(sock.recv_capacity(), 4096);
        assert_eq!(sock.send_capacity(), 4096);
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

    #[test]
    fn next_device_mtu_clamps_to_the_floor_and_only_signals_real_changes() {
        // A shrink above the floor is reported verbatim.
        assert_eq!(next_device_mtu(1400, 900), Some(900));
        // No change: reported as `None` so the caller skips the interface rebuild.
        assert_eq!(next_device_mtu(900, 900), None);
        // A candidate below the floor is clamped up to it.
        assert_eq!(next_device_mtu(1400, 100), Some(MIN_NETSTACK_MTU));
        // Already at the floor, and the candidate clamps to that same floor:
        // no change reported (a prior refresh already applied it).
        assert_eq!(next_device_mtu(MIN_NETSTACK_MTU, 50), None);
        // Growth (a recovered path) is reported too, not just shrinks.
        assert_eq!(next_device_mtu(900, 1400), Some(1400));
    }

    /// Parses a raw IPv4/TCP frame's announced MSS option via smoltcp's own
    /// wire parser (rather than hand-rolled byte offsets, which would just
    /// duplicate smoltcp's layout assumptions).
    fn syn_mss(frame: &[u8]) -> u16 {
        let ip = smoltcp::wire::Ipv4Packet::new_checked(frame).expect("valid ipv4");
        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("valid tcp");
        let repr = smoltcp::wire::TcpRepr::parse(
            &tcp,
            &IpAddress::from(ip.src_addr()),
            &IpAddress::from(ip.dst_addr()),
            &smoltcp::phy::ChecksumCapabilities::default(),
        )
        .expect("valid tcp repr");
        repr.max_seg_size.expect("SYN carries an MSS option")
    }

    #[test]
    fn refresh_mtu_updates_the_mss_smoltcp_announces_in_a_new_syn() {
        // Proves the live-MTU plumbing reaches smoltcp itself, not just the
        // `TunnelDevice.mtu` field: smoltcp bakes `DeviceCapabilities` into the
        // `Interface` once at construction (see `Engine::build_interface`'s
        // doc), so if `refresh_mtu` only updated the device without rebuilding
        // the interface, a NEW connection opened after a shrink would still
        // announce the OLD, oversized MSS and smoltcp would keep emitting
        // segments too large for the shrunk path.
        let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
        let (_inbound_tx, inbound_rx) = mpsc::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let live_mtu = Arc::new(AtomicUsize::new(1400));
        let mut engine = Engine {
            device: TunnelDevice {
                rx: VecDeque::new(),
                tx: outbound_tx,
                mtu: 1400,
            },
            conns: HashMap::new(),
            resolvers: Vec::new(),
            dns_cache: HashMap::new(),
            udp_flows: Vec::new(),
            listeners: Vec::new(),
            next_conn_id: 0,
            next_port: EPHEMERAL_BASE,
            used_ports: HashSet::new(),
            local_ip: "10.0.0.2".parse().unwrap(),
            prefix: 24,
            gateway: "10.0.0.1".parse().unwrap(),
            dns_server: "10.0.0.1".parse().unwrap(),
            ipv6: None,
            tcp_buffer_bytes: 4096,
            cmd_rx,
            inbound: inbound_rx,
            wake: Arc::new(Notify::new()),
            live_mtu: Some(Arc::clone(&live_mtu)),
        };
        let start = SmolInstant::from_millis(0);
        let mut iface = engine.build_interface(start);
        let mut sockets = SocketSet::new(Vec::new());

        // First connection at the initial 1400-byte MTU: announced MSS is
        // 1400 - 20 (IPv4 header) - 20 (TCP header) = 1360.
        let (reply_tx, _reply_rx) = oneshot::channel();
        engine.open(
            &mut iface,
            &mut sockets,
            OpenCommand {
                addr: "1.2.3.4:80".parse().unwrap(),
                reply: reply_tx,
            },
            start,
        );
        while iface.poll(start, &mut engine.device, &mut sockets) != PollResult::None {}
        let first_syn = outbound_rx.try_recv().expect("first SYN sent");
        assert_eq!(syn_mss(&first_syn), 1360, "MSS at the initial MTU");

        // Shrink the live budget (a fresh PMTU probe on the underlay) and
        // refresh: the interface must be rebuilt, not just the device field.
        live_mtu.store(700, Ordering::Relaxed);
        engine.refresh_mtu(&mut iface, start);
        assert_eq!(engine.device.mtu, 700, "the device field itself is updated");

        let (reply_tx2, _reply_rx2) = oneshot::channel();
        engine.open(
            &mut iface,
            &mut sockets,
            OpenCommand {
                addr: "1.2.3.4:81".parse().unwrap(),
                reply: reply_tx2,
            },
            start,
        );
        while iface.poll(start, &mut engine.device, &mut sockets) != PollResult::None {}
        let second_syn = outbound_rx.try_recv().expect("second SYN sent");
        assert_eq!(
            syn_mss(&second_syn),
            660,
            "a NEW connection after the shrink must announce the smaller MSS"
        );
    }
}
