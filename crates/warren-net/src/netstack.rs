//! Userspace TCP/IP for the non-root proxy datapath.
//!
//! A single-threaded smoltcp engine runs on its own task. It owns a [`smoltcp`]
//! interface over a [`TunnelDevice`] whose frames are bare IP packets (no
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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::PollSender;

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

/// Open a TCP connection to `addr`, replying with the bridged stream or an error.
struct OpenCommand {
    addr: SocketAddr,
    reply: oneshot::Sender<Result<NetstackStream, NetError>>,
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

/// A [`Connector`] backed by the userspace netstack engine.
#[derive(Clone)]
pub struct TunnelConnector {
    commands: mpsc::UnboundedSender<OpenCommand>,
    wake: Arc<Notify>,
}

impl Connector for TunnelConnector {
    type Stream = NetstackStream;

    async fn connect(&self, target: Target) -> Result<Self::Stream, NetError> {
        let addr = match target {
            Target::Ip(addr @ SocketAddr::V4(_)) => addr,
            // IPv6 has no default route wired yet; reject rather than silently
            // black-hole a v6 target.
            Target::Ip(SocketAddr::V6(_)) => {
                return Err(NetError::Unsupported("IPv6 targets not yet routed"));
            }
            // Names must be resolved at the exit (DNS-over-tunnel); not yet wired.
            Target::Domain(_, _) => {
                return Err(NetError::Unsupported(
                    "domain targets require DNS-over-tunnel (not implemented)",
                ));
            }
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(OpenCommand {
                addr,
                reply: reply_tx,
            })
            .map_err(|_| NetError::EngineStopped)?;
        self.wake.notify_one();
        reply_rx.await.map_err(|_| NetError::EngineStopped)?
    }
}

/// Spawns the netstack engine over IP-frame channels and returns a connector.
///
/// `local_ip`/`prefix` is the tunnel-assigned client address (for example
/// `10.66.0.2/16`) and `gateway` the exit-side tunnel gateway (for example
/// `10.66.0.1`), installed as the default route so traffic to public targets is
/// sent to the exit. `mtu` is the inner IP MTU and MUST fit one tunnel frame
/// (derive it from `PacketSink::max_payload`, never the raw policy MTU).
/// `inbound` delivers IP packets arriving from the tunnel; `outbound` receives
/// IP packets the stack wants to send.
#[must_use]
pub fn spawn_engine(
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    mtu: usize,
    inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
) -> TunnelConnector {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let wake = Arc::new(Notify::new());

    let engine = Engine {
        device: TunnelDevice {
            rx: VecDeque::new(),
            tx: outbound,
            mtu,
        },
        conns: HashMap::new(),
        next_conn_id: 0,
        next_port: EPHEMERAL_BASE,
        used_ports: HashSet::new(),
        local_ip,
        prefix,
        gateway,
        cmd_rx,
        inbound,
        wake: Arc::clone(&wake),
    };
    tokio::spawn(engine.run());

    TunnelConnector {
        commands: cmd_tx,
        wake,
    }
}

struct Engine {
    device: TunnelDevice,
    conns: HashMap<u64, Conn>,
    next_conn_id: u64,
    next_port: u16,
    used_ports: HashSet<u16>,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    cmd_rx: mpsc::UnboundedReceiver<OpenCommand>,
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
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::from(self.local_ip), self.prefix));
        });
        // Default route to the exit gateway so out-of-subnet (public) targets
        // egress through the tunnel rather than being unroutable.
        let _ = iface.routes_mut().add_default_ipv4_route(self.gateway);
        let mut sockets = SocketSet::new(Vec::new());

        loop {
            while let Ok(cmd) = self.cmd_rx.try_recv() {
                self.open(&mut iface, &mut sockets, cmd, now(base));
            }
            self.ingest_writes();

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

            let delay = iface
                .poll_delay(now(base), &sockets)
                .map_or(std::time::Duration::from_secs(30), |d| {
                    std::time::Duration::from_micros(d.total_micros())
                });

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
/// [`PacketSink`]: crate::PacketSink
#[must_use]
pub fn spawn_over_sink<S>(
    sink: Arc<S>,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    mtu: usize,
) -> TunnelConnector
where
    S: crate::PacketSink + 'static,
{
    let (inbound_tx, inbound_rx) = mpsc::channel(FRAME_CHANNEL_DEPTH);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(FRAME_CHANNEL_DEPTH);

    let reader = Arc::clone(&sink);
    tokio::spawn(async move {
        while let Ok(packet) = reader.recv_packet().await {
            if inbound_tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            // Drop-and-continue on a per-packet send error; tunnel teardown is
            // detected by the reader task closing `inbound`.
            let _ = sink.send_packet(&frame).await;
        }
    });

    spawn_engine(local_ip, prefix, gateway, mtu, inbound_rx, outbound_tx)
}

/// Converts a std IP address to smoltcp's wire type.
fn to_smol_ip(ip: std::net::IpAddr) -> IpAddress {
    match ip {
        std::net::IpAddr::V4(a) => IpAddress::from(a),
        std::net::IpAddr::V6(a) => IpAddress::from(a),
    }
}
