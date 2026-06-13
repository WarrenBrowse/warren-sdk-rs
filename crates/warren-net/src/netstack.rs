//! Userspace TCP/IP for the non-root proxy datapath.
//!
//! A single-threaded smoltcp engine runs on its own task. It owns a [`smoltcp`]
//! interface over a [`TunnelDevice`] whose frames are bare IP packets (no
//! Ethernet: `Medium::Ip`) carried in and out over channels. Application TCP
//! flows accepted by the SOCKS5 proxy become smoltcp TCP sockets; their bytes
//! are bridged to tokio through per-connection channels exposed as a
//! [`NetstackStream`] (`AsyncRead`/`AsyncWrite`).
//!
//! The same client-side stack runs whether the peer is a real Warren exit or an
//! in-process test exit: only the frame transport differs. Per CLAUDE.md, the
//! end-to-end behavior must still be validated against a real exit before this
//! is relied on in production.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::error::NetError;
use crate::proxy::Connector;
use crate::socks5::Target;

/// Per-direction TCP buffer (64 KiB), matching a typical socket window.
const TCP_BUFFER: usize = 64 * 1024;
/// First ephemeral local port handed to outbound connects.
const EPHEMERAL_BASE: u16 = 49152;

/// A smoltcp [`Device`] over IP-packet channels.
struct TunnelDevice {
    rx: VecDeque<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    mtu: usize,
}

/// Receives one queued inbound frame.
struct RxToken(Vec<u8>);
/// Emits one outbound frame to the tunnel.
struct TxToken(mpsc::UnboundedSender<Vec<u8>>);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // A closed receiver means the tunnel is gone; the engine will exit.
        let _ = self.0.send(buf);
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

/// An app->net write addressed to a specific connection.
enum WriteOp {
    Data(Vec<u8>),
    Shutdown,
}

/// Engine-side state for one connection.
struct Conn {
    handle: smoltcp::iface::SocketHandle,
    to_app: mpsc::UnboundedSender<Vec<u8>>,
    pending_out: VecDeque<u8>,
    want_close: bool,
    /// Set until the socket reaches `Established` (or fails), then taken.
    connect: Option<(
        oneshot::Sender<Result<NetstackStream, NetError>>,
        NetstackStream,
    )>,
}

/// Handle used to drive a userspace-netstack TCP connection from tokio.
pub struct NetstackStream {
    handle: smoltcp::iface::SocketHandle,
    writes: mpsc::UnboundedSender<(smoltcp::iface::SocketHandle, WriteOp)>,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    leftover: Vec<u8>,
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
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes
            .send((self.handle, WriteOp::Data(buf.to_vec())))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack engine stopped"))?;
        self.wake.notify_one();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.writes.send((self.handle, WriteOp::Shutdown));
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
            Target::Ip(addr) => addr,
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
            .map_err(|_| NetError::Unsupported("netstack engine stopped"))?;
        self.wake.notify_one();
        reply_rx
            .await
            .map_err(|_| NetError::Unsupported("netstack engine dropped the request"))?
    }
}

/// Spawns the netstack engine over raw IP-frame channels and returns a connector.
///
/// `local_ip`/`prefix` is the tunnel-assigned client address (for example
/// `10.66.0.2/16`) and `gateway` the exit-side tunnel gateway (for example
/// `10.66.0.1`), installed as the default route so traffic to public targets is
/// sent to the exit. `inbound` delivers IP packets arriving from the tunnel;
/// `outbound` receives IP packets the stack wants to send.
#[must_use]
pub fn spawn_engine(
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    mtu: usize,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound: mpsc::UnboundedSender<Vec<u8>>,
) -> TunnelConnector {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (write_tx, write_rx) = mpsc::unbounded_channel();
    let wake = Arc::new(Notify::new());

    let engine = Engine {
        device: TunnelDevice {
            rx: VecDeque::new(),
            tx: outbound,
            mtu,
        },
        conns: Vec::new(),
        next_port: EPHEMERAL_BASE,
        local_ip,
        prefix,
        gateway,
        cmd_rx,
        write_rx,
        write_tx: write_tx.clone(),
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
    conns: Vec<Conn>,
    next_port: u16,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    cmd_rx: mpsc::UnboundedReceiver<OpenCommand>,
    write_rx: mpsc::UnboundedReceiver<(smoltcp::iface::SocketHandle, WriteOp)>,
    write_tx: mpsc::UnboundedSender<(smoltcp::iface::SocketHandle, WriteOp)>,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    wake: Arc<Notify>,
}

impl Engine {
    async fn run(mut self) {
        let base = tokio::time::Instant::now();
        let now = |b: tokio::time::Instant| {
            SmolInstant::from_micros(i64::try_from(b.elapsed().as_micros()).unwrap_or(i64::MAX))
        };

        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5741_5252_454e_0001;
        let mut iface = Interface::new(config, &mut self.device, now(base));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::from(self.local_ip), self.prefix));
        });
        // Default route to the exit gateway so out-of-subnet (public) targets
        // egress through the tunnel rather than being unroutable.
        let _ = iface.routes_mut().add_default_ipv4_route(self.gateway);
        let mut sockets = SocketSet::new(Vec::new());

        loop {
            // 1. New connection requests.
            while let Ok(cmd) = self.cmd_rx.try_recv() {
                self.open(&mut iface, &mut sockets, cmd);
            }
            // 2. App -> net writes.
            while let Ok((handle, op)) = self.write_rx.try_recv() {
                if let Some(conn) = self.conns.iter_mut().find(|c| c.handle == handle) {
                    match op {
                        WriteOp::Data(bytes) => conn.pending_out.extend(bytes),
                        WriteOp::Shutdown => conn.want_close = true,
                    }
                }
            }
            // 3. Inbound frames from the tunnel into the device.
            let mut tunnel_open = true;
            loop {
                match self.inbound.try_recv() {
                    Ok(frame) => self.device.rx.push_back(frame),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        tunnel_open = false;
                        break;
                    }
                }
            }
            if !tunnel_open {
                return;
            }

            // 4. Push buffered app bytes into sockets, then poll, then drain.
            self.pump_sockets(&mut sockets);
            let _ = iface.poll(now(base), &mut self.device, &mut sockets);
            self.drain_sockets(&mut sockets);

            // 5. Sleep until the next timer or any external event.
            let delay = iface
                .poll_delay(now(base), &sockets)
                .map(|d| std::time::Duration::from_micros(d.total_micros()))
                .unwrap_or_else(|| std::time::Duration::from_secs(3600));

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

    fn open(&mut self, iface: &mut Interface, sockets: &mut SocketSet<'_>, cmd: OpenCommand) {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        let handle = sockets.add(socket);
        let local_port = self.next_port;
        self.next_port = self.next_port.checked_add(1).unwrap_or(EPHEMERAL_BASE);

        let sock = sockets.get_mut::<tcp::Socket<'_>>(handle);
        let remote = (to_smol_ip(cmd.addr.ip()), cmd.addr.port());
        if sock.connect(iface.context(), remote, local_port).is_err() {
            let _ = cmd
                .reply
                .send(Err(NetError::Unsupported("connect rejected locally")));
            return;
        }

        let (to_app_tx, to_app_rx) = mpsc::unbounded_channel();
        let stream = NetstackStream {
            handle,
            writes: self.write_tx.clone(),
            incoming: to_app_rx,
            leftover: Vec::new(),
            read_pos: 0,
            wake: Arc::clone(&self.wake),
        };
        self.conns.push(Conn {
            handle,
            to_app: to_app_tx,
            pending_out: VecDeque::new(),
            want_close: false,
            connect: Some((cmd.reply, stream)),
        });
    }

    /// Moves buffered app bytes into socket send buffers and applies closes.
    fn pump_sockets(&mut self, sockets: &mut SocketSet<'_>) {
        for conn in &mut self.conns {
            let sock = sockets.get_mut::<tcp::Socket<'_>>(conn.handle);
            while sock.can_send() && !conn.pending_out.is_empty() {
                let (head, _) = conn.pending_out.as_slices();
                if head.is_empty() {
                    break;
                }
                match sock.send_slice(head) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.pending_out.drain(..n);
                    }
                    Err(_) => break,
                }
            }
            if conn.want_close && conn.pending_out.is_empty() && sock.can_send() {
                sock.close();
            }
        }
    }

    /// Delivers established streams, drains socket recv buffers to apps, and
    /// reaps closed connections.
    fn drain_sockets(&mut self, sockets: &mut SocketSet<'_>) {
        for conn in &mut self.conns {
            let sock = sockets.get_mut::<tcp::Socket<'_>>(conn.handle);

            if let Some((reply, stream)) = conn.connect.take() {
                match sock.state() {
                    tcp::State::Established => {
                        let _ = reply.send(Ok(stream));
                    }
                    tcp::State::Closed => {
                        let _ = reply.send(Err(NetError::Unsupported("connection refused")));
                    }
                    // Still handshaking: put it back.
                    _ => conn.connect = Some((reply, stream)),
                }
            }

            let mut buf = [0u8; 4096];
            while sock.can_recv() {
                match sock.recv_slice(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = conn.to_app.send(buf[..n].to_vec());
                    }
                    Err(_) => break,
                }
            }
        }

        // Reap connections whose socket is fully closed and which are not still
        // mid-connect: dropping `to_app` signals EOF to the reader.
        self.conns.retain(|conn| {
            let sock = sockets.get::<tcp::Socket<'_>>(conn.handle);
            let done = !sock.is_active() && sock.state() == tcp::State::Closed;
            if done && conn.connect.is_none() {
                sockets.remove(conn.handle);
                false
            } else {
                true
            }
        });
    }
}

/// Bridges a [`PacketSink`] to the netstack engine: a reader task feeds inbound
/// frames and a writer task drains outbound frames.
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
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let reader = Arc::clone(&sink);
    tokio::spawn(async move {
        while let Ok(packet) = reader.recv_packet().await {
            if inbound_tx.send(packet.to_vec()).is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            if sink.send_packet(&frame).await.is_err() {
                break;
            }
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
