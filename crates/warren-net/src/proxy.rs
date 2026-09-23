//! Local SOCKS5 proxy server for the non-root datapath.
//!
//! The server terminates application TCP flows locally and hands each one to a
//! [`Connector`], the seam to the outside world. In production the connector
//! drives a userspace netstack over the QUIC tunnel (so the exit, never the
//! local resolver, sees the destination); tests use a direct connector. Keeping
//! the connector abstract is what lets the whole accept/handshake/relay loop be
//! tested in-process without a tunnel.
//!
//! Both servers authenticate every client against the session's
//! [`ProxyCredentials`] before the connector is touched; see
//! [`crate::proxy_auth`] for why a loopback listener needs it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zeroize::Zeroizing;

use crate::error::NetError;
use crate::http_forward;
use crate::proxy_auth::{
    HTTP_PROOF_HEADER, HTTP_PROOF_METHOD, ListenerKind, PROOF_NONCE_LEN, ProxyCredentials,
};
use crate::socks5::{
    Command, METHOD_NONE, METHOD_USERPASS, METHOD_WARREN_PROOF, Reply, Socks5Error, Target,
    USERPASS_VERSION, build_method_reply, build_reply, encode_udp_datagram, parse_greeting,
    parse_request, parse_udp_datagram,
};

/// How long a client has to authenticate and say what it wants. A client that
/// connects and stays silent would otherwise hold a descriptor as long as it
/// likes, and enough of them starve the process of descriptors.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Pause before accepting again after a transient accept failure.
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Accepts the next connection. Running out of descriptors, or a connection
/// aborted before it was accepted, is a condition of this moment and not of the
/// listener: it is waited out, because returning it ends the datapath's epoch
/// and redials a healthy tunnel.
async fn accept(listener: &TcpListener) -> Result<TcpStream, NetError> {
    loop {
        match listener.accept().await {
            Ok((client, _peer)) => return Ok(client),
            Err(e) if is_transient_accept_error(&e) => tokio::time::sleep(ACCEPT_BACKOFF).await,
            Err(e) => return Err(NetError::Io(e)),
        }
    }
}

/// Whether an accept failure passes on its own: an aborted or reset pending
/// connection, an interrupted call, or descriptor exhaustion (EMFILE and ENFILE
/// on Unix, WSAEMFILE on Windows).
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    let exhausted = match e.raw_os_error() {
        Some(code) if cfg!(windows) => code == 10024,
        Some(code) => code == 24 || code == 23,
        None => false,
    };
    exhausted
        || matches!(
            e.kind(),
            ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
        )
}

/// Runs a client's handshake under [`HANDSHAKE_TIMEOUT`]; running out of time
/// refuses the client like a wrong password.
async fn within_handshake<T>(
    handshake: impl std::future::Future<Output = Result<T, NetError>>,
) -> Result<T, NetError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| NetError::ProxyAuth)?
}

/// The SOCKS5 greeting, authentication and request. `None` when the client
/// only asked for a proof, which it has been given.
async fn socks_handshake(
    client: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<Option<(Command, Target)>, NetError> {
    if negotiate_method(client, credentials).await? == Negotiated::Proved {
        return Ok(None);
    }
    read_request(client).await.map(Some)
}

/// The unspecified bound address echoed in a successful SOCKS5 reply. A CONNECT
/// reply does not need a meaningful bound address.
const REPLY_BOUND: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Opens a byte stream to a SOCKS5 [`Target`].
///
/// This is the boundary between the proxy front end and the network. The tunnel
/// connector (userspace netstack over the QUIC datagram plane) implements this;
/// [`DirectConnector`] implements it with the local OS stack for tests and a
/// plain non-tunnel mode.
pub trait Connector: Send + Sync + 'static {
    /// The bidirectional stream to the target.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Connects to `target`, returning the stream or a [`NetError`].
    ///
    /// # Errors
    ///
    /// A [`NetError`] when the connection cannot be established (refused, timed
    /// out, name resolution failed, or the tunnel/engine is gone).
    fn connect(
        &self,
        target: Target,
    ) -> impl std::future::Future<Output = Result<Self::Stream, NetError>> + Send;
}

/// A UDP datagram flow to the outside world, backing SOCKS5 UDP associate. The
/// tunnel netstack implements it so datagrams egress at the exit.
pub trait UdpFlow: Send + 'static {
    /// Sends `data` to `dst` through the flow (lossy, like UDP).
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] if the netstack engine has gone; transient
    /// per-datagram drops are silent (lossy by design), not errors.
    fn send_to(
        &self,
        data: Bytes,
        dst: SocketAddr,
    ) -> impl std::future::Future<Output = Result<(), NetError>> + Send;

    /// Receives the next datagram and its source, or `None` when the flow ends.
    fn recv_from(
        &mut self,
    ) -> impl std::future::Future<Output = Option<(Bytes, SocketAddr)>> + Send;
}

/// A [`Connector`] that can also open UDP flows and resolve names over the same
/// path, so a UDP target given as a name is resolved at the exit (no DNS leak).
pub trait UdpConnector: Connector {
    /// The UDP flow type opened by [`open_udp`](Self::open_udp).
    type Flow: UdpFlow;

    /// Opens a UDP flow (an ephemeral egress port) for a UDP association.
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] if the netstack engine has stopped.
    fn open_udp(&self) -> impl std::future::Future<Output = Result<Self::Flow, NetError>> + Send;

    /// Resolves `host` to an address through the same path as the data plane.
    ///
    /// # Errors
    ///
    /// A [`NetError`] when resolution fails (no record, timeout, or the engine is
    /// gone).
    fn resolve_host(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Result<IpAddr, NetError>> + Send;

    /// Whether IPv6 targets are routable (the engine has a v6 assignment). UDP
    /// associate refuses v6 datagrams when this is false, rather than sending
    /// them into a v6 black hole.
    fn supports_ipv6(&self) -> bool;
}

/// A [`Connector`] that dials the target with the local OS TCP stack.
///
/// Resolves and connects locally, so it does NOT use the tunnel and leaks DNS to
/// the host resolver: it exists for tests and an explicit non-tunnel mode, not
/// for the privacy datapath.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectConnector;

impl Connector for DirectConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: Target) -> Result<Self::Stream, NetError> {
        let stream = match target {
            Target::Ip(addr) => TcpStream::connect(addr).await,
            Target::Domain(host, port) => TcpStream::connect((host.as_str(), port)).await,
        };
        stream.map_err(NetError::Io)
    }
}

/// A SOCKS5 proxy server over a [`Connector`], admitting only clients that
/// authenticate with the session's credentials (RFC 1929).
pub struct Socks5Proxy<C> {
    connector: Arc<C>,
    credentials: Arc<ProxyCredentials>,
}

impl<C: Connector> Socks5Proxy<C> {
    /// Builds a proxy that opens upstream flows through `connector` for clients
    /// presenting `credentials`.
    pub fn new(connector: C, credentials: ProxyCredentials) -> Self {
        Self {
            connector: Arc::new(connector),
            credentials: Arc::new(credentials),
        }
    }

    /// Accepts connections on `listener` until it errors, handling each on its
    /// own task. Per-connection failures are isolated and never surface raw
    /// addresses to a log (no-log discipline).
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), NetError> {
        loop {
            let client = accept(&listener).await?;
            let connector = Arc::clone(&self.connector);
            let credentials = Arc::clone(&self.credentials);
            tokio::spawn(async move {
                let _ = handle_connection(client, connector.as_ref(), &credentials).await;
            });
        }
    }
}

/// Opens the upstream flow for a `CONNECT` target and relays bytes both ways,
/// replying success, or the RFC 1928 code naming the local condition that
/// refused it ([`connect_failure_reply`]). Shared by the plain and UDP-capable
/// SOCKS5 handlers so the CONNECT leg lives in one place.
async fn relay_connect<C: Connector>(
    client: &mut TcpStream,
    connector: &C,
    target: Target,
) -> Result<(), NetError> {
    let mut upstream = match connector.connect(target).await {
        Ok(s) => s,
        Err(e) => {
            write_reply(client, connect_failure_reply(&e)).await?;
            return Err(e);
        }
    };
    write_reply(client, Reply::Succeeded).await?;
    tokio::io::copy_bidirectional(client, &mut upstream)
        .await
        .map_err(NetError::Io)?;
    Ok(())
}

/// Drives one client through the SOCKS5 handshake, then relays bytes both ways.
async fn handle_connection<C: Connector>(
    mut client: TcpStream,
    connector: &C,
    credentials: &ProxyCredentials,
) -> Result<(), NetError> {
    let Some((command, target)) =
        within_handshake(socks_handshake(&mut client, credentials)).await?
    else {
        return Ok(());
    };

    if !command.is_supported() {
        write_reply(&mut client, Reply::CommandNotSupported).await?;
        return Ok(());
    }
    relay_connect(&mut client, connector, target).await
}

impl<C: UdpConnector> Socks5Proxy<C> {
    /// Like [`serve`](Self::serve) but also handles `UDP ASSOCIATE`: it binds a
    /// local UDP relay, opens a UDP flow through the connector, and relays
    /// datagrams both ways for the lifetime of the control connection. `CONNECT`
    /// is handled exactly as in [`serve`](Self::serve).
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve_with_udp(&self, listener: TcpListener) -> Result<(), NetError> {
        loop {
            let client = accept(&listener).await?;
            let connector = Arc::clone(&self.connector);
            let credentials = Arc::clone(&self.credentials);
            tokio::spawn(async move {
                let _ = handle_with_udp(client, connector.as_ref(), &credentials).await;
            });
        }
    }

    /// Like [`serve_with_udp`](Self::serve_with_udp) but accepts on a *borrowed*
    /// listener until `run` goes `false`, then returns. The borrowed listener
    /// lets a supervisor reuse one stable local address across tunnel rebuilds:
    /// each reconnect builds a fresh connector and a new proxy over the same
    /// bound port. `run` starting `false` (or its sender dropped) returns at once.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve_with_udp_until(
        &self,
        listener: &TcpListener,
        mut run: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), NetError> {
        loop {
            if !*run.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                // Prefer the stop signal so a torn-down tunnel halts accepting promptly.
                biased;
                changed = run.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                }
                accepted = accept(listener) => {
                    let client = accepted?;
                    let connector = Arc::clone(&self.connector);
                    let credentials = Arc::clone(&self.credentials);
                    tokio::spawn(async move {
                        let _ = handle_with_udp(client, connector.as_ref(), &credentials).await;
                    });
                }
            }
        }
    }
}

/// SOCKS5 handler that supports `CONNECT` and `UDP ASSOCIATE`.
async fn handle_with_udp<C: UdpConnector>(
    mut client: TcpStream,
    connector: &C,
    credentials: &ProxyCredentials,
) -> Result<(), NetError> {
    let Some((command, target)) =
        within_handshake(socks_handshake(&mut client, credentials)).await?
    else {
        return Ok(());
    };
    match command {
        Command::Connect => relay_connect(&mut client, connector, target).await,
        Command::UdpAssociate => udp_associate(client, connector, &target).await,
        Command::Bind => {
            write_reply(&mut client, Reply::CommandNotSupported).await?;
            Ok(())
        }
    }
}

/// Largest UDP datagram (header + payload) the relay buffers.
const MAX_UDP_DATAGRAM: usize = 64 * 1024;

/// Runs one UDP association: bind a loopback relay socket, reply with its
/// address, then relay datagrams between the client and the tunnel flow until
/// the TCP control connection closes (which ends the association, per RFC 1928).
async fn udp_associate<C: UdpConnector>(
    mut client: TcpStream,
    connector: &C,
    declared: &Target,
) -> Result<(), NetError> {
    // The relay port is visible to every local process, and only the TCP
    // control connection is authenticated. A client that declared where it
    // will send from (RFC 1928 section 6) is held to it; one that declared
    // nothing is bound to its first well-formed datagram.
    let declared = match declared {
        Target::Ip(addr) if addr.port() != 0 => Some(*addr),
        _ => None,
    };
    // The client sends its datagrams to this loopback relay socket; the BND
    // address in the reply tells it where.
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(NetError::Io)?;
    let relay_addr = relay.local_addr().map_err(NetError::Io)?;
    client
        .write_all(&build_reply(Reply::Succeeded, relay_addr))
        .await
        .map_err(NetError::Io)?;

    let mut flow = connector.open_udp().await?;

    // A single task owns the flow (recv needs `&mut`, send needs `&`), so no
    // shared state: `client_src` is the address of the most recent client
    // datagram, where replies are sent back.
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    let mut ctrl = [0u8; 256];
    let mut client_src: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            // Client -> tunnel: strip the SOCKS5 UDP header, resolve a name over
            // the tunnel if needed, forward the payload.
            r = relay.recv_from(&mut buf) => {
                // The relay is an unconnected loopback socket, so a recv error is
                // fatal (fd gone), not transient: ending the association is right.
                let (n, src) = r.map_err(NetError::Io)?;
                if declared.is_some_and(|d| !is_declared_source(d, src)) {
                    continue;
                }
                let Ok((target, payload)) = parse_udp_datagram(&buf[..n]) else {
                    continue;
                };
                // Bind the association to the first client source and drop
                // datagrams from any other local source: otherwise a co-resident
                // process could inject traffic and, by setting `client_src`,
                // hijack the reply stream.
                match client_src {
                    None => client_src = Some(src),
                    Some(known) if known != src => continue,
                    Some(_) => {}
                }
                let dst = match target {
                    Target::Ip(addr @ SocketAddr::V4(_)) => Some(addr),
                    // Route v6 only when the engine has a v6 assignment;
                    // otherwise drop rather than black-hole it.
                    Target::Ip(addr @ SocketAddr::V6(_)) => {
                        connector.supports_ipv6().then_some(addr)
                    }
                    Target::Domain(host, port) => connector
                        .resolve_host(&host)
                        .await
                        .ok()
                        .map(|ip| SocketAddr::new(ip, port)),
                };
                if let Some(dst) = dst {
                    let _ = flow.send_to(Bytes::copy_from_slice(payload), dst).await;
                }
            }
            // Tunnel -> client: re-wrap with the SOCKS5 UDP header and deliver to
            // the last-seen client source.
            res = flow.recv_from() => {
                match res {
                    Some((data, src)) => {
                        if let Some(dst) = client_src {
                            let _ = relay.send_to(&encode_udp_datagram(src, &data), dst).await;
                        }
                    }
                    None => return Ok(()), // flow/engine ended
                }
            }
            // The TCP control connection closing tears down the association.
            r = client.read(&mut ctrl) => {
                match r {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => {} // clients normally send nothing here; ignore
                }
            }
        }
    }
}

/// How a SOCKS5 method negotiation ended without an error.
#[derive(Debug, PartialEq, Eq)]
enum Negotiated {
    /// The client authenticated: its request may be served.
    Authenticated,
    /// The client asked for a proof of possession and got it; the connection
    /// carries nothing else.
    Proved,
}

/// Whether `src` is the address a client declared for its UDP association: the
/// same port, and the same IP unless the client left it unspecified.
fn is_declared_source(declared: SocketAddr, src: SocketAddr) -> bool {
    declared.port() == src.port() && (declared.ip().is_unspecified() || declared.ip() == src.ip())
}

/// Reads the greeting, then either authenticates the client (RFC 1929) or
/// answers a proof request. A client offering neither is told no method is
/// acceptable; a client with the wrong credentials gets a failure status. Both
/// refusals are fixed bytes that say nothing about what was wrong.
async fn negotiate_method(
    client: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<Negotiated, NetError> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.map_err(NetError::Io)?;
    let mut greeting = head.to_vec();
    greeting.resize(2 + head[1] as usize, 0);
    client
        .read_exact(&mut greeting[2..])
        .await
        .map_err(NetError::Io)?;

    let methods = parse_greeting(&greeting)?;
    if methods.contains(&METHOD_USERPASS) {
        write_all(client, &build_method_reply(METHOD_USERPASS)).await?;
        let accepted = read_userpass(client, credentials).await?;
        let status = if accepted { 0x00 } else { 0x01 };
        write_all(client, &[USERPASS_VERSION, status]).await?;
        return if accepted {
            Ok(Negotiated::Authenticated)
        } else {
            Err(NetError::ProxyAuth)
        };
    }
    if methods.contains(&METHOD_WARREN_PROOF) {
        write_all(client, &build_method_reply(METHOD_WARREN_PROOF)).await?;
        let mut nonce = [0u8; PROOF_NONCE_LEN];
        client.read_exact(&mut nonce).await.map_err(NetError::Io)?;
        write_all(client, &credentials.proof(ListenerKind::Socks5, &nonce)).await?;
        return Ok(Negotiated::Proved);
    }
    write_all(client, &build_method_reply(METHOD_NONE)).await?;
    Err(NetError::ProxyAuth)
}

/// Reads one RFC 1929 sub-negotiation (`VER ULEN UNAME PLEN PASSWD`) and says
/// whether it carries `credentials`. A wrong version byte is a mismatch rather
/// than a protocol error, so it earns the same refusal as a wrong password.
async fn read_userpass(
    client: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<bool, NetError> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.map_err(NetError::Io)?;
    let mut username = vec![0u8; usize::from(head[1])];
    client
        .read_exact(&mut username)
        .await
        .map_err(NetError::Io)?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).await.map_err(NetError::Io)?;
    let mut password = Zeroizing::new(vec![0u8; usize::from(plen[0])]);
    client
        .read_exact(&mut password)
        .await
        .map_err(NetError::Io)?;
    let matched = credentials.matches(&username, &password);
    Ok(head[0] == USERPASS_VERSION && matched)
}

async fn write_all(client: &mut TcpStream, bytes: &[u8]) -> Result<(), NetError> {
    client.write_all(bytes).await.map_err(NetError::Io)
}

/// Reads exactly one SOCKS5 request, reconstructing the wire buffer for the
/// codec so the address parsing stays in one place ([`parse_request`]).
async fn read_request(client: &mut TcpStream) -> Result<(Command, Target), NetError> {
    let mut head = [0u8; 4]; // VER CMD RSV ATYP
    client.read_exact(&mut head).await.map_err(NetError::Io)?;
    let mut buf = head.to_vec();
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 4 + 2];
            client.read_exact(&mut rest).await.map_err(NetError::Io)?;
            buf.extend_from_slice(&rest);
        }
        0x04 => {
            let mut rest = [0u8; 16 + 2];
            client.read_exact(&mut rest).await.map_err(NetError::Io)?;
            buf.extend_from_slice(&rest);
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await.map_err(NetError::Io)?;
            buf.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            client.read_exact(&mut rest).await.map_err(NetError::Io)?;
            buf.extend_from_slice(&rest);
        }
        other => return Err(NetError::Socks5(Socks5Error::BadAtyp(other))),
    }
    Ok(parse_request(&buf)?)
}

async fn write_reply(client: &mut TcpStream, reply: Reply) -> Result<(), NetError> {
    client
        .write_all(&build_reply(reply, REPLY_BOUND))
        .await
        .map_err(NetError::Io)
}

/// Largest request head (request line plus headers) accepted. A plain-HTTP
/// request carries the page's cookies, so this is sized for a browser's head
/// rather than for a bare CONNECT.
const MAX_HTTP_HEAD: usize = 32 * 1024;

/// Bytes read per call while scanning for the end of a request head.
const HEAD_CHUNK: usize = 256;

/// An HTTP proxy server over a [`Connector`].
///
/// Serves `CONNECT host:port`, the tunneling verb a browser or HTTP client uses
/// for HTTPS, and plain `http://` requests in absolute form, one request per
/// connection, with `Proxy-Authorization` and the other hop-by-hop fields kept
/// off the wire to the origin. Any other request is refused. Like
/// [`Socks5Proxy`] it relays through the connector, so the same tunnel datapath
/// backs it, and it admits only requests carrying the session's credentials in
/// `Proxy-Authorization: Basic`.
pub struct HttpConnectProxy<C> {
    connector: Arc<C>,
    credentials: Arc<ProxyCredentials>,
}

impl<C: Connector> HttpConnectProxy<C> {
    /// Builds a CONNECT proxy that opens upstream flows through `connector` for
    /// requests presenting `credentials`.
    pub fn new(connector: C, credentials: ProxyCredentials) -> Self {
        Self {
            connector: Arc::new(connector),
            credentials: Arc::new(credentials),
        }
    }

    /// Accepts connections on `listener` until it errors, one task each.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), NetError> {
        loop {
            let client = accept(&listener).await?;
            let connector = Arc::clone(&self.connector);
            let credentials = Arc::clone(&self.credentials);
            tokio::spawn(async move {
                let _ = handle_connect(client, connector.as_ref(), &credentials).await;
            });
        }
    }

    /// Like [`serve`](Self::serve) but accepts on a *borrowed* listener until
    /// `run` goes `false`, so a supervisor can reuse one bound port across tunnel
    /// rebuilds. `run` starting `false` (or its sender dropped) returns at once.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve_until(
        &self,
        listener: &TcpListener,
        mut run: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), NetError> {
        loop {
            if !*run.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                biased;
                changed = run.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                }
                accepted = accept(listener) => {
                    let client = accepted?;
                    let connector = Arc::clone(&self.connector);
                    let credentials = Arc::clone(&self.credentials);
                    tokio::spawn(async move {
                        let _ = handle_connect(client, connector.as_ref(), &credentials).await;
                    });
                }
            }
        }
    }
}

/// Header naming which local condition refused a CONNECT, so a reader does not
/// have to parse prose to branch on it.
const TUNNEL_CAUSE_HEADER: &str = "Warren-Tunnel";

/// The SOCKS5 reply code for a CONNECT this proxy could not carry.
///
/// A reply code is a CLAIM ABOUT THE PATH, and the client acts on it: codes 5
/// and 4 arrive as ECONNREFUSED and EHOSTUNREACH, which HTTP clients treat as
/// terminal and stop retrying on. So only a condition this proxy can actually
/// source earns its own code. `EngineStopped` qualifies: there is no tunnel, and
/// "network unreachable" is precisely that.
///
/// A refused connect and a connect timeout do NOT qualify, whatever their
/// `NetError` is called. `NetError::ConnectionRefused` is raised when the
/// smoltcp socket reaches `Closed` while a connect is pending (`netstack.rs`),
/// which covers SYN exhaustion on a lossy path as much as a peer RST, and
/// `ConnectTimeout` is this proxy's own deadline. Reported as 5 and 4 they told
/// a member on a congested uplink that a firewall was blocking them, and stopped
/// their client from retrying something that would have worked. They stay
/// `GeneralFailure`; the condition still travels in
/// [`connect_failure_cause`] and the log, where it cannot change retry
/// semantics.
fn connect_failure_reply(err: &NetError) -> Reply {
    match err {
        NetError::EngineStopped => Reply::NetworkUnreachable,
        _ => Reply::GeneralFailure,
    }
}

/// Short, fixed tag for a CONNECT that never left this machine.
///
/// The set is deliberately tiny and every arm is a literal: this value reaches a
/// member's terminal and a log, so it may never carry a host, an address, a port
/// or any error text from elsewhere.
fn connect_failure_cause(err: &NetError) -> &'static str {
    match err {
        NetError::EngineStopped => "tunnel-gone",
        NetError::ConnectionRefused => "exit-refused",
        NetError::ConnectTimeout => "connect-timeout",
        _ => "connect-failed",
    }
}

/// The CONNECT response for an upstream this proxy could not reach.
///
/// A bare `502` with no body is what an API client renders as "this is a
/// server-side issue, usually temporary, check the status page", so a member
/// whose own tunnel had just been torn down was sent to diagnose an outage at
/// the other end of the world
/// (`incidents/2026-09-12-bufferbloat-fixed-probe-budget-reconnect-storm.md`
/// section 9.1). The status stays `502`, because a client's retry policy is
/// keyed on it and this failure genuinely is a gateway that could not reach
/// upstream; everything added is the answer to "whose gateway".
pub(crate) fn connect_failure_response(err: &NetError) -> Vec<u8> {
    let cause = connect_failure_cause(err);
    let body = format!(
        "warren: the local proxy has no working tunnel to reach the target ({cause}).\n\
         This is a condition of the VPN on this machine, not an outage at the target service.\n"
    );
    format!(
        "HTTP/1.1 502 Warren Tunnel Unavailable\r\n\
         {TUNNEL_CAUSE_HEADER}: {cause}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
    .into_bytes()
}

/// The answer to a request without the session's credentials. Identical for a
/// missing and a wrong `Proxy-Authorization`, and the realm names nothing.
const PROXY_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\
\r\n";

/// The answer to a proof request for `nonce_hex`, or `None` when the argument
/// is not a nonce (the request is then refused like any other).
fn proof_response(credentials: &ProxyCredentials, nonce_hex: &str) -> Option<Vec<u8>> {
    let nonce: [u8; PROOF_NONCE_LEN] = hex::decode(nonce_hex).ok()?.try_into().ok()?;
    let proof = hex::encode(credentials.proof(ListenerKind::Http, &nonce));
    Some(
        format!(
            "HTTP/1.1 200 OK\r\n{HTTP_PROOF_HEADER}: {proof}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
}

async fn handle_connect<C: Connector>(
    mut client: TcpStream,
    connector: &C,
    credentials: &ProxyCredentials,
) -> Result<(), NetError> {
    let Some((head, early_data)) = within_handshake(read_request_head(&mut client)).await? else {
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await;
        return Ok(());
    };
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("");
    let argument = request_line.next().unwrap_or("");

    if method == HTTP_PROOF_METHOD
        && let Some(response) = proof_response(credentials, argument)
    {
        let _ = client.write_all(&response).await;
        return Ok(());
    }
    let authorized = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
        .is_some_and(|(_, value)| credentials.matches_basic(value));
    if !authorized {
        let _ = client.write_all(PROXY_AUTH_REQUIRED).await;
        return Err(NetError::ProxyAuth);
    }
    if method != "CONNECT" && http_forward::is_absolute_http(argument) {
        return match http_forward::rewrite_request(&head) {
            Ok(request) => http_forward::forward(&mut client, early_data, connector, request).await,
            Err(_) => {
                let _ = client.write_all(http_forward::BAD_REQUEST).await;
                Ok(())
            }
        };
    }
    let target = match (method, parse_authority(argument)) {
        ("CONNECT", Some(target)) => target,
        _ => {
            let _ = client
                .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let mut upstream = match connector.connect(target).await {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(&connect_failure_response(&e)).await;
            return Err(e);
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(NetError::Io)?;
    // A pipelining client may have sent tunnel bytes right after the head; they
    // were read while scanning for the terminator, so forward them before the
    // bidirectional copy takes over.
    if !early_data.is_empty() {
        upstream
            .write_all(&early_data)
            .await
            .map_err(NetError::Io)?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(NetError::Io)?;
    Ok(())
}

/// Reads a request head and returns it (without its terminating blank line)
/// plus any tunnel bytes already received after it, or `None` when the client
/// closed first, sent more than [`MAX_HTTP_HEAD`] bytes of head, or sent a head
/// that is not UTF-8.
///
/// Reads in chunks rather than one byte per syscall; any bytes past the head
/// terminator are returned so the caller can replay them to the upstream.
async fn read_request_head(
    client: &mut TcpStream,
) -> Result<Option<(Zeroizing<String>, Vec<u8>)>, NetError> {
    // The head carries the client's `Proxy-Authorization`. Sized so it never
    // reallocates, which would leave a copy of it in freed memory.
    let mut head = Zeroizing::new(Vec::with_capacity(MAX_HTTP_HEAD + HEAD_CHUNK));
    let mut chunk = Zeroizing::new([0u8; HEAD_CHUNK]);
    let head_len = loop {
        let n = client.read(&mut *chunk).await.map_err(NetError::Io)?;
        if n == 0 {
            return Ok(None); // connection closed before a full head
        }
        head.extend_from_slice(&chunk[..n]);
        if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if head.len() > MAX_HTTP_HEAD {
            return Ok(None);
        }
    };
    let early_data = head.split_off(head_len);
    head.truncate(head_len - 4);
    match String::from_utf8(std::mem::take(&mut *head)) {
        Ok(text) => Ok(Some((Zeroizing::new(text), early_data))),
        Err(not_utf8) => {
            drop(Zeroizing::new(not_utf8.into_bytes()));
            Ok(None)
        }
    }
}

/// Parses an HTTP `CONNECT` authority into a [`Target`], keeping domain names
/// for remote resolution. IPv6 literals use the `[addr]:port` form; a bare
/// (unbracketed) IPv6 literal or a zoned address is malformed in an authority
/// and is rejected rather than coerced into a bogus domain name.
pub(crate) fn parse_authority(authority: &str) -> Option<Target> {
    // Bracketed IPv6 literal: `[addr]:port`. The address must be a real v6
    // literal (a scope/zone id is not meaningful to a remote exit), so parse it
    // strictly; anything else is rejected.
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let ip: std::net::Ipv6Addr = host.parse().ok()?;
        let port: u16 = port.parse().ok()?;
        return Some(Target::Ip(std::net::SocketAddr::from((ip, port))));
    }
    if let Ok(addr) = authority.parse::<std::net::SocketAddr>() {
        return Some(Target::Ip(addr));
    }
    let (host, port) = authority.rsplit_once(':')?;
    // A remaining colon in the host means an unbracketed IPv6 literal, which is
    // not a valid authority: reject it instead of producing a bogus domain.
    if host.contains(':') {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some(Target::Domain(host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_exhaustion_and_aborted_connections_are_waited_out() {
        let exhausted = if cfg!(windows) {
            vec![10024]
        } else {
            vec![24, 23]
        };
        for code in exhausted {
            assert!(is_transient_accept_error(
                &std::io::Error::from_raw_os_error(code)
            ));
        }
        for kind in [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::Interrupted,
        ] {
            assert!(is_transient_accept_error(&kind.into()), "{kind:?}");
        }
        assert!(
            !is_transient_accept_error(&std::io::ErrorKind::PermissionDenied.into()),
            "a listener that cannot accept at all still ends the epoch"
        );
    }

    #[test]
    fn a_failed_connect_answers_a_response_that_names_this_proxy() {
        // The defect this pins: a bodyless 502 is rendered by an API client as
        // "this is a server-side issue, usually temporary", which sends a member
        // whose own tunnel just died to go read the API provider's status page.
        // The response has to say whose gateway failed.
        let raw = connect_failure_response(&NetError::EngineStopped);
        let text = String::from_utf8(raw).expect("the response is ASCII");
        assert!(
            text.starts_with("HTTP/1.1 502 "),
            "the status stays 502 so a client's retry policy is untouched: {text}"
        );
        assert!(
            text.contains(&format!("{TUNNEL_CAUSE_HEADER}: tunnel-gone")),
            "a machine reader needs the cause on its own header: {text}"
        );
        let body = text.split("\r\n\r\n").nth(1).expect("a body is present");
        assert!(
            !body.is_empty() && body.contains("warren"),
            "the body must name this proxy, got {body:?}"
        );
        assert!(
            text.contains(&format!("Content-Length: {}", body.len())),
            "the length must match the body or the client hangs: {text}"
        );
    }

    #[test]
    fn only_a_sourced_condition_earns_its_own_reply_code() {
        // `EngineStopped` is sourced: there is no tunnel, so the network really
        // is unreachable and RFC 1928's code 3 says exactly that.
        assert_eq!(
            connect_failure_reply(&NetError::EngineStopped),
            Reply::NetworkUnreachable
        );
        // The other two are NOT, and claiming them cost a member a wrong and
        // alarming message. `NetError::ConnectionRefused` is raised whenever the
        // smoltcp socket reaches `Closed` with a connect pending
        // (`netstack.rs`), which on a lossy tunnel is SYN exhaustion, not a peer
        // RST; `ConnectTimeout` is our own deadline, not evidence about the
        // host. Reported as codes 5 and 4 they reach the client as ECONNREFUSED
        // and EHOSTUNREACH, which HTTP clients treat as terminal and stop
        // retrying on, so a congested minute reads as "a firewall is blocking
        // you". The condition still travels, in the cause tag and the log, where
        // it cannot change retry semantics.
        for err in [NetError::ConnectionRefused, NetError::ConnectTimeout] {
            assert_eq!(
                connect_failure_reply(&err),
                Reply::GeneralFailure,
                "{err:?} is not sourced well enough to claim its own RFC 1928 code"
            );
        }
        assert_eq!(
            connect_failure_reply(&NetError::ConnectFailed),
            Reply::GeneralFailure,
            "an unclassified failure must stay the generic code, never a guess"
        );
    }

    #[test]
    fn each_local_failure_carries_its_own_cause_tag() {
        // Low cardinality and fixed strings on purpose: this reaches a log and a
        // user's screen, so it may never carry a host, an address or a port.
        for (err, tag) in [
            (NetError::EngineStopped, "tunnel-gone"),
            (NetError::ConnectionRefused, "exit-refused"),
            (NetError::ConnectTimeout, "connect-timeout"),
            (NetError::ConnectFailed, "connect-failed"),
            (NetError::NoDnsRecord, "connect-failed"),
        ] {
            let text = String::from_utf8(connect_failure_response(&err)).expect("ascii");
            assert!(
                text.contains(&format!("{TUNNEL_CAUSE_HEADER}: {tag}")),
                "{err:?} must report {tag}, got: {text}"
            );
        }
    }

    /// A connector that only ever fails, so the CONNECT path is exercised for
    /// real against a real socket pair.
    struct DeadConnector(NetError);

    impl Connector for DeadConnector {
        type Stream = tokio::net::TcpStream;

        async fn connect(&self, _target: Target) -> Result<Self::Stream, NetError> {
            Err(match self.0 {
                NetError::EngineStopped => NetError::EngineStopped,
                _ => NetError::ConnectFailed,
            })
        }
    }

    #[tokio::test]
    async fn a_connect_over_a_dead_tunnel_reaches_the_client_with_its_cause() {
        // The seam under test is the real `handle_connect`, over a real TCP
        // socket: a pure-function test alone would not catch a response written
        // without its body or with the head and body out of step.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let credentials = ProxyCredentials::generate();
        let server_credentials = credentials.clone();
        let server = tokio::spawn(async move {
            let (client, _) = listener.accept().await.expect("accept");
            let _ = handle_connect(
                client,
                &DeadConnector(NetError::EngineStopped),
                &server_credentials,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: {}\r\n\r\n",
            &*credentials.basic_authorization()
        );
        client.write_all(request.as_bytes()).await.expect("write");
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("read");
        server.await.expect("join");

        let text = String::from_utf8(got).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 502 "), "{text}");
        assert!(text.contains("tunnel-gone"), "{text}");
        assert!(
            text.contains("warren"),
            "the member must be able to tell a local tunnel from an API outage: {text}"
        );
        assert!(
            !text.contains("example.com"),
            "the response may never echo the target back: {text}"
        );
    }

    #[test]
    fn parse_authority_ipv4_literal() {
        assert_eq!(
            parse_authority("1.2.3.4:443"),
            Some(Target::Ip("1.2.3.4:443".parse().unwrap()))
        );
    }

    #[test]
    fn parse_authority_bracketed_ipv6_literal() {
        assert_eq!(
            parse_authority("[2001:db8::1]:8080"),
            Some(Target::Ip("[2001:db8::1]:8080".parse().unwrap()))
        );
    }

    #[test]
    fn parse_authority_domain_keeps_the_name() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(Target::Domain("example.com".to_owned(), 443))
        );
    }

    #[test]
    fn parse_authority_rejects_malformed_v6_authorities() {
        // Zoned v6 literal: not meaningful to a remote exit.
        assert_eq!(parse_authority("[fe80::1%eth0]:443"), None);
        // Bracketed but no port.
        assert_eq!(parse_authority("[::1]"), None);
        // Unbracketed v6 literal: an invalid authority, must not become a domain.
        assert_eq!(parse_authority("2001:db8::1:443"), None);
        // Missing port / non-numeric port.
        assert_eq!(parse_authority("example.com"), None);
        assert_eq!(parse_authority("example.com:http"), None);
    }
}
