//! Local SOCKS5 proxy server for the non-root datapath.
//!
//! The server terminates application TCP flows locally and hands each one to a
//! [`Connector`], the seam to the outside world. In production the connector
//! drives a userspace netstack over the QUIC tunnel (so the exit, never the
//! local resolver, sees the destination); tests use a direct connector. Keeping
//! the connector abstract is what lets the whole accept/handshake/relay loop be
//! tested in-process without a tunnel.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::NetError;
use crate::socks5::{
    Command, METHOD_NO_AUTH, METHOD_NONE, Reply, Socks5Error, Target, VERSION, build_method_reply,
    build_reply, encode_udp_datagram, parse_greeting, parse_request, parse_udp_datagram,
};

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

/// A SOCKS5 proxy server over a [`Connector`].
pub struct Socks5Proxy<C> {
    connector: Arc<C>,
}

impl<C: Connector> Socks5Proxy<C> {
    /// Builds a proxy that opens upstream flows through `connector`.
    pub fn new(connector: C) -> Self {
        Self {
            connector: Arc::new(connector),
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
            let (client, _peer) = listener.accept().await.map_err(NetError::Io)?;
            let connector = Arc::clone(&self.connector);
            tokio::spawn(async move {
                let _ = handle_connection(client, connector.as_ref()).await;
            });
        }
    }
}

/// Opens the upstream flow for a `CONNECT` target and relays bytes both ways,
/// replying success or general-failure to the client. Shared by the plain and
/// UDP-capable SOCKS5 handlers so the CONNECT leg lives in one place.
async fn relay_connect<C: Connector>(
    client: &mut TcpStream,
    connector: &C,
    target: Target,
) -> Result<(), NetError> {
    let mut upstream = match connector.connect(target).await {
        Ok(s) => s,
        Err(e) => {
            write_reply(client, Reply::GeneralFailure).await?;
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
) -> Result<(), NetError> {
    negotiate_method(&mut client).await?;
    let (command, target) = read_request(&mut client).await?;

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
            let (client, _peer) = listener.accept().await.map_err(NetError::Io)?;
            let connector = Arc::clone(&self.connector);
            tokio::spawn(async move {
                let _ = handle_with_udp(client, connector.as_ref()).await;
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
                accepted = listener.accept() => {
                    let (client, _peer) = accepted.map_err(NetError::Io)?;
                    let connector = Arc::clone(&self.connector);
                    tokio::spawn(async move {
                        let _ = handle_with_udp(client, connector.as_ref()).await;
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
) -> Result<(), NetError> {
    negotiate_method(&mut client).await?;
    let (command, target) = read_request(&mut client).await?;
    match command {
        Command::Connect => relay_connect(&mut client, connector, target).await,
        Command::UdpAssociate => udp_associate(client, connector).await,
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
) -> Result<(), NetError> {
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
                // Bind the association to the first client source and drop
                // datagrams from any other local source: otherwise a co-resident
                // process could inject traffic and, by setting `client_src`,
                // hijack the reply stream.
                match client_src {
                    None => client_src = Some(src),
                    Some(known) if known != src => continue,
                    Some(_) => {}
                }
                if let Ok((target, payload)) = parse_udp_datagram(&buf[..n]) {
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

/// Reads the greeting and replies with the selected method.
async fn negotiate_method(client: &mut TcpStream) -> Result<(), NetError> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.map_err(NetError::Io)?;
    let mut greeting = head.to_vec();
    greeting.resize(2 + head[1] as usize, 0);
    client
        .read_exact(&mut greeting[2..])
        .await
        .map_err(NetError::Io)?;

    let methods = parse_greeting(&greeting)?;
    let method = if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NONE
    };
    client
        .write_all(&build_method_reply(method))
        .await
        .map_err(NetError::Io)?;
    if method == METHOD_NONE {
        return Err(NetError::Socks5(Socks5Error::BadVersion(VERSION)));
    }
    Ok(())
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

/// Largest CONNECT request head (request line plus headers) accepted.
const MAX_HTTP_HEAD: usize = 8 * 1024;

/// An HTTP CONNECT proxy server over a [`Connector`].
///
/// Handles only the `CONNECT host:port` method (the tunneling verb a browser or
/// HTTP client uses for HTTPS); other methods are refused. Like [`Socks5Proxy`]
/// it relays through the connector, so the same tunnel datapath backs it.
pub struct HttpConnectProxy<C> {
    connector: Arc<C>,
}

impl<C: Connector> HttpConnectProxy<C> {
    /// Builds a CONNECT proxy that opens upstream flows through `connector`.
    pub fn new(connector: C) -> Self {
        Self {
            connector: Arc::new(connector),
        }
    }

    /// Accepts connections on `listener` until it errors, one task each.
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] only if accepting on the listener fails.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), NetError> {
        loop {
            let (client, _peer) = listener.accept().await.map_err(NetError::Io)?;
            let connector = Arc::clone(&self.connector);
            tokio::spawn(async move {
                let _ = handle_connect(client, connector.as_ref()).await;
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
                accepted = listener.accept() => {
                    let (client, _peer) = accepted.map_err(NetError::Io)?;
                    let connector = Arc::clone(&self.connector);
                    tokio::spawn(async move {
                        let _ = handle_connect(client, connector.as_ref()).await;
                    });
                }
            }
        }
    }
}

async fn handle_connect<C: Connector>(
    mut client: TcpStream,
    connector: &C,
) -> Result<(), NetError> {
    let (target, early_data) = match read_connect_target(&mut client).await? {
        Some(t) => t,
        None => {
            let _ = client
                .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let mut upstream = match connector.connect(target).await {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
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

/// Reads the CONNECT request head and returns the target plus any tunnel bytes
/// already received after the head (`\r\n\r\n`), or `None` if the method is not
/// CONNECT or the head is malformed.
///
/// Reads in chunks rather than one byte per syscall; any bytes past the head
/// terminator are returned so the caller can replay them to the upstream.
async fn read_connect_target(
    client: &mut TcpStream,
) -> Result<Option<(Target, Vec<u8>)>, NetError> {
    let mut head = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    let head_len = loop {
        let n = client.read(&mut chunk).await.map_err(NetError::Io)?;
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
    let text = match std::str::from_utf8(&head) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let request_line = text.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    if parts.next() != Some("CONNECT") {
        return Ok(None);
    }
    let authority = match parts.next() {
        Some(a) => a,
        None => return Ok(None),
    };
    Ok(parse_authority(authority).map(|target| (target, early_data)))
}

/// Parses an HTTP `CONNECT` authority into a [`Target`], keeping domain names
/// for remote resolution. IPv6 literals use the `[addr]:port` form; a bare
/// (unbracketed) IPv6 literal or a zoned address is malformed in an authority
/// and is rejected rather than coerced into a bogus domain name.
fn parse_authority(authority: &str) -> Option<Target> {
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
