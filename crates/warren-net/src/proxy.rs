//! Local SOCKS5 proxy server for the non-root datapath.
//!
//! The server terminates application TCP flows locally and hands each one to a
//! [`Connector`], the seam to the outside world. In production the connector
//! drives a userspace netstack over the QUIC tunnel (so the exit, never the
//! local resolver, sees the destination); tests use a direct connector. Keeping
//! the connector abstract is what lets the whole accept/handshake/relay loop be
//! tested in-process without a tunnel.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::NetError;
use crate::socks5::{
    Command, METHOD_NO_AUTH, METHOD_NONE, Reply, Socks5Error, Target, VERSION, build_method_reply,
    build_reply, parse_greeting, parse_request,
};

/// The unspecified bound address echoed in a successful SOCKS5 reply. A CONNECT
/// reply does not need a meaningful bound address.
const REPLY_BOUND: &str = "0.0.0.0:0";

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
    fn connect(
        &self,
        target: Target,
    ) -> impl std::future::Future<Output = Result<Self::Stream, NetError>> + Send;
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

    let mut upstream = match connector.connect(target).await {
        Ok(s) => s,
        Err(e) => {
            write_reply(&mut client, Reply::GeneralFailure).await?;
            return Err(e);
        }
    };

    write_reply(&mut client, Reply::Succeeded).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(NetError::Io)?;
    Ok(())
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
    let bound = REPLY_BOUND.parse().expect("static bound address parses");
    client
        .write_all(&build_reply(reply, bound))
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
}

async fn handle_connect<C: Connector>(
    mut client: TcpStream,
    connector: &C,
) -> Result<(), NetError> {
    let target = match read_connect_target(&mut client).await? {
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
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(NetError::Io)?;
    Ok(())
}

/// Reads the CONNECT request head and returns the target, or `None` if the
/// method is not CONNECT or the head is malformed.
async fn read_connect_target(client: &mut TcpStream) -> Result<Option<Target>, NetError> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = client.read(&mut byte).await.map_err(NetError::Io)?;
        if n == 0 {
            return Ok(None); // connection closed before a full head
        }
        head.push(byte[0]);
        if head.len() > MAX_HTTP_HEAD {
            return Ok(None);
        }
    }
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
    Ok(parse_authority(authority))
}

/// Parses `host:port` into a [`Target`], keeping domain names for remote
/// resolution. IPv6 literals use the `[addr]:port` form.
fn parse_authority(authority: &str) -> Option<Target> {
    if let Ok(addr) = authority.parse::<std::net::SocketAddr>() {
        return Some(Target::Ip(addr));
    }
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some(Target::Domain(host.to_owned(), port))
}
