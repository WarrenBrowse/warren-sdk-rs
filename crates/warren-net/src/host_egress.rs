//! Egress through the host's own route, pinned to one tunnel interface.
//!
//! A proxy client that runs beside a system-wide Warren tunnel should not stack a
//! second tunnel on top of it: the host's route already exits through Warren, and
//! the system tunnel's kill switch does not let a second client reach the relay the
//! two share. [`BoundHostConnector`] opens the upstream flows with the OS stack
//! instead, every socket bound to the system tunnel's interface and to its
//! address, as a check proved that route exits through Warren. The binding is the
//! safety: if the system tunnel goes away, its interface goes with it and every
//! socket bound to it fails, so a flow can never fall back to the physical route.
//! Binding the address alone is not enough on a host that routes by destination
//! (Linux): a route moved to the physical card would carry the tunnel's source out
//! of it. Names are resolved the same way, by a query sent over that interface to
//! a given resolver, never by the host resolver.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::dns::{DnsError, RecordType, encode_query, parse_response};
use crate::error::NetError;
use crate::proxy::Connector;
use crate::socks5::Target;

/// How long a name resolution through the host route may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(4);
/// How long a TCP connect through the host route may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A [`Connector`] over the OS stack whose sockets are all bound to `source`, and
/// which resolves names by asking `resolver` from that same address.
///
/// IPv4 only: the source it is built from is the address of a system tunnel that
/// carries IPv4, and an IPv6 target would have to leave by another route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundHostConnector {
    source: Ipv4Addr,
    interface: Option<NonZeroU32>,
    resolver: SocketAddr,
}

impl BoundHostConnector {
    /// A connector whose flows leave from `source` and whose names are resolved
    /// by `resolver`, reached from `source` too.
    #[must_use]
    pub fn new(source: Ipv4Addr, resolver: SocketAddr) -> Self {
        Self {
            source,
            interface: None,
            resolver,
        }
    }

    /// Binds every socket to the interface with this index as well, so a flow
    /// can only ever leave through it. On macOS, iOS, Linux and Android the
    /// socket is bound to the device. On Windows the source address does it:
    /// its strong host model sends a socket bound to an adapter's address out
    /// of that adapter only, and the bind fails once the adapter is gone.
    /// Elsewhere every flow fails with [`NetError::Unsupported`].
    #[must_use]
    pub fn on_interface(mut self, index: NonZeroU32) -> Self {
        self.interface = Some(index);
        self
    }

    /// A socket of `kind`, bound to the interface and the source address.
    ///
    /// A bind refused because the host no longer holds that interface or that
    /// address means the system tunnel went away. It is reported as
    /// [`NetError::EngineStopped`], a path that is gone, so a proxy keeps the
    /// request for its next path instead of refusing it as if the target had.
    /// Any other bind failure (a missing privilege, no free port) stays an
    /// [`NetError::Io`]: another path would not cure it.
    fn bound_socket(&self, kind: Type, protocol: Protocol) -> Result<Socket, NetError> {
        let socket = Socket::new(Domain::IPV4, kind, Some(protocol)).map_err(NetError::Io)?;
        if let Some(index) = self.interface {
            bind_interface(&socket, index).map_err(|e| match e {
                NetError::Io(io) => path_gone_or(io),
                other => other,
            })?;
        }
        socket
            .bind(&SocketAddr::new(IpAddr::V4(self.source), 0).into())
            .map_err(path_gone_or)?;
        socket.set_nonblocking(true).map_err(NetError::Io)?;
        Ok(socket)
    }

    /// The source address every flow is bound to.
    #[must_use]
    pub fn source(&self) -> Ipv4Addr {
        self.source
    }

    async fn resolve(&self, host: &str) -> Result<Ipv4Addr, NetError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => Ok(v4),
                IpAddr::V6(_) => Err(NetError::Unsupported("IPv6 target on the host route")),
            };
        }
        let socket = self.bound_socket(Type::DGRAM, Protocol::UDP)?;
        let socket = UdpSocket::from_std(socket.into()).map_err(NetError::Io)?;
        socket.connect(self.resolver).await.map_err(NetError::Io)?;
        let id: u16 = rand::random();
        let query = encode_query(host, id, RecordType::A).map_err(|_| NetError::ConnectFailed)?;
        socket.send(&query).await.map_err(NetError::Io)?;
        let mut buf = [0u8; 1500];
        let len = tokio::time::timeout(RESOLVE_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| NetError::ConnectTimeout)?
            .map_err(NetError::Io)?;
        parse_response(&buf[..len], id, RecordType::A)
            .map_err(|e| match e {
                DnsError::NoAddress => NetError::NoDnsRecord,
                _ => NetError::ConnectFailed,
            })?
            .into_iter()
            .find_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .ok_or(NetError::NoDnsRecord)
    }
}

impl Connector for BoundHostConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: Target) -> Result<Self::Stream, NetError> {
        let addr = match target {
            Target::Ip(SocketAddr::V4(v4)) => v4,
            Target::Ip(SocketAddr::V6(_)) => {
                return Err(NetError::Unsupported("IPv6 target on the host route"));
            }
            Target::Domain(host, port) => {
                std::net::SocketAddrV4::new(self.resolve(&host).await?, port)
            }
        };
        let socket = self.bound_socket(Type::STREAM, Protocol::TCP)?;
        let socket = TcpSocket::from_std_stream(socket.into());
        tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(SocketAddr::V4(addr)))
            .await
            .map_err(|_| NetError::ConnectTimeout)?
            .map_err(NetError::Io)
    }
}

/// ENXIO and ENODEV, what binding to an interface index that no longer exists
/// answers on the Unix systems that support it.
const NO_SUCH_DEVICE: [i32; 2] = [6, 19];

/// [`NetError::EngineStopped`] for a bind refused because the interface or the
/// address is gone, the error itself otherwise.
fn path_gone_or(e: std::io::Error) -> NetError {
    let gone = e.kind() == std::io::ErrorKind::AddrNotAvailable
        || (cfg!(unix)
            && e.raw_os_error()
                .is_some_and(|c| NO_SUCH_DEVICE.contains(&c)));
    if gone {
        NetError::EngineStopped
    } else {
        NetError::Io(e)
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
fn bind_interface(socket: &Socket, index: NonZeroU32) -> Result<(), NetError> {
    socket
        .bind_device_by_index_v4(Some(index))
        .map_err(NetError::Io)
}

/// The source address the socket is bound to next pins the adapter (see
/// [`BoundHostConnector::on_interface`]); the index adds nothing Windows would
/// enforce without an option this crate cannot set safely.
#[cfg(windows)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature for every platform's binding"
)]
fn bind_interface(_socket: &Socket, _index: NonZeroU32) -> Result<(), NetError> {
    Ok(())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn bind_interface(_socket: &Socket, _index: NonZeroU32) -> Result<(), NetError> {
    Err(NetError::Unsupported("binding a socket to an interface"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

    /// Answers every query it receives with one `A` record for `answer`, and
    /// counts the queries.
    async fn fake_resolver(
        answer: Ipv4Addr,
    ) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let socket = UdpSocket::bind((LOOPBACK, 0)).await.expect("bind resolver");
        let addr = socket.local_addr().expect("resolver addr");
        let queries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&queries);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut reply = buf[..len].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                reply.extend_from_slice(&answer.octets());
                let _ = socket.send_to(&reply, from).await;
            }
        });
        (addr, queries)
    }

    async fn echo_listener() -> SocketAddr {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut stream, peer)) = listener.accept().await {
                let _ = stream.write_all(peer.ip().to_string().as_bytes()).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_name_is_resolved_by_the_given_resolver_and_reached_from_the_source() {
        let target = echo_listener().await;
        let (resolver, _) = fake_resolver(LOOPBACK).await;
        let connector = BoundHostConnector::new(LOOPBACK, resolver);

        let mut stream = connector
            .connect(Target::Domain("upstream.example".into(), target.port()))
            .await
            .expect("the name resolves and the flow connects");

        let mut seen = String::new();
        stream.read_to_string(&mut seen).await.expect("read");
        assert_eq!(seen, "127.0.0.1", "the flow leaves from the bound source");
    }

    /// The whole safety of the host route: once the system tunnel's address is
    /// gone, a flow must fail rather than leave by the physical route.
    #[tokio::test]
    async fn a_source_address_the_host_no_longer_holds_fails_instead_of_leaving_elsewhere() {
        let target = echo_listener().await;
        let gone = Ipv4Addr::new(192, 0, 2, 1);
        let connector = BoundHostConnector::new(gone, SocketAddr::new(LOOPBACK.into(), 53));

        let result = connector.connect(Target::Ip(target)).await;

        // Failing as a path that went away, not as a target that refused: the
        // proxy then keeps the request for the next path instead of showing
        // the member an error for the second the system tunnel dropped.
        assert!(
            matches!(result, Err(NetError::EngineStopped)),
            "binding to an address the host does not hold must fail as a gone path, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_name_is_never_resolved_from_a_source_the_host_no_longer_holds() {
        let (resolver, queries) = fake_resolver(LOOPBACK).await;
        let connector = BoundHostConnector::new(Ipv4Addr::new(192, 0, 2, 1), resolver);

        let result = connector
            .connect(Target::Domain("upstream.example".into(), 443))
            .await;

        assert!(
            matches!(result, Err(NetError::EngineStopped)),
            "got {result:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            queries.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the name must not leave by another route"
        );
    }

    #[cfg(target_os = "macos")]
    fn index_of(name: &str) -> NonZeroU32 {
        NonZeroU32::new(nix::net::if_::if_nametoindex(name).expect("interface exists"))
            .expect("non-zero index")
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_flow_bound_to_the_tunnel_interface_leaves_through_it() {
        let target = echo_listener().await;
        let connector = BoundHostConnector::new(LOOPBACK, SocketAddr::new(LOOPBACK.into(), 53))
            .on_interface(index_of("lo0"));

        let mut stream = connector
            .connect(Target::Ip(target))
            .await
            .expect("the bound interface reaches the target");

        let mut seen = String::new();
        stream.read_to_string(&mut seen).await.expect("read");
        assert_eq!(seen, "127.0.0.1");
    }

    /// The source address alone does not pin the route: bound to another
    /// interface, the flow must fail rather than leave by it.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_flow_bound_to_another_interface_than_its_route_fails() {
        let target = echo_listener().await;
        let (resolver, queries) = fake_resolver(LOOPBACK).await;
        let other = nix::ifaddrs::getifaddrs()
            .expect("interfaces")
            .filter(|a| a.interface_name != "lo0")
            .find_map(|a| {
                NonZeroU32::new(nix::net::if_::if_nametoindex(a.interface_name.as_str()).ok()?)
            })
            .expect("a non-loopback interface");
        let connector = BoundHostConnector::new(LOOPBACK, resolver).on_interface(other);

        let by_ip = connector.connect(Target::Ip(target)).await;
        let by_name = connector
            .connect(Target::Domain("upstream.example".into(), target.port()))
            .await;

        assert!(by_ip.is_err(), "got {by_ip:?}");
        assert!(by_name.is_err(), "got {by_name:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(queries.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn only_a_gone_interface_or_address_reads_as_a_gone_path() {
        for gone in [
            std::io::Error::from(std::io::ErrorKind::AddrNotAvailable),
            std::io::Error::from_raw_os_error(if cfg!(unix) { 6 } else { 10049 }),
        ] {
            assert!(
                matches!(path_gone_or(gone), NetError::EngineStopped),
                "a vanished interface or address is a gone path"
            );
        }
        for other in [
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            std::io::Error::from(std::io::ErrorKind::AddrInUse),
        ] {
            assert!(
                matches!(path_gone_or(other), NetError::Io(_)),
                "no other path would cure this"
            );
        }
    }

    #[tokio::test]
    async fn an_ipv6_target_is_refused() {
        let connector = BoundHostConnector::new(LOOPBACK, SocketAddr::new(LOOPBACK.into(), 53));

        let by_ip = connector
            .connect(Target::Ip("[2001:db8::1]:443".parse().expect("literal")))
            .await;
        let by_literal = connector
            .connect(Target::Domain("2001:db8::1".into(), 443))
            .await;

        assert!(
            matches!(by_ip, Err(NetError::Unsupported(_))),
            "got {by_ip:?}"
        );
        assert!(
            matches!(by_literal, Err(NetError::Unsupported(_))),
            "got {by_literal:?}"
        );
    }
}
