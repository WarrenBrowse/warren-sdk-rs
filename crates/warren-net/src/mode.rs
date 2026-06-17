//! Configuration for the non-root proxy datapath.

use std::net::{Ipv4Addr, SocketAddr};

/// Configuration for the non-root proxy datapath.
///
/// The listeners are unauthenticated, so they MUST stay loopback-bound for the
/// single-app use case. The default binds `127.0.0.1`; binding a non-loopback
/// address (for example `0.0.0.0`) turns the SDK into an open proxy reachable by
/// other hosts on the network. Only do that in an isolated network namespace or
/// container where you control reachability.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Local address for the SOCKS5 listener. Keep this loopback (see the type
    /// docs); the listener is unauthenticated.
    pub socks5: SocketAddr,
    /// Optional local address for an HTTP CONNECT listener. Keep this loopback;
    /// the listener is unauthenticated.
    pub http: Option<SocketAddr>,
    /// DNS resolver to query over the tunnel. `None` uses the exit's gateway
    /// forwarder (the common case). Set this for a `dns_disabled` exit to a
    /// public resolver; the query still egresses through the tunnel, so it never
    /// leaks to the host resolver.
    pub dns_server: Option<Ipv4Addr>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socks5: SocketAddr::from(([127, 0, 0, 1], 1080)),
            http: None,
            dns_server: None,
        }
    }
}
