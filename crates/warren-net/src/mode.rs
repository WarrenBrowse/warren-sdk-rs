//! Configuration for the non-root proxy datapath.

use std::net::{Ipv4Addr, SocketAddr};

use crate::proxy_auth::ProxyCredentials;

/// Configuration for the non-root proxy datapath.
///
/// Every connection to the listeners must present the session's credentials
/// (see [`crate::proxy_auth`]). The default binds `127.0.0.1`; binding a
/// non-loopback address (for example `0.0.0.0`) exposes them to the network,
/// where only those credentials stand between the tunnel and every host that
/// can reach the port, and where they travel in clear.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Local address for the SOCKS5 listener.
    pub socks5: SocketAddr,
    /// Optional local address for an HTTP CONNECT listener.
    pub http: Option<SocketAddr>,
    /// DNS resolver to query over the tunnel. `None` uses the exit's gateway
    /// forwarder (the common case). Set this for a `dns_disabled` exit to a
    /// public resolver; the query still egresses through the tunnel, so it never
    /// leaks to the host resolver.
    pub dns_server: Option<Ipv4Addr>,
    /// The credentials clients present. `None` generates fresh ones for the
    /// session ([`ProxyCredentials::generate`]), read back from the handle; set
    /// them only when clients are configured by hand (a headless daemon).
    pub credentials: Option<ProxyCredentials>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socks5: SocketAddr::from(([127, 0, 0, 1], 1080)),
            http: None,
            dns_server: None,
            credentials: None,
        }
    }
}
