//! Datapath selection: the non-root proxy mode (default) or the privileged TUN
//! mode.

use std::net::{Ipv4Addr, SocketAddr};

/// How the SDK captures application traffic and feeds it to the tunnel.
#[derive(Debug, Clone)]
pub enum ConnectMode {
    /// Non-root: expose a local SOCKS5 (and optional HTTP CONNECT) proxy.
    /// Feature-complete on Linux, macOS and Windows without elevated
    /// privileges. This is the default.
    Proxy(ProxyConfig),
    /// Privileged: capture all OS traffic via a TUN device with split-default
    /// routing, DNS push and a killswitch. Requires root/admin (or `CAP_NET_ADMIN`
    /// on Linux). Built per OS behind the `tun` feature.
    Tun(TunConfig),
}

impl Default for ConnectMode {
    fn default() -> Self {
        ConnectMode::Proxy(ProxyConfig::default())
    }
}

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

/// Configuration for the privileged TUN datapath.
#[derive(Debug, Clone, Default)]
pub struct TunConfig {
    /// Desired TUN interface name (OS may adjust). Empty means OS default.
    pub interface_name: String,
    /// Whether to install a killswitch alongside the tunnel.
    pub killswitch: bool,
}
