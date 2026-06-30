use std::net::SocketAddr;
use std::sync::Arc;

use warren_transport::MultihopSession;

use crate::error::SdkError;

/// Tunnel network prefix length (`10.66.0.0/16`), matching warren-core.
pub(crate) const TUNNEL_PREFIX: u8 = 16;
/// Tunnel gateway (exit side), matching warren-core's `10.66.0.1`.
pub(crate) const TUNNEL_GATEWAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 66, 0, 1);

/// Liveness of a running proxy datapath's tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnelState {
    /// The tunnel is up and the proxy is forwarding.
    Connected,
    /// The tunnel read side closed; traffic no longer egresses at the exit. The
    /// app should stop sending (or tear down and reconnect) to avoid a leak.
    Disconnected,
}

/// A detached, cloneable capability to request NAT-PMP port forwards over a
/// running datapath (see [`ProxyHandle::forwarder`]). It does not own the
/// datapath lifecycle, so it can be held and used independently of the
/// [`ProxyHandle`] (the FFI layer keeps one alongside the handle's lock).
#[derive(Clone)]
pub struct ProxyForwarder {
    pub(crate) connector: warren_net::TunnelConnector,
    pub(crate) gateway: std::net::Ipv4Addr,
}

impl ProxyForwarder {
    /// Forwards a tunnel-side port: maps `internal_port` at the exit via NAT-PMP
    /// and relays inbound connections to `local_target`, renewing until the
    /// returned [`warren_net::ForwardedPort`] is dropped. See
    /// [`ProxyHandle::forward_port`].
    ///
    /// # Errors
    ///
    /// [`SdkError::PortForward`] if the engine has stopped, a socket cannot be
    /// opened, or the exit refuses the mapping.
    pub async fn forward_port(
        &self,
        proto: warren_net::MapProto,
        internal_port: u16,
        local_target: SocketAddr,
    ) -> Result<warren_net::ForwardedPort, SdkError> {
        self.forward_port_with_suggested(proto, internal_port, local_target, 0)
            .await
    }

    /// Like [`Self::forward_port`], but asks the exit to grant
    /// `suggested_external_port` (`0` lets the gateway choose). The supervised
    /// forward re-suggests the last-granted port across reconnects so the public
    /// port follows the client; a taken port surfaces as
    /// [`SdkError::PortForward`] rather than a silent random fallback.
    ///
    /// # Errors
    ///
    /// [`SdkError::PortForward`] if the engine has stopped, a socket cannot be
    /// opened, or the exit refuses (or cannot honour) the mapping.
    pub async fn forward_port_with_suggested(
        &self,
        proto: warren_net::MapProto,
        internal_port: u16,
        local_target: SocketAddr,
        suggested_external_port: u16,
    ) -> Result<warren_net::ForwardedPort, SdkError> {
        warren_net::forward_port_with_suggested(
            &self.connector,
            self.gateway,
            proto,
            internal_port,
            local_target,
            suggested_external_port,
        )
        .await
        .map_err(SdkError::from)
    }
}

/// A running non-root proxy datapath. Dropping it stops the proxy.
pub struct ProxyHandle {
    pub(crate) local_addr: SocketAddr,
    pub(crate) http_addr: Option<SocketAddr>,
    pub(crate) state_rx: tokio::sync::watch::Receiver<TunnelState>,
    pub(crate) forward_connector: warren_net::TunnelConnector,
    pub(crate) gateway: std::net::Ipv4Addr,
    pub(crate) tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Live session counters, present for the multihop datapath (`None` for the
    /// single-hop `start_proxy`, which has no sealed-session metrics).
    pub(crate) metrics: Option<std::sync::Arc<warren_transport::MultihopMetrics>>,
}

impl ProxyHandle {
    /// The address the SOCKS5 listener actually bound (useful when `cfg.socks5`
    /// used port 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// A snapshot of the datapath's live counters (bytes/packets/epoch/uptime),
    /// or `None` for the single-hop [`start_proxy`](crate::WarrenClient::start_proxy)
    /// path, which carries no sealed-session metrics.
    #[must_use]
    pub fn metrics(&self) -> Option<warren_transport::MultihopMetricsSnapshot> {
        self.metrics.as_ref().map(|m| m.snapshot())
    }

    /// The address the HTTP CONNECT listener bound, if one was configured.
    #[must_use]
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// The current tunnel state ([`TunnelState::Connected`] until the tunnel
    /// read side closes).
    #[must_use]
    pub fn state(&self) -> TunnelState {
        *self.state_rx.borrow()
    }

    /// A watch receiver for tunnel-state changes, so an app can await a
    /// disconnect (`state_rx.changed().await`) rather than poll [`Self::state`].
    #[must_use]
    pub fn watch_state(&self) -> tokio::sync::watch::Receiver<TunnelState> {
        self.state_rx.clone()
    }

    /// Forwards a tunnel-side port: asks the exit to map `internal_port` via
    /// NAT-PMP and relays every inbound connection to `local_target` (a TCP
    /// server the app runs locally), renewing the mapping until the returned
    /// [`warren_net::ForwardedPort`] is dropped. Resolves once the exit grants
    /// the mapping, so [`warren_net::ForwardedPort::external_port`] is the port
    /// remote peers reach the app on.
    ///
    /// This needs an exit that runs a NAT-PMP gateway; not every exit does.
    ///
    /// # Errors
    ///
    /// [`SdkError::PortForward`] if the engine has stopped, a socket cannot be
    /// opened, or the exit refuses the mapping.
    pub async fn forward_port(
        &self,
        proto: warren_net::MapProto,
        internal_port: u16,
        local_target: SocketAddr,
    ) -> Result<warren_net::ForwardedPort, SdkError> {
        self.forwarder()
            .forward_port(proto, internal_port, local_target)
            .await
    }

    /// A cheap, cloneable [`ProxyForwarder`] for this datapath, detached from the
    /// handle's lifecycle so a caller (notably the FFI layer) can request port
    /// forwards without holding the handle across an `.await`.
    #[must_use]
    pub fn forwarder(&self) -> ProxyForwarder {
        ProxyForwarder {
            connector: self.forward_connector.clone(),
            gateway: self.gateway,
        }
    }

    /// Stops the proxy datapath.
    pub fn shutdown(self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Builds a [`warren_net::NetstackConfig`] from the given addressing parameters.
///
/// Reads the path-aware payload size from `sink` for the MTU, then optionally
/// enables the dual-stack v6 datapath and a DNS server override.
pub(crate) fn build_netstack_config<S: warren_net::PacketSink>(
    sink: &S,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    ipv6: Option<warren_net::Ipv6Addressing>,
    dns_server: Option<std::net::Ipv4Addr>,
) -> warren_net::NetstackConfig {
    // The inner IP MTU must fit one QUIC datagram: use the path-aware payload
    // size, NOT the raw policy MTU (which can exceed the datagram capacity and
    // make every full-size packet silently fail to send).
    let mtu = warren_net::PacketSink::max_payload(sink);
    let mut config = warren_net::NetstackConfig::new(local_ip, prefix, gateway, mtu);
    // Enable the dual-stack v6 datapath only when the exit actually granted v6.
    if let Some(v6) = ipv6 {
        config = config.with_ipv6(v6.local_ip, v6.prefix, v6.gateway);
    }
    // dns_disabled exits run no gateway forwarder; honor the operator's override
    // so lookups still egress through the tunnel rather than the host resolver.
    if let Some(dns) = dns_server {
        config = config.with_dns_server(dns);
    }
    config
}

/// Runs the userspace netstack over `sink` and serves the local SOCKS5 (and
/// optional HTTP CONNECT) proxy. Shared by the single-hop and multihop datapaths.
pub(crate) async fn serve_proxy_over_sink<S>(
    sink: S,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    ipv6: Option<warren_net::Ipv6Addressing>,
    cfg: &warren_net::ProxyConfig,
) -> Result<ProxyHandle, SdkError>
where
    S: warren_net::PacketSink + 'static,
{
    let config = build_netstack_config(&sink, local_ip, prefix, gateway, ipv6, cfg.dns_server);
    let (connector, mut alive_rx) = warren_net::spawn_over_sink(Arc::new(sink), config);

    let socks_listener = tokio::net::TcpListener::bind(cfg.socks5)
        .await
        .map_err(SdkError::Proxy)?;
    let local_addr = socks_listener.local_addr().map_err(SdkError::Proxy)?;
    let socks = warren_net::Socks5Proxy::new(connector.clone());
    // serve_with_udp also handles UDP ASSOCIATE (datagrams egress at the exit
    // via the netstack UDP flow); CONNECT behaves identically to serve.
    let mut tasks = vec![tokio::spawn(async move {
        let _ = socks.serve_with_udp(socks_listener).await;
    })];

    // Surface tunnel liveness as a connection state an app can observe: the
    // datapath starts Connected and flips to Disconnected when the tunnel read
    // side closes (the leak window), so the app can stop sending or reconnect.
    let (state_tx, state_rx) = tokio::sync::watch::channel(TunnelState::Connected);
    tasks.push(tokio::spawn(async move {
        while alive_rx.changed().await.is_ok() {
            if !*alive_rx.borrow() {
                let _ = state_tx.send(TunnelState::Disconnected);
                break;
            }
        }
    }));

    // Keep a connector clone for on-demand port forwarding; the HTTP branch below
    // may move `connector`, so clone before it does.
    let forward_connector = connector.clone();

    let mut http_addr = None;
    if let Some(http_bind) = cfg.http {
        let http_listener = tokio::net::TcpListener::bind(http_bind)
            .await
            .map_err(SdkError::Proxy)?;
        http_addr = Some(http_listener.local_addr().map_err(SdkError::Proxy)?);
        let http = warren_net::HttpConnectProxy::new(connector);
        tasks.push(tokio::spawn(async move {
            let _ = http.serve(http_listener).await;
        }));
    }

    Ok(ProxyHandle {
        local_addr,
        http_addr,
        state_rx,
        forward_connector,
        gateway,
        tasks,
        metrics: None,
    })
}

/// Derives the netstack addressing from a multihop session's `IpAssign`: the v4
/// CIDR + gateway, and dual-stack v6 only when the exit granted a v6 address, its
/// gateway and a sane prefix (else v4-only, so a misbehaving exit cannot install
/// an unroutable or `/0` v6 route; v6 traffic still stays in the tunnel). A real
/// exit may assign a different prefix or gateway per session, so this is read
/// fresh on every (re)connect rather than assumed.
pub(crate) fn addressing_from_session(
    session: &MultihopSession,
) -> (
    std::net::Ipv4Addr,
    u8,
    std::net::Ipv4Addr,
    Option<warren_net::Ipv6Addressing>,
) {
    let a = session.assignment();
    let local_ip = std::net::Ipv4Addr::from(a.ipv4);
    let prefix = a.prefix_len;
    let gateway = std::net::Ipv4Addr::from(a.gateway_ipv4);
    let ipv6 = match (a.ipv6, a.gateway_ipv6) {
        (Some(ip), Some(gw)) if (1..=128).contains(&a.prefix_len_v6) => {
            Some(warren_net::Ipv6Addressing {
                local_ip: std::net::Ipv6Addr::from(ip),
                prefix: a.prefix_len_v6,
                gateway: std::net::Ipv6Addr::from(gw),
            })
        }
        _ => None,
    };
    (local_ip, prefix, gateway, ipv6)
}
