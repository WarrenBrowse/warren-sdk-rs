use std::net::SocketAddr;
use std::sync::Arc;

use warren_net::ProxyCredentials;
use warren_transport::MultihopSession;

use crate::error::SdkError;

/// The credentials a datapath's listeners demand: the configured ones, or fresh
/// ones for this session.
fn session_credentials(cfg: &warren_net::ProxyConfig) -> ProxyCredentials {
    cfg.credentials
        .clone()
        .unwrap_or_else(ProxyCredentials::generate)
}

/// The bound local proxy listeners and the credentials their clients present.
///
/// Clones share the same sockets. A host that must never release its ports
/// while clients still point at them (a released loopback port can be taken
/// over by any other process on the machine, which then receives those
/// clients' traffic) keeps a clone for as long as those clients live and hands
/// it to every datapath it starts
/// ([`WarrenClient::start_proxy_supervised_on`](crate::WarrenClient::start_proxy_supervised_on)).
/// Between one datapath and the next the ports stay bound, and a connection
/// made meanwhile waits in the listen backlog for the next datapath instead of
/// being refused. One datapath serves a set of listeners at a time.
#[derive(Debug, Clone)]
pub struct ProxyListeners {
    socks: Arc<tokio::net::TcpListener>,
    socks_addr: SocketAddr,
    http: Option<Arc<tokio::net::TcpListener>>,
    http_addr: Option<SocketAddr>,
    credentials: ProxyCredentials,
    serving: Arc<tokio::sync::Mutex<()>>,
}

impl ProxyListeners {
    /// Binds the SOCKS5 listener (and the HTTP CONNECT one when configured) and
    /// fixes the credentials every client of them must present.
    ///
    /// # Errors
    ///
    /// [`SdkError::Proxy`] if a listener cannot bind.
    pub async fn bind(cfg: &warren_net::ProxyConfig) -> Result<Self, SdkError> {
        let socks = tokio::net::TcpListener::bind(cfg.socks5)
            .await
            .map_err(SdkError::Proxy)?;
        let socks_addr = socks.local_addr().map_err(SdkError::Proxy)?;
        let (http, http_addr) = match cfg.http {
            Some(bind) => {
                let listener = tokio::net::TcpListener::bind(bind)
                    .await
                    .map_err(SdkError::Proxy)?;
                let addr = listener.local_addr().map_err(SdkError::Proxy)?;
                (Some(Arc::new(listener)), Some(addr))
            }
            None => (None, None),
        };
        Ok(Self {
            socks: Arc::new(socks),
            socks_addr,
            http,
            http_addr,
            credentials: session_credentials(cfg),
            serving: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// The address the SOCKS5 listener bound.
    #[must_use]
    pub fn socks5_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// The address the HTTP CONNECT listener bound, if one was configured.
    #[must_use]
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// The credentials every client of these listeners must present.
    #[must_use]
    pub fn credentials(&self) -> &ProxyCredentials {
        &self.credentials
    }

    pub(crate) fn socks_listener(&self) -> Arc<tokio::net::TcpListener> {
        Arc::clone(&self.socks)
    }

    pub(crate) fn http_listener(&self) -> Option<Arc<tokio::net::TcpListener>> {
        self.http.clone()
    }

    /// Waits until no other datapath serves these listeners, and holds them
    /// until the returned guard drops (with the datapath task that owns it).
    pub(crate) async fn serve_lease(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.serving).lock_owned().await
    }
}

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
    /// doc 79: whether the selected exit advertises an enabled NAT-PMP gateway.
    /// The forward-port calls fail closed with [`SdkError::PortForwardUnsupported`]
    /// when this is `false`, so the SDK never emits a mapping an exit would
    /// reject. Defaults `true` for datapaths whose exit capability is not known
    /// on this path (e.g. multihop), preserving prior behaviour.
    pub(crate) port_forward_supported: bool,
    /// The wallet's port entitlements (warren-core doc 105): every mapping
    /// presents its rule's slot. `None` presents nothing, which an enforcing
    /// exit refuses.
    pub(crate) entitlements: Option<crate::entitlements::PortEntitlements>,
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
    /// The mapping presents a port entitlement from its own slot of the
    /// wallet's batch, held for the life of the returned port and freed with
    /// it (warren-core doc 105).
    ///
    /// # Errors
    ///
    /// [`SdkError::PortForward`] if the engine has stopped, a socket cannot be
    /// opened, or the exit refuses (or cannot honour) the mapping;
    /// [`SdkError::PortForwardRefused`] when the exit refuses it for want of an
    /// entitlement it would spend; [`SdkError::Api`] with
    /// [`ClientError::Banned`](warren_api::ClientError::Banned) when that
    /// refusal is explained by the issuer banning the wallet.
    pub async fn forward_port_with_suggested(
        &self,
        proto: warren_net::MapProto,
        internal_port: u16,
        local_target: SocketAddr,
        suggested_external_port: u16,
    ) -> Result<warren_net::ForwardedPort, SdkError> {
        self.forward_port_for_rule(
            proto,
            internal_port,
            local_target,
            suggested_external_port,
            &crate::entitlements::RuleSlot::default(),
        )
        .await
    }

    /// [`Self::forward_port_with_suggested`] for a rule that keeps `rule`'s
    /// slot across the mappings it re-establishes.
    pub(crate) async fn forward_port_for_rule(
        &self,
        proto: warren_net::MapProto,
        internal_port: u16,
        local_target: SocketAddr,
        suggested_external_port: u16,
        rule: &crate::entitlements::RuleSlot,
    ) -> Result<warren_net::ForwardedPort, SdkError> {
        // doc 79: gate the feature on the exit's advertised capability. Warren
        // is mono-IP, so an exit that does not run NAT-PMP cannot honour a
        // mapping; refuse up front with a clear typed error rather than emit a
        // request the exit would reject. This is the single choke point for
        // ProxyHandle::forward_port, ProxyForwarder::forward_port and the
        // supervised self-healing forward.
        if !self.port_forward_supported {
            return Err(SdkError::PortForwardUnsupported);
        }
        let (credential, lease) = rule.provider(self.entitlements.as_ref()).await.unzip();
        warren_net::forward_port_with_suggested(
            &self.connector,
            self.gateway,
            proto,
            internal_port,
            local_target,
            suggested_external_port,
            credential,
        )
        .await
        .map_err(|e| {
            crate::entitlements::forward_error(e, self.entitlements.as_ref(), lease.as_deref())
        })
    }
}

/// A running non-root proxy datapath. Dropping it stops the proxy.
pub struct ProxyHandle {
    pub(crate) local_addr: SocketAddr,
    pub(crate) http_addr: Option<SocketAddr>,
    pub(crate) credentials: ProxyCredentials,
    pub(crate) state_rx: tokio::sync::watch::Receiver<TunnelState>,
    pub(crate) forward_connector: warren_net::TunnelConnector,
    pub(crate) gateway: std::net::Ipv4Addr,
    /// doc 79: the selected exit's NAT-PMP capability, threaded onto every
    /// [`ProxyForwarder`] this handle hands out so [`Self::forward_port`] gates
    /// on it. `true` by default (set by [`serve_proxy_over_sink`]); the
    /// single-hop [`start_proxy`](crate::WarrenClient::start_proxy) overrides it
    /// from the resolved relay's roster flag.
    pub(crate) port_forward_supported: bool,
    /// The wallet's port entitlements, threaded onto every [`ProxyForwarder`]
    /// this handle hands out. Set by the client that started the datapath.
    pub(crate) entitlements: Option<crate::entitlements::PortEntitlements>,
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

    /// The credentials every client of this datapath's listeners must present.
    #[must_use]
    pub fn credentials(&self) -> &ProxyCredentials {
        &self.credentials
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
            port_forward_supported: self.port_forward_supported,
            entitlements: self.entitlements.clone(),
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
/// optional HTTP CONNECT) proxy. Shared by the single-hop and multihop circuit modes.
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

    let credentials = session_credentials(cfg);
    let socks_listener = tokio::net::TcpListener::bind(cfg.socks5)
        .await
        .map_err(SdkError::Proxy)?;
    let local_addr = socks_listener.local_addr().map_err(SdkError::Proxy)?;
    let socks = warren_net::Socks5Proxy::new(connector.clone(), credentials.clone());
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
        let http = warren_net::HttpConnectProxy::new(connector, credentials.clone());
        tasks.push(tokio::spawn(async move {
            let _ = http.serve(http_listener).await;
        }));
    }

    Ok(ProxyHandle {
        local_addr,
        http_addr,
        credentials,
        state_rx,
        forward_connector,
        gateway,
        // Default to permissive: the exit's roster capability is not known on
        // this shared path (multihop carries no such flag yet). The single-hop
        // start_proxy overrides this from the resolved relay (doc 79).
        port_forward_supported: true,
        entitlements: None,
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
