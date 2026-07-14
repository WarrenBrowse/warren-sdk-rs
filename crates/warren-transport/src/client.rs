//! Identity-bound QUIC client tunnel: handshake and datagram session.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warren_wire::DEVICE_ID_LEN;
use warrenguard_socket_bypass::{SocketBypass, apply as apply_socket_bypass};
use warrenguard_transport_core::error::TunnelError as EngineTunnelError;

use crate::tls;

/// ALPN offered by the client: IETF HTTP/3, mimicking a casual h3 dial.
const ALPN_H3: &[u8] = b"h3";

/// Client-side QUIC tuning for a VPN datagram workload. Mirrors warren-core's
/// pinned constants: large datagram buffers to absorb internet jitter, an idle
/// timeout and keepalive to detect dead peers and survive NAT expiry, and an
/// initial MTU of 1280 (IPv6 minimum, safe on every path) to start PMTU
/// discovery one round trip ahead.
const DATAGRAM_RECV_BUFFER: usize = 8 * 1024 * 1024;
const DATAGRAM_SEND_BUFFER: usize = 4 * 1024 * 1024;
const MAX_IDLE_TIMEOUT_SECS: u64 = 180;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 20;
const INITIAL_MTU: u16 = 1280;

/// Resolves the QUIC endpoint bind address: an explicit pin wins; else, when
/// `auto` is set, the detected default-route source IP (port 0); else `None`
/// (unspecified bind, OS chooses). Shared by both tunnels.
pub(crate) fn effective_bind(
    explicit: Option<SocketAddr>,
    auto: bool,
    exit_addr: SocketAddr,
) -> Option<SocketAddr> {
    if explicit.is_some() {
        return explicit;
    }
    auto.then(|| local_ip_for_endpoint(exit_addr).map(|ip| SocketAddr::new(ip, 0)))
        .flatten()
}

/// Detects the local source IP the OS would use to reach `exit_addr`, for pinning
/// the QUIC endpoint to the default-route interface on a multi-homed host.
///
/// It binds a UDP socket and `connect`s it to the endpoint, which selects a route
/// and source address without sending any packet, then reads the chosen local IP.
/// Returns `None` if the IP is unspecified (no route) or the probe fails, in which
/// case the caller should fall back to an unspecified bind (let the OS choose).
#[must_use]
pub fn local_ip_for_endpoint(exit_addr: SocketAddr) -> Option<std::net::IpAddr> {
    let bind: SocketAddr = if exit_addr.is_ipv6() {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    };
    let sock = std::net::UdpSocket::bind(bind).ok()?;
    sock.connect(exit_addr).ok()?;
    let local = sock.local_addr().ok()?.ip();
    (!local.is_unspecified()).then_some(local)
}

/// Failure dialing the QUIC connection, before any Warren framing. Mapped by
/// each tunnel into its own error enum (see the `From` impls), so the shared
/// [`dial_quic`] handshake prefix is written once.
#[derive(Debug)]
pub(crate) enum QuicDialError {
    Tls(tls::WarrenTlsError),
    Bind(std::io::Error),
    Connect(quinn::ConnectError),
    Quic(quinn::ConnectionError),
    /// The opt-in TLS-over-TCP fallback race ended without a connection: the UDP
    /// handshake failed or timed out and the TCP carrier was disabled or also
    /// failed. Carries the engine's typed outcome (its `Display` has no address).
    Fallback(warrenguard_tcp_fallback::FallbackError),
}

/// Builds the inner QUIC client config shared by the UDP dial and the
/// TLS-over-TCP carrier: RPK TLS 1.3 pinning the exit pubkey via the SNI, the
/// `h3` ALPN, and the effective (obfuscated) transport config. Keeping it in one
/// place is what makes the carrier's QUIC handshake byte-for-byte the UDP one.
pub(crate) fn build_inner_rpk_client_config(
    transport_config: Option<Arc<quinn::TransportConfig>>,
) -> Result<quinn::ClientConfig, QuicDialError> {
    let mut client_cfg = tls::make_client_config(tls::default_crypto_provider(), &[ALPN_H3])
        .map_err(QuicDialError::Tls)?;
    client_cfg.transport_config(effective_transport_config(transport_config));
    Ok(client_cfg)
}

/// WebPKI (X.509 cover-domain) analogue of [`build_inner_rpk_client_config`]: the
/// inner QUIC config for the cover-posture dial, validating the exit's real
/// certificate chain against Mozilla roots with the cover domain as SNI, the `h3`
/// ALPN, and the effective transport config. Keeping it here is what makes the
/// carrier's inner QUIC handshake byte-for-byte the [`dial_quic_webpki`] UDP one,
/// so the only thing that changes over the carrier is the socket underneath.
pub(crate) fn build_inner_webpki_client_config(
    transport_config: Option<Arc<quinn::TransportConfig>>,
) -> Result<quinn::ClientConfig, QuicDialError> {
    let mut client_cfg = tls::make_client_config_webpki(
        tls::mozilla_root_store(),
        tls::default_crypto_provider(),
        &[ALPN_H3],
    )
    .map_err(QuicDialError::Tls)?;
    client_cfg.transport_config(effective_transport_config(transport_config));
    Ok(client_cfg)
}

/// Binds the carrier UDP socket for a QUIC endpoint and applies the per-OS
/// tunnel bypass to it BEFORE it can send, so a privileged TUN datapath's
/// split-default capture keeps this socket on the physical link instead of
/// looping it into the tunnel (`SO_MARK` on Linux, `IP_BOUND_IF` on macOS,
/// `IP_UNICAST_IF` on Windows). This is what lets the datapath drop the old
/// `<exit_ip>/32` host route, closing Port Fail / TunnelCrack ServerIP.
///
/// Fail-closed: a bypass this OS cannot honour is returned as a [`QuicDialError::Bind`],
/// so a mis-wired caller refuses the socket rather than letting the carrier leak.
pub(crate) fn bind_endpoint_socket(
    bind: SocketAddr,
    socket_bypass: Option<SocketBypass>,
) -> Result<std::net::UdpSocket, QuicDialError> {
    let socket = std::net::UdpSocket::bind(bind).map_err(QuicDialError::Bind)?;
    if let Some(bypass) = socket_bypass {
        apply_socket_bypass(&socket, bypass).map_err(QuicDialError::Bind)?;
    }
    Ok(socket)
}

/// Builds the QUIC client endpoint bound to `bind`. With no bypass this is
/// `Endpoint::client` verbatim (userland proxy, mobile): the userland datapath
/// installs no OS tunnel, so its socket must never be marked/bound. With a bypass
/// the socket is bound and pinned to the physical link first, then handed to
/// quinn (privileged TUN datapath).
fn build_client_endpoint(
    bind: SocketAddr,
    socket_bypass: Option<SocketBypass>,
) -> Result<quinn::Endpoint, QuicDialError> {
    if socket_bypass.is_none() {
        return quinn::Endpoint::client(bind).map_err(QuicDialError::Bind);
    }
    let socket = bind_endpoint_socket(bind, socket_bypass)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| QuicDialError::Bind(std::io::Error::other("no quinn async runtime")))?;
    quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
        .map_err(QuicDialError::Bind)
}

/// Dials and authenticates a QUIC connection to `exit_addr`: builds the TLS
/// raw-public-key client config, binds a local endpoint matching the address
/// family (unless `bind_local_ip` pins one), connects with the SNI-encoded exit
/// key, and confirms the authenticated peer key equals `exit_pubkey`. The shared
/// prefix of every Warren tunnel handshake (single-hop and multihop).
/// `socket_bypass` keeps the carrier socket on the physical link for a privileged
/// TUN datapath (`None` for the userland proxy). Returns the dialed
/// `(Endpoint, Connection)`. The endpoint drives the connection's I/O, so the
/// caller must keep it alive for the session's lifetime.
pub(crate) async fn dial_quic(
    exit_pubkey: [u8; 32],
    exit_addr: SocketAddr,
    bind_local_ip: Option<SocketAddr>,
    transport_config: Option<Arc<quinn::TransportConfig>>,
    socket_bypass: Option<SocketBypass>,
) -> Result<(quinn::Endpoint, quinn::Connection), QuicDialError> {
    // v5: the client is anonymous at the TLS layer (no client cert). The exit
    // identity is pinned via the SNI: the server-cert verifier fails the
    // handshake unless the exit proves possession of `exit_pubkey`, so a
    // separate post-handshake peer-pubkey check is redundant. The CLIENT proves
    // its own identity in-band when it sends `Setup` (see `connect`).
    let client_cfg = build_inner_rpk_client_config(transport_config)?;

    let bind = bind_local_ip.unwrap_or_else(|| {
        if exit_addr.is_ipv6() {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        }
    });
    let mut endpoint = build_client_endpoint(bind, socket_bypass)?;
    endpoint.set_default_client_config(client_cfg);

    let server_name = tls::name::encode(tls::WarrenPubkey::from_bytes(exit_pubkey));
    let conn = endpoint
        .connect(exit_addr, &server_name)
        .map_err(QuicDialError::Connect)?
        .await
        .map_err(QuicDialError::Quic)?;

    Ok((endpoint, conn))
}

/// Dials a QUIC connection to `exit_addr` using WebPKI (X.509) certificate
/// validation: the relay must present a real certificate chain trusted by
/// `roots` (Mozilla roots in production), and `server_name` is the SNI sent in
/// the ClientHello (the cover domain from the relay roster). This is the
/// X.509 cover-domain path (ADR-0004); the relay's Warren identity is then
/// confirmed in-band by the caller via the relay-auth proof exchange. Returns
/// `(Endpoint, Connection)`.
pub(crate) async fn dial_quic_webpki(
    server_name: &str,
    exit_addr: SocketAddr,
    bind_local_ip: Option<SocketAddr>,
    transport_config: Option<Arc<quinn::TransportConfig>>,
    socket_bypass: Option<SocketBypass>,
) -> Result<(quinn::Endpoint, quinn::Connection), QuicDialError> {
    let mut client_cfg = tls::make_client_config_webpki(
        tls::mozilla_root_store(),
        tls::default_crypto_provider(),
        &[ALPN_H3],
    )
    .map_err(QuicDialError::Tls)?;
    client_cfg.transport_config(effective_transport_config(transport_config));

    let bind = bind_local_ip.unwrap_or_else(|| {
        if exit_addr.is_ipv6() {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        }
    });
    let mut endpoint = build_client_endpoint(bind, socket_bypass)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(exit_addr, server_name)
        .map_err(QuicDialError::Connect)?
        .await
        .map_err(QuicDialError::Quic)?;

    Ok((endpoint, conn))
}

pub(crate) fn warren_transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
    tc.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    tc.keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)));
    tc.initial_mtu(INITIAL_MTU);
    // Anti-ossification Initial fragmentation, on by default so every consumer
    // of this SDK (proxy mode included) presents the same handshake shape: cap
    // the first CRYPTO fragment and pad the first Initial datagram(s) so the
    // handshake spans two or more UDP datagrams.
    tc.initial_crypto_first_fragment_size(Some(64));
    tc.initial_datagram_min_size(INITIAL_MTU);
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS)) {
        tc.max_idle_timeout(Some(idle));
    }
    tc
}

/// Transport config for ADR-0006 idle cover. When `idle_cover` is true the
/// keep-alive PING is DISABLED: the idle cover driver
/// ([`crate::idle_cover::IdleCoverDriver`]) refreshes the NAT mapping and resets
/// the idle timeout with jittered, size-varied dummies instead, removing the
/// fixed keep-alive beacon. The idle timeout still detects a dead exit. The
/// caller MUST run the cover driver when this is set, or the connection has no
/// liveness mechanism beyond the idle timeout. With `idle_cover` false this is
/// identical to [`warren_transport_config`].
#[must_use]
pub(crate) fn warren_transport_config_with_idle_cover(idle_cover: bool) -> quinn::TransportConfig {
    let mut tc = warren_transport_config();
    if idle_cover {
        tc.keep_alive_interval(None);
    }
    tc
}

/// Picks the transport config for a dial: an explicit caller override wins, else
/// the SDK's upstream-quinn default ([`warren_transport_config`]). The override
/// is how a fork-patched workspace (the privileged system-VPN daemon) injects
/// the engine's QUIC-Initial obfuscation config without this crate ever naming a
/// fork-only quinn API, so the SDK keeps building on upstream quinn. See
/// ARCHITECTURE.md "QUIC handshake obfuscation".
pub(crate) fn effective_transport_config(
    override_cfg: Option<Arc<quinn::TransportConfig>>,
) -> Arc<quinn::TransportConfig> {
    override_cfg.unwrap_or_else(|| Arc::new(warren_transport_config()))
}

/// Errors from establishing or driving a tunnel.
///
/// Underlying causes are attached via [`std::error::Error::source`] rather than
/// formatted into the message: this keeps the top-level `Display` free of any
/// address or peer detail (no-log discipline) while preserving the full chain
/// for callers that opt into deeper diagnostics.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// Building the TLS configuration failed.
    #[error("tls config error")]
    Tls(#[from] tls::WarrenTlsError),
    /// Binding the local UDP socket / endpoint failed.
    #[error("endpoint bind failed")]
    Bind(#[source] std::io::Error),
    /// The QUIC connection could not be set up (bad address or config).
    #[error("connect setup failed")]
    Connect(#[source] quinn::ConnectError),
    /// A QUIC stream or connection error occurred mid-handshake.
    #[error("quic error: {context}")]
    Quic {
        /// Where the error happened.
        context: &'static str,
        /// Underlying quinn connection error.
        #[source]
        source: quinn::ConnectionError,
    },
    /// Writing or reading the Setup/SetupAck frame failed: a quinn stream I/O
    /// error, or the engine's own Setup/SetupAck wire encode/decode failure
    /// (delegated via [`map_engine_err`]), kept behind a boxed `dyn Error`.
    #[error("handshake i/o error: {context}")]
    HandshakeIo {
        /// Which handshake step failed.
        context: &'static str,
        /// Underlying quinn stream or wire-codec error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The Setup/SetupAck frame did not decode.
    #[error("handshake frame error")]
    Frame(#[from] warren_wire::ProtocolError),
    /// The exit's in-band identity proof (`SetupAck.exit_auth_sig`, wg-0005
    /// Stage 1) did not verify against the pubkey the client dialed.
    #[error("exit identity mismatch (possible MITM)")]
    ExitIdentityMismatch,
    /// Sending a datagram failed (too large, or connection closing).
    #[error("send datagram failed")]
    SendDatagram(#[source] quinn::SendDatagramError),
    /// Reading a datagram failed (connection closed).
    #[error("read datagram failed")]
    ReadDatagram(#[source] quinn::ConnectionError),
    /// The exit explicitly rejected the handshake: this client's identity is
    /// not authorized (no active subscription / not enrolled). The caller
    /// MUST NOT silently retry (retrying reproduces the same outcome); the
    /// user needs to provision or renew access.
    #[error("exit rejected the handshake: identity not authorized")]
    AuthRejected,
    /// The opt-in TLS-over-TCP fallback race ended without a connection: UDP
    /// failed or timed out and the carrier was disabled or also failed. The
    /// engine's typed outcome is attached via `source()`; its `Display` carries
    /// no address (no-log discipline).
    #[error("tcp fallback dial failed")]
    TcpFallback {
        /// The engine's auto-activation outcome.
        #[source]
        source: warrenguard_tcp_fallback::FallbackError,
    },
    /// The account already has the maximum number of simultaneous devices.
    #[error("device limit reached for this account")]
    DeviceLimitReached,
    /// Catch-all for a delegated engine transport error that cannot occur on
    /// the codepath [`ClientTunnel::connect`] delegates to (dial-time-only,
    /// exit-side-only, or TUN/DAITA variants); kept so [`map_engine_err`]
    /// stays exhaustive against the engine's `#[non_exhaustive]` error type
    /// as it grows.
    #[error("internal tunnel error: {0}")]
    Internal(String),
}

/// Maps a delegated engine
/// [`warrenguard_transport_core::error::TunnelError`] to this crate's
/// [`TunnelError`]. Precise for the variants reachable from
/// [`warrenguard_transport::ClientTunnel::from_established_connection`]
/// (the only engine call [`ClientTunnel::connect`] makes): this SDK dials via
/// its own [`dial_quic`], never the engine's own `bind_client_endpoint`, so
/// the dial-time-only variants (`Bind`/`NoExitAddr`/`QuicConnect`/
/// `QuicEndpoint`), the exit-side-only variants
/// (`InbandAuthFailed`/`DivertedToDecoy`/`AllowlistDenied`), and the
/// TUN/DAITA/persistence variants never surface here; they map to
/// [`TunnelError::Internal`] so the match stays exhaustive against future
/// engine additions.
fn map_engine_err(e: EngineTunnelError) -> TunnelError {
    use EngineTunnelError as E;
    match e {
        E::QuicConnection { context, source } => TunnelError::Quic { context, source },
        E::ChannelBindingExport => TunnelError::Tls(tls::WarrenTlsError::ChannelBindingUnavailable),
        E::ExitAuthFailed => TunnelError::ExitIdentityMismatch,
        E::AuthRejected => TunnelError::AuthRejected,
        E::DeviceLimitReached => TunnelError::DeviceLimitReached,
        E::QuicStream { source, .. } | E::SetupWire { source, .. } => TunnelError::HandshakeIo {
            context: "setup handshake",
            source,
        },
        E::QuicSendDatagram { source, .. } => TunnelError::SendDatagram(source),
        E::QuicReadDatagram { source, .. } => TunnelError::ReadDatagram(source),
        other => TunnelError::Internal(other.to_string()),
    }
}

impl From<QuicDialError> for TunnelError {
    fn from(e: QuicDialError) -> Self {
        match e {
            QuicDialError::Tls(x) => TunnelError::Tls(x),
            QuicDialError::Bind(x) => TunnelError::Bind(x),
            QuicDialError::Connect(x) => TunnelError::Connect(x),
            QuicDialError::Quic(source) => TunnelError::Quic {
                context: "connect",
                source,
            },
            QuicDialError::Fallback(source) => TunnelError::TcpFallback { source },
        }
    }
}

/// Builder for an identity-bound client tunnel.
#[derive(Clone)]
pub struct ClientTunnel {
    signing_key: SigningKey,
    features: u32,
    daita_support: bool,
    device_id: [u8; DEVICE_ID_LEN],
    bind_local_ip: Option<SocketAddr>,
    auto_local_ip: bool,
    transport_config: Option<Arc<quinn::TransportConfig>>,
    idle_cover: bool,
    tcp_fallback: bool,
}

// Manual Debug (no-log discipline): render only a short public-key prefix and the
// non-sensitive flags. The signing key is secret, and `bind_local_ip` is the
// user's own address, so neither is printed.
impl std::fmt::Debug for ClientTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.signing_key.verifying_key().to_bytes();
        f.debug_struct("ClientTunnel")
            .field(
                "public_key",
                &format_args!("{:02x}{:02x}{:02x}{:02x}..", b[0], b[1], b[2], b[3]),
            )
            .field("features", &self.features)
            .field("daita_support", &self.daita_support)
            .field("auto_local_ip", &self.auto_local_ip)
            .finish_non_exhaustive()
    }
}

impl ClientTunnel {
    /// Builds a tunnel for the given identity, default features off.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            features: 0,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            bind_local_ip: None,
            auto_local_ip: false,
            transport_config: None,
            idle_cover: false,
            tcp_fallback: false,
        }
    }

    /// Sets the requested feature bitmask (see `warren_wire::features`).
    #[must_use]
    pub fn with_features(mut self, features: u32) -> Self {
        self.features = features;
        self
    }

    /// Advertises DAITA v2 support in the handshake.
    #[must_use]
    pub fn with_daita(mut self, enable: bool) -> Self {
        self.daita_support = enable;
        self
    }

    /// Sets the per-run device id (16 bytes).
    #[must_use]
    pub fn with_device_id(mut self, device_id: [u8; DEVICE_ID_LEN]) -> Self {
        self.device_id = device_id;
        self
    }

    /// Forces the local bind address (multi-NIC). Defaults to `0.0.0.0:0`.
    #[must_use]
    pub fn with_bind_local_ip(mut self, addr: SocketAddr) -> Self {
        self.bind_local_ip = Some(addr);
        self
    }

    /// Auto-detects the default-route source IP for the exit and binds to it
    /// (multi-NIC determinism). Ignored when [`with_bind_local_ip`](Self::with_bind_local_ip)
    /// is set, and falls back to an unspecified bind if detection fails.
    #[must_use]
    pub fn with_auto_local_ip(mut self) -> Self {
        self.auto_local_ip = true;
        self
    }

    /// Overrides the QUIC transport config (advanced). The default applies the
    /// SDK's upstream-quinn settings; a fork-patched system-VPN workspace passes
    /// the engine's obfuscated config here to match warren-app's anti-DPI
    /// handshake. The `quinn::TransportConfig` type is fork-agnostic. See
    /// ARCHITECTURE.md "QUIC handshake obfuscation".
    #[must_use]
    pub fn with_transport_config(mut self, cfg: Arc<quinn::TransportConfig>) -> Self {
        self.transport_config = Some(cfg);
        self
    }

    /// Enables ADR-0006 idle cover traffic: the keep-alive PING is disabled and
    /// the caller drives [`crate::idle_cover::IdleCoverDriver`] over the returned
    /// session so jittered, size-varied dummies replace the fixed keep-alive
    /// beacon. No effect when an explicit [`with_transport_config`](Self::with_transport_config)
    /// override is set (the override's keep-alive wins). Off by default. The
    /// caller MUST spawn the cover driver, or the session has no keep-alive.
    #[must_use]
    pub fn with_idle_cover(mut self, enable: bool) -> Self {
        self.idle_cover = enable;
        self
    }

    /// Resolves the client's cover-defense request from a single
    /// [`warrenguard_config::knobs::CoverDefenses`] and flips
    /// [`with_daita`](Self::with_daita) and
    /// [`with_idle_cover`](Self::with_idle_cover) together.
    ///
    /// This is the knob-driven switch (the equivalent of a Stealth profile
    /// toggle): the caller resolves the coupled decision once from the process
    /// knobs via [`warrenguard_config::knobs::cover_defenses`] (which enforces
    /// the DAITA / idle-cover mutual exclusion, DAITA superseding idle cover)
    /// and threads it here, so the handshake advertisement and the idle-cover
    /// transport config can never disagree. Off by default: a client that never
    /// calls this requests neither defense.
    #[must_use]
    pub fn with_cover_defenses(
        mut self,
        defenses: warrenguard_config::knobs::CoverDefenses,
    ) -> Self {
        self.daita_support = defenses.daita;
        self.idle_cover = defenses.idle_cover;
        self
    }

    /// Opts this client into the TLS-over-TCP fallback carrier (anti-censorship
    /// datapath). Off by default. This is only the deployer's arm switch: the
    /// fallback still fires only for an exit whose signed roster advertises the
    /// carrier and carries a cover domain, and only after the UDP handshake
    /// fails or times out (see [`connect_with_tcp_fallback`](Self::connect_with_tcp_fallback)).
    #[must_use]
    pub fn with_tcp_fallback(mut self, enable: bool) -> Self {
        self.tcp_fallback = enable;
        self
    }

    /// True if the client is armed for the TLS-over-TCP fallback carrier. The
    /// fallback still gates on the per-exit roster capability and cover domain.
    #[must_use]
    pub fn tcp_fallback(&self) -> bool {
        self.tcp_fallback
    }

    /// True if the client advertises DAITA support in the handshake. The exit
    /// decides whether to honour it from its own pool configuration.
    #[must_use]
    pub fn daita_support(&self) -> bool {
        self.daita_support
    }

    /// True if the client disables the keep-alive PING in favour of idle cover.
    /// The caller MUST drive the cover driver when this is set.
    #[must_use]
    pub fn idle_cover(&self) -> bool {
        self.idle_cover
    }

    /// The client's 32-byte Ed25519 public key.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Connects to an exit and completes the bare Setup/SetupAck handshake.
    ///
    /// `exit_pubkey` is the exit's expected Ed25519 identity (from discovery);
    /// it is encoded into the SNI and re-checked against the authenticated peer
    /// key after the handshake.
    ///
    /// # Production reality
    ///
    /// Production warren-core exits read an HPKE-sealed multihop frame as the
    /// first frame on every connection and reject a bare
    /// [`Setup`](warren_wire::Setup) with `malformed setup frame`. This
    /// single-hop path therefore only completes against the in-repo fake
    /// exits and test harnesses; the live datapath is
    /// [`MultihopClientTunnel`](crate::MultihopClientTunnel). Use this only for
    /// local/test exits, not to reach a real exit.
    ///
    /// # Errors
    ///
    /// See [`TunnelError`].
    pub async fn connect(
        &self,
        exit_pubkey: [u8; 32],
        exit_addr: SocketAddr,
    ) -> Result<ClientSession, TunnelError> {
        // No roster capability is known here, so the fallback stays off (its
        // gate needs the exit's advertised flag): this is the plain UDP dial.
        self.connect_with_tcp_fallback(exit_pubkey, exit_addr, false, None)
            .await
    }

    /// Like [`connect`](Self::connect) but the dial may fall back to the
    /// TLS-over-TCP carrier when UDP is blocked.
    ///
    /// `exit_advertises_fallback` and `cover_domain` come from the selected
    /// exit's signed roster ([`warrenguard_wire::WarrenExitAddr::tcp_fallback`]
    /// and `cover_domain`). The fallback fires only when this client was armed
    /// with [`with_tcp_fallback(true)`](Self::with_tcp_fallback), the exit
    /// advertises the carrier, a cover domain is present, AND the UDP handshake
    /// fails or times out; otherwise the dial is UDP-only and unchanged. On
    /// fallback the same QUIC handshake (RPK identity, `Setup`/`SetupAck`) runs
    /// over the carrier, so the resulting session is indistinguishable.
    ///
    /// # Errors
    /// See [`TunnelError`]; the carrier race surfaces as
    /// [`TunnelError::TcpFallback`].
    pub async fn connect_with_tcp_fallback(
        &self,
        exit_pubkey: [u8; 32],
        exit_addr: SocketAddr,
        exit_advertises_fallback: bool,
        cover_domain: Option<&str>,
    ) -> Result<ClientSession, TunnelError> {
        // An explicit override wins; else, when idle cover is on, use the
        // keep-alive-disabled config so the cover driver replaces the beacon.
        let transport_config = self.transport_config.clone().or_else(|| {
            self.idle_cover
                .then(|| Arc::new(warren_transport_config_with_idle_cover(true)))
        });

        let policy = crate::tcp_fallback::resolve_fallback_policy(
            self.tcp_fallback,
            exit_advertises_fallback,
            cover_domain,
        );
        // Build the cover-domain WebPKI client config (roots + a plausible TCP
        // ALPN) only when the policy is armed; a disabled policy never touches
        // the carrier. `resolve_fallback_policy` guarantees a cover domain here.
        let cover = if policy.tcp_fallback_enabled {
            let client_config = tls_webpki_cover_config()?;
            cover_domain.map(|domain| crate::tcp_fallback::CoverTls {
                addr: SocketAddr::new(exit_addr.ip(), crate::tcp_fallback::COVER_TCP_PORT),
                domain,
                client_config,
            })
        } else {
            None
        };

        let (endpoint, conn) = crate::tcp_fallback::dial_quic_with_fallback(
            exit_pubkey,
            exit_addr,
            effective_bind(self.bind_local_ip, self.auto_local_ip, exit_addr),
            transport_config,
            // Single-hop is not a privileged system-VPN datapath, so its carrier
            // socket is never bypassed (the desktop TUN datapath uses multihop).
            None,
            &policy,
            cover,
        )
        .await?;

        // The Setup/SetupAck handshake (the v5 in-band client auth proof and
        // the wg-0005 Stage 1 in-band exit-identity proof) is delegated to the
        // shared engine `ClientTunnel`, so that protocol logic lives once,
        // shared with warren-core. This SDK keeps only its own dial glue
        // (`dial_quic`, above): `auto_local_ip` detection and the fork-patched
        // `transport_config` override, neither of which the engine's own
        // `bind_client_endpoint` supports.
        let inner = warrenguard_transport::ClientTunnel::with_signing_key(&self.signing_key)
            .with_features(self.features)
            .with_daita(self.daita_support)
            .with_device_id(self.device_id);
        let session = inner
            .from_established_connection(endpoint, conn, tls::WarrenPubkey::from_bytes(exit_pubkey))
            .await
            .map_err(map_engine_err)?;
        let conn = session.clone_conn();

        Ok(ClientSession {
            inner: session,
            conn,
            exit_pubkey,
        })
    }
}

/// Builds the WebPKI client config for the cover-domain TLS handshake of the
/// fallback carrier: standard Mozilla roots and the plausible TCP ALPN, exactly
/// as a browser dialling the cover host over HTTPS. Shared by the single-hop and
/// multihop carrier paths (each maps the error into its own tunnel error).
pub(crate) fn cover_tls_client_config() -> Result<Arc<rustls::ClientConfig>, tls::WarrenTlsError> {
    let cfg = warrenguard_tls::build_client_rustls_config_webpki(
        tls::mozilla_root_store(),
        tls::default_crypto_provider(),
        crate::tcp_fallback::COVER_TCP_ALPN,
    )?;
    Ok(Arc::new(cfg))
}

/// Single-hop wrapper over [`cover_tls_client_config`] mapping to [`TunnelError`].
fn tls_webpki_cover_config() -> Result<Arc<rustls::ClientConfig>, TunnelError> {
    cover_tls_client_config().map_err(TunnelError::Tls)
}

/// An established tunnel session over which IP packets travel as QUIC
/// datagrams. Thin wrapper over the shared engine
/// [`warrenguard_transport::ClientSession`]: the Setup/SetupAck
/// handshake and the datagram plane live once, in `warrenguard-transport`,
/// shared with warren-core.
pub struct ClientSession {
    inner: warrenguard_transport::ClientSession,
    // A cheap clone of the engine's connection (`quinn::Connection` is an
    // Arc-backed handle), for `Self::connection`'s `&self -> &Connection`
    // borrow contract: the engine only exposes to-be-cloned accessors.
    conn: quinn::Connection,
    // Kept SDK-side: the engine session does not retain the dialed pubkey
    // (it only checks it during the handshake), and `Self::exit_pubkey` is a
    // caller convenience predating the delegation.
    exit_pubkey: [u8; 32],
}

// Manual Debug (no-log discipline): the quinn `conn` renders the peer/local
// socket addresses (the user's real outbound IP and the exit IP), and the
// assigned tunnel IPs are address material, so none are printed. Only the exit
// public-key prefix and non-sensitive parameters are shown.
impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.exit_pubkey;
        f.debug_struct("ClientSession")
            .field(
                "exit_pubkey",
                &format_args!("{:02x}{:02x}{:02x}{:02x}..", b[0], b[1], b[2], b[3]),
            )
            .field("assigned_max_mtu", &self.inner.assigned_max_mtu())
            .field("daita", &self.inner.daita_spec().is_some())
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    /// The tunnel IPv4 the exit assigned to this session.
    #[must_use]
    pub fn assigned_ipv4(&self) -> Ipv4Addr {
        self.inner.assigned_ipv4()
    }

    /// The tunnel IPv6 the exit assigned, if any.
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<Ipv6Addr> {
        self.inner.assigned_ipv6()
    }

    /// The negotiated maximum MTU.
    #[must_use]
    pub fn assigned_max_mtu(&self) -> u16 {
        self.inner.assigned_max_mtu()
    }

    /// The exit's authenticated pubkey.
    #[must_use]
    pub fn exit_pubkey(&self) -> [u8; 32] {
        self.exit_pubkey
    }

    /// The DAITA machine spec the exit negotiated in the `SetupAck`, if DAITA was
    /// enabled for this single-hop session (`None` if the exit disabled it).
    #[must_use]
    pub fn negotiated_daita(&self) -> Option<&warren_wire::DaitaConfig> {
        self.inner.daita_spec()
    }

    /// Builds a [`warren_daita::DaitaState`] from the exit-negotiated spec, ready
    /// to drive cover traffic on this session. Returns `None` if the exit did not
    /// negotiate DAITA.
    ///
    /// # Errors
    ///
    /// [`warren_daita::DaitaError`] if a negotiated machine spec is unparseable or
    /// a cap is out of range (the maybenot framework rejects the configuration).
    #[must_use]
    pub fn build_daita_state(
        &self,
        start_time: std::time::Instant,
    ) -> Option<Result<warren_daita::DaitaState, warren_daita::DaitaError>> {
        self.inner.build_daita_state(start_time)
    }

    /// The largest inner payload a cover datagram can carry on the current path.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        self.inner.max_inner_payload()
    }

    /// Sends one DAITA cover (dummy) datagram: a `0xFF` tag followed by
    /// `padding_len` zero bytes. The exit drops it (the first byte is not a valid
    /// IP version), so it shapes traffic without reaching the destination.
    ///
    /// # Errors
    ///
    /// [`TunnelError::SendDatagram`] if the datagram is too large or the
    /// connection is closing.
    pub fn send_cover_traffic(&self, padding_len: usize) -> Result<(), TunnelError> {
        self.inner
            .send_cover_traffic(padding_len)
            .map_err(map_engine_err)
    }

    /// The largest datagram payload the current path can carry, if known.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// The underlying quinn connection (for the pump and advanced callers).
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// The QUIC path round-trip time estimate for this connection, as
    /// smoothed by the congestion controller after the handshake. Feeds
    /// the client-side RTT proximity cache (doc 52 P4). Meaningful once at
    /// least one RTT sample has been taken (post-handshake), which is
    /// always true for a returned [`ClientSession`].
    #[must_use]
    pub fn path_rtt(&self) -> std::time::Duration {
        self.conn.stats().path.rtt
    }

    /// Sends one IP packet as a QUIC datagram (unreliable, unordered).
    ///
    /// Accepts anything convertible into [`bytes::Bytes`] so the caller can pass
    /// a `Bytes` slice without an intermediate copy.
    ///
    /// # Errors
    ///
    /// [`TunnelError::SendDatagram`] if the datagram is too large or the
    /// connection is closing.
    pub fn send_datagram(&self, payload: impl Into<bytes::Bytes>) -> Result<(), TunnelError> {
        self.inner
            .send_datagram_bytes(payload)
            .map_err(map_engine_err)
    }

    /// Awaits the next inbound datagram, returning the zero-copy [`bytes::Bytes`]
    /// from quinn directly (no per-packet allocation).
    ///
    /// # Errors
    ///
    /// [`TunnelError::ReadDatagram`] if the connection closed.
    pub async fn read_datagram(&self) -> Result<bytes::Bytes, TunnelError> {
        self.inner.read_datagram().await.map_err(map_engine_err)
    }

    /// Closes the connection cleanly.
    pub fn disconnect(&self) {
        self.inner.disconnect();
    }
}

impl crate::idle_cover::CoverSink for ClientSession {
    fn send_cover(&self, padding_len: usize) -> bool {
        self.send_cover_traffic(padding_len).is_ok()
    }
    fn max_inner_payload(&self) -> usize {
        self.max_inner_payload()
    }
    fn cover_seed(&self) -> u64 {
        self.conn.stable_id() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn bind_endpoint_socket_applies_the_bypass_and_fails_closed_on_a_wrong_os_variant() {
        // The dialer routes the carrier socket through the per-OS bypass before
        // it can send. A bypass this OS cannot honour must fail closed (the
        // socket is refused), never bind silently and leak the carrier: the
        // routing/killswitch have dropped the destination escape, so an
        // unmarked/unbound socket would be captured into the tunnel. If the
        // dialer ignored the bypass this call would wrongly return `Ok`.
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // No bypass (userland proxy): a plain bind, unchanged.
        assert!(bind_endpoint_socket(bind, None).is_ok());

        // The variant this OS cannot honour (a macOS/Windows interface-bind on
        // Linux, a Linux fwmark on Apple) must be refused as a Bind failure.
        #[cfg(target_vendor = "apple")]
        let wrong = SocketBypass::Fwmark(0x7761_7272);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let wrong = SocketBypass::BoundIf(1);
        #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
        assert!(
            matches!(
                bind_endpoint_socket(bind, Some(wrong)),
                Err(QuicDialError::Bind(_))
            ),
            "a wrong-OS bypass variant must be refused (fail-closed)"
        );
    }

    #[test]
    fn with_cover_defenses_threads_the_resolved_knob_switch() {
        use warrenguard_config::knobs::resolve_cover_defenses;

        let key = SigningKey::from_bytes(&[3u8; 32]);

        // Opt-in only: a fresh client requests neither defense, so a build
        // that never calls the switch is byte-identical to before.
        let fresh = ClientTunnel::new(key.clone());
        assert!(
            !fresh.daita_support() && !fresh.idle_cover(),
            "a fresh ClientTunnel must default to no cover defense"
        );

        // DAITA supersedes idle cover: even with both knobs on, the resolver
        // suppresses idle cover and the switch flips only DAITA on.
        let daita =
            ClientTunnel::new(key.clone()).with_cover_defenses(resolve_cover_defenses(true, true));
        assert!(
            daita.daita_support() && !daita.idle_cover(),
            "requesting DAITA must advertise DAITA and keep idle cover off (mutual exclusion)"
        );

        // Idle-cover-only defenses flip idle cover on and leave DAITA off.
        let idle = ClientTunnel::new(key).with_cover_defenses(resolve_cover_defenses(false, true));
        assert!(
            idle.idle_cover() && !idle.daita_support(),
            "idle-cover-only defenses must enable idle cover and leave DAITA off"
        );
    }

    #[tokio::test]
    async fn negotiated_daita_flows_through_the_delegated_session() {
        // Regression: the exit-negotiated DAITA spec must flow from the
        // delegated engine SetupAck all the way to a runnable maybenot state,
        // through `ClientSession::negotiated_daita` / `build_daita_state`.
        // The maybenot construction itself (including the unparseable-spec
        // error path) is covered by the engine's own
        // `warrenguard_transport::client` tests; this test proves the
        // wrapper's delegation wiring, not the framework internals.
        let exit_key = SigningKey::from_bytes(&[0x51; 32]);
        let exit_pubkey = exit_key.verifying_key().to_bytes();
        let machine = warren_daita::DaitaPool::default_pool()
            .pick_named_os("tamaraw")
            .expect("tamaraw is in the pool");
        let daita_spec = warren_wire::DaitaConfig {
            machine_specs: machine.machine_specs.clone(),
            max_padding_frac: machine.max_padding_frac,
            max_blocking_frac: machine.max_blocking_frac,
        };

        let cfg = tls::make_server_config(&exit_key, tls::default_crypto_provider(), &[b"h3"])
            .expect("server config");
        let endpoint =
            quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind");
        let addr = endpoint.local_addr().expect("local addr");
        let server_spec = daita_spec.clone();
        tokio::spawn(async move {
            let conn = endpoint
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            recv.read_to_end(65536).await.expect("read setup");
            let cb = tls::channel_binding(&conn).expect("server channel binding");
            let ack = warren_wire::SetupAck {
                protocol_version: warren_wire::PROTOCOL_VERSION,
                tunnel_ipv4: [10, 88, 0, 2],
                tunnel_ipv6: None,
                exit_pubkey,
                max_mtu: 1350,
                multiconn_attached: true,
                daita_spec: Some(server_spec),
                exit_auth_sig: warren_wire::AuthSig(tls::sign_server_auth(&exit_key, &cb)),
            };
            send.write_all(&warren_wire::encode_setup_ack(&ack).expect("encode ack"))
                .await
                .expect("write ack");
            send.finish().expect("finish");
            // Keep the connection (and its endpoint) alive until the client
            // closes it, or dropping `endpoint` here could race the FIN flush
            // and abort the reply before the client finishes reading it.
            while conn.read_datagram().await.is_ok() {}
            drop(endpoint);
        });

        let client_key = SigningKey::from_bytes(&[0x22; 32]);
        let session = ClientTunnel::new(client_key)
            .connect(exit_pubkey, addr)
            .await
            .expect("connect must succeed against a correctly-signed exit_auth_sig");

        assert!(session.negotiated_daita().is_some());
        let state = session
            .build_daita_state(std::time::Instant::now())
            .expect("daita_spec was negotiated, so build_daita_state must return Some")
            .expect("the curated tamaraw spec must build a valid DaitaState");
        assert!(state.is_enabled());
    }

    #[test]
    fn local_ip_for_a_loopback_endpoint_is_loopback() {
        // The OS source IP for a loopback destination is loopback, deterministically.
        let ip = local_ip_for_endpoint("127.0.0.1:9".parse().unwrap())
            .expect("a loopback route always exists");
        assert_eq!(ip, std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn effective_transport_config_prefers_the_caller_override() {
        // The override is the seam a fork-patched system-VPN workspace uses to
        // inject the engine's obfuscated config; when present it is used verbatim.
        let custom = Arc::new(warren_transport_config());
        let chosen = effective_transport_config(Some(Arc::clone(&custom)));
        assert!(
            Arc::ptr_eq(&custom, &chosen),
            "an explicit transport config override must be used as-is"
        );
    }

    #[test]
    fn effective_transport_config_falls_back_to_the_default() {
        // No override: a fresh default (SDK upstream-quinn settings) is built.
        let a = effective_transport_config(None);
        let b = effective_transport_config(None);
        assert!(
            !Arc::ptr_eq(&a, &b),
            "the default path builds a fresh config each call (no shared override)"
        );
    }

    #[test]
    fn effective_bind_prefers_explicit_then_auto_then_unspecified() {
        let exit: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let explicit: SocketAddr = "10.0.0.5:0".parse().unwrap();
        // An explicit pin always wins, even with auto on.
        assert_eq!(effective_bind(Some(explicit), true, exit), Some(explicit));
        // No pin, no auto: let the OS choose (unspecified bind).
        assert_eq!(effective_bind(None, false, exit), None);
        // No pin, auto on: detect the source IP (loopback here), OS-chosen port.
        let auto = effective_bind(None, true, exit).expect("auto detects a source");
        assert_eq!(
            auto.ip(),
            std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(auto.port(), 0);
    }

    #[test]
    fn typed_errors_preserve_their_source() {
        let bind = TunnelError::Bind(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "addr in use",
        ));
        assert!(bind.source().is_some(), "Bind must chain its io::Error");

        let send = TunnelError::SendDatagram(quinn::SendDatagramError::TooLarge);
        assert!(
            send.source().is_some(),
            "SendDatagram must chain its quinn error"
        );

        let handshake = TunnelError::HandshakeIo {
            context: "write setup",
            source: Box::new(std::io::Error::other("stream closed")),
        };
        assert!(
            handshake.source().is_some(),
            "HandshakeIo must chain its boxed source"
        );
    }

    #[test]
    fn top_level_display_omits_the_underlying_detail() {
        // No-log discipline: the address-bearing cause stays in source(), not in
        // the Display the embedder is most likely to log.
        let bind = TunnelError::Bind(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "198.51.100.7:443 already in use",
        ));
        assert!(!bind.to_string().contains("198.51.100.7"));
    }
}
