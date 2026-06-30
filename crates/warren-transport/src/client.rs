//! Identity-bound QUIC client tunnel: handshake and datagram session.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warren_wire::{DEVICE_ID_LEN, MAX_SETUP_FRAME_BYTES, Setup, decode_setup_ack, encode_setup};

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
}

/// Dials and authenticates a QUIC connection to `exit_addr`: builds the TLS
/// raw-public-key client config, binds a local endpoint matching the address
/// family (unless `bind_local_ip` pins one), connects with the SNI-encoded exit
/// key, and confirms the authenticated peer key equals `exit_pubkey`. The shared
/// prefix of every Warren tunnel handshake (single-hop and multihop).
/// Returns the dialed `(Endpoint, Connection)`. The endpoint drives the
/// connection's I/O, so the caller must keep it alive for the session's lifetime.
pub(crate) async fn dial_quic(
    exit_pubkey: [u8; 32],
    exit_addr: SocketAddr,
    bind_local_ip: Option<SocketAddr>,
    transport_config: Option<Arc<quinn::TransportConfig>>,
) -> Result<(quinn::Endpoint, quinn::Connection), QuicDialError> {
    // v5: the client is anonymous at the TLS layer (no client cert). The exit
    // identity is pinned via the SNI: the server-cert verifier fails the
    // handshake unless the exit proves possession of `exit_pubkey`, so a
    // separate post-handshake peer-pubkey check is redundant. The CLIENT proves
    // its own identity in-band when it sends `Setup` (see `connect`).
    let mut client_cfg = tls::make_client_config(tls::default_crypto_provider(), &[ALPN_H3])
        .map_err(QuicDialError::Tls)?;
    client_cfg.transport_config(effective_transport_config(transport_config));

    let bind = bind_local_ip.unwrap_or_else(|| {
        if exit_addr.is_ipv6() {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        }
    });
    let mut endpoint = quinn::Endpoint::client(bind).map_err(QuicDialError::Bind)?;
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
    let mut endpoint = quinn::Endpoint::client(bind).map_err(QuicDialError::Bind)?;
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
    /// Writing or reading the Setup/SetupAck frame failed. The source is one of
    /// quinn's stream error types, kept behind a boxed `dyn Error`.
    #[error("handshake i/o error: {context}")]
    HandshakeIo {
        /// Which handshake step failed.
        context: &'static str,
        /// Underlying quinn stream error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The Setup/SetupAck frame did not decode.
    #[error("handshake frame error")]
    Frame(#[from] warren_wire::ProtocolError),
    /// The exit's authenticated pubkey did not match the expected one.
    #[error("exit identity mismatch (possible MITM)")]
    ExitIdentityMismatch,
    /// Sending a datagram failed (too large, or connection closing).
    #[error("send datagram failed")]
    SendDatagram(#[source] quinn::SendDatagramError),
    /// Reading a datagram failed (connection closed).
    #[error("read datagram failed")]
    ReadDatagram(#[source] quinn::ConnectionError),
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
    /// first frame on every connection and reject a bare [`Setup`] with `malformed
    /// setup frame`. This single-hop path therefore only completes against the
    /// in-repo fake exits and test harnesses; the live datapath is
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
        // An explicit override wins; else, when idle cover is on, use the
        // keep-alive-disabled config so the cover driver replaces the beacon.
        let transport_config = self.transport_config.clone().or_else(|| {
            self.idle_cover
                .then(|| Arc::new(warren_transport_config_with_idle_cover(true)))
        });
        let (endpoint, conn) = dial_quic(
            exit_pubkey,
            exit_addr,
            effective_bind(self.bind_local_ip, self.auto_local_ip, exit_addr),
            transport_config,
        )
        .await?;

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| TunnelError::Quic {
            context: "open_bi",
            source: e,
        })?;

        // v5 in-band client auth: sign this connection's channel binding (bound
        // to the device_id) with the client identity key; the exit verifies it
        // before admitting the session (the exit requests no TLS client cert).
        let cb = tls::channel_binding(&conn).map_err(TunnelError::Tls)?;
        let setup = Setup {
            protocol_version: warren_wire::PROTOCOL_VERSION,
            features: self.features,
            connection_index: 0,
            total_connections: 1,
            daita_support: self.daita_support,
            device_id: self.device_id,
            client_pubkey: self.signing_key.verifying_key().to_bytes(),
            auth_sig: warren_wire::AuthSig(tls::sign_client_auth(
                &self.signing_key,
                &cb,
                &self.device_id,
            )),
        };
        send.write_all(&encode_setup(&setup)?)
            .await
            .map_err(|e| TunnelError::HandshakeIo {
                context: "write setup",
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::HandshakeIo {
            context: "finish setup",
            source: Box::new(e),
        })?;

        let ack_bytes = recv.read_to_end(MAX_SETUP_FRAME_BYTES).await.map_err(|e| {
            TunnelError::HandshakeIo {
                context: "read setup_ack",
                source: Box::new(e),
            }
        })?;
        let ack = decode_setup_ack(&ack_bytes)?;

        Ok(ClientSession {
            _endpoint: endpoint,
            conn,
            assigned_ipv4: Ipv4Addr::from(ack.tunnel_ipv4),
            assigned_ipv6: ack.tunnel_ipv6.map(Ipv6Addr::from),
            assigned_max_mtu: ack.max_mtu,
            exit_pubkey,
            negotiated_daita: ack.daita_spec,
        })
    }
}

/// First byte of a DAITA cover (dummy) datagram. Not a valid IP version nibble
/// (4 or 6), so the exit drops it; same convention as the multihop data plane.
const DAITA_DUMMY_FIRST_BYTE: u8 = 0xFF;

/// Converts a negotiated wire DAITA spec into a runnable maybenot state. Shared
/// by [`ClientSession::build_daita_state`] and its tests.
fn daita_state_from_spec(
    spec: &warren_wire::DaitaConfig,
    start_time: std::time::Instant,
) -> Result<warren_daita::DaitaState, warren_daita::DaitaError> {
    let cfg = warren_daita::DaitaConfig::from_specs(
        spec.machine_specs.clone(),
        spec.max_padding_frac,
        spec.max_blocking_frac,
    );
    warren_daita::DaitaState::from_config(&cfg, start_time)
}

/// An established tunnel session over which IP packets travel as QUIC datagrams.
pub struct ClientSession {
    // Held so the endpoint outlives the connection.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    assigned_ipv4: Ipv4Addr,
    assigned_ipv6: Option<Ipv6Addr>,
    assigned_max_mtu: u16,
    exit_pubkey: [u8; 32],
    /// The DAITA machine spec the exit negotiated in the `SetupAck`, if any.
    /// Single-hop DAITA is negotiated (unlike the client-unilateral multihop
    /// path): the exit dictates the schedule both sides run.
    negotiated_daita: Option<warren_wire::DaitaConfig>,
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
            .field("assigned_max_mtu", &self.assigned_max_mtu)
            .field("daita", &self.negotiated_daita.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    /// The tunnel IPv4 the exit assigned to this session.
    #[must_use]
    pub fn assigned_ipv4(&self) -> Ipv4Addr {
        self.assigned_ipv4
    }

    /// The tunnel IPv6 the exit assigned, if any.
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<Ipv6Addr> {
        self.assigned_ipv6
    }

    /// The negotiated maximum MTU.
    #[must_use]
    pub fn assigned_max_mtu(&self) -> u16 {
        self.assigned_max_mtu
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
        self.negotiated_daita.as_ref()
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
        let spec = self.negotiated_daita.as_ref()?;
        Some(daita_state_from_spec(spec, start_time))
    }

    /// The largest inner payload a cover datagram can carry on the current path.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        const BASE_MTU: usize = 1280;
        self.conn.max_datagram_size().unwrap_or(BASE_MTU)
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
        let mut dummy = Vec::with_capacity(padding_len + 1);
        dummy.push(DAITA_DUMMY_FIRST_BYTE);
        dummy.resize(padding_len + 1, 0u8);
        self.send_datagram(dummy)
    }

    /// The largest datagram payload the current path can carry, if known.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// The underlying quinn connection (for the pump and advanced callers).
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
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
        self.conn
            .send_datagram(payload.into())
            .map_err(TunnelError::SendDatagram)
    }

    /// Awaits the next inbound datagram, returning the zero-copy [`bytes::Bytes`]
    /// from quinn directly (no per-packet allocation).
    ///
    /// # Errors
    ///
    /// [`TunnelError::ReadDatagram`] if the connection closed.
    pub async fn read_datagram(&self) -> Result<bytes::Bytes, TunnelError> {
        self.conn
            .read_datagram()
            .await
            .map_err(TunnelError::ReadDatagram)
    }

    /// Closes the connection cleanly.
    pub fn disconnect(&self) {
        self.conn.close(0u32.into(), b"client disconnect");
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
    fn negotiated_daita_spec_builds_a_runnable_state() {
        // The negotiated single-hop spec must flow from the wire DaitaConfig into
        // a runnable maybenot DaitaState (consuming the SetupAck.daita_spec that
        // was previously discarded). Use a real curated machine spec.
        let machine = warren_daita::DaitaPool::default_pool()
            .pick_named_os("tamaraw")
            .expect("tamaraw is in the pool");
        let spec = warren_wire::DaitaConfig {
            machine_specs: machine.machine_specs.clone(),
            max_padding_frac: machine.max_padding_frac,
            max_blocking_frac: machine.max_blocking_frac,
        };
        let state = daita_state_from_spec(&spec, std::time::Instant::now())
            .expect("a valid negotiated spec builds a state");
        assert!(state.is_enabled());
    }

    #[test]
    fn an_unparseable_negotiated_machine_spec_is_an_error() {
        let spec = warren_wire::DaitaConfig {
            machine_specs: vec!["not-a-valid-machine".to_owned()],
            max_padding_frac: 0.1,
            max_blocking_frac: 0.1,
        };
        assert!(daita_state_from_spec(&spec, std::time::Instant::now()).is_err());
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
