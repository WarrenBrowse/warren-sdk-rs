//! Shared QUIC dial glue for the Warren client datapaths.
//!
//! The building blocks the multihop tunnel ([`crate::multihop`]) and the
//! TLS-over-TCP carrier ([`crate::tcp_fallback`]) dial with: source-IP / bind
//! resolution, the raw-public-key and WebPKI inner QUIC client configs, the
//! shared engine transport profile, and the [`dial_quic`] / [`dial_quic_webpki`]
//! handshake prefix. Pure protocol logic: no TUN, routing, DNS or OS coupling.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

// The client ALPN (IETF HTTP/3, mimicking a casual h3 dial) has a single home in
// the engine config, shared with the fake exit and the real exit.
use warrenguard_config::ALPN_H3;
use warrenguard_socket_bypass::{SocketBypass, apply as apply_socket_bypass};

use crate::tls;

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
/// prefix of every Warren tunnel handshake.
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
    // its own identity in-band in the sealed multihop setup exchange.
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

/// The Warren userland **client** QUIC transport profile: the single,
/// production-proven engine profile
/// ([`warrenguard_transport_core::warren_transport_config_client`]), shared with
/// warren-app and warren-core. The SDK builds on the same warren-quinn fork, so
/// it consumes this directly rather than keeping a private, drifting copy. It
/// carries fast dead-exit detection (5 s keep-alive / 25 s idle), the RFC 9312
/// spin-bit fingerprint defense (`allow_spin(false)`), BBR with tuned windows
/// and DPLPMTUD from a 1200-byte floor, and the Initial-obfuscation knobs
/// (ClientHello split + first-datagram padding) every consumer, proxy mode
/// included, presents.
pub(crate) fn warren_transport_config() -> Arc<quinn::TransportConfig> {
    warrenguard_transport_core::warren_transport_config_client()
}

/// Transport config for ADR-0006 idle cover. When `idle_cover` is true the
/// keep-alive PING is DISABLED: the idle cover driver
/// ([`warrenguard_pump::idle_cover::IdleCoverDriver`]) refreshes the NAT mapping and resets
/// the idle timeout with jittered, size-varied dummies instead, removing the
/// fixed keep-alive beacon. The idle timeout still detects a dead exit. The
/// caller MUST run the cover driver when this is set, or the connection has no
/// liveness mechanism beyond the idle timeout. With `idle_cover` false this is
/// identical to [`warren_transport_config`].
#[must_use]
pub(crate) fn warren_transport_config_with_idle_cover(
    idle_cover: bool,
) -> Arc<quinn::TransportConfig> {
    warrenguard_transport_core::warren_transport_config_client_with_idle_cover(true, idle_cover)
}

/// Picks the transport config for a dial: an explicit caller override wins, else
/// the shared engine client profile ([`warren_transport_config`]). The override
/// seam is kept for a caller that needs a bespoke `quinn::TransportConfig` (a
/// custom bench or a differently-tuned datapath); it is not needed to obtain the
/// obfuscation or liveness profile any more, since that is now the default.
pub(crate) fn effective_transport_config(
    override_cfg: Option<Arc<quinn::TransportConfig>>,
) -> Arc<quinn::TransportConfig> {
    override_cfg.unwrap_or_else(warren_transport_config)
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
    /// Writing or reading a handshake frame failed: a quinn stream I/O error, or
    /// a wire encode/decode failure, kept behind a boxed `dyn Error` so the
    /// concrete cause chains via `source()` without leaking into `Display`.
    #[error("handshake i/o error: {context}")]
    HandshakeIo {
        /// Which handshake step failed.
        context: &'static str,
        /// Underlying quinn stream or wire-codec error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The handshake frame did not decode.
    #[error("handshake frame error")]
    Frame(#[from] warren_wire::ProtocolError),
    /// The exit's in-band identity proof (wg-0005 Stage 1) did not verify
    /// against the pubkey the client dialed.
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
    /// The exit is draining for planned maintenance and refused this NEW
    /// session. The account is fine, but redialing THIS exit re-hits the
    /// refusal, so the caller reselects another exit
    /// ([`Retryability::RetryReselect`](warrenguard_transport::Retryability)).
    /// Distinct from [`TunnelError::Internal`] so the engine's
    /// `ExitDrainingRefused` keeps its reselect signal instead of being
    /// flattened.
    #[error("exit is draining: new sessions refused")]
    ExitDraining,
    /// The exit's tunnel IP pool is exhausted. Like [`TunnelError::ExitDraining`]
    /// this reselects a different exit rather than surfacing fatal or hammering
    /// the full one (aligns with multi-hop `IpExhausted`).
    #[error("exit ip pool exhausted")]
    PoolExhausted,
    /// Catch-all for an engine transport error variant not otherwise mapped,
    /// kept so the error surface stays exhaustive against the engine's
    /// `#[non_exhaustive]` error type as it grows.
    #[error("internal tunnel error: {0}")]
    Internal(String),
}

impl TunnelError {
    /// The engine's reconnect verdict for this failure, mapped (never
    /// re-decided) from the engine's own classification: business rejections
    /// are fatal, the drain/pool-exhaustion refusals reselect another exit, and
    /// every transport-level loss retries the same target.
    #[must_use]
    pub fn retryability(&self) -> warrenguard_transport::Retryability {
        use warrenguard_transport::{FatalCause, Retryability};
        match self {
            TunnelError::AuthRejected => Retryability::Fatal(FatalCause::NotAuthorized),
            TunnelError::DeviceLimitReached => Retryability::Fatal(FatalCause::DeviceLimit),
            TunnelError::ExitDraining | TunnelError::PoolExhausted => Retryability::RetryReselect,
            _ => Retryability::RetrySameTarget,
        }
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

/// Builds the WebPKI client config for the cover-domain TLS handshake of the
/// fallback carrier: standard Mozilla roots and the plausible TCP ALPN, exactly
/// as a browser dialling the cover host over HTTPS. Shared by the multihop
/// carrier path (which maps the error into its own tunnel error).
pub(crate) fn cover_tls_client_config() -> Result<Arc<rustls::ClientConfig>, tls::WarrenTlsError> {
    let cfg = warrenguard_tls::build_client_rustls_config_webpki(
        tls::mozilla_root_store(),
        tls::default_crypto_provider(),
        crate::tcp_fallback::COVER_TCP_ALPN,
    )?;
    Ok(Arc::new(cfg))
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
        let custom = warren_transport_config();
        let chosen = effective_transport_config(Some(Arc::clone(&custom)));
        assert!(
            Arc::ptr_eq(&custom, &chosen),
            "an explicit transport config override must be used as-is"
        );
    }

    #[test]
    fn effective_transport_config_falls_back_to_the_default() {
        // No override: a fresh default (the shared engine client profile) is built.
        let a = effective_transport_config(None);
        let b = effective_transport_config(None);
        assert!(
            !Arc::ptr_eq(&a, &b),
            "the default path builds a fresh config each call (no shared override)"
        );
    }

    #[test]
    fn default_transport_config_is_the_engine_userland_client_profile() {
        // Anti-drift: the SDK's default dial profile MUST be the single,
        // production-proven engine client profile, not a private copy that
        // silently mirrored the SERVER idle/keep-alive pair. These are the facts
        // the profile pins and the old SDK copy got wrong: fast dead-exit
        // detection (5 s keep-alive / 25 s idle, not 20 s / 180 s), the RFC 9312
        // spin-bit fingerprint defense (allow_spin off), the 1200-byte min-MTU
        // floor, and the Initial-obfuscation knobs.
        let rendered = format!("{:?}", warren_transport_config());
        assert!(
            rendered.contains("keep_alive_interval: Some(5s)"),
            "keep-alive must be 5 s (engine client profile), got: {rendered}"
        );
        assert!(
            rendered.contains("max_idle_timeout: Some(25000)"),
            "idle timeout must be 25 s (engine client profile), got: {rendered}"
        );
        assert!(
            rendered.contains("allow_spin: false"),
            "the RFC 9312 spin-bit defense must be on (allow_spin false), got: {rendered}"
        );
        assert!(
            rendered.contains("min_mtu: 1200"),
            "the min-MTU floor must be 1200 (engine client profile), got: {rendered}"
        );
        assert!(
            rendered.contains("initial_crypto_first_fragment_size: Some(64)"),
            "the ClientHello-split obfuscation knob must be set, got: {rendered}"
        );
        assert!(
            rendered.contains("initial_datagram_min_size: 1200"),
            "the first-Initial padding obfuscation knob must be set to the engine's \
             reduced-MTU-safe 1200 (a larger padded Initial black-holes on nested/reduced-MTU \
             paths), got: {rendered}"
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
