//! Multihop QUIC client tunnel (the handshake real exits actually require).
//!
//! Production exits read an HPKE-sealed [`WarrenMultihopFrame`](warren_wire::multihop::WarrenMultihopFrame) as the first
//! frame on every connection (single-hop included), not a bare
//! `Setup`: a raw Setup is rejected with `malformed setup
//! frame`. This module implements that path:
//!
//! 1. QUIC + TLS handshake against the dialed peer. In X.509 cover-domain mode
//!    (see [`MultihopClientTunnel::with_cover_domain`]), the client validates the
//!    relay's real X.509 chain via WebPKI (Mozilla roots), dialing the cover
//!    domain as the SNI, exactly like a browser. In RPK mode (the default), the
//!    relay's Ed25519 identity is pinned via the SNI (base32-encoded pubkey) and
//!    the raw-public-key TLS verifier.
//! 2. Open a reliable bidi stream and send the sealed setup frame, whose inner
//!    plaintext is an [`IpRequest`](warren_wire::WarrenControlMessage) carrying
//!    the account pubkey and a proof of possession over the session's
//!    `encapsulated_key`. The exit replies with a sealed
//!    [`IpAssign`](warren_wire::WarrenControlMessage) (or `Rejected` /
//!    `IpExhausted`). In X.509 cover-domain mode, step 2 includes an in-band
//!    relay-identity proof exchange (see ADR-0004): after the setup frame is
//!    sent, the client reads the relay's server-initiated bi stream carrying its
//!    Ed25519 signature over the channel binding, and verifies it before reading
//!    the reply. A relay that cannot produce this proof is rejected.
//! 3. IP packets then ride per-packet sealed `WarrenMultihopFrame`s on the QUIC
//!    datagram plane, forward seq continuing from `1` (the setup frame was the
//!    first forward frame, `seq = 0`).
//!
//! The live [`MultihopSession`] can rotate its HPKE epoch in place
//! ([`MultihopSession::rekey`]) without tearing down the connection: a fresh KEM
//! (new `encapsulated_key`), epoch `+1`, the forward sequence restarted at `0`,
//! and the previous epoch retained for an overlap window. The exit re-derives its
//! receiver context implicitly on the new `encapsulated_key` (no rekey control
//! message). [`RekeyPolicy`] carries the warren-core doctrine (rotate within 8 h,
//! 5-second overlap); a supervisor drives it. The whole rotation is validated
//! live against the real `warren-core` exit (see the `real_exit_tests` module).
//! The reverse direction is anti-replay-protected by a per-epoch sliding window,
//! so the new epoch's low sequence numbers are not mistaken for replays.
//!
//! The multihop wire protocol itself (HPKE seal/open, rekey/epoch, the
//! setup-over-stream exchange, and the anti-replay window) is implemented once,
//! in the shared engine crate [`warrenguard_transport::multihop::MultiHopClient`]
//! (also consumed by `warren-core`): [`MultihopSession`] and
//! [`MultihopClientTunnel`] own one and delegate to it, keeping only the pieces
//! genuinely specific to this SDK - the TLS dial (this SDK dials the exit
//! directly, verified via the signed multihop directory, rather than through the
//! engine's relay-descriptor-verified two-hop [`MultiHopClient::connect`]), the
//! per-session byte/packet metrics shape, and the drop-and-retry resilience
//! contract of [`MultihopSession::recv_packet`] (a single malformed, replayed, or
//! misdirected datagram is dropped and retried, never surfaced as a fatal error).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use warren_multihop::{ExitId, IpAssignment, SetupError};
use warren_wire::control::{CONTROL_FIRST_BYTE, WarrenControlMessage, try_decode_control};
use warren_wire::multihop::EXIT_ID_LEN;
use warrenguard_transport::multihop::{
    MultiHopClient, MultiHopError as EngineMultihopError, RekeyPolicy as EngineRekeyPolicy,
};

use crate::client::{QuicDialError, dial_quic, dial_quic_webpki, effective_bind};
use crate::tls;
use warrenguard_socket_bypass::SocketBypass;

/// DAITA dummy first byte (padding traffic), dropped on the receive path.
const DAITA_DUMMY_FIRST_BYTE: u8 = 0xFF;

/// Errors from the multihop tunnel handshake and data plane.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultihopError {
    /// Binding the local UDP socket failed.
    #[error("bind local endpoint failed")]
    Bind(#[source] std::io::Error),
    /// Configuring the QUIC client (TLS provider / RPK) failed.
    #[error("tls configuration failed")]
    Tls(#[source] tls::WarrenTlsError),
    /// Starting the QUIC connection failed (bad address / config).
    #[error("connect setup failed")]
    Connect(#[source] quinn::ConnectError),
    /// A QUIC connection or stream error occurred.
    #[error("quic error during {context}")]
    Quic {
        /// Which step failed.
        context: &'static str,
        /// The underlying quinn error.
        #[source]
        source: quinn::ConnectionError,
    },
    /// The authenticated peer key did not match the pinned exit identity.
    #[error("exit identity mismatch")]
    ExitIdentityMismatch,
    /// Writing or reading the sealed setup frame on the reliable stream failed.
    #[error("setup stream i/o error during {context}")]
    SetupIo {
        /// Which step failed.
        context: &'static str,
        /// The underlying error (boxed: open/write/read types differ).
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The multihop frame failed to encode or decode.
    #[error("multihop frame codec error")]
    Frame(#[source] warren_wire::multihop::MultihopError),
    /// The HPKE setup exchange failed (seal/open, policy rejection, exhaustion).
    #[error("multihop setup failed")]
    Setup(#[source] SetupError),
    /// Sending a datagram failed (too large, or the connection is closing).
    #[error("send datagram failed")]
    SendDatagram(#[source] quinn::SendDatagramError),
    /// Reading a datagram failed (the connection closed).
    #[error("read datagram failed")]
    ReadDatagram(#[source] quinn::ConnectionError),
    /// X.509 cover-domain mode only (ADR-0004): the entry relay did not prove
    /// possession of the Ed25519 identity pinned in the signed relay roster. The
    /// WebPKI handshake succeeded (the relay holds a valid cover-domain cert) but
    /// the in-band relay-auth proof was absent, malformed, or signed by the wrong
    /// key. Fail-closed: a man-in-the-middle holding only the cover-domain cert
    /// must not be dialed through.
    #[error("entry relay identity proof failed: {0}")]
    RelayIdentity(&'static str),
    /// The opt-in TLS-over-TCP carrier race ended without a connection: the UDP
    /// handshake to the entry failed or timed out and the carrier was disabled or
    /// also failed. Carries the engine's typed outcome (its `Display` has no
    /// address). Only reachable in cover-domain mode with the carrier armed.
    #[error("tcp fallback carrier failed")]
    TcpFallback(#[source] warrenguard_tcp_fallback::FallbackError),
}

impl From<QuicDialError> for MultihopError {
    fn from(e: QuicDialError) -> Self {
        match e {
            QuicDialError::Tls(x) => MultihopError::Tls(x),
            QuicDialError::Bind(x) => MultihopError::Bind(x),
            QuicDialError::Connect(x) => MultihopError::Connect(x),
            QuicDialError::Quic(source) => MultihopError::Quic {
                context: "connect",
                source,
            },
            // Reachable only in cover-domain mode with the carrier armed
            // (`with_tcp_fallback`), where the entry dial uses
            // `dial_quic_webpki_with_fallback`; the RPK and un-armed webpki dials
            // never produce it. Carries the engine's typed carrier outcome.
            QuicDialError::Fallback(e) => MultihopError::TcpFallback(e),
        }
    }
}

impl MultihopError {
    /// The engine's reconnect verdict for this dial/setup failure, mapped (never
    /// re-decided) from the engine's own classification.
    ///
    /// The setup-policy verdict is owned by the engine's `SetupError` (a policy
    /// rejection is fatal, exhaustion reselects). A dial that closed with the
    /// exit's maintenance-drain code reselects another exit (redialing this
    /// circuit re-hits the drain), matching the engine's
    /// `MultiHopError::dial_refusal` classification. Everything else is a
    /// transient dial failure worth retrying the same target.
    #[must_use]
    pub fn retryability(&self) -> warrenguard_transport::Retryability {
        use warrenguard_transport::Retryability;
        match self {
            MultihopError::Setup(e) => e.retryability(),
            MultihopError::Quic { source, .. } | MultihopError::ReadDatagram(source)
                if is_exit_drain_close(source) =>
            {
                Retryability::RetryReselect
            }
            _ => Retryability::RetrySameTarget,
        }
    }
}

/// Whether a QUIC connection error is the exit's maintenance-drain application
/// close (`WARREN_MH_DRAINING`): a reselect signal, not a transient loss. Reads
/// the engine's wire constant, so the SDK maps the engine's decision rather than
/// re-deciding the policy.
fn is_exit_drain_close(err: &quinn::ConnectionError) -> bool {
    matches!(
        err,
        quinn::ConnectionError::ApplicationClosed(ac)
            if u64::from(ac.error_code) == u64::from(warrenguard_multihop::WARREN_MH_DRAINING)
    )
}

/// Maps a delegated engine [`warrenguard_transport::multihop::MultiHopError`] to
/// this crate's [`MultihopError`]. Precise for the variants reachable from the
/// calls this wrapper actually makes
/// ([`MultiHopClient::from_established_connection`],
/// [`MultiHopClient::setup_over_stream`],
/// [`MultiHopClient::send`]/[`send_packet`](MultiHopClient::send_packet),
/// [`MultiHopClient::rekey`]); the dial-time-only variants
/// (`RelayPki`/`Tls`/`Bind`/`Connect`/`Handshake`) are never returned by those
/// calls (this SDK dials via its own [`dial_quic`] / [`dial_quic_webpki`], never
/// the engine's own `connect()`), and `Rejected` is never constructed on this
/// path either (a policy refusal rides the sealed `IpAssign`-reply control
/// message, decoded in [`MultihopClientTunnel::connect`], not this error type).
/// Those unreachable variants map generically; the engine enum is
/// `#[non_exhaustive]`, so unknown future variants take the same generic
/// arm instead of a compile error.
fn map_engine_err(e: EngineMultihopError) -> MultihopError {
    use EngineMultihopError as E;
    match e {
        E::Session(inner) => MultihopError::Setup(SetupError::Session(inner)),
        E::Encode(p) | E::Decode(p) => {
            MultihopError::Setup(SetupError::Session(warren_multihop::MultihopError::from(p)))
        }
        E::Send(inner) => MultihopError::SendDatagram(inner),
        E::SetupStream { context, detail } => MultihopError::SetupIo {
            context,
            source: detail.into(),
        },
        E::Recv(inner) => MultihopError::ReadDatagram(inner),
        E::UnexpectedExitId => MultihopError::ExitIdentityMismatch,
        E::RelayIdentity(reason) => MultihopError::RelayIdentity(reason),
        E::RelayPki(_)
        | E::Tls(_)
        | E::Bind { .. }
        | E::Connect(_)
        | E::Handshake(_)
        | E::Rejected(_)
        | E::Replay { .. } => MultihopError::Setup(SetupError::UnexpectedReply),
        _ => MultihopError::Setup(SetupError::UnexpectedReply),
    }
}

/// Builder/dialer for a multihop client tunnel.
pub struct MultihopClientTunnel {
    /// Account signing key: signs the multi-hop setup proof of possession.
    /// Since protocol v5 it is NOT a TLS identity (the relay->exit dial is
    /// anonymous at the TLS layer); the client is authenticated to the exit
    /// solely by the PoP carried in the sealed `IpRequest`.
    signing_key: SigningKey,
    bind_local_ip: Option<SocketAddr>,
    auto_local_ip: bool,
    wants_ipv6: bool,
    transport_config: Option<std::sync::Arc<quinn::TransportConfig>>,
    idle_cover: bool,
    /// X.509 cover-domain SNI (ADR-0004). When set, the client dials
    /// `cover_domain` as the SNI and validates the relay's real X.509
    /// certificate via WebPKI (Mozilla roots) instead of pinning the relay's
    /// raw public key. The relay then proves its Warren identity in-band via a
    /// server-initiated bi stream after the setup frame is sent. `None` keeps
    /// the historical RPK path.
    cover_domain: Option<String>,
    /// Arms the TLS-over-TCP anti-censorship carrier for the entry dial (roster
    /// v10). Set by the SDK caller only when the dialed entry advertises the
    /// carrier; the race fires solely in cover-domain mode (the carrier needs the
    /// SNI, and prod carrier hops are all X.509 cover-posture) and only when the
    /// UDP handshake fails, so arming it whenever available is free on an
    /// uncensored path. Off by default. Set via [`Self::with_tcp_fallback`].
    tcp_fallback: bool,
    /// When `Some`, the QUIC carrier socket is marked/bound to the physical link
    /// (`SO_MARK` / `IP_BOUND_IF` / `IP_UNICAST_IF`) before its first send, so a
    /// privileged TUN datapath's split-default capture keeps it out of the tunnel
    /// and can drop the `<exit_ip>/32` host route (Port Fail / TunnelCrack
    /// ServerIP fix). `None` (default) for the userland proxy (no OS tunnel) and
    /// mobile (`VpnService.protect`). Set via [`Self::with_socket_bypass`].
    socket_bypass: Option<SocketBypass>,
    /// Advertises DAITA support in the sealed setup (`IpRequest.wants_daita`):
    /// the exit then samples a machine and returns it in
    /// `IpAssign.daita_spec` (the negotiated model shared with the app). Off
    /// by default; when unset the exit MUST NOT grant a spec, keeping its
    /// downlink unpadded so the session is never misreported as defended.
    daita_support: bool,
}

impl MultihopClientTunnel {
    /// Create a tunnel dialer bound to the given account key.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            bind_local_ip: None,
            auto_local_ip: false,
            wants_ipv6: false,
            transport_config: None,
            idle_cover: false,
            cover_domain: None,
            tcp_fallback: false,
            socket_bypass: None,
            daita_support: false,
        }
    }

    /// Advertises DAITA support so the exit samples and returns the machine
    /// spec (`IpAssign.daita_spec`): the negotiated enablement model. The
    /// caller reads the grant back via
    /// [`MultihopSession::assignment`]`().daita_spec` and drives it on the
    /// uplink; `None` in the reply means the exit declined and the defense is
    /// NOT running.
    #[must_use]
    pub fn with_daita(mut self, enable: bool) -> Self {
        self.daita_support = enable;
        self
    }

    /// Override the local bind address (defaults to the unspecified address with
    /// an OS-chosen port, matching the dialed address family).
    #[must_use]
    pub fn with_bind_local_ip(mut self, addr: SocketAddr) -> Self {
        self.bind_local_ip = Some(addr);
        self
    }

    /// Auto-detect the default-route source IP for the exit and bind to it
    /// (multi-NIC determinism). Ignored when [`with_bind_local_ip`](Self::with_bind_local_ip)
    /// is set; falls back to an unspecified bind if detection fails.
    #[must_use]
    pub fn with_auto_local_ip(mut self) -> Self {
        self.auto_local_ip = true;
        self
    }

    /// Request a dual-stack IPv6 assignment alongside the IPv4. The exit may
    /// still decline (the reply's `ipv6` is the capability echo).
    #[must_use]
    pub fn with_ipv6(mut self, enable: bool) -> Self {
        self.wants_ipv6 = enable;
        self
    }

    /// Overrides the QUIC transport config (advanced). The default is already the
    /// shared production engine client profile (anti-DPI obfuscation, spin-bit
    /// defense, fast dead-exit detection), so this is only for a caller that needs
    /// a bespoke `quinn::TransportConfig`. See ARCHITECTURE.md "QUIC handshake
    /// obfuscation".
    #[must_use]
    pub fn with_transport_config(mut self, cfg: std::sync::Arc<quinn::TransportConfig>) -> Self {
        self.transport_config = Some(cfg);
        self
    }

    /// Enables ADR-0006 idle cover traffic: the keep-alive PING is disabled and
    /// the caller drives [`warrenguard_pump::idle_cover::IdleCoverDriver`] over the returned
    /// session so jittered, size-varied dummies replace the fixed keep-alive
    /// beacon. No effect when an explicit
    /// [`with_transport_config`](Self::with_transport_config) override is set. Off
    /// by default. The caller MUST spawn the cover driver, or the session has no
    /// keep-alive.
    #[must_use]
    pub fn with_idle_cover(mut self, enable: bool) -> Self {
        self.idle_cover = enable;
        self
    }

    /// Opts into X.509 cover-domain mode (ADR-0004): dial `cover_domain` as the
    /// TLS SNI and validate the relay's real certificate via WebPKI (Mozilla roots)
    /// instead of pinning its raw public key. The relay then proves its Warren
    /// identity in-band (see the module docs). Pass `None` to revert to RPK mode.
    ///
    /// The `exit_pubkey` passed to [`Self::connect`] doubles as the expected
    /// relay Ed25519 key for the in-band proof, so both the WebPKI cert and the
    /// proof must pass before the session is accepted.
    #[must_use]
    pub fn with_cover_domain(mut self, cover_domain: Option<String>) -> Self {
        self.cover_domain = cover_domain;
        self
    }

    /// Arms the TLS-over-TCP anti-censorship carrier (roster v10) for the entry
    /// dial: when the UDP/QUIC handshake to the entry fails on a UDP-hostile
    /// network, retry the SAME QUIC datagrams inside one cover-domain TLS stream
    /// on the entry's `:443/tcp`. Effective ONLY in cover-domain mode (see
    /// [`Self::with_cover_domain`]); the SDK caller sets this only when the dialed
    /// entry advertises the carrier. The carrier is dormant unless UDP fails, so
    /// arming it whenever available costs nothing on an open path. Off by default.
    #[must_use]
    pub fn with_tcp_fallback(mut self, enabled: bool) -> Self {
        self.tcp_fallback = enabled;
        self
    }

    /// Keep the QUIC carrier socket on the physical link, out of the full-tunnel
    /// capture a system-VPN datapath installs, via a socket-level mark/bind
    /// (`SO_MARK` on Linux, `IP_BOUND_IF` on macOS, `IP_UNICAST_IF` on Windows).
    /// The privileged TUN datapath sets this so it can drop the `<exit_ip>/32`
    /// host route: with the escape keyed on the socket instead of the exit
    /// destination, application traffic to the exit IP is tunnelled like anything
    /// else and cannot leak (Port Fail / TunnelCrack ServerIP). Leave unset for
    /// the userland proxy (no OS tunnel) and mobile (`VpnService.protect`).
    #[must_use]
    pub fn with_socket_bypass(mut self, bypass: SocketBypass) -> Self {
        self.socket_bypass = Some(bypass);
        self
    }

    /// The socket bypass pinned by [`Self::with_socket_bypass`], if any.
    #[must_use]
    pub fn socket_bypass(&self) -> Option<SocketBypass> {
        self.socket_bypass
    }

    /// The account public key (TLS identity and PoP key).
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Connect to a dialed peer and complete the multihop setup exchange.
    ///
    /// `exit_pubkey` is the Ed25519 identity of the dialed peer: in RPK mode it
    /// is pinned as the TLS raw public key; in X.509 cover-domain mode (see
    /// [`Self::with_cover_domain`]) it is the expected relay identity for the
    /// in-band relay-auth proof (ADR-0004). `exit_x25519` and `exit_id` come from
    /// the verified multihop directory: the HPKE recipient key and the cleartext
    /// routing tag.
    ///
    /// # Errors
    ///
    /// See [`MultihopError`]. In particular [`MultihopError::Setup`] wraps a
    /// policy rejection ([`SetupError::Rejected`]) or pool exhaustion
    /// ([`SetupError::IpExhausted`]), and [`MultihopError::RelayIdentity`] means
    /// the relay's in-band identity proof was absent, malformed, or signed by the
    /// wrong key (X.509 cover-domain mode only).
    pub async fn connect(
        &self,
        exit_pubkey: [u8; 32],
        exit_x25519: [u8; 32],
        exit_id: [u8; EXIT_ID_LEN],
        exit_addr: SocketAddr,
    ) -> Result<MultihopSession, MultihopError> {
        // An explicit override wins; else, when idle cover is on, use the
        // keep-alive-disabled config so the cover driver replaces the beacon.
        let transport_config = self.transport_config.clone().or_else(|| {
            self.idle_cover
                .then(|| crate::client::warren_transport_config_with_idle_cover(true))
        });

        // In X.509 cover-domain mode, dial the cover domain as the SNI and
        // validate the relay's real X.509 chain via WebPKI (Mozilla roots),
        // exactly like a browser. In RPK mode (no cover domain), pin the relay's
        // Ed25519 pubkey in the SNI and use the raw-public-key verifier. The
        // relay's Warren identity is verified in-band after the setup frame is
        // sent (cover-domain mode, inside `setup_over_stream` below) or at the
        // TLS layer (RPK mode).
        let bind = effective_bind(self.bind_local_ip, self.auto_local_ip, exit_addr);
        let (endpoint, conn) = if let Some(ref domain) = self.cover_domain {
            if self.tcp_fallback {
                // Carrier armed (roster v10): race the UDP/QUIC handshake against
                // the cover-domain TLS-over-TCP carrier on the entry's :443/tcp, so
                // a UDP-blocked network still connects. Both legs use the WebPKI
                // cover posture; the relay identity is proven in-band below exactly
                // as the plain webpki dial. The policy gate folds the armed signal
                // (opt-in + advertised, decided by the caller) with the cover domain
                // we are already inside; a disabled policy would make the fallback
                // dial the plain `dial_quic_webpki` verbatim.
                let policy = crate::tcp_fallback::resolve_fallback_policy(
                    self.tcp_fallback,
                    self.tcp_fallback,
                    Some(domain),
                );
                let cover = policy
                    .tcp_fallback_enabled
                    .then(|| -> Result<_, MultihopError> {
                        Ok(crate::tcp_fallback::CoverTls {
                            addr: SocketAddr::new(
                                exit_addr.ip(),
                                crate::tcp_fallback::COVER_TCP_PORT,
                            ),
                            domain,
                            client_config: crate::client::cover_tls_client_config()
                                .map_err(MultihopError::Tls)?,
                        })
                    })
                    .transpose()?;
                crate::tcp_fallback::dial_quic_webpki_with_fallback(
                    domain,
                    exit_addr,
                    bind,
                    transport_config,
                    self.socket_bypass,
                    &policy,
                    cover,
                )
                .await?
            } else {
                dial_quic_webpki(
                    domain,
                    exit_addr,
                    bind,
                    transport_config,
                    self.socket_bypass,
                )
                .await?
            }
        } else {
            dial_quic(
                exit_pubkey,
                exit_addr,
                bind,
                transport_config,
                self.socket_bypass,
            )
            .await?
        };

        // X.509 cover-domain mode (ADR-0004): `exit_pubkey` doubles as the
        // expected relay identity for the in-band proof; the engine verifies it
        // internally (inside `setup_over_stream`, right after the setup frame is
        // written and before the reply is read). RPK mode (no cover domain)
        // pins the identity at the TLS layer already and needs no in-band proof.
        let relay_auth_pubkey = self
            .cover_domain
            .is_some()
            .then(|| tls::WarrenPubkey::from_bytes(exit_pubkey));

        let mut inner = MultiHopClient::from_established_connection(
            endpoint,
            conn.clone(),
            ExitId::from_bytes(exit_id),
            &exit_x25519,
            relay_auth_pubkey,
        )
        .map_err(map_engine_err)?;
        // This SDK's rekey timing is caller-driven, via `RekeyPolicy` /
        // `MultihopSession::rekey` below (warren-core's own 8h/5s doctrine), not
        // the engine's internal frame-count/age auto-trigger (10M frames / 30 min
        // by default): disable it so `setup_over_stream` / `send_packet` never
        // rekey on our behalf, only when the caller asks.
        inner.set_rekey_policy(EngineRekeyPolicy {
            max_frames: u64::MAX,
            max_age: Duration::MAX,
        });

        // The negotiated DAITA model: `wants_daita` only advertises support;
        // the exit samples the machine and returns it in the assignment. A
        // caller that advertises MUST drive the granted spec on its uplink,
        // otherwise the session would be misreported as defended, the exact
        // lie the /v3 capability echo exists to prevent.
        let opened = inner
            .setup_over_stream(Some(&self.signing_key), self.wants_ipv6, self.daita_support)
            .await
            .map_err(map_engine_err)?;

        // `setup_over_stream` succeeds once the reply authenticates, regardless
        // of which control message it carries (a `Rejected` / `IpExhausted`
        // policy refusal opens just as cleanly as an `IpAssign`), so interpret
        // `opened` exactly like `ClientSession::open_setup_reply` would. The
        // engine already decoded a successful `IpAssign` as a side effect
        // (`MultiHopClient::assignment`); read it back rather than
        // reconstructing it here (`IpAssignment` is `#[non_exhaustive]` outside
        // its defining crate, so this wrapper cannot build one itself).
        let assignment = match try_decode_control(&opened) {
            Ok(Some(WarrenControlMessage::IpAssign { .. })) => inner.assignment().expect(
                "MultiHopClient::setup_over_stream captures the assignment for every IpAssign reply",
            ),
            Ok(Some(WarrenControlMessage::Rejected)) => {
                return Err(MultihopError::Setup(SetupError::Rejected));
            }
            Ok(Some(WarrenControlMessage::IpExhausted)) => {
                return Err(MultihopError::Setup(SetupError::IpExhausted));
            }
            Ok(Some(
                WarrenControlMessage::IpRequest { .. }
                | WarrenControlMessage::IpRequestV7 { .. }
                | WarrenControlMessage::ExitDraining { .. },
            ))
            | Ok(None) => {
                // Request-type frames (v6 or v7) are client-to-exit only; a
                // client receiving one back is an unexpected reply.
                return Err(MultihopError::Setup(SetupError::UnexpectedReply));
            }
            Err(e) => return Err(MultihopError::Setup(SetupError::Control(e))),
        };

        Ok(MultihopSession {
            inner,
            conn,
            assignment,
            metrics: Arc::new(MultihopMetrics::new(0)),
            drain_tx: tokio::sync::watch::channel(None).0,
        })
    }
}

/// Live data-plane counters for a multihop session, cheaply shareable (`Arc`):
/// a clone can be held past the session (e.g. by a proxy handle) to read totals.
#[derive(Debug)]
pub struct MultihopMetrics {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    packets_sent: AtomicU64,
    packets_recv: AtomicU64,
    cover_packets_sent: AtomicU64,
    epoch: AtomicU32,
    connected_since: Instant,
}

impl MultihopMetrics {
    fn new(epoch: u32) -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            cover_packets_sent: AtomicU64::new(0),
            epoch: AtomicU32::new(epoch),
            connected_since: Instant::now(),
        }
    }

    /// A point-in-time snapshot of the counters.
    #[must_use]
    pub fn snapshot(&self) -> MultihopMetricsSnapshot {
        MultihopMetricsSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            cover_packets_sent: self.cover_packets_sent.load(Ordering::Relaxed),
            epoch: self.epoch.load(Ordering::Relaxed),
            uptime_secs: self.connected_since.elapsed().as_secs(),
        }
    }
}

/// A serializable point-in-time view of a session's counters. Plain scalars so it
/// maps cleanly across the FFI boundary to the sibling-language SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MultihopMetricsSnapshot {
    /// Total inner IP bytes sealed and sent.
    pub bytes_sent: u64,
    /// Total inner IP bytes received and opened.
    pub bytes_recv: u64,
    /// Total IP packets sent.
    pub packets_sent: u64,
    /// Total IP packets received.
    pub packets_recv: u64,
    /// Total DAITA cover-traffic (dummy) frames sent (not app data).
    pub cover_packets_sent: u64,
    /// Current HPKE epoch (rotates on rekey).
    pub epoch: u32,
    /// Seconds since the session was established.
    pub uptime_secs: u64,
}

/// The session rekey doctrine (warren-core doc 19 § 11.6): rotate the HPKE
/// context within `interval` to bound a long-lived session's AEAD exposure, and
/// keep the previous epoch openable for `overlap` so in-flight reverse frames
/// sealed just before the rotation still decrypt (the exit's session cache TTL).
///
/// This is a pure policy value; a supervisor drives it:
/// `if policy.is_due(session.since_last_rekey()) { session.rekey()?;
/// sleep(policy.overlap()); session.prune_old_epoch(); }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyPolicy {
    interval: Duration,
    overlap: Duration,
}

impl RekeyPolicy {
    /// The warren-core doctrine: rekey before 8 hours, 5-second overlap (the
    /// exit's `SESSION_CACHE_TTL`).
    #[must_use]
    pub const fn doctrine() -> Self {
        Self {
            interval: Duration::from_secs(8 * 60 * 60),
            overlap: Duration::from_secs(5),
        }
    }

    /// Override the rotation interval (kept at or below the 8-hour doctrine cap).
    #[must_use]
    pub const fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Override the overlap window.
    #[must_use]
    pub const fn with_overlap(mut self, overlap: Duration) -> Self {
        self.overlap = overlap;
        self
    }

    /// The rotation interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// The overlap window during which the previous epoch stays openable.
    #[must_use]
    pub const fn overlap(&self) -> Duration {
        self.overlap
    }

    /// Whether a rekey is due given the time since the last rotation.
    #[must_use]
    pub fn is_due(&self, since_last_rekey: Duration) -> bool {
        since_last_rekey >= self.interval
    }
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self::doctrine()
    }
}

/// Maintenance-drain advisory the exit emitted mid-session (ADR 36).
///
/// The exit publishes a sealed `ExitDraining` control frame on the live
/// downlink when an operator drains it for maintenance.
/// [`MultihopSession::recv_packet`] decodes it and republishes it on the
/// session's drain watch so an upper layer (the SDK supervisor / FFI host)
/// can migrate off the draining exit before its hard-close deadline.
/// `Copy + Eq` so a `watch` can dedupe identical re-emits. The type is the
/// engine's (single advisory home, next to the drain-reaction policy).
pub use warrenguard_transport::drain_policy::ExitDrainAdvisory as DrainAdvisory;

/// Extract a drain advisory from a decoded control plaintext, or `None`
/// if it is not an `ExitDraining` frame (DAITA dummy, other control
/// variant, or a malformed frame).
fn drain_advisory_from_plaintext(plaintext: &[u8]) -> Option<DrainAdvisory> {
    match try_decode_control(plaintext) {
        Ok(Some(msg)) => DrainAdvisory::from_control(&msg),
        _ => None,
    }
}

/// An established multihop session: IP packets travel as per-packet sealed
/// `WarrenMultihopFrame`s over QUIC datagrams.
///
/// The session can rotate its HPKE epoch in place ([`rekey`](Self::rekey)) while
/// the datapath keeps sealing under `&self`. All of the wire protocol (HPKE
/// seal/open, rekey/epoch, anti-replay) is delegated to the shared engine
/// [`MultiHopClient`]; this type keeps only the SDK-specific per-session byte
/// metrics, the drain-advisory watch, and the drop-and-retry resilience contract
/// of [`Self::recv_packet`].
pub struct MultihopSession {
    inner: MultiHopClient,
    // A cheap clone of the engine's connection (quinn::Connection is an Arc-backed
    // handle), for `Self::connection`'s `&self -> &Connection` borrow contract:
    // the engine only exposes to-be-cloned or higher-level accessors.
    conn: quinn::Connection,
    assignment: IpAssignment,
    metrics: Arc<MultihopMetrics>,
    /// ADR 36: republishes a mid-session `ExitDraining` advisory to the upper
    /// layer. Holds `None` until the exit signals a drain.
    drain_tx: tokio::sync::watch::Sender<Option<DrainAdvisory>>,
}

impl MultihopSession {
    /// The exit's IP assignment for this session.
    #[must_use]
    pub fn assignment(&self) -> &IpAssignment {
        &self.assignment
    }

    /// The assigned tunnel IPv4.
    #[must_use]
    pub fn assigned_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.assignment.ipv4)
    }

    /// The assigned tunnel IPv6, if the exit granted dual-stack.
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<Ipv6Addr> {
        self.assignment.ipv6.map(Ipv6Addr::from)
    }

    /// The largest datagram payload the current path can carry, if known.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// The largest inner IP packet that fits in one sealed datagram: the path
    /// datagram size minus the worst-case frame overhead. Falls back to the
    /// 1280-byte base MTU before the first PMTU probe.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        self.inner.max_inner_payload()
    }

    /// The underlying quinn connection, for read-only inspection (stats, RTT,
    /// path MTU) and the datagram pump's lifecycle wiring.
    ///
    /// INVARIANT: callers MUST NOT send raw datagrams on this connection. Every
    /// uplink datagram has to be a sealed [`WarrenMultihopFrame`](warren_wire::multihop::WarrenMultihopFrame) produced by
    /// [`Self::send_packet`] / [`Self::send_cover_traffic`]; a raw send would put
    /// cleartext on the wire and break the HPKE confidentiality the exit relies
    /// on. Use the sealing methods for all writes.
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// QUIC path round-trip time to the first hop of this multihop
    /// connection, smoothed post-handshake. Feeds the client-side RTT
    /// proximity cache (doc 52 §6.2 client): for a single-region path it is
    /// a good proximity signal for reaching this exit.
    #[must_use]
    pub fn path_rtt(&self) -> std::time::Duration {
        self.conn.stats().path.rtt
    }

    /// Seal one IP packet and send it as a QUIC datagram.
    ///
    /// # Errors
    ///
    /// [`MultihopError::Setup`] if sealing fails, [`MultihopError::Frame`] if
    /// the frame fails to encode, [`MultihopError::SendDatagram`] if quinn
    /// refuses the datagram.
    pub fn send_packet(&self, ip_packet: &[u8]) -> Result<(), MultihopError> {
        self.inner.send_packet(ip_packet).map_err(map_engine_err)?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(ip_packet.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Rotate the HPKE context: a fresh KEM (new `encapsulated_key`), epoch `+1`,
    /// the forward sequence restarted at `0` (warren-core doc 19 § 5.4), and the
    /// previous epoch retained for the overlap so the exit's just-sent reverse
    /// frames still open. The exit re-derives its receiver context implicitly on
    /// the new `encapsulated_key`; there is no rekey control message.
    ///
    /// Close the overlap with [`prune_old_epoch`](Self::prune_old_epoch) once the
    /// policy's overlap window elapses.
    ///
    /// # Errors
    ///
    /// [`MultihopError::Setup`] if the fresh `setup_sender` fails.
    pub fn rekey(&self) -> Result<u32, MultihopError> {
        let new_epoch = self.inner.rekey().map_err(map_engine_err)?;
        self.metrics.epoch.store(new_epoch, Ordering::Relaxed);
        Ok(new_epoch)
    }

    /// End the rekey overlap: drop the previous-epoch context so old-epoch reverse
    /// frames no longer open. Call once the [`RekeyPolicy::overlap`] deadline
    /// elapses. Idempotent.
    ///
    /// The engine also lazily auto-prunes the overlap on its own fixed 5-second
    /// doctrine TTL (matching [`RekeyPolicy::doctrine`]'s default) the next time
    /// [`Self::send_packet`] / [`Self::recv_packet`] runs; a caller that
    /// configures a longer [`RekeyPolicy::with_overlap`] should still call this
    /// explicitly at its own deadline; the engine's fixed 5 s floor is not
    /// currently overridable from here.
    pub fn prune_old_epoch(&self) {
        self.inner.prune_old_epoch();
    }

    /// The current HPKE epoch (starts at `0`, `+1` per [`rekey`](Self::rekey)).
    #[must_use]
    pub fn current_epoch(&self) -> u32 {
        self.inner.current_epoch()
    }

    /// Time since the current epoch was installed (construction or last rekey).
    /// Feed it to [`RekeyPolicy::is_due`] to decide when to rotate.
    #[must_use]
    pub fn since_last_rekey(&self) -> Duration {
        self.inner.since_last_rekey()
    }

    /// Sends a DAITA cover-traffic (dummy) frame: a sealed frame whose plaintext
    /// begins with the dummy tag (`0xFF`) followed by `padding_len` zero bytes,
    /// which the exit drops on receipt (it is not an IP packet). Client-unilateral
    /// traffic shaping to blur real-traffic timing/volume; carries no app data and
    /// is not counted in the app-data metrics. This is the cover-traffic building
    /// block; a full DAITA defense schedule that decides WHEN to emit dummies is
    /// driven above this seam (and validated against a real exit before relied on).
    ///
    /// # Errors
    ///
    /// Same as [`send_packet`](Self::send_packet) (seal, encode, or datagram send).
    pub fn send_cover_traffic(&self, padding_len: usize) -> Result<(), MultihopError> {
        self.inner
            .send_cover_traffic(padding_len)
            .map_err(map_engine_err)?;
        self.metrics
            .cover_packets_sent
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// A cheap, cloneable handle to this session's live counters. Hold it past the
    /// session (e.g. a proxy handle) to read totals without the session itself.
    #[must_use]
    pub fn metrics(&self) -> Arc<MultihopMetrics> {
        Arc::clone(&self.metrics)
    }

    /// A point-in-time snapshot of this session's counters.
    #[must_use]
    pub fn metrics_snapshot(&self) -> MultihopMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Await the next inbound IP packet, opening sealed datagrams and skipping
    /// DAITA dummies, control messages, and frames that fail the exit-id pin,
    /// the anti-replay window, or the AEAD open.
    ///
    /// # Errors
    ///
    /// [`MultihopError::ReadDatagram`] if the connection closed.
    pub async fn recv_packet(&self) -> Result<Vec<u8>, MultihopError> {
        loop {
            let plaintext = match self.inner.recv().await {
                Ok(p) => p,
                // `MultiHopClient::recv`'s documented error set is exactly
                // { Recv, Decode, UnexpectedExitId, Replay, Session }: `Recv`
                // means the QUIC connection itself closed (fatal, matching this
                // method's `ReadDatagram` contract below); the other four are
                // per-frame decode/replay/exit-id/AEAD failures. This session has
                // always dropped and retried those rather than surfaced them (a
                // single malformed, hostile, or replayed datagram must never kill
                // the whole recv path - a hostile relay could otherwise DoS the
                // downlink with one poisoned frame). Contrast
                // `warrenguard_pump`'s own consumer, which intentionally treats
                // the same per-frame errors as fatal at the connection level:
                // this SDK's drop-and-retry contract is a deliberate, tested
                // SDK-side choice, preserved here rather than adopting the
                // engine's own (differently reliable) pump-loop policy.
                Err(EngineMultihopError::Recv(e)) => return Err(MultihopError::ReadDatagram(e)),
                Err(_) => continue,
            };
            match plaintext.first() {
                // DAITA padding or a control message: not an IP packet.
                Some(&DAITA_DUMMY_FIRST_BYTE) | Some(&CONTROL_FIRST_BYTE) => {
                    // A DAITA dummy is discarded. A control frame on the data
                    // plane is the ADR 36 maintenance-drain advisory (the
                    // setup control exchange is already complete): surface it
                    // on the drain watch so the upper layer can migrate off
                    // the draining exit before its hard-close deadline.
                    if let Some(adv) = drain_advisory_from_plaintext(&plaintext) {
                        // Dedupe: the exit re-emits the same advisory every few
                        // seconds until the deadline. Publish only on a real
                        // change so a `changed()`-based consumer is not woken by
                        // every identical re-emit (`DrainAdvisory: Eq`).
                        self.drain_tx.send_if_modified(|cur| {
                            if *cur == Some(adv) {
                                false
                            } else {
                                *cur = Some(adv);
                                true
                            }
                        });
                    }
                    continue;
                }
                Some(_) => {
                    self.metrics.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .bytes_recv
                        .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                    return Ok(plaintext);
                }
                None => continue,
            }
        }
    }

    /// Subscribe to mid-session maintenance-drain advisories (ADR 36).
    ///
    /// The receiver holds `None` until the exit signals it is draining, then
    /// yields `Some(DrainAdvisory)`. An upper layer (the SDK supervisor / FFI
    /// host) reacts by migrating off the draining exit before its hard-close
    /// deadline (make-before-break).
    pub fn watch_drain(&self) -> tokio::sync::watch::Receiver<Option<DrainAdvisory>> {
        self.drain_tx.subscribe()
    }

    /// Close the connection cleanly.
    pub fn disconnect(&self) {
        self.inner.close(0, b"client disconnect");
    }
}

impl warrenguard_pump::idle_cover::CoverSink for MultihopSession {
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
impl MultihopSession {
    /// Builds a session over an already-dialed raw connection, skipping the
    /// setup/IpAssign exchange. Used to drive the multihop echo exit (which does
    /// not run the setup stream) through the live rekey datapath in tests.
    fn from_raw_for_test(
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        exit_id: [u8; EXIT_ID_LEN],
        exit_x25519: [u8; 32],
    ) -> Self {
        let inner = MultiHopClient::from_established_connection(
            endpoint,
            conn.clone(),
            ExitId::from_bytes(exit_id),
            &exit_x25519,
            None,
        )
        .expect("from_established_connection");
        Self {
            inner,
            conn,
            assignment: IpAssignment::placeholder_for_test(),
            metrics: Arc::new(MultihopMetrics::new(0)),
            drain_tx: tokio::sync::watch::channel(None).0,
        }
    }
}

/// Wire-compatibility validation against the genuine `warren-core` exit.
///
/// These tests spawn the real `warren-exit` binary in multihop echo mode (the
/// reference implementation, not the in-repo fake) and drive its HPKE datagram
/// plane with this SDK's [`ClientSession`](warren_multihop::ClientSession). They
/// are the authoritative wire-compat oracle: if the per-packet key derivation,
/// the AAD layout, the encapsulated-key serialization, the postcard frame shape,
/// or the rekey contract drift from the reference, the round-trip stops opening.
///
/// They are gated on the `WARREN_EXIT_BIN` env var (absolute path to a built
/// `warren-exit`); without it each test returns immediately so `cargo test`
/// stays green on machines that do not have the reference checkout. Build the
/// binary with `cargo build -p warren-exit` in the `warren-core` checkout and
/// point `WARREN_EXIT_BIN` at `target/debug/warren-exit`.
#[cfg(test)]
mod real_exit_tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use warren_multihop::{ClientSession, ExitId, parse_exit_x25519_pubkey};
    use warren_wire::multihop::WarrenMultihopFrame;

    /// Frozen BIP39 test vector. The exit derives BOTH its Ed25519 QUIC RPK
    /// (via the identity HKDF) and its long-lived X25519 multihop key from this
    /// mnemonic; we re-derive the RPK locally to pin the TLS peer.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// Matches the `--multihop-exit-id` hex we pass the exit.
    const TEST_EXIT_ID: [u8; EXIT_ID_LEN] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const TEST_EXIT_ID_HEX: &str = "00112233445566778899aabbccddeeff";
    /// Deterministic client identity (the value is irrelevant in permissive mode).
    const CLIENT_SEED: [u8; 32] = [0x77; 32];

    /// Kills the spawned exit on drop so a panicking test never leaks the process.
    struct ExitGuard(Child);
    impl Drop for ExitGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A bound-then-released loopback UDP port. Small TOCTOU window before the
    /// exit rebinds it; acceptable for a serial, opt-in integration test.
    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind ephemeral udp")
            .local_addr()
            .expect("local_addr")
            .port()
    }

    /// Spawns the real exit in multihop echo mode. Returns `None` when
    /// `WARREN_EXIT_BIN` is unset (the test then no-ops to keep CI green).
    /// On success: the running exit, its address, its X25519 multihop pubkey,
    /// and its Ed25519 RPK (re-derived here from the same mnemonic).
    fn spawn_real_exit() -> Option<(ExitGuard, SocketAddr, [u8; 32], [u8; 32])> {
        let bin = std::env::var("WARREN_EXIT_BIN").ok()?;

        let dir = tempfile::tempdir().expect("tempdir");
        let mnemonic_file = dir.path().join("mnemonic.txt");
        std::fs::write(&mnemonic_file, format!("{TEST_MNEMONIC}\n")).expect("write mnemonic");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mnemonic_file, std::fs::Permissions::from_mode(0o600))
                .expect("chmod mnemonic");
        }
        let pubkey_out = dir.path().join("multihop_pub.hex");
        let port = free_udp_port();

        let child = Command::new(&bin)
            .arg("--multihop")
            .arg("--allow-anonymous-clients")
            .arg("--bind-addr")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--mnemonic-file")
            .arg(&mnemonic_file)
            .arg("--multihop-exit-id")
            .arg(TEST_EXIT_ID_HEX)
            .arg("--multihop-pubkey-out")
            .arg(&pubkey_out)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn warren-exit (is WARREN_EXIT_BIN a valid path?)");
        let guard = ExitGuard(child);

        // The exit writes its X25519 pubkey just before binding the endpoint, so
        // poll for it as a readiness signal (then still retry the QUIC dial).
        let mut exit_x25519 = [0u8; 32];
        let mut ready = false;
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&pubkey_out) {
                let s = s.trim();
                if s.len() == 64 && hex::decode_to_slice(s, &mut exit_x25519).is_ok() {
                    ready = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(ready, "exit did not publish its X25519 multihop pubkey");

        // Re-derive the exit's Ed25519 RPK from the same mnemonic (identical
        // frozen identity derivation): pinning it proves both ends agree.
        let exit_rpk = warren_identity::WarrenIdentity::from_mnemonic(TEST_MNEMONIC)
            .expect("derive exit identity")
            .public_key();

        Some((
            guard,
            (Ipv4Addr::LOCALHOST, port).into(),
            exit_x25519,
            exit_rpk,
        ))
    }

    /// Dials the exit's raw multihop QUIC plane, retrying until it is listening.
    async fn dial_with_retry(
        exit_rpk: [u8; 32],
        addr: SocketAddr,
    ) -> (quinn::Endpoint, quinn::Connection) {
        for attempt in 0..50u32 {
            match crate::client::dial_quic(
                exit_rpk,
                addr,
                effective_bind(None, false, addr),
                None,
                None,
            )
            .await
            {
                Ok(pair) => return pair,
                Err(_) if attempt < 49 => tokio::time::sleep(Duration::from_millis(100)).await,
                Err(e) => panic!("dial_quic never succeeded: {e:?}"),
            }
        }
        unreachable!()
    }

    /// One sealed forward datagram, echoed back and opened. Asserts the exit
    /// returned our exact plaintext through the reverse HPKE direction.
    async fn echo_roundtrip(
        conn: &quinn::Connection,
        session: &ClientSession,
        epoch: u32,
        seq: u64,
        payload: &[u8],
    ) {
        let frame = session.seal(payload, epoch, seq).expect("seal");
        conn.send_datagram(frame.encode().expect("encode").into())
            .expect("send_datagram");
        let resp = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("echo within 5s")
            .expect("read_datagram");
        let resp_frame = WarrenMultihopFrame::decode(&resp).expect("decode echo");
        let opened = session.open_response(&resp_frame).expect("open echo");
        assert_eq!(
            opened, payload,
            "echo must match the sealed payload byte-for-byte"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rekey_round_trips_across_epochs_against_the_real_exit() {
        let Some((_exit, addr, exit_x25519, exit_rpk)) = spawn_real_exit() else {
            eprintln!("skipping: WARREN_EXIT_BIN not set");
            return;
        };

        let _client_key = SigningKey::from_bytes(&CLIENT_SEED);
        let (endpoint, conn) = dial_with_retry(exit_rpk, addr).await;

        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let exit_key = parse_exit_x25519_pubkey(&exit_x25519).expect("parse exit x25519");
        let mut session = ClientSession::new(&exit_key, ExitId::from_bytes(TEST_EXIT_ID), &mut rng)
            .expect("HPKE setup_sender");

        // Epoch 0: a handful of frames open cleanly (baseline datapath).
        for seq in 0..8u64 {
            let payload: Vec<u8> = (0..200).map(|i| (i as u64 ^ seq) as u8).collect();
            echo_roundtrip(&conn, &session, 0, seq, &payload).await;
        }

        // Rekey: a fresh encapsulated_key makes the exit's session cache MISS and
        // run a brand new `setup_receiver`. The new-epoch datapath must round-trip.
        // The engine rekey returns the new encapsulated key and bumps the epoch
        // internally; read the epoch back for the round-trip assertions.
        session.rekey(&exit_key, &mut rng).expect("rekey");
        let new_epoch = session.epoch();
        assert_eq!(new_epoch, 1);
        for seq in 0..8u64 {
            let payload: Vec<u8> = (0..200).map(|i| (i as u64 ^ seq ^ 0xA5) as u8).collect();
            echo_roundtrip(&conn, &session, new_epoch, seq, &payload).await;
        }

        // The overlap window keeps the OLD epoch openable for in-flight REVERSE
        // frames the exit already sealed under it. The engine `ClientSession` is
        // a pure crypto primitive: `seal` binds the payload to whatever (epoch,
        // seq) the caller passes, and the transport's `seal_and_send` only ever
        // passes the current epoch (read under the session lock), so a forward
        // seal at a retired epoch cannot occur in real operation. Closing the
        // overlap is client-side bookkeeping: it drops the old context used to
        // open reverse stragglers.
        session.prune_pending_old_epoch();

        // The current epoch is unaffected by the prune.
        echo_roundtrip(&conn, &session, new_epoch, 8, b"current epoch still works").await;

        conn.close(0u32.into(), b"done");
        drop(endpoint);
    }

    /// Sends an IP-looking packet through the live session and asserts the exit
    /// echoes it back through `recv_packet` (so the whole driver, not just the
    /// raw `ClientSession`, survives the round-trip).
    async fn session_echo(sess: &MultihopSession, payload: &[u8]) {
        sess.send_packet(payload).expect("send_packet");
        let got = tokio::time::timeout(Duration::from_secs(5), sess.recv_packet())
            .await
            .expect("echo within 5s")
            .expect("recv_packet");
        assert_eq!(
            got, payload,
            "echo must match the sent packet byte-for-byte"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_session_rekeys_in_place_against_the_real_exit() {
        let Some((_exit, addr, exit_x25519, exit_rpk)) = spawn_real_exit() else {
            eprintln!("skipping: WARREN_EXIT_BIN not set");
            return;
        };

        let _client_key = SigningKey::from_bytes(&CLIENT_SEED);
        let (endpoint, conn) = dial_with_retry(exit_rpk, addr).await;
        let session = MultihopSession::from_raw_for_test(endpoint, conn, TEST_EXIT_ID, exit_x25519);

        // An IPv4-looking packet (first nibble 4) so recv_packet returns it
        // instead of dropping it as DAITA padding or a control message.
        let make_pkt = |tag: u8| -> Vec<u8> {
            let mut p = vec![0x45u8];
            p.extend((0..160u16).map(|i| (i as u8) ^ tag));
            p
        };

        assert_eq!(session.current_epoch(), 0);
        for tag in 0..6u8 {
            session_echo(&session, &make_pkt(tag)).await;
        }

        // Rotate the live session in place under &self: fresh KEM, epoch+1, the
        // forward sequence restarts at 0. The datapath must keep working without
        // tearing down the connection.
        let new_epoch = session.rekey().expect("rekey");
        assert_eq!(new_epoch, 1);
        assert_eq!(session.current_epoch(), 1);
        assert_eq!(
            session.metrics_snapshot().epoch,
            1,
            "metrics reflect the rotated epoch"
        );

        for tag in 6..12u8 {
            session_echo(&session, &make_pkt(tag)).await;
        }

        // A second rotation works too (epoch counter keeps climbing).
        assert_eq!(session.rekey().expect("rekey 2"), 2);
        session_echo(&session, &make_pkt(0xC3)).await;

        // Pruning the overlap is safe and leaves the current epoch usable.
        session.prune_old_epoch();
        session_echo(&session, &make_pkt(0xD4)).await;

        session.disconnect();
    }

    /// Connects to an ALREADY-RUNNING full exit (TUN termination + allocator),
    /// addressed by `WARREN_EXIT_ADDR` (e.g. `127.0.0.1:4434`), with its X25519
    /// multihop pubkey at `WARREN_EXIT_PUBKEY_FILE`. Unlike the echo harness, this
    /// exit performs the real setup handshake and assigns a tunnel IP, so it
    /// validates `connect()` end-to-end and the sticky-IP allocator (multipath
    /// coherence). Needs the exit run under root (`--use-tun`); skipped otherwise.
    fn running_full_exit() -> Option<(SocketAddr, [u8; 32], [u8; 32])> {
        let addr: SocketAddr = std::env::var("WARREN_EXIT_ADDR")
            .ok()?
            .parse()
            .expect("WARREN_EXIT_ADDR must be host:port");
        let pubkey_file = std::env::var("WARREN_EXIT_PUBKEY_FILE")
            .unwrap_or_else(|_| "/tmp/warren-exit-poc/pub.hex".to_string());
        let mut exit_x25519 = [0u8; 32];
        hex::decode_to_slice(
            std::fs::read_to_string(&pubkey_file)
                .expect("read WARREN_EXIT_PUBKEY_FILE")
                .trim(),
            &mut exit_x25519,
        )
        .expect("exit pubkey hex");
        let exit_rpk = warren_identity::WarrenIdentity::from_mnemonic(TEST_MNEMONIC)
            .expect("derive exit identity")
            .public_key();
        Some((addr, exit_x25519, exit_rpk))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_handshake_assigns_a_real_ip_with_sticky_multipath_coherence() {
        let Some((addr, exit_x25519, exit_rpk)) = running_full_exit() else {
            eprintln!("skipping: WARREN_EXIT_ADDR not set (needs a rooted --use-tun exit)");
            return;
        };

        // First connection completes the real sealed IpRequest -> IpAssign exchange.
        let key = SigningKey::from_bytes(&CLIENT_SEED);
        let s1 = MultihopClientTunnel::new(key.clone())
            .connect(exit_rpk, exit_x25519, TEST_EXIT_ID, addr)
            .await
            .expect("full multihop handshake");
        let ip1 = s1.assigned_ipv4();
        assert_eq!(
            (ip1.octets()[0], ip1.octets()[1]),
            (10, 66),
            "assigned a real 10.66.0.0/16 tunnel IP, got {ip1}"
        );

        // A second connection under the SAME account identity must land on the
        // SAME tunnel IP: this is exactly the multipath/bonding coherence the exit
        // guarantees via its sticky allocator keyed on client_pubkey.
        let s2 = MultihopClientTunnel::new(key.clone())
            .connect(exit_rpk, exit_x25519, TEST_EXIT_ID, addr)
            .await
            .expect("second same-identity handshake");
        assert_eq!(
            s2.assigned_ipv4(),
            ip1,
            "same identity must receive the same sticky IP across the bundle"
        );

        // A DISTINCT identity must get a DISTINCT IP (the allocator does not share
        // an address across accounts).
        let other = SigningKey::from_bytes(&[0x42u8; 32]);
        let s3 = MultihopClientTunnel::new(other)
            .connect(exit_rpk, exit_x25519, TEST_EXIT_ID, addr)
            .await
            .expect("distinct-identity handshake");
        assert_ne!(
            s3.assigned_ipv4(),
            ip1,
            "a distinct account must receive a distinct tunnel IP"
        );

        s1.disconnect();
        s2.disconnect();
        s3.disconnect();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn daita_cover_traffic_is_accepted_by_a_daita_active_exit() {
        let Some((addr, exit_x25519, exit_rpk)) = running_full_exit() else {
            eprintln!("skipping: WARREN_EXIT_ADDR not set (needs a rooted --use-tun exit)");
            return;
        };

        // The exit advertises DAITA (e.g. a tamaraw machine). The client's
        // cover-traffic frame (first byte 0xFF, high nibble not 4/6) must be
        // recognised as a dummy and dropped, never mistaken for an IP packet that
        // would fault the session. Interleave dummies with IP-looking packets.
        let key = SigningKey::from_bytes(&CLIENT_SEED);
        let session = MultihopClientTunnel::new(key)
            .connect(exit_rpk, exit_x25519, TEST_EXIT_ID, addr)
            .await
            .expect("handshake against the DAITA-active exit");

        for i in 0..16u8 {
            session
                .send_cover_traffic(200)
                .expect("exit accepts cover traffic");
            if i % 4 == 0 {
                let mut pkt = vec![0x45u8];
                pkt.extend((0..120u16).map(|b| b as u8 ^ i));
                session
                    .send_packet(&pkt)
                    .expect("exit accepts a real packet");
            }
        }

        // Give any exit-side rejection time to surface as a connection close.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            session.connection().close_reason().is_none(),
            "the DAITA-active exit must not reset the session over cover traffic: {:?}",
            session.connection().close_reason()
        );
        let snap = session.metrics_snapshot();
        assert_eq!(snap.cover_packets_sent, 16, "all dummies were counted");

        session.disconnect();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn daita_driver_emits_scheduled_padding_against_the_real_exit() {
        use std::sync::Arc;

        use tokio::sync::Notify;
        use warren_daita::{DaitaConfig, DaitaPool, DaitaState};

        use crate::daita_driver::DaitaDriver;

        let Some((addr, exit_x25519, exit_rpk)) = running_full_exit() else {
            eprintln!("skipping: WARREN_EXIT_ADDR not set (needs a rooted --use-tun exit)");
            return;
        };

        let key = SigningKey::from_bytes(&CLIENT_SEED);
        let session = Arc::new(
            MultihopClientTunnel::new(key)
                .connect(exit_rpk, exit_x25519, TEST_EXIT_ID, addr)
                .await
                .expect("handshake for the DAITA driver"),
        );

        // Drive the curated Tamaraw machine, but with a permissive padding cap so
        // its constant-rate schedule actually emits within the short test window
        // (the pool's 0.15 cap would throttle padding without sustained traffic).
        let base = DaitaPool::default_pool()
            .pick_named_os("tamaraw")
            .expect("tamaraw entry");
        let cfg = DaitaConfig::from_specs(base.machine_specs, 0.9, 0.0);
        let state = DaitaState::from_config(&cfg, std::time::Instant::now()).expect("daita state");
        assert!(state.is_enabled());

        let driver = DaitaDriver::new(Arc::clone(&session), state);
        let handle = driver.handle();
        let stop = Arc::new(Notify::new());
        let run = tokio::spawn(Arc::clone(&driver).run(Arc::clone(&stop)));

        // Feed real uplink events so the machine stays in its padding state and
        // the cap keeps headroom; the driver schedules and emits cover frames.
        for _ in 0..10 {
            handle.note_uplink();
            tokio::time::sleep(Duration::from_millis(40)).await;
        }

        stop.notify_one();
        run.await.expect("driver task joins");

        assert!(
            driver.metrics().padding_fired >= 1,
            "the maybenot machine scheduled at least one padding action"
        );
        assert!(
            session.metrics_snapshot().cover_packets_sent >= 1,
            "the driver emitted cover frames the real exit accepted"
        );
        assert!(
            session.connection().close_reason().is_none(),
            "the exit kept the session up through the driven padding"
        );

        session.disconnect();
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn socket_bypass_is_threaded_from_the_builder() {
        // A privileged TUN datapath keys its carrier-socket escape on a socket
        // mark/bind (Port Fail fix), which the tunnel must carry down to the QUIC
        // socket bind. The builder pins it and exposes it for the dialer.
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let bypass = SocketBypass::Fwmark(0x7761_7272);
        let tunnel = MultihopClientTunnel::new(key).with_socket_bypass(bypass);
        assert_eq!(tunnel.socket_bypass(), Some(bypass));
    }

    #[test]
    fn no_socket_bypass_by_default_so_the_userland_proxy_is_unaffected() {
        // The userland proxy installs no OS tunnel, so it must never mark/bind
        // its socket; the default is `None` (verbatim bind).
        let key = SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(MultihopClientTunnel::new(key).socket_bypass(), None);
    }

    #[test]
    fn multihop_error_display_never_leaks_the_source_detail() {
        // No-log discipline: the top-level Display is a static label; the wrapped
        // source (which may carry an address) is reachable via `source()` for
        // debugging but must never appear in the rendered message.
        let secret = "10.66.13.37:51820";
        let io = std::io::Error::other(format!("connect to {secret} refused"));
        let bind = MultihopError::Bind(io);
        assert!(
            !bind.to_string().contains(secret),
            "Bind leaked the address: {bind}"
        );

        let setup_io = MultihopError::SetupIo {
            context: "open setup stream",
            source: format!("peer {secret} reset").into(),
        };
        assert!(
            !setup_io.to_string().contains(secret),
            "SetupIo leaked the address: {setup_io}"
        );
        // The static context label is fine (it is a step name, not identity).
        assert!(setup_io.to_string().contains("open setup stream"));
    }

    #[test]
    fn drain_advisory_decodes_an_exit_draining_control_frame() {
        // ADR 36: the exit's sealed ExitDraining frame, once HPKE-opened to
        // its plaintext, must decode to a DrainAdvisory carrying the exact
        // deadline + reason so the upper layer can migrate before the close.
        let plaintext = warren_wire::control::encode_control(&WarrenControlMessage::ExitDraining {
            deadline_unix_secs: 1_700_000_000,
            reason_code: 7,
        })
        .expect("encode ExitDraining");
        let adv =
            drain_advisory_from_plaintext(&plaintext).expect("ExitDraining must yield an advisory");
        assert_eq!(adv.deadline_unix_secs, 1_700_000_000);
        assert_eq!(adv.reason_code, 7);
    }

    #[test]
    fn drain_advisory_ignores_other_control_and_data_frames() {
        // A non-draining control frame (Rejected) is not an advisory...
        let rejected = warren_wire::control::encode_control(&WarrenControlMessage::Rejected)
            .expect("encode Rejected");
        assert!(drain_advisory_from_plaintext(&rejected).is_none());
        // ...and a raw IPv4 packet (first nibble 4) is not even a control frame.
        assert!(drain_advisory_from_plaintext(&[0x45, 0x00, 0x00, 0x14]).is_none());
    }

    #[test]
    fn rekey_policy_doctrine_is_eight_hours_with_five_second_overlap() {
        let p = RekeyPolicy::doctrine();
        assert_eq!(p.interval(), Duration::from_secs(8 * 60 * 60));
        assert_eq!(p.overlap(), Duration::from_secs(5));
        assert_eq!(RekeyPolicy::default(), p);
    }

    #[test]
    fn rekey_policy_is_due_only_past_the_interval() {
        let p = RekeyPolicy::doctrine().with_interval(Duration::from_secs(100));
        assert!(!p.is_due(Duration::from_secs(99)));
        assert!(p.is_due(Duration::from_secs(100)));
        assert!(p.is_due(Duration::from_secs(101)));
    }
}
