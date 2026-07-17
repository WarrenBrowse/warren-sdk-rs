//! Warren QUIC transport.
//!
//! [`ClientTunnel`] dials an exit over QUIC with a TLS 1.3 raw-public-key
//! handshake ([`tls`]), exchanges the Setup/SetupAck frames, and yields a
//! [`ClientSession`] that carries IP packets as RFC 9221 datagrams. The session
//! is the data-plane seam the `warren-net` backends drive.
//!
//! Pure protocol logic: no TUN, routing, DNS or OS coupling here.

pub mod client;
pub mod daita_driver;
pub mod multihop;
pub mod reconnect;
pub(crate) mod tcp_fallback;
pub mod tls;

pub use client::{ClientSession, ClientTunnel, TunnelError, local_ip_for_endpoint};
// ADR-0006 idle cover: the scheduler + driver live in the engine
// (`warrenguard_pump::idle_cover`), the single home. Re-exported here so SDK
// consumers keep the `warren_transport::{CoverSink, IdleCoverDriver, ..}` path;
// the SDK's `ClientSession`/`MultihopSession` implement the engine `CoverSink`.
pub use warrenguard_pump::idle_cover::{
    CoverSink, IdleCover, IdleCoverDriver, IdleCoverDriverHandle,
};
// Re-export so callers can build a custom transport config (e.g. a fork-patched
// system-VPN workspace injecting the engine's obfuscated config) and pass it to
// `with_transport_config` without depending on quinn directly. The type is
// fork-agnostic: identical whether the workspace patches quinn or not.
pub use daita_driver::{DaitaDriver, DaitaDriverHandle};
pub use multihop::{
    DrainAdvisory, MultihopClientTunnel, MultihopError, MultihopMetrics, MultihopMetricsSnapshot,
    MultihopSession, RekeyPolicy,
};
// The engine setup-failure type carried by `MultihopError::Setup`, re-exported so
// a consumer can match on / construct the policy verdict (`Rejected`,
// `IpExhausted`) without reaching into the engine crate directly.
pub use quinn::TransportConfig;
pub use reconnect::{
    Backoff, BackoffIter, ConnectionState, JitterBackoff, RetryError, connect_with_retry,
    connect_with_state,
};
pub use tls::{WarrenTlsError, default_crypto_provider, make_client_config, make_server_config};
pub use warren_multihop::SetupError;
// The engine's reconnect verdict (fatal / retry-same / retry-reselect) and its
// fatal cause, re-exported so a supervisor consuming a `TunnelError` /
// `MultihopError` verdict names them without depending on the engine crate.
pub use warrenguard_transport::{FatalCause, Retryability};
// The reusable in-tunnel egress-liveness probe scheduler + its IO trait. The SDK
// proxy supervisor implements `EgressProbeIo` over its userland datapath, so the
// dead-exit-forwards-nothing verdict is decided once, in the engine.
pub use warrenguard_transport::egress_probe;
// The drain-reaction anti-stampede policy (jitter, cooldown, avoid TTL) is
// engine-owned; consumers spread reconnects with it instead of re-deciding.
pub use warrenguard_transport::drain_policy;
// The client redial schedule (shared backoff preset + the healthy-vs-flapping
// session verdict) is engine-owned; supervisors draw delays from it instead
// of re-declaring a local schedule.
pub use warrenguard_transport::redial_policy;
// The per-OS carrier-socket bypass value a privileged TUN datapath pins on the
// tunnel (via `MultihopClientTunnel::with_socket_bypass`) so the SDK can name it
// without depending on the engine crate directly.
pub use warrenguard_socket_bypass::SocketBypass;
