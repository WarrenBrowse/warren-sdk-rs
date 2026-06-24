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
pub mod idle_cover;
pub mod multihop;
pub mod reconnect;
pub mod tls;

pub use client::{ClientSession, ClientTunnel, TunnelError, local_ip_for_endpoint};
pub use idle_cover::{CoverSink, IdleCover, IdleCoverDriver, IdleCoverDriverHandle};
// Re-export so callers can build a custom transport config (e.g. a fork-patched
// system-VPN workspace injecting the engine's obfuscated config) and pass it to
// `with_transport_config` without depending on quinn directly. The type is
// fork-agnostic: identical whether the workspace patches quinn or not.
pub use daita_driver::{DaitaDriver, DaitaDriverHandle};
pub use multihop::{
    MultihopClientTunnel, MultihopError, MultihopMetrics, MultihopMetricsSnapshot, MultihopSession,
    RekeyPolicy,
};
pub use quinn::TransportConfig;
pub use reconnect::{
    Backoff, BackoffIter, ConnectionState, JitterBackoff, RetryError, connect_with_retry,
    connect_with_state,
};
pub use tls::{WarrenTlsError, default_crypto_provider, make_client_config, make_server_config};
