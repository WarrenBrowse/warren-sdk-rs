//! Warren QUIC transport.
//!
//! [`ClientTunnel`] dials an exit over QUIC with a TLS 1.3 raw-public-key
//! handshake ([`tls`]), exchanges the Setup/SetupAck frames, and yields a
//! [`ClientSession`] that carries IP packets as RFC 9221 datagrams. The session
//! is the data-plane seam the `warren-net` backends drive.
//!
//! Pure protocol logic: no TUN, routing, DNS or OS coupling here.

pub mod client;
pub mod multihop;
pub mod reconnect;
pub mod tls;

pub use client::{ClientSession, ClientTunnel, TunnelError};
pub use multihop::{MultihopClientTunnel, MultihopError, MultihopSession};
pub use reconnect::{
    Backoff, BackoffIter, ConnectionState, JitterBackoff, RetryError, connect_with_retry,
    connect_with_state,
};
pub use tls::{WarrenTlsError, default_crypto_provider, make_client_config, make_server_config};
