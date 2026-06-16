//! Warren VPN client SDK: the single crate applications depend on.
//!
//! [`WarrenClient`] composes the layers into one flow. The recommended path is
//! the sealed multihop tunnel (the handshake production exits accept) behind a
//! local SOCKS5 proxy the integrating app points itself at:
//!
//! ```no_run
//! # async fn run() -> Result<(), warren_sdk::SdkError> {
//! use warren_sdk::{WarrenClient, identity::WarrenIdentity};
//! use warren_sdk::net::ProxyConfig;
//!
//! let (identity, _mnemonic) = WarrenIdentity::generate();
//! let client = WarrenClient::builder()
//!     .identity(identity)
//!     .api_base("https://api.warrenbrowse.com")
//!     // The pinned server pubkey: 32 bytes (64 hex chars). Ship the real one.
//!     .server_pubkey_pin("0000000000000000000000000000000000000000000000000000000000000000")
//!     .build()?;
//!
//! // Fetch and verify the signed multihop directory (full PKI chain).
//! let exits = client.fetch_multihop_directory().await?;
//! if let Some(exit) = exits.first() {
//!     // Start the non-root datapath: a local SOCKS5 listener (127.0.0.1:1080
//!     // by default) whose traffic egresses at the exit over the sealed tunnel.
//!     let proxy = client.start_proxy_multihop(exit, &ProxyConfig::default()).await?;
//!     // Point the app's SOCKS5 client at `proxy.local_addr()`; drop the handle
//!     // (or call `shutdown`) to stop the datapath.
//!     let _ = proxy.local_addr();
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Account, payment and incident operations are reached through
//! [`WarrenClient::api`]. The single-hop [`WarrenClient::connect_tunnel`] returns
//! a raw [`warren_net::QuicPacketSink`] for tests and bespoke datapaths; real
//! exits require the multihop path above.
//!
//! Beyond the one-shot [`WarrenClient::start_proxy_multihop`]:
//! - [`WarrenClient::start_proxy_multihop_supervised`] returns a
//!   [`SupervisedProxyHandle`] that keeps the tunnel up across drops behind a
//!   stable local address, reporting [`ConnectionState`] transitions (the
//!   app-driven alternative is to watch [`ProxyHandle::state`] and reconnect).
//!   [`WarrenClient::start_proxy_multihop_supervised_failover`] does the same over
//!   a prioritized exit list, rotating past a broken or unreachable exit.
//! - [`ProxyHandle::forward_port`] maps a tunnel-side port at the exit (NAT-PMP)
//!   and relays inbound connections to a local server, returning a
//!   [`warren_net::ForwardedPort`].

pub use warren_api as api;
pub use warren_discovery as discovery;
pub use warren_identity as identity;
pub use warren_net as net;
pub use warren_transport as transport;

/// Lifecycle state of a supervised connection (`Connecting`, `Connected`,
/// `Reconnecting`, `Failed`), re-exported for [`SupervisedProxyHandle`].
pub use warren_transport::ConnectionState;

mod client;
mod error;
mod proxy;
mod store;
mod supervisor;

#[cfg(all(unix, feature = "experimental-tun"))]
pub use client::TunDatapathHandle;
pub use client::{
    DefaultClient, GenerationStore, InMemoryGenerationStore, ServerKeyStore, WarrenClient,
    WarrenClientBuilder,
};
pub use error::{BuildError, SdkError};
pub use proxy::{ProxyForwarder, ProxyHandle, TunnelState};
pub use store::{FileGenerationStore, FileServerKeyStore};
pub use supervisor::SupervisedProxyHandle;

#[cfg(test)]
mod tests;
