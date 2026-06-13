//! Warren VPN client SDK: the single crate applications depend on.
//!
//! [`WarrenClient`] composes the layers into one flow:
//!
//! ```no_run
//! # async fn run() -> Result<(), warren_sdk::SdkError> {
//! use warren_sdk::{WarrenClient, identity::WarrenIdentity};
//! use warren_sdk::discovery::ExitQuery;
//!
//! let (identity, _mnemonic) = WarrenIdentity::generate();
//! let client = WarrenClient::builder()
//!     .identity(identity)
//!     .api_base("https://api.warrenbrowse.com")
//!     .server_pubkey_pin("….hex….")
//!     .build();
//!
//! let selector = client.fetch_exits().await?;        // signed list, verified
//! let exit = selector.select(&ExitQuery::country("RO"))?.clone();
//! let sink = client.connect_tunnel(&exit).await?;    // QUIC packet plane
//! # let _ = sink; Ok(())
//! # }
//! ```
//!
//! The returned [`warren_net::QuicPacketSink`] is the packet plane; the proxy
//! (non-root, default) and TUN (privileged) datapaths in [`warren_net`] drive
//! it. Wiring a datapath onto the sink is the remaining `warren-net` work.

pub use warren_api as api;
pub use warren_discovery as discovery;
pub use warren_identity as identity;
pub use warren_net as net;
pub use warren_transport as transport;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use warren_api::{ClientError, HttpTransport, WarrenApiClient};
use warren_discovery::{ExitSelector, Relay, SelectorError, SignedError, verify_signed_relay_list};
use warren_identity::WarrenIdentity;
use warren_net::QuicPacketSink;
use warren_transport::{ClientTunnel, TunnelError};

#[cfg(feature = "reqwest-transport")]
use warren_api::ReqwestTransport;

/// Errors surfaced by the facade.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SdkError {
    /// An account API call failed.
    #[error(transparent)]
    Api(#[from] ClientError),
    /// The signed exit list failed verification.
    #[error(transparent)]
    Discovery(#[from] SignedError),
    /// No exit matched the selection query.
    #[error(transparent)]
    Selector(#[from] SelectorError),
    /// Establishing the tunnel failed.
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
    /// The chosen exit has no dialable address.
    #[error("exit has no dialable address")]
    NoExitAddress,
    /// The signed exit list is past its `expires_at` (anti-freeze / replay).
    #[error("signed exit list is expired")]
    StaleRelayList,
    /// The signed exit list's `generation` is below the highest already trusted
    /// (anti-rollback).
    #[error("signed exit list rolled back: generation {got} < trusted floor {floor}")]
    RolledBackRelayList {
        /// Generation in the fetched list.
        got: u64,
        /// Highest generation previously trusted.
        floor: u64,
    },
}

/// Builder for a [`WarrenClient`].
pub struct WarrenClientBuilder {
    identity: Option<WarrenIdentity>,
    api_base: String,
    server_pubkey_pin: Option<String>,
}

impl WarrenClientBuilder {
    /// Sets the wallet identity (required).
    #[must_use]
    pub fn identity(mut self, identity: WarrenIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sets the API base URL (no trailing slash).
    #[must_use]
    pub fn api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Pins the API server's Ed25519 pubkey (64-char hex) used to verify the
    /// signed exit list.
    ///
    /// Production MUST set this. When unset, verification accepts any
    /// self-consistent signature on every fetch (no trust-on-first-use
    /// persistence), so an attacker who can serve a self-signed list is trusted.
    #[must_use]
    pub fn server_pubkey_pin(mut self, hex: impl Into<String>) -> Self {
        self.server_pubkey_pin = Some(hex.into());
        self
    }

    /// Builds the client with the bundled reqwest transport.
    ///
    /// # Panics
    ///
    /// Panics if no identity was set.
    #[cfg(feature = "reqwest-transport")]
    #[must_use]
    pub fn build(self) -> WarrenClient<ReqwestTransport> {
        self.build_with_transport(ReqwestTransport::new())
    }

    /// Builds the client with a caller-provided transport.
    ///
    /// # Panics
    ///
    /// Panics if no identity was set.
    #[must_use]
    pub fn build_with_transport<T: HttpTransport>(self, transport: T) -> WarrenClient<T> {
        let identity = self
            .identity
            .expect("WarrenClientBuilder requires an identity");
        let pin = self.server_pubkey_pin.clone();
        // The wallet key doubles as the QUIC tunnel client identity, so keep a
        // copy before the identity moves into the API client.
        let signing = identity.signing_key();
        let api = WarrenApiClient::new(self.api_base, identity, transport);
        WarrenClient {
            api,
            signing,
            server_pubkey_pin: pin,
            generation_floor: AtomicU64::new(0),
        }
    }
}

/// The high-level Warren client.
pub struct WarrenClient<T> {
    api: WarrenApiClient<T>,
    signing: warren_identity::ed25519_dalek::SigningKey,
    server_pubkey_pin: Option<String>,
    /// Highest signed-list `generation` trusted so far (anti-rollback floor).
    generation_floor: AtomicU64,
}

impl WarrenClient<()> {
    /// Starts building a client.
    #[must_use]
    pub fn builder() -> WarrenClientBuilder {
        WarrenClientBuilder {
            identity: None,
            api_base: warren_api_default_base(),
            server_pubkey_pin: None,
        }
    }
}

impl<T: HttpTransport> WarrenClient<T> {
    /// The account API client (subscription, register, sessions, ...).
    #[must_use]
    pub fn api(&self) -> &WarrenApiClient<T> {
        &self.api
    }

    /// Fetches the signed exit list, verifies it against the pinned server
    /// pubkey, enforces freshness and anti-rollback, and returns a selector over
    /// the resolved exits.
    ///
    /// On the live-fetch path the caller must enforce the signed `expires_at`
    /// (anti-freeze) and a monotonic `generation` (anti-rollback): a valid but
    /// stale or replayed list is otherwise accepted. This method does both,
    /// tracking the highest trusted `generation` for the client's lifetime.
    ///
    /// # Errors
    ///
    /// [`SdkError::Api`] on fetch failure, [`SdkError::Discovery`] on bad
    /// signature/version, [`SdkError::StaleRelayList`] if expired, and
    /// [`SdkError::RolledBackRelayList`] if the generation regressed.
    pub async fn fetch_exits(&self) -> Result<ExitSelector, SdkError> {
        let json = self.api.list_exits().await?;
        let verified = verify_signed_relay_list(&json, self.server_pubkey_pin.as_deref())?;

        if verified.is_expired(now_unix_secs()) {
            return Err(SdkError::StaleRelayList);
        }
        let floor = self.generation_floor.load(Ordering::Acquire);
        if verified.generation < floor {
            return Err(SdkError::RolledBackRelayList {
                got: verified.generation,
                floor,
            });
        }
        self.generation_floor
            .fetch_max(verified.generation, Ordering::AcqRel);

        Ok(ExitSelector::new(verified.relays))
    }

    /// Establishes the QUIC tunnel to `exit` and returns the packet plane.
    ///
    /// # Errors
    ///
    /// [`SdkError::NoExitAddress`] if the exit lists no address,
    /// [`SdkError::Tunnel`] if the handshake fails.
    pub async fn connect_tunnel(&self, exit: &Relay) -> Result<QuicPacketSink, SdkError> {
        let addr: SocketAddr = *exit.addrs().first().ok_or(SdkError::NoExitAddress)?;
        let tunnel = ClientTunnel::new(self.signing.clone());
        let session = tunnel.connect(exit.endpoint_id(), addr).await?;
        Ok(QuicPacketSink::new(session))
    }
}

#[cfg(feature = "reqwest-transport")]
fn warren_api_default_base() -> String {
    "https://api.warrenbrowse.com".to_owned()
}

#[cfg(not(feature = "reqwest-transport"))]
fn warren_api_default_base() -> String {
    String::new()
}

/// Current Unix time in seconds; `0` if the clock is before the epoch (which
/// makes `is_expired` conservatively treat the list as not-yet-expired rather
/// than spuriously rejecting it).
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_constructs_with_identity() {
        let (id, _m) = WarrenIdentity::generate();
        let addr = id.address();
        let client = WarrenClient::builder()
            .identity(id)
            .api_base("https://api.example.test")
            .build();
        assert_eq!(client.api().address(), addr);
    }
}
