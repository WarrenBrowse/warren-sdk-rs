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
//!     .build()?;
//!
//! let selector = client.fetch_exits().await?;        // signed list, verified
//! let exit = selector.select_weighted(&ExitQuery::country("RO"))?.clone();
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
use std::sync::Arc;
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
    /// Binding the local proxy listener failed.
    #[error("proxy listener bind failed")]
    Proxy(#[source] std::io::Error),
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
    /// The client builder was misconfigured.
    #[error(transparent)]
    Build(#[from] BuildError),
}

/// Reasons [`WarrenClientBuilder::build`] can reject a configuration.
///
/// Returned instead of panicking so an FFI embedder gets a recoverable error
/// rather than an unwind across the language boundary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// No identity was provided.
    #[error("a Warren identity is required")]
    MissingIdentity,
    /// No server pubkey pin was set and pinning was not explicitly waived.
    #[error("no server pubkey pin set; call server_pubkey_pin(..) or allow_any_server_key()")]
    UnpinnedServerKey,
}

/// Persists the highest trusted signed-list `generation`, the anti-rollback
/// floor.
///
/// The default store ([`InMemoryGenerationStore`]) lives only for the process,
/// so anti-rollback resets on every restart: an attacker who can serve HTTP can
/// replay an older but validly signed (and not yet expired) list to a freshly
/// launched client. Supply a persistent implementation (disk, keychain) to make
/// anti-rollback survive restarts.
pub trait GenerationStore: Send + Sync {
    /// Returns the highest generation trusted so far (`0` if none yet).
    fn load_floor(&self) -> u64;
    /// Records `generation` as trusted; implementations keep the maximum seen.
    fn store_floor(&self, generation: u64);
}

/// Persists the trusted server pubkey for trust-on-first-use (TOFU) pinning.
///
/// Supplying a store (with [`allow_any_server_key`] or on its own) makes the
/// client accept any self-consistent signature on the *first* fetch, remember
/// that server pubkey, and pin every later fetch to it. This upgrades the
/// unpinned default from trust-on-every-use to trust-on-first-use.
///
/// [`allow_any_server_key`]: WarrenClientBuilder::allow_any_server_key
pub trait ServerKeyStore: Send + Sync {
    /// The pinned server pubkey hex, if one has been stored.
    fn load_pin(&self) -> Option<String>;
    /// Records the server pubkey hex trusted on first use.
    fn store_pin(&self, server_pubkey_hex: &str);
}

/// Process-memory [`GenerationStore`]; anti-rollback holds only within one run.
#[derive(Debug, Default)]
pub struct InMemoryGenerationStore(AtomicU64);

impl GenerationStore for InMemoryGenerationStore {
    fn load_floor(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn store_floor(&self, generation: u64) {
        self.0.fetch_max(generation, Ordering::AcqRel);
    }
}

/// Builder for a [`WarrenClient`].
pub struct WarrenClientBuilder {
    identity: Option<WarrenIdentity>,
    api_base: String,
    api_alternative_hosts: Vec<String>,
    server_pubkey_pin: Option<String>,
    allow_any_server_key: bool,
    generation_store: Arc<dyn GenerationStore>,
    server_key_store: Option<Arc<dyn ServerKeyStore>>,
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

    /// Sets alternative API hostnames (bare DNS names) tried in order when the
    /// primary host fails to connect (anti-censorship fallback).
    #[must_use]
    pub fn api_alternative_hosts(mut self, hosts: Vec<String>) -> Self {
        self.api_alternative_hosts = hosts;
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

    /// Waives server-key pinning: accept any self-consistent signature on the
    /// signed exit list.
    ///
    /// INSECURE. Only for tests or a transport you already trust end to end.
    /// Without it, [`build`](Self::build) refuses to construct an unpinned
    /// client rather than silently trusting any self-signed list.
    #[must_use]
    pub fn allow_any_server_key(mut self) -> Self {
        self.allow_any_server_key = true;
        self
    }

    /// Sets the anti-rollback [`GenerationStore`]. Defaults to
    /// [`InMemoryGenerationStore`] (process-scoped); supply a persistent store
    /// to keep anti-rollback across restarts.
    #[must_use]
    pub fn generation_store(mut self, store: Arc<dyn GenerationStore>) -> Self {
        self.generation_store = store;
        self
    }

    /// Sets a [`ServerKeyStore`] to enable trust-on-first-use pinning of the
    /// signed-exit-list server key. A TOFU store is itself a valid pinning
    /// strategy, so setting it satisfies the build-time pin requirement.
    #[must_use]
    pub fn server_key_store(mut self, store: Arc<dyn ServerKeyStore>) -> Self {
        self.server_key_store = Some(store);
        self
    }

    /// Builds the client with the bundled reqwest transport.
    ///
    /// # Errors
    ///
    /// [`BuildError::MissingIdentity`] if no identity was set, or
    /// [`BuildError::UnpinnedServerKey`] if neither a pin nor
    /// [`allow_any_server_key`](Self::allow_any_server_key) was set.
    #[cfg(feature = "reqwest-transport")]
    pub fn build(self) -> Result<WarrenClient<ReqwestTransport>, BuildError> {
        self.build_with_transport(ReqwestTransport::new())
    }

    /// Builds the client with a caller-provided transport.
    ///
    /// # Errors
    ///
    /// [`BuildError::MissingIdentity`] if no identity was set, or
    /// [`BuildError::UnpinnedServerKey`] if neither a pin nor
    /// [`allow_any_server_key`](Self::allow_any_server_key) was set.
    pub fn build_with_transport<T: HttpTransport>(
        self,
        transport: T,
    ) -> Result<WarrenClient<T>, BuildError> {
        let identity = self.identity.ok_or(BuildError::MissingIdentity)?;
        // A TOFU store is a deliberate pinning strategy, so it also satisfies
        // the requirement that an unpinned client be an explicit choice.
        if self.server_pubkey_pin.is_none()
            && !self.allow_any_server_key
            && self.server_key_store.is_none()
        {
            return Err(BuildError::UnpinnedServerKey);
        }
        let pin = self.server_pubkey_pin.clone();
        // The wallet key doubles as the QUIC tunnel client identity, so keep a
        // copy before the identity moves into the API client.
        let signing = identity.signing_key();
        let api = WarrenApiClient::new_with_fallback(
            self.api_base,
            self.api_alternative_hosts,
            identity,
            transport,
        );
        Ok(WarrenClient {
            api,
            signing,
            server_pubkey_pin: pin,
            generation_store: self.generation_store,
            server_key_store: self.server_key_store,
        })
    }
}

/// The Warren client over the bundled reqwest transport: the type most apps use.
/// `WarrenClient::builder()...build()` yields one.
#[cfg(feature = "reqwest-transport")]
pub type DefaultClient = WarrenClient<ReqwestTransport>;

/// The high-level Warren client.
pub struct WarrenClient<T> {
    api: WarrenApiClient<T>,
    signing: warren_identity::ed25519_dalek::SigningKey,
    server_pubkey_pin: Option<String>,
    /// Anti-rollback floor: highest signed-list `generation` trusted so far.
    generation_store: Arc<dyn GenerationStore>,
    /// Trust-on-first-use pin store, when enabled.
    server_key_store: Option<Arc<dyn ServerKeyStore>>,
}

impl WarrenClient<()> {
    /// Starts building a client.
    #[must_use]
    pub fn builder() -> WarrenClientBuilder {
        WarrenClientBuilder {
            identity: None,
            api_base: warren_api_default_base(),
            api_alternative_hosts: Vec::new(),
            server_pubkey_pin: None,
            allow_any_server_key: false,
            generation_store: Arc::new(InMemoryGenerationStore::default()),
            server_key_store: None,
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

        // Effective pin: an explicit pin wins; otherwise a TOFU store's
        // remembered key; otherwise none (first use, accept any self-consistent
        // signature and remember it below).
        let tofu_pin = self
            .server_pubkey_pin
            .is_none()
            .then(|| self.server_key_store.as_ref().and_then(|s| s.load_pin()))
            .flatten();
        let effective_pin = self.server_pubkey_pin.as_deref().or(tofu_pin.as_deref());

        let verified = verify_signed_relay_list(&json, effective_pin)?;

        if verified.is_expired(now_unix_secs()) {
            return Err(SdkError::StaleRelayList);
        }
        let floor = self.generation_store.load_floor();
        if verified.generation < floor {
            return Err(SdkError::RolledBackRelayList {
                got: verified.generation,
                floor,
            });
        }
        self.generation_store.store_floor(verified.generation);

        // Trust-on-first-use: with no explicit pin, remember the verified server
        // key the first time so later fetches are pinned to it.
        if self.server_pubkey_pin.is_none()
            && let Some(store) = &self.server_key_store
            && store.load_pin().is_none()
        {
            store.store_pin(&verified.server_pubkey_hex);
        }

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

    /// Starts the non-root proxy datapath against `exit`: connects the tunnel,
    /// runs a userspace netstack over it, and serves a local SOCKS5 proxy on
    /// `cfg.socks5`. Application traffic sent through the proxy egresses at the
    /// exit. Returns a handle whose drop stops the proxy.
    ///
    /// This is the feature-complete non-root mode on every OS. Validate against a
    /// real exit before relying on it (per the engineering rules).
    ///
    /// # Errors
    ///
    /// [`SdkError::NoExitAddress`]/[`SdkError::Tunnel`] from the tunnel, or
    /// [`SdkError::Proxy`] if the local listener cannot bind.
    pub async fn start_proxy(
        &self,
        exit: &Relay,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<ProxyHandle, SdkError> {
        let sink = self.connect_tunnel(exit).await?;
        let local_ip = sink.session().assigned_ipv4();
        let mtu = usize::from(sink.session().assigned_max_mtu());
        let connector = warren_net::spawn_over_sink(
            Arc::new(sink),
            local_ip,
            TUNNEL_PREFIX,
            TUNNEL_GATEWAY,
            mtu,
        );

        let socks_listener = tokio::net::TcpListener::bind(cfg.socks5)
            .await
            .map_err(SdkError::Proxy)?;
        let local_addr = socks_listener.local_addr().map_err(SdkError::Proxy)?;
        let socks = warren_net::Socks5Proxy::new(connector.clone());
        let mut tasks = vec![tokio::spawn(async move {
            let _ = socks.serve(socks_listener).await;
        })];

        let mut http_addr = None;
        if let Some(http_bind) = cfg.http {
            let http_listener = tokio::net::TcpListener::bind(http_bind)
                .await
                .map_err(SdkError::Proxy)?;
            http_addr = Some(http_listener.local_addr().map_err(SdkError::Proxy)?);
            let http = warren_net::HttpConnectProxy::new(connector);
            tasks.push(tokio::spawn(async move {
                let _ = http.serve(http_listener).await;
            }));
        }

        Ok(ProxyHandle {
            local_addr,
            http_addr,
            tasks,
        })
    }
}

/// Tunnel network prefix length (`10.66.0.0/16`), matching warren-core.
const TUNNEL_PREFIX: u8 = 16;
/// Tunnel gateway (exit side), matching warren-core's `10.66.0.1`.
const TUNNEL_GATEWAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 66, 0, 1);

/// A running non-root proxy datapath. Dropping it stops the proxy.
pub struct ProxyHandle {
    local_addr: SocketAddr,
    http_addr: Option<SocketAddr>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    /// The address the SOCKS5 listener actually bound (useful when `cfg.socks5`
    /// used port 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The address the HTTP CONNECT listener bound, if one was configured.
    #[must_use]
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
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
    use warren_api::{HttpRequest, HttpResponse, TransportError};

    /// A transport that is never actually called by these builder tests.
    struct NullTransport;

    impl HttpTransport for NullTransport {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
            Err(TransportError::Io("unused".into()))
        }
    }

    #[test]
    fn builder_constructs_with_identity() {
        let (id, _m) = WarrenIdentity::generate();
        let addr = id.address();
        let client = WarrenClient::builder()
            .identity(id)
            .api_base("https://api.example.test")
            .allow_any_server_key()
            .build()
            .expect("build");
        assert_eq!(client.api().address(), addr);
    }

    #[test]
    fn build_requires_identity() {
        let result = WarrenClient::builder()
            .api_base("https://api.example.test")
            .allow_any_server_key()
            .build_with_transport(NullTransport);
        assert!(matches!(result, Err(BuildError::MissingIdentity)));
    }

    #[test]
    fn build_refuses_unpinned_unless_explicit() {
        let (id, _m) = WarrenIdentity::generate();
        let result = WarrenClient::builder()
            .identity(id)
            .api_base("https://api.example.test")
            .build_with_transport(NullTransport);
        assert!(matches!(result, Err(BuildError::UnpinnedServerKey)));
    }
}
