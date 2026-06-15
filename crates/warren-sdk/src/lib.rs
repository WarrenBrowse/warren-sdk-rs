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
//!     .server_pubkey_pin("….hex….")
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use warren_api::{ClientError, HttpTransport, WarrenApiClient};
use warren_discovery::{
    DirectoryError, ExitSelector, Relay, SelectorError, SignedError, VerifiedExit,
    verify_multihop_directory, verify_signed_relay_list,
};
use warren_identity::WarrenIdentity;
use warren_net::{MultihopPacketSink, QuicPacketSink};
use warren_transport::{
    ClientTunnel, MultihopClientTunnel, MultihopError, MultihopSession, TunnelError,
};

/// Lifecycle state of a supervised connection (`Connecting`, `Connected`,
/// `Reconnecting`, `Failed`), re-exported for [`SupervisedProxyHandle`].
pub use warren_transport::ConnectionState;

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
    /// The signed multihop directory failed verification.
    #[error(transparent)]
    MultihopDirectory(#[from] DirectoryError),
    /// Establishing the multihop tunnel failed (handshake, policy, or datapath).
    #[error(transparent)]
    Multihop(#[from] MultihopError),
    /// The API has no multihop directory published (`404`).
    #[error("no multihop directory is published")]
    NoMultihopDirectory,
    /// The multihop directory is past its `expires_at` (anti-freeze / replay).
    #[error("multihop directory is expired")]
    StaleMultihopDirectory,
    /// The multihop directory's `generation` regressed below the trusted floor.
    #[error("multihop directory rolled back: generation {got} < trusted floor {floor}")]
    RolledBackMultihopDirectory {
        /// Generation in the fetched directory.
        got: u64,
        /// Highest generation previously trusted.
        floor: u64,
    },
    /// No multihop exit matched the selection.
    #[error("no multihop exit matched the selection")]
    NoMultihopExit,
    /// The chosen exit has no dialable address.
    #[error("exit has no dialable address")]
    NoExitAddress,
    /// The chosen exit runs no in-tunnel DNS forwarder and no override resolver
    /// was configured, so name resolution over the tunnel would fail closed.
    /// Set [`ProxyConfig::dns_server`](warren_net::ProxyConfig) to a reachable
    /// resolver, or pick an exit that resolves DNS.
    #[error("exit runs no DNS forwarder and no resolver was configured")]
    ExitDnsDisabled,
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
    /// A port-forwarding (NAT-PMP) operation failed.
    #[error(transparent)]
    PortForward(#[from] warren_net::PortForwardError),
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
    multihop_root_pubkey_pins: Vec<String>,
    allow_any_server_key: bool,
    generation_store: Arc<dyn GenerationStore>,
    multihop_generation_store: Arc<dyn GenerationStore>,
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

    /// Pins an offline multihop-directory ROOT Ed25519 pubkey (64-char hex). Call
    /// more than once to trust several roots (key rotation).
    ///
    /// The root is the anchor a compromised online server cannot outrun: when at
    /// least one root is pinned, the directory's operational certificate must be
    /// signed by a pinned root, so a holder of the online server key alone cannot
    /// mint exits the client accepts. When NONE is set the operational cert is
    /// accepted on trust-on-first-use terms (the server pin still authenticates the
    /// envelope, and each exit's Ed25519 identity should be cross-checked against
    /// [`WarrenClient::fetch_exits`]). Production using multihop SHOULD pin a root.
    #[must_use]
    pub fn multihop_root_pubkey_pin(mut self, hex: impl Into<String>) -> Self {
        self.multihop_root_pubkey_pins.push(hex.into());
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

    /// Sets the anti-rollback [`GenerationStore`] for the multihop directory
    /// (a separate generation sequence from the signed exit list). Defaults to a
    /// distinct [`InMemoryGenerationStore`]; supply a persistent store to keep
    /// directory anti-rollback across restarts.
    #[must_use]
    pub fn multihop_generation_store(mut self, store: Arc<dyn GenerationStore>) -> Self {
        self.multihop_generation_store = store;
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
            multihop_root_pubkey_pins: self.multihop_root_pubkey_pins,
            generation_store: self.generation_store,
            multihop_generation_store: self.multihop_generation_store,
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
    /// Pinned offline multihop-directory root keys (empty = root TOFU).
    multihop_root_pubkey_pins: Vec<String>,
    /// Anti-rollback floor: highest signed-list `generation` trusted so far.
    generation_store: Arc<dyn GenerationStore>,
    /// Anti-rollback floor for the multihop directory (separate sequence).
    multihop_generation_store: Arc<dyn GenerationStore>,
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
            multihop_root_pubkey_pins: Vec::new(),
            allow_any_server_key: false,
            generation_store: Arc::new(InMemoryGenerationStore::default()),
            multihop_generation_store: Arc::new(InMemoryGenerationStore::default()),
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
        // Single-hop SetupAck carries no subnet (and no v6 gateway/prefix), so
        // fall back to the frozen v4 tunnel defaults (10.66.0.0/16, gw 10.66.0.1)
        // and stay v4-only.
        serve_proxy_over_sink(sink, local_ip, TUNNEL_PREFIX, TUNNEL_GATEWAY, None, cfg).await
    }

    /// Fetches and verifies the signed multihop directory, returning the trusted
    /// exits. Enforces the version and the `expires_at` freshness bound; the full
    /// PKI trust chain (server envelope, operational cert, exit descriptor) is
    /// verified inside [`verify_multihop_directory`].
    ///
    /// The configured server pubkey pin, when set, authenticates which server
    /// signed the directory; otherwise the chain is accepted on trust-on-first-
    /// use terms. Any root pins set via
    /// [`multihop_root_pubkey_pin`](WarrenClientBuilder::multihop_root_pubkey_pin)
    /// additionally anchor the operational certificate to the offline root. Each
    /// exit's Ed25519 identity should additionally be cross-checked against
    /// [`Self::fetch_exits`] before use.
    ///
    /// # Errors
    ///
    /// [`SdkError::Api`] on fetch failure, [`SdkError::NoMultihopDirectory`] if
    /// none is published, [`SdkError::MultihopDirectory`] on a bad signature or
    /// version, and [`SdkError::StaleMultihopDirectory`] if expired.
    pub async fn fetch_multihop_directory(&self) -> Result<Vec<VerifiedExit>, SdkError> {
        let json = self
            .api
            .get_multihop_directory()
            .await?
            .ok_or(SdkError::NoMultihopDirectory)?;

        // The configured relay-list pin doubles as the directory server pin when
        // present; with no pin, accept the self-consistent chain (TOFU).
        let pins: Vec<&str> = self.server_pubkey_pin.as_deref().into_iter().collect();
        // Anchor the operational cert to the pinned offline root(s) when set, so a
        // holder of the online server key alone cannot mint accepted exits. Empty =
        // root TOFU (documented on `multihop_root_pubkey_pin`).
        let roots: Vec<&str> = self
            .multihop_root_pubkey_pins
            .iter()
            .map(String::as_str)
            .collect();
        let verified = verify_multihop_directory(&json, &pins, &roots)?;

        if now_unix_secs() >= verified.expires_at {
            return Err(SdkError::StaleMultihopDirectory);
        }
        // Anti-rollback on the directory's own generation sequence (separate from
        // the signed exit list): reject a replayed older-but-signed directory.
        let floor = self.multihop_generation_store.load_floor();
        if verified.generation < floor {
            return Err(SdkError::RolledBackMultihopDirectory {
                got: verified.generation,
                floor,
            });
        }
        self.multihop_generation_store
            .store_floor(verified.generation);
        Ok(verified.exits)
    }

    /// Establishes a multihop tunnel to `exit` (the handshake real exits require:
    /// an HPKE-sealed setup frame, not a bare `Setup`) and returns the sealed
    /// packet plane.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] if the handshake, policy gate, or datapath fails.
    pub async fn connect_multihop(
        &self,
        exit: &VerifiedExit,
    ) -> Result<MultihopPacketSink, SdkError> {
        let tunnel = MultihopClientTunnel::new(self.signing.clone());
        let session = tunnel
            .connect(
                exit.exit_ed25519_pubkey,
                exit.exit_x25519_multihop_pubkey,
                exit.exit_id,
                exit.endpoint,
            )
            .await?;
        Ok(MultihopPacketSink::new(session))
    }

    /// Starts the non-root proxy datapath over a multihop tunnel to `exit`. Same
    /// shape as [`Self::start_proxy`] but every packet is HPKE-sealed, so it
    /// works against production exits.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] from the tunnel, or [`SdkError::Proxy`] if the
    /// local listener cannot bind.
    pub async fn start_proxy_multihop(
        &self,
        exit: &VerifiedExit,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<ProxyHandle, SdkError> {
        ensure_dns_reachable(exit.dns_disabled, cfg)?;
        let sink = self.connect_multihop(exit).await?;
        let (local_ip, prefix, gateway, ipv6) = addressing_from_session(sink.session());
        serve_proxy_over_sink(sink, local_ip, prefix, gateway, ipv6, cfg).await
    }

    /// Starts a *self-healing* multihop proxy datapath: it binds the local
    /// SOCKS5 (and optional HTTP CONNECT) listeners once, then keeps a sealed
    /// tunnel to `exit` up across drops, rebuilding the netstack from a freshly
    /// fetched `IpAssign` on each reconnect while the app-facing proxy address
    /// stays stable. Observe progress via [`SupervisedProxyHandle::watch_state`].
    ///
    /// Unlike [`Self::start_proxy_multihop`], the returned handle stays valid
    /// across reconnects: the app keeps pointing at the same proxy address and the
    /// datapath transparently re-establishes. Reconnection targets the same
    /// `exit`; the first attempt's failure is surfaced (the handle reports
    /// [`ConnectionState::Reconnecting`]) but does not error the call. For
    /// resilience to a permanently-unreachable exit, see
    /// [`Self::start_proxy_multihop_supervised_failover`].
    ///
    /// # Errors
    ///
    /// [`SdkError::Proxy`] if a local listener cannot bind. Tunnel establishment
    /// happens in the background, so connect failures surface as state, not here.
    pub async fn start_proxy_multihop_supervised(
        &self,
        exit: &VerifiedExit,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<SupervisedProxyHandle, SdkError> {
        ensure_dns_reachable(exit.dns_disabled, cfg)?;
        let signing = self.signing.clone();
        let exit = exit.clone();
        self.spawn_supervised(cfg, move || {
            let signing = signing.clone();
            let exit = exit.clone();
            async move { establish_multihop(signing, &exit).await }
        })
        .await
    }

    /// Self-healing multihop proxy with exit FAILOVER: same stable-listener,
    /// self-rebuilding datapath as [`Self::start_proxy_multihop_supervised`], but
    /// over a prioritized list of candidate `exits`. It sticks with the first exit
    /// that connects (stable egress), and only rotates to the next candidate when
    /// the current one fails to (re)establish, wrapping around the list. The app
    /// chooses the candidate set (for example every exit in the desired country),
    /// so egress stays within its constraints while a single broken or
    /// unreachable exit no longer wedges the datapath.
    ///
    /// # Errors
    ///
    /// [`SdkError::NoMultihopExit`] if `exits` is empty; [`SdkError::Proxy`] if a
    /// local listener cannot bind. Connect failures surface as state, not here.
    pub async fn start_proxy_multihop_supervised_failover(
        &self,
        exits: &[VerifiedExit],
        cfg: &warren_net::ProxyConfig,
    ) -> Result<SupervisedProxyHandle, SdkError> {
        if exits.is_empty() {
            return Err(SdkError::NoMultihopExit);
        }
        // No candidate can resolve names without a forwarder or an override.
        if cfg.dns_server.is_none() && exits.iter().all(|e| e.dns_disabled) {
            return Err(SdkError::ExitDnsDisabled);
        }
        let signing = self.signing.clone();
        let exits = exits.to_vec();
        // Shared cursor: advanced only on a failed attempt, so a working exit is
        // kept (stable egress) and a broken one is rotated past on the next try.
        let cursor = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        self.spawn_supervised(cfg, move || {
            let signing = signing.clone();
            let exits = exits.clone();
            let cursor = Arc::clone(&cursor);
            async move {
                let idx = cursor.load(Ordering::Relaxed) % exits.len();
                match establish_multihop(signing, &exits[idx]).await {
                    Ok(tunnel) => Ok(tunnel),
                    Err(e) => {
                        cursor.fetch_add(1, Ordering::Relaxed);
                        Err(e)
                    }
                }
            }
        })
        .await
    }

    /// Binds the stable proxy listeners, spawns the supervisor over `connect`, and
    /// returns the [`SupervisedProxyHandle`]. Shared by the single-exit and
    /// failover supervised datapaths; only the (re)connect closure differs.
    async fn spawn_supervised<F, Fut>(
        &self,
        cfg: &warren_net::ProxyConfig,
        connect: F,
    ) -> Result<SupervisedProxyHandle, SdkError>
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<EstablishedTunnel<MultihopPacketSink>, SdkError>>
            + Send,
    {
        let socks_listener = tokio::net::TcpListener::bind(cfg.socks5)
            .await
            .map_err(SdkError::Proxy)?;
        let local_addr = socks_listener.local_addr().map_err(SdkError::Proxy)?;
        let (http_listener, http_addr) = match cfg.http {
            Some(bind) => {
                let l = tokio::net::TcpListener::bind(bind)
                    .await
                    .map_err(SdkError::Proxy)?;
                let a = l.local_addr().map_err(SdkError::Proxy)?;
                (Some(l), Some(a))
            }
            None => (None, None),
        };

        let (state_tx, state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
        let dns_server = cfg.dns_server;
        let task = tokio::spawn(async move {
            supervise_proxy(socks_listener, http_listener, dns_server, state_tx, connect).await;
        });

        Ok(SupervisedProxyHandle {
            local_addr,
            http_addr,
            state_rx,
            task,
        })
    }
}

/// Runs the userspace netstack over `sink` and serves the local SOCKS5 (and
/// optional HTTP CONNECT) proxy. Shared by the single-hop and multihop datapaths.
async fn serve_proxy_over_sink<S>(
    sink: S,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    ipv6: Option<warren_net::Ipv6Addressing>,
    cfg: &warren_net::ProxyConfig,
) -> Result<ProxyHandle, SdkError>
where
    S: warren_net::PacketSink + 'static,
{
    // The inner IP MTU must fit one QUIC datagram: use the path-aware payload
    // size, NOT the raw policy MTU (which can exceed the datagram capacity and
    // make every full-size packet silently fail to send).
    let mtu = warren_net::PacketSink::max_payload(&sink);
    let mut config = warren_net::NetstackConfig::new(local_ip, prefix, gateway, mtu);
    // Enable the dual-stack v6 datapath only when the exit actually granted v6.
    if let Some(v6) = ipv6 {
        config = config.with_ipv6(v6.local_ip, v6.prefix, v6.gateway);
    }
    // dns_disabled exits run no gateway forwarder; honor the operator's override
    // so lookups still egress through the tunnel rather than the host resolver.
    if let Some(dns) = cfg.dns_server {
        config = config.with_dns_server(dns);
    }
    let (connector, mut alive_rx) = warren_net::spawn_over_sink(Arc::new(sink), config);

    let socks_listener = tokio::net::TcpListener::bind(cfg.socks5)
        .await
        .map_err(SdkError::Proxy)?;
    let local_addr = socks_listener.local_addr().map_err(SdkError::Proxy)?;
    let socks = warren_net::Socks5Proxy::new(connector.clone());
    // serve_with_udp also handles UDP ASSOCIATE (datagrams egress at the exit
    // via the netstack UDP flow); CONNECT behaves identically to serve.
    let mut tasks = vec![tokio::spawn(async move {
        let _ = socks.serve_with_udp(socks_listener).await;
    })];

    // Surface tunnel liveness as a connection state an app can observe: the
    // datapath starts Connected and flips to Disconnected when the tunnel read
    // side closes (the leak window), so the app can stop sending or reconnect.
    let (state_tx, state_rx) = tokio::sync::watch::channel(TunnelState::Connected);
    tasks.push(tokio::spawn(async move {
        while alive_rx.changed().await.is_ok() {
            if !*alive_rx.borrow() {
                let _ = state_tx.send(TunnelState::Disconnected);
                break;
            }
        }
    }));

    // Keep a connector clone for on-demand port forwarding; the HTTP branch below
    // may move `connector`, so clone before it does.
    let forward_connector = connector.clone();

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
        state_rx,
        forward_connector,
        gateway,
        tasks,
    })
}

/// Derives the netstack addressing from a multihop session's `IpAssign`: the v4
/// CIDR + gateway, and dual-stack v6 only when the exit granted a v6 address, its
/// gateway and a sane prefix (else v4-only, so a misbehaving exit cannot install
/// an unroutable or `/0` v6 route; v6 traffic still stays in the tunnel). A real
/// exit may assign a different prefix or gateway per session, so this is read
/// fresh on every (re)connect rather than assumed.
fn addressing_from_session(
    session: &MultihopSession,
) -> (
    std::net::Ipv4Addr,
    u8,
    std::net::Ipv4Addr,
    Option<warren_net::Ipv6Addressing>,
) {
    let a = session.assignment();
    let local_ip = std::net::Ipv4Addr::from(a.ipv4);
    let prefix = a.prefix_len;
    let gateway = std::net::Ipv4Addr::from(a.gateway_ipv4);
    let ipv6 = match (a.ipv6, a.gateway_ipv6) {
        (Some(ip), Some(gw)) if (1..=128).contains(&a.prefix_len_v6) => {
            Some(warren_net::Ipv6Addressing {
                local_ip: std::net::Ipv6Addr::from(ip),
                prefix: a.prefix_len_v6,
                gateway: std::net::Ipv6Addr::from(gw),
            })
        }
        _ => None,
    };
    (local_ip, prefix, gateway, ipv6)
}

/// Opens a sealed multihop tunnel to `exit` and packages it with the netstack
/// addressing derived from its fresh `IpAssign`. The (re)connect step shared by
/// the supervised single-exit and failover datapaths.
async fn establish_multihop(
    signing: warren_identity::ed25519_dalek::SigningKey,
    exit: &VerifiedExit,
) -> Result<EstablishedTunnel<MultihopPacketSink>, SdkError> {
    let session = MultihopClientTunnel::new(signing)
        .connect(
            exit.exit_ed25519_pubkey,
            exit.exit_x25519_multihop_pubkey,
            exit.exit_id,
            exit.endpoint,
        )
        .await?;
    let sink = MultihopPacketSink::new(session);
    let (local_ip, prefix, gateway, ipv6) = addressing_from_session(sink.session());
    Ok(EstablishedTunnel {
        sink,
        local_ip,
        prefix,
        gateway,
        ipv6,
    })
}

/// An established tunnel plus the netstack addressing derived from its `IpAssign`.
/// Generic over the sink so the supervisor loop is unit-testable with a fake sink.
struct EstablishedTunnel<S> {
    sink: S,
    local_ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    ipv6: Option<warren_net::Ipv6Addressing>,
}

/// Resolves once the datapath's tunnel read side closes (or the engine is gone),
/// the signal a supervisor uses to tear the serve loops down and reconnect.
async fn wait_until_dead(mut alive_rx: tokio::sync::watch::Receiver<bool>) {
    while *alive_rx.borrow_and_update() {
        if alive_rx.changed().await.is_err() {
            return;
        }
    }
}

/// Aborts the wrapped task when dropped, so a spawned helper cannot outlive the
/// scope that owns it (even if that scope is itself cancelled).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serves SOCKS5 (and optional HTTP CONNECT) on the *borrowed* stable listeners
/// using `connector`, until the tunnel dies (or an accept loop fails). Returns so
/// the supervisor can rebuild and resume on the same listeners.
async fn serve_epoch(
    socks_listener: &tokio::net::TcpListener,
    http_listener: Option<&tokio::net::TcpListener>,
    connector: warren_net::TunnelConnector,
    alive_rx: tokio::sync::watch::Receiver<bool>,
) {
    // `run` gates both accept loops; the bridge flips it off when the tunnel dies.
    // Wrapped in `AbortOnDrop` so cancelling this future (handle dropped mid-epoch)
    // does not leak the bridge task: it is aborted whether we return or are dropped.
    let (run_tx, run_rx) = tokio::sync::watch::channel(true);
    let _bridge = AbortOnDrop(tokio::spawn(async move {
        wait_until_dead(alive_rx).await;
        let _ = run_tx.send(false);
    }));
    let socks = warren_net::Socks5Proxy::new(connector.clone());
    // `select!`, not `join!`: the first loop to return ends the epoch. On tunnel
    // death the bridge flips `run` and whichever loop sees it first returns; if an
    // accept loop instead fails on its own, that also ends the epoch (a `join!`
    // would hang waiting on the still-running sibling while the tunnel is alive).
    match http_listener {
        Some(http_listener) => {
            let http = warren_net::HttpConnectProxy::new(connector);
            tokio::select! {
                _ = socks.serve_with_udp_until(socks_listener, run_rx.clone()) => {}
                _ = http.serve_until(http_listener, run_rx) => {}
            }
        }
        None => {
            let _ = socks.serve_with_udp_until(socks_listener, run_rx).await;
        }
    }
}

/// Supervises a proxy datapath across tunnel rebuilds, keeping the local
/// listeners (and thus the app-facing proxy addresses) stable: it establishes a
/// tunnel, serves until the tunnel dies, then reconnects (immediately after a
/// drop, with capped exponential backoff between failed attempts), reporting each
/// [`ConnectionState`] transition. `connect` is the (re)establish closure; it is
/// generic so the loop is testable with a fake sink and a fake connector.
async fn supervise_proxy<S, F, Fut>(
    socks_listener: tokio::net::TcpListener,
    http_listener: Option<tokio::net::TcpListener>,
    dns_server: Option<std::net::Ipv4Addr>,
    state_tx: tokio::sync::watch::Sender<ConnectionState>,
    mut connect: F,
) where
    S: warren_net::PacketSink + 'static,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<EstablishedTunnel<S>, SdkError>>,
{
    const INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(20);
    // A session that stayed up at least this long is treated as healthy, so its
    // next reconnect starts fresh. A shorter one is "flapping" (the exit accepts
    // the handshake then drops immediately): apply backoff so we do not tight-loop
    // full cryptographic handshakes and hammer the exit.
    const MIN_HEALTHY_UPTIME: std::time::Duration = std::time::Duration::from_secs(5);
    let mut backoff = INITIAL_BACKOFF;
    let mut first = true;
    loop {
        let _ = state_tx.send(if first {
            ConnectionState::Connecting
        } else {
            ConnectionState::Reconnecting
        });
        first = false;
        match connect().await {
            Ok(est) => {
                let mtu = warren_net::PacketSink::max_payload(&est.sink);
                let mut config =
                    warren_net::NetstackConfig::new(est.local_ip, est.prefix, est.gateway, mtu);
                if let Some(v6) = est.ipv6 {
                    config = config.with_ipv6(v6.local_ip, v6.prefix, v6.gateway);
                }
                if let Some(dns) = dns_server {
                    config = config.with_dns_server(dns);
                }
                let (connector, alive_rx) = warren_net::spawn_over_sink(Arc::new(est.sink), config);
                let _ = state_tx.send(ConnectionState::Connected);
                let up_since = std::time::Instant::now();
                serve_epoch(&socks_listener, http_listener.as_ref(), connector, alive_rx).await;
                // The tunnel died. A healthy session resets backoff and reconnects
                // at once; a flapping one (died almost immediately) backs off first.
                if up_since.elapsed() >= MIN_HEALTHY_UPTIME {
                    backoff = INITIAL_BACKOFF;
                } else {
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
                }
            }
            Err(_) => {
                // No identity material is logged. Back off before the next attempt.
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Tunnel network prefix length (`10.66.0.0/16`), matching warren-core.
const TUNNEL_PREFIX: u8 = 16;
/// Tunnel gateway (exit side), matching warren-core's `10.66.0.1`.
const TUNNEL_GATEWAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 66, 0, 1);

/// Liveness of a running proxy datapath's tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnelState {
    /// The tunnel is up and the proxy is forwarding.
    Connected,
    /// The tunnel read side closed; traffic no longer egresses at the exit. The
    /// app should stop sending (or tear down and reconnect) to avoid a leak.
    Disconnected,
}

/// A detached, cloneable capability to request NAT-PMP port forwards over a
/// running datapath (see [`ProxyHandle::forwarder`]). It does not own the
/// datapath lifecycle, so it can be held and used independently of the
/// [`ProxyHandle`] (the FFI layer keeps one alongside the handle's lock).
#[derive(Clone)]
pub struct ProxyForwarder {
    connector: warren_net::TunnelConnector,
    gateway: std::net::Ipv4Addr,
}

impl ProxyForwarder {
    /// Forwards a tunnel-side port: maps `internal_port` at the exit via NAT-PMP
    /// and relays inbound connections to `local_target`, renewing until the
    /// returned [`warren_net::ForwardedPort`] is dropped. See
    /// [`ProxyHandle::forward_port`].
    ///
    /// # Errors
    ///
    /// [`SdkError::PortForward`] if the engine has stopped, a socket cannot be
    /// opened, or the exit refuses the mapping.
    pub async fn forward_port(
        &self,
        proto: warren_net::MapProto,
        internal_port: u16,
        local_target: SocketAddr,
    ) -> Result<warren_net::ForwardedPort, SdkError> {
        warren_net::forward_port(
            &self.connector,
            self.gateway,
            proto,
            internal_port,
            local_target,
        )
        .await
        .map_err(SdkError::from)
    }
}

/// A running non-root proxy datapath. Dropping it stops the proxy.
pub struct ProxyHandle {
    local_addr: SocketAddr,
    http_addr: Option<SocketAddr>,
    state_rx: tokio::sync::watch::Receiver<TunnelState>,
    forward_connector: warren_net::TunnelConnector,
    gateway: std::net::Ipv4Addr,
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

    /// The current tunnel state ([`TunnelState::Connected`] until the tunnel
    /// read side closes).
    #[must_use]
    pub fn state(&self) -> TunnelState {
        *self.state_rx.borrow()
    }

    /// A watch receiver for tunnel-state changes, so an app can await a
    /// disconnect (`state_rx.changed().await`) rather than poll [`Self::state`].
    #[must_use]
    pub fn watch_state(&self) -> tokio::sync::watch::Receiver<TunnelState> {
        self.state_rx.clone()
    }

    /// Forwards a tunnel-side port: asks the exit to map `internal_port` via
    /// NAT-PMP and relays every inbound connection to `local_target` (a TCP
    /// server the app runs locally), renewing the mapping until the returned
    /// [`warren_net::ForwardedPort`] is dropped. Resolves once the exit grants
    /// the mapping, so [`warren_net::ForwardedPort::external_port`] is the port
    /// remote peers reach the app on.
    ///
    /// This needs an exit that runs a NAT-PMP gateway; not every exit does.
    ///
    /// # Errors
    ///
    /// [`SdkError::PortForward`] if the engine has stopped, a socket cannot be
    /// opened, or the exit refuses the mapping.
    pub async fn forward_port(
        &self,
        proto: warren_net::MapProto,
        internal_port: u16,
        local_target: SocketAddr,
    ) -> Result<warren_net::ForwardedPort, SdkError> {
        self.forwarder()
            .forward_port(proto, internal_port, local_target)
            .await
    }

    /// A cheap, cloneable [`ProxyForwarder`] for this datapath, detached from the
    /// handle's lifecycle so a caller (notably the FFI layer) can request port
    /// forwards without holding the handle across an `.await`.
    #[must_use]
    pub fn forwarder(&self) -> ProxyForwarder {
        ProxyForwarder {
            connector: self.forward_connector.clone(),
            gateway: self.gateway,
        }
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

/// A self-healing proxy datapath (see
/// [`WarrenClient::start_proxy_multihop_supervised`]). The local proxy
/// address(es) stay stable while the supervisor rebuilds the tunnel across drops.
/// Dropping the handle stops the supervisor and the datapath.
pub struct SupervisedProxyHandle {
    local_addr: SocketAddr,
    http_addr: Option<SocketAddr>,
    state_rx: tokio::sync::watch::Receiver<ConnectionState>,
    task: tokio::task::JoinHandle<()>,
}

impl SupervisedProxyHandle {
    /// The stable SOCKS5 listener address the app points at across reconnects.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The stable HTTP CONNECT listener address, if one was configured.
    #[must_use]
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// The current connection state ([`ConnectionState::Connecting`] until the
    /// first tunnel is up, then `Connected`/`Reconnecting` as it heals).
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        *self.state_rx.borrow()
    }

    /// A watch receiver for state changes, so an app can await transitions
    /// (`state_rx.changed().await`) rather than poll [`Self::state`].
    #[must_use]
    pub fn watch_state(&self) -> tokio::sync::watch::Receiver<ConnectionState> {
        self.state_rx.clone()
    }

    /// Stops the supervisor and tears down the datapath.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

impl Drop for SupervisedProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
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

/// Fails closed when an exit runs no DNS forwarder and the caller supplied no
/// override resolver: starting the datapath anyway would leave every name-based
/// connection silently unresolvable. (In proxy mode lookups never touch the host
/// resolver, so this is a fail-fast usability guard, not a leak fix; the leak
/// concern is the privileged TUN backend's, which is deferred.)
fn ensure_dns_reachable(
    dns_disabled: bool,
    cfg: &warren_net::ProxyConfig,
) -> Result<(), SdkError> {
    if dns_disabled && cfg.dns_server.is_none() {
        return Err(SdkError::ExitDnsDisabled);
    }
    Ok(())
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

    /// A packet sink whose read side closes on demand, modelling a tunnel that
    /// dies when its `close` notifier fires (so the supervisor must reconnect).
    struct ClosableSink {
        close: Arc<tokio::sync::Notify>,
    }

    impl warren_net::PacketSink for ClosableSink {
        async fn send_packet(&self, _packet: &[u8]) -> Result<(), warren_net::NetError> {
            Ok(())
        }

        async fn recv_packet(&self) -> Result<bytes::Bytes, warren_net::NetError> {
            self.close.notified().await;
            Err(warren_net::NetError::EngineStopped)
        }

        fn max_payload(&self) -> usize {
            1280
        }
    }

    /// A bare TCP connect to `addr` succeeds within ~2s (the supervisor's accept
    /// loop is live there). Retried because the serve loop starts asynchronously.
    async fn proxy_accepts(addr: SocketAddr) -> bool {
        for _ in 0..40 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn supervisor_reconnects_on_drop_keeping_a_stable_listener() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stable_addr = socks_listener.local_addr().unwrap();

        let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
        // Each (re)connect publishes its kill notifier so the test can drop that
        // session; the mpsc (unlike a watch) never coalesces, so every cycle shows.
        let (kill_tx, mut kill_rx) = tokio::sync::mpsc::unbounded_channel();
        let cycles = Arc::new(AtomicUsize::new(0));

        let task = {
            let cycles = Arc::clone(&cycles);
            tokio::spawn(async move {
                supervise_proxy(socks_listener, None, None, state_tx, move || {
                    let kill_tx = kill_tx.clone();
                    let cycles = Arc::clone(&cycles);
                    async move {
                        let close = Arc::new(tokio::sync::Notify::new());
                        let _ = kill_tx.send(Arc::clone(&close));
                        cycles.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, SdkError>(EstablishedTunnel {
                            sink: ClosableSink { close },
                            local_ip: "10.66.0.2".parse().unwrap(),
                            prefix: 24,
                            gateway: "10.66.0.1".parse().unwrap(),
                            ipv6: None,
                        })
                    }
                })
                .await;
            })
        };

        // Cycle 1 establishes and accepts on the stable address.
        let kill1 = tokio::time::timeout(std::time::Duration::from_secs(5), kill_rx.recv())
            .await
            .expect("first connect happened")
            .expect("kill handle");
        assert!(proxy_accepts(stable_addr).await, "listener live in cycle 1");

        // Simulate a tunnel drop: the supervisor must re-establish on its own.
        kill1.notify_one();
        let kill2 = tokio::time::timeout(std::time::Duration::from_secs(5), kill_rx.recv())
            .await
            .expect("supervisor reconnected after the drop")
            .expect("kill handle");

        // The SAME bound address still accepts after the automatic reconnect.
        assert!(
            proxy_accepts(stable_addr).await,
            "listener stays stable across the reconnect"
        );
        assert_eq!(cycles.load(Ordering::SeqCst), 2, "exactly one reconnect");

        kill2.notify_one();
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn supervisor_serves_both_socks_and_http_listeners() {
        // Exercises the dual-listener serve epoch (the `select!` two-branch path):
        // both stable addresses accept once the tunnel is up.
        let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let http_addr = http_listener.local_addr().unwrap();

        let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
        let keep_open = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(async move {
            supervise_proxy(
                socks_listener,
                Some(http_listener),
                None,
                state_tx,
                move || {
                    let keep_open = Arc::clone(&keep_open);
                    async move {
                        Ok::<_, SdkError>(EstablishedTunnel {
                            sink: ClosableSink { close: keep_open },
                            local_ip: "10.66.0.2".parse().unwrap(),
                            prefix: 24,
                            gateway: "10.66.0.1".parse().unwrap(),
                            ipv6: None,
                        })
                    }
                },
            )
            .await;
        });

        assert!(proxy_accepts(socks_addr).await, "SOCKS5 listener is live");
        assert!(proxy_accepts(http_addr).await, "HTTP listener is live");
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn supervisor_failover_rotates_past_a_broken_exit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Two candidate "exits": index 0 always fails to connect (a broken exit
        // like prod SG), index 1 connects. This mirrors the rotating closure of
        // start_proxy_multihop_supervised_failover: the cursor advances only on
        // failure, so the supervisor must rotate past 0 and succeed on 1.
        let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
        let cursor = Arc::new(AtomicUsize::new(0));
        let (ok_tx, mut ok_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let keep_open = Arc::new(tokio::sync::Notify::new());

        let task = tokio::spawn(async move {
            supervise_proxy(socks_listener, None, None, state_tx, move || {
                let cursor = Arc::clone(&cursor);
                let ok_tx = ok_tx.clone();
                let keep_open = Arc::clone(&keep_open);
                async move {
                    let idx = cursor.load(Ordering::Relaxed) % 2;
                    if idx == 0 {
                        cursor.fetch_add(1, Ordering::Relaxed); // rotate past the broken exit
                        return Err(SdkError::NoMultihopExit);
                    }
                    let _ = ok_tx.send(idx);
                    Ok(EstablishedTunnel {
                        sink: ClosableSink { close: keep_open },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            })
            .await;
        });

        let success_idx = tokio::time::timeout(std::time::Duration::from_secs(5), ok_rx.recv())
            .await
            .expect("failover reached a working exit in time")
            .expect("a connect succeeded");
        assert_eq!(
            success_idx, 1,
            "failover rotated past the broken exit 0 to the working exit 1"
        );
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn supervisor_failover_sticks_with_a_working_exit_across_a_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Same rotate-only-on-failure cursor as the failover closure, but exit 0
        // always works. After a healthy session drops, the supervisor must
        // reconnect on the SAME exit 0 (stable egress), not rotate away: the
        // cursor advances on connect failure, never on a mere drop.
        let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
        let cursor = Arc::new(AtomicUsize::new(0));
        let (used_tx, mut used_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let (close_tx, mut close_rx) =
            tokio::sync::mpsc::unbounded_channel::<Arc<tokio::sync::Notify>>();

        let task = tokio::spawn(async move {
            supervise_proxy(socks_listener, None, None, state_tx, move || {
                let cursor = Arc::clone(&cursor);
                let used_tx = used_tx.clone();
                let close_tx = close_tx.clone();
                async move {
                    let idx = cursor.load(Ordering::Relaxed) % 2;
                    if idx != 0 {
                        cursor.fetch_add(1, Ordering::Relaxed);
                        return Err(SdkError::NoMultihopExit);
                    }
                    // Exit 0 works: hand the test a fresh close handle for this
                    // session so it can drop it, and report the idx used.
                    let close = Arc::new(tokio::sync::Notify::new());
                    let _ = close_tx.send(Arc::clone(&close));
                    let _ = used_tx.send(idx);
                    Ok(EstablishedTunnel {
                        sink: ClosableSink { close },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            })
            .await;
        });

        // Cycle 1: connected on exit 0.
        let used1 = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
            .await
            .expect("first connect happened")
            .expect("idx");
        let close1 = close_rx.recv().await.expect("close handle 1");
        assert_eq!(used1, 0);

        // Drop the healthy session; the supervisor reconnects.
        close1.notify_one();
        let used2 = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
            .await
            .expect("reconnected after the drop")
            .expect("idx");
        assert_eq!(
            used2, 0,
            "a healthy drop reconnects on the SAME exit (stable egress), no rotation"
        );
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn supervisor_retries_past_failed_attempts_then_connects() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stable_addr = socks_listener.local_addr().unwrap();

        let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
        let attempts = Arc::new(AtomicUsize::new(0));

        let task = {
            let attempts = Arc::clone(&attempts);
            // Keeps the eventual success session's read side open (never closes).
            let keep_open = Arc::new(tokio::sync::Notify::new());
            tokio::spawn(async move {
                supervise_proxy(socks_listener, None, None, state_tx, move || {
                    let attempts = Arc::clone(&attempts);
                    let keep_open = Arc::clone(&keep_open);
                    async move {
                        // Fail the first two attempts, then establish: exercises the
                        // backoff/retry branch and the recovery to Connected.
                        if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                            return Err(SdkError::NoMultihopExit);
                        }
                        Ok(EstablishedTunnel {
                            sink: ClosableSink { close: keep_open },
                            local_ip: "10.66.0.2".parse().unwrap(),
                            prefix: 24,
                            gateway: "10.66.0.1".parse().unwrap(),
                            ipv6: None,
                        })
                    }
                })
                .await;
            })
        };

        // The supervisor must retry past the two failures (with backoff) and make
        // the third, successful attempt rather than giving up after the first.
        let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while attempts.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "supervisor retried past the failures to a successful connect"
        );
        // A successful (third) attempt means the serve loop is now live on the
        // stable address; a bare TCP connect to it succeeds.
        assert!(proxy_accepts(stable_addr).await, "stable listener is live");
        task.abort();
    }

    /// Builds a `VerifiedExit` pointing at an in-process fake multihop exit.
    fn fake_verified_exit(
        addr: SocketAddr,
        keys: &warren_test_support::MultihopExitKeys,
    ) -> VerifiedExit {
        VerifiedExit {
            exit_id: keys.exit_id,
            exit_ed25519_pubkey: keys.ed25519_pubkey,
            exit_x25519_multihop_pubkey: keys.x25519_pubkey,
            endpoint: addr,
            country: "ZZ".to_owned(),
            city: "Test".to_owned(),
            weight: 100,
            dns_disabled: false,
        }
    }

    fn test_client() -> DefaultClient {
        let (id, _m) = WarrenIdentity::generate();
        WarrenClient::builder()
            .identity(id)
            .api_base("https://api.example.test")
            .allow_any_server_key()
            .build()
            .expect("build")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_multihop_against_a_fake_exit_assigns_ip() {
        // Validates the facade's multihop connect + IpAssign extraction in process
        // (otherwise only exercised by the live examples) against a fake exit that
        // completes the sealed handshake and assigns 10.66.0.2/24.
        let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
        let exit = fake_verified_exit(addr, &keys);

        let sink = test_client()
            .connect_multihop(&exit)
            .await
            .expect("multihop connect succeeds against the fake exit");
        assert_eq!(
            sink.session().assigned_ipv4(),
            std::net::Ipv4Addr::new(10, 66, 0, 2)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn supervised_proxy_reaches_connected_against_a_fake_exit() {
        // Full supervised facade wiring in process: bind listener, background
        // establish over the fake exit, report Connected on the state watch.
        let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
        let exit = fake_verified_exit(addr, &keys);

        let cfg = warren_net::ProxyConfig {
            socks5: "127.0.0.1:0".parse().unwrap(),
            http: None,
            dns_server: None,
        };
        let handle = test_client()
            .start_proxy_multihop_supervised(&exit, &cfg)
            .await
            .expect("supervised proxy binds");

        let mut rx = handle.watch_state();
        let connected = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if *rx.borrow_and_update() == ConnectionState::Connected {
                    return true;
                }
                if rx.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            connected,
            "the supervised proxy reaches Connected against the fake exit"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_proxy_multihop_against_a_fake_exit_is_connected() {
        // The non-supervised datapath sets up over the fake exit and reports a
        // live tunnel (the proxy listener is bound and the state is Connected).
        let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
        let exit = fake_verified_exit(addr, &keys);
        let cfg = warren_net::ProxyConfig {
            socks5: "127.0.0.1:0".parse().unwrap(),
            http: None,
            dns_server: None,
        };
        let handle = test_client()
            .start_proxy_multihop(&exit, &cfg)
            .await
            .expect("proxy datapath starts over the fake exit");
        assert_eq!(handle.state(), TunnelState::Connected);
    }

    #[tokio::test]
    async fn start_proxy_multihop_refuses_a_dns_disabled_exit_without_a_resolver() {
        // The guard must fire before any connect attempt, so an unroutable address
        // never matters: a dns_disabled exit with no override resolver is rejected.
        let exit = VerifiedExit {
            exit_id: [0u8; 16],
            exit_ed25519_pubkey: [0u8; 32],
            exit_x25519_multihop_pubkey: [0u8; 32],
            endpoint: "203.0.113.1:443".parse().unwrap(),
            country: "ZZ".to_owned(),
            city: "Test".to_owned(),
            weight: 1,
            dns_disabled: true,
        };
        let cfg = warren_net::ProxyConfig {
            socks5: "127.0.0.1:0".parse().unwrap(),
            http: None,
            dns_server: None,
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            test_client().start_proxy_multihop(&exit, &cfg),
        )
        .await
        .expect("the guard returns immediately, well before any connect timeout");
        match result {
            Err(SdkError::ExitDnsDisabled) => {}
            Err(other) => panic!("expected ExitDnsDisabled, got {other:?}"),
            Ok(_) => panic!("a dns_disabled exit without a resolver must be refused"),
        }
    }

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
