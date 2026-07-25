#[cfg(all(unix, feature = "experimental-tun"))]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use warren_api::{HttpTransport, WarrenApiClient};
use warren_discovery::{
    CircuitPolicy, DEFAULT_RTT_TTL_SECS, ExitQuery, ExitSelector, PATH_QUALITY_VERSION,
    PathAwareParams, PathQualityAdvisory, Relay, RttCache, SelectorError, VerifiedEntry,
    VerifiedExit, entry_rtt_from, select_entry_path_aware, verify_multihop_directory,
    verify_signed_relay_list,
};
use warren_identity::WarrenIdentity;
use warren_net::MultihopPacketSink;
use warren_transport::{ConnectionState, MultihopClientTunnel, SocketBypass};

#[cfg(feature = "reqwest-transport")]
use warren_api::ReqwestTransport;

#[cfg(all(unix, feature = "experimental-tun"))]
use warrenguard_config::TUNNEL_GATEWAY_IP;

use crate::error::{BuildError, SdkError};
use crate::proxy::{ProxyHandle, addressing_from_session, serve_proxy_over_sink};
use crate::supervisor::{
    EstablishedTunnel, SupervisedProxyHandle, establish_multihop, supervise_proxy,
};

/// A dial target, labeled by hop count. Both variants run the same supervised
/// datapath (the HPKE multihop transport); the label records how many nodes the
/// traffic crosses, and is the named home of the single-hop vs multi-hop
/// distinction. Single-hop dials the exit directly; multi-hop dials an
/// entry-composed exit built with [`WarrenClient::select_multihop_entry`], whose
/// result already folds the entry edge over the exit's HPKE anchor (so the
/// composition lives in exactly one place, not here).
pub enum Circuit {
    /// One exit, dialed directly: the client and the exit are the only nodes.
    SingleHop(VerifiedExit),
    /// An entry relay then the exit: the dialed descriptor carries the entry
    /// edge (endpoint and identity) over the exit's HPKE anchor.
    MultiHop(VerifiedExit),
}

impl Circuit {
    /// The exit descriptor to dial for this circuit.
    fn dialed_exit(&self) -> &VerifiedExit {
        match self {
            Circuit::SingleHop(exit) | Circuit::MultiHop(exit) => exit,
        }
    }
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
///
/// Start from [`WarrenClient::builder`], set an identity and a pinned server
/// key, then [`build`](Self::build).
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> Result<(), warren_sdk::SdkError> {
/// use warren_sdk::{WarrenClient, identity::WarrenIdentity};
///
/// let (identity, _mnemonic) = WarrenIdentity::generate();
/// let client = WarrenClient::builder()
///     .identity(identity)
///     .api_base("https://api.warrenbrowse.com")
///     .server_pubkey_pin("0000000000000000000000000000000000000000000000000000000000000000")
///     .daita() // optional: traffic-analysis defense on the uplink
///     .build()?;
/// let _ = client.fetch_multihop_directory().await?;
/// # Ok(())
/// # }
/// ```
pub struct WarrenClientBuilder {
    pub(crate) identity: Option<WarrenIdentity>,
    pub(crate) api_base: String,
    pub(crate) api_alternative_hosts: Vec<String>,
    pub(crate) server_pubkey_pin: Option<String>,
    pub(crate) multihop_root_pubkey_pins: Vec<String>,
    pub(crate) allow_any_server_key: bool,
    pub(crate) auto_local_ip: bool,
    pub(crate) wants_ipv6: bool,
    pub(crate) daita: bool,
    pub(crate) daita_machine: Option<String>,
    pub(crate) transport_config: Option<Arc<warren_transport::TransportConfig>>,
    pub(crate) generation_store: Arc<dyn GenerationStore>,
    pub(crate) multihop_generation_store: Arc<dyn GenerationStore>,
    pub(crate) server_key_store: Option<Arc<dyn ServerKeyStore>>,
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

    /// Pins the QUIC endpoint to the default-route source IP for each exit
    /// (multi-NIC determinism). Off by default (the OS chooses the source); falls
    /// back to an unspecified bind if detection fails.
    #[must_use]
    pub fn auto_local_ip(mut self) -> Self {
        self.auto_local_ip = true;
        self
    }

    /// Requests a dual-stack IPv6 address from the exit on multihop tunnels.
    ///
    /// Off by default. When enabled the client asks the exit for an IPv6
    /// allocation; an exit that serves no v6 simply echoes none and the tunnel
    /// stays v4-only, so this is always safe to enable. When the exit does grant
    /// v6, the datapath routes IPv6 egress through the tunnel.
    #[must_use]
    pub fn request_ipv6(mut self) -> Self {
        self.wants_ipv6 = true;
        self
    }

    /// Overrides the QUIC transport config for every tunnel (advanced). The
    /// default already applies the SDK's obfuscated config (Initial padding plus
    /// CRYPTO fragmentation on the warren-quinn fork), so out of the box the
    /// SDK's QUIC-Initial handshake matches warren-app's anti-DPI behaviour.
    /// Pass a custom `warren_transport::TransportConfig` only to deviate from
    /// that default. See ARCHITECTURE.md "QUIC handshake obfuscation".
    #[must_use]
    pub fn transport_config(mut self, cfg: Arc<warren_transport::TransportConfig>) -> Self {
        self.transport_config = Some(cfg);
        self
    }

    /// Enables DAITA on multihop tunnels, negotiated with the exit (the
    /// production model): the client advertises support, the exit samples the
    /// machine and returns it in the assignment, and the client drives that
    /// spec on its uplink while the exit pads the downlink. If the exit
    /// declines, the defense is NOT running (no blind padding). Off by
    /// default. Only affects multihop connects.
    #[must_use]
    pub fn daita(mut self) -> Self {
        self.daita = true;
        self
    }

    /// Explicit override of [`daita`](Self::daita): pins the uplink defense to
    /// a named curated machine (`netflow`, `tamaraw`, `front`,
    /// `interspace_server`, `scrambler_server`) picked CLIENT-side, unilateral
    /// (nothing is negotiated with the exit, whose downlink stays unpadded).
    /// Useful for deterministic behaviour in tests and ops debugging.
    #[must_use]
    pub fn daita_machine(mut self, name: impl Into<String>) -> Self {
        self.daita = true;
        self.daita_machine = Some(name.into());
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
    /// [`BuildError::MissingIdentity`] if no identity was set,
    /// [`BuildError::UnpinnedServerKey`] if neither a pin nor
    /// [`allow_any_server_key`](Self::allow_any_server_key) was set, or
    /// [`BuildError::TransportInit`] if the bundled HTTP transport cannot
    /// initialize (a broken TLS backend).
    #[cfg(feature = "reqwest-transport")]
    pub fn build(self) -> Result<WarrenClient<ReqwestTransport>, BuildError> {
        // Fallible construction (no panic across the FFI boundary): a broken TLS
        // stack surfaces as BuildError::TransportInit instead of unwinding.
        let transport = ReqwestTransport::try_new().map_err(|_| BuildError::TransportInit)?;
        self.build_with_transport(transport)
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
            auto_local_ip: self.auto_local_ip,
            wants_ipv6: self.wants_ipv6,
            daita: self.daita,
            daita_machine: self.daita_machine,
            transport_config: self.transport_config,
            generation_store: self.generation_store,
            multihop_generation_store: self.multihop_generation_store,
            server_key_store: self.server_key_store,
            rtt_cache: Arc::new(Mutex::new(RttCache::new())),
        })
    }
}

/// The Warren client over the bundled reqwest transport: the type most apps use.
/// `WarrenClient::builder()...build()` yields one.
#[cfg(feature = "reqwest-transport")]
pub type DefaultClient = WarrenClient<ReqwestTransport>;

/// The high-level Warren client.
pub struct WarrenClient<T> {
    pub(crate) api: WarrenApiClient<T>,
    pub(crate) signing: warren_identity::ed25519_dalek::SigningKey,
    pub(crate) server_pubkey_pin: Option<String>,
    /// Pinned offline multihop-directory root keys (empty = root TOFU).
    pub(crate) multihop_root_pubkey_pins: Vec<String>,
    /// Pin the QUIC endpoint to the default-route source IP for each exit.
    pub(crate) auto_local_ip: bool,
    /// Request a dual-stack IPv6 allocation from the exit on multihop tunnels.
    pub(crate) wants_ipv6: bool,
    /// Enable DAITA uplink cover traffic on multihop tunnels.
    pub(crate) daita: bool,
    /// Pin DAITA to a named curated machine (else a random pool pick).
    pub(crate) daita_machine: Option<String>,
    /// Optional QUIC transport config override applied to every tunnel (the
    /// system-VPN obfuscation injection seam). `None` = SDK upstream default.
    pub(crate) transport_config: Option<Arc<warren_transport::TransportConfig>>,
    /// Anti-rollback floor: highest signed-list `generation` trusted so far.
    pub(crate) generation_store: Arc<dyn GenerationStore>,
    /// Anti-rollback floor for the multihop directory (separate sequence).
    pub(crate) multihop_generation_store: Arc<dyn GenerationStore>,
    /// Trust-on-first-use pin store, when enabled.
    pub(crate) server_key_store: Option<Arc<dyn ServerKeyStore>>,
    /// Client-side RTT proximity cache (doc 52 §6.2 client): every successful
    /// single-hop connect records the measured path RTT keyed by exit, and
    /// [`Self::select_exit_by_proximity`] biases selection toward nearer
    /// exits at equal weight. Shared behind a mutex so `&self` connects can
    /// populate it. Empty until the first connect, so selection is
    /// weight-only until real measurements accumulate.
    pub(crate) rtt_cache: Arc<Mutex<RttCache>>,
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
            auto_local_ip: false,
            wants_ipv6: false,
            daita: false,
            daita_machine: None,
            transport_config: None,
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

    /// Record a measured path RTT for the exit identified by its Ed25519
    /// endpoint pubkey into the proximity cache. Best effort: a poisoned
    /// lock is silently skipped (proximity is an optimisation, never
    /// load-bearing).
    fn record_rtt(&self, endpoint_id: [u8; 32], rtt: std::time::Duration) {
        record_rtt_in(&self.rtt_cache, endpoint_id, rtt);
    }

    fn close_rtt_recorder(&self, endpoint_id: [u8; 32]) -> warren_net::CloseRttObserver {
        close_rtt_recorder_for(&self.rtt_cache, endpoint_id)
    }

    /// Selects an exit from `selector` weighted by `weight * f(rtt)` using
    /// the RTT measurements gathered on prior connects (doc 52 §6.2 client).
    /// At equal weight a nearer exit is preferred; before any measurement it
    /// is exactly [`ExitSelector::select_weighted`]. Returns an owned
    /// [`Relay`].
    ///
    /// # Errors
    ///
    /// [`SelectorError::NoRelayMatch`] if no active, positive-weight relay
    /// matches, or if the cache lock is poisoned (falls back to an error
    /// rather than an unweighted pick).
    pub fn select_exit_by_proximity(
        &self,
        selector: &ExitSelector,
        query: &ExitQuery,
    ) -> Result<Relay, SelectorError> {
        let now = now_unix_secs();
        let cache = self
            .rtt_cache
            .lock()
            .map_err(|_| SelectorError::NoRelayMatch)?;
        selector
            .select_weighted_by_proximity(query, &cache, now)
            .cloned()
    }

    /// Snapshot of the current RTT proximity cache (doc 52 §6.2 client),
    /// e.g. for an app to surface measured latencies in its UI.
    #[must_use]
    pub fn rtt_cache_snapshot(&self) -> RttCache {
        self.rtt_cache.lock().map(|c| c.clone()).unwrap_or_default()
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
        Ok(self.fetch_multihop_directory_full().await?.exits)
    }

    /// Like [`Self::fetch_multihop_directory`] but returns the whole verified
    /// directory, including the [`VerifiedEntry`](warren_discovery::VerifiedEntry)
    /// view used to compose entry-selected circuits with
    /// [`VerifiedExit::via_entry`]. Same trust, freshness and anti-rollback
    /// enforcement.
    ///
    /// # Errors
    ///
    /// Same as [`Self::fetch_multihop_directory`].
    pub async fn fetch_multihop_directory_full(
        &self,
    ) -> Result<warren_discovery::VerifiedDirectory, SdkError> {
        let json = self
            .api
            .fetch_multihop_directory()
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
        Ok(verified)
    }

    /// Best-effort fetch of the UNSIGNED path-quality advisory
    /// (`GET /v1/multihop/path-quality`). `None` on ANY failure: a missing
    /// endpoint (older API), a transport error, a garbage body, or an
    /// unknown advisory version all mean "no advisory", and selection then
    /// keeps today's weight-ordered behavior. The advisory can only bias
    /// ordering among directory-verified circuits, never admit a node, so
    /// nothing here is trusted.
    pub async fn fetch_path_quality(&self) -> Option<PathQualityAdvisory> {
        let body = self.api.fetch_path_quality().await.ok().flatten()?;
        let advisory: PathQualityAdvisory = serde_json::from_str(&body).ok()?;
        (advisory.version == PATH_QUALITY_VERSION).then_some(advisory)
    }

    /// Path-aware ENTRY pick for `exit` over a verified `dir`: prefers
    /// measured-healthy, low-RTT entries (client-measured RTT from this
    /// client's own connection history plus the advisory's relay->exit leg)
    /// over any advertised location, with switch hysteresis so a transient
    /// blip cannot flap circuits. Every candidate is gated by the shared
    /// [`warren_discovery::CircuitPolicy`], and the returned circuit view
    /// comes from [`VerifiedExit::via_entry`], so no signal can produce a
    /// topology the diversity rule forbids.
    ///
    /// With `advisory: None` and no RTT history this reduces to the
    /// deterministic highest-weight pick (today's behavior).
    /// `prev_entry_node_id` is the currently-flying entry's node id (its
    /// `exit_id` field), for hysteresis. `None` when no policy-legal entry
    /// exists for this exit.
    #[must_use]
    pub fn select_multihop_entry(
        &self,
        dir: &warren_discovery::VerifiedDirectory,
        exit: &VerifiedExit,
        advisory: Option<&PathQualityAdvisory>,
        prev_entry_node_id: Option<&[u8; 16]>,
    ) -> Option<VerifiedExit> {
        self.select_multihop_entry_among(
            &dir.entries,
            exit,
            &dir.policy,
            advisory,
            prev_entry_node_id,
        )
    }

    /// [`Self::select_multihop_entry`] over a caller-filtered subset of the
    /// directory's entries (e.g. a geographic pre-filter): the ONE wiring of
    /// the shared path-aware entry selection to this client's own RTT
    /// history, so no embedding (bindings included) re-implements the pick.
    /// `entries` and `policy` must come from the same verified directory.
    #[must_use]
    pub fn select_multihop_entry_among(
        &self,
        entries: &[VerifiedEntry],
        exit: &VerifiedExit,
        policy: &CircuitPolicy,
        advisory: Option<&PathQualityAdvisory>,
        prev_entry_node_id: Option<&[u8; 16]>,
    ) -> Option<VerifiedExit> {
        let now = now_unix_secs();
        let cache = self.rtt_cache_snapshot();
        let entry = select_entry_path_aware(
            entries,
            exit,
            policy,
            advisory,
            entry_rtt_from(&cache, now, DEFAULT_RTT_TTL_SECS),
            now,
            prev_entry_node_id,
            &PathAwareParams::default(),
        )?;
        exit.via_entry(entry, policy)
    }

    /// Establishes a multihop tunnel to `exit` (the handshake real exits require
    /// an HPKE-sealed setup frame) and returns the sealed
    /// packet plane.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] if the handshake, policy gate, or datapath fails.
    /// When DAITA is enabled (see [`WarrenClientBuilder::daita`]):
    /// [`SdkError::UnknownDaitaMachine`] if a named machine is not in the pool,
    /// [`SdkError::EmptyDaitaPool`] if the pool is empty, or
    /// [`SdkError::DaitaConfig`] if the maybenot framework rejects the config.
    /// How the multihop DAITA defense is armed: negotiated with
    /// the exit by default (the production-proven model); a NAMED machine is
    /// the explicit client-side unilateral override.
    pub async fn connect_multihop(
        &self,
        exit: &VerifiedExit,
    ) -> Result<MultihopPacketSink, SdkError> {
        // The userland proxy installs no OS tunnel, so its carrier socket is never
        // marked/bound (no bypass): the privileged TUN datapath is the only caller
        // that sets one, via `connect_multihop_with_bypass`.
        self.connect_multihop_with_bypass(exit, None).await
    }

    /// [`Self::connect_multihop`] with an explicit carrier-socket bypass. The
    /// privileged TUN datapath passes `Some(..)` so the QUIC socket is kept on the
    /// physical link (`SO_MARK` / `IP_BOUND_IF`) BEFORE its first send, which is
    /// what lets the split-default routing drop the `<exit_ip>/32` host route
    /// (Port Fail / TunnelCrack ServerIP fix). `None` is the userland proxy path.
    async fn connect_multihop_with_bypass(
        &self,
        exit: &VerifiedExit,
        socket_bypass: Option<SocketBypass>,
    ) -> Result<MultihopPacketSink, SdkError> {
        // Resolve the coupled cover-defense switch from the engine knobs (idle
        // cover default ON, DAITA mutual exclusion), the single home shared with
        // the app. The SDK's DAITA is builder-driven (`self.daita`), so cover is
        // armed only on the non-DAITA path below.
        let cover = warrenguard_config::knobs::cover_defenses();
        let daita = daita_mode(self.daita, self.daita_machine.as_deref());
        let mut tunnel = MultihopClientTunnel::new(self.signing.clone());
        if daita == DaitaMode::Negotiated {
            tunnel = tunnel.with_daita(true);
        }
        if self.auto_local_ip {
            tunnel = tunnel.with_auto_local_ip();
        }
        if self.wants_ipv6 {
            tunnel = tunnel.with_ipv6(true);
        }
        if let Some(cfg) = &self.transport_config {
            tunnel = tunnel.with_transport_config(cfg.clone());
        }
        // Thread the cover domain from the verified relay descriptor so the
        // tunnel dials in X.509 WebPKI mode when the relay roster advertises one,
        // and keeps the historical RPK path otherwise.
        if exit.cover_domain.is_some() {
            tunnel = tunnel.with_cover_domain(exit.cover_domain.clone());
        }
        // Arm the TLS-over-TCP anti-censorship carrier (roster v10) when the dialed
        // entry advertises it: a UDP-blocked handshake then retries over the
        // entry's :443/tcp. Dormant unless UDP fails, so no cost on an open path.
        if exit.tcp_fallback {
            tunnel = tunnel.with_tcp_fallback(true);
        }
        // Prefer the post-quantum X-Wing seal when the verified directory bound a
        // signed ML-KEM key to this exit; `None` keeps the classical seal
        // (byte-identical) and the dial never fails over a missing PQ key.
        #[cfg(feature = "pq-hpke")]
        {
            tunnel = tunnel.with_exit_mlkem768(exit.exit_mlkem768_pubkey.clone());
        }
        if let Some(bypass) = socket_bypass {
            tunnel = tunnel.with_socket_bypass(bypass);
        }
        if daita == DaitaMode::Off && cover.idle_cover {
            // Disable the fixed keep-alive PING; the armed cover driver replaces
            // it with a jittered, size-varied idle footprint. DAITA runs its own
            // cover, so this is the non-DAITA path only.
            tunnel = tunnel.with_idle_cover(true);
        }
        let session = tunnel
            .connect(
                exit.exit_ed25519_pubkey,
                exit.exit_x25519_multihop_pubkey,
                exit.exit_id,
                exit.endpoint,
            )
            .await?;
        // Feed the RTT proximity cache (doc 52 §6.2 client): the first-hop path RTT is
        // available once the multihop handshake completes. Keyed by the exit's
        // Ed25519 endpoint pubkey, the same key the selector looks up.
        self.record_rtt(exit.exit_ed25519_pubkey, session.path_rtt());
        // DAITA on: resolve the uplink machine, build the driver over a shared
        // session, and spawn its padding loop. The loop self-terminates when the
        // tunnel closes (a cover send then errors), so no explicit stop is needed.
        let cfg = match &daita {
            DaitaMode::Off => {
                return Ok(MultihopPacketSink::new(session)
                    .arm_idle_cover(cover.idle_cover)
                    .with_close_rtt_observer(self.close_rtt_recorder(exit.exit_ed25519_pubkey)));
            }
            // Negotiated (the default): drive exactly what the exit granted.
            DaitaMode::Negotiated => match session.assignment().daita_spec.clone() {
                Some(cfg) => cfg,
                None => {
                    // The exit declined: the defense is NOT running; return the
                    // undefended sink instead of padding blindly (the lie the
                    // /v3 capability echo exists to prevent).
                    return Ok(MultihopPacketSink::new(session).with_close_rtt_observer(
                        self.close_rtt_recorder(exit.exit_ed25519_pubkey),
                    ));
                }
            },
            // Explicit override: client-side unilateral pick.
            DaitaMode::LocalPick(name) => warren_daita::DaitaPool::default_pool()
                .pick_named_os(name)
                .ok_or_else(|| SdkError::UnknownDaitaMachine { name: name.clone() })?,
        };
        let state = warren_daita::DaitaState::from_config(&cfg, std::time::Instant::now())
            .map_err(SdkError::DaitaConfig)?;
        let session = Arc::new(session);
        let driver = warren_transport::DaitaDriver::new(Arc::clone(&session), state);
        let handle = driver.handle();
        // The `stop` notify is intentionally never signaled here: the returned sink
        // and this clone hold the only `session` Arcs, so once the datapath drops
        // them the QUIC tunnel closes and the driver's next cover send errors,
        // ending the loop. The notify just satisfies `run`'s signature (the
        // explicit-stop path is for callers that hold their own handle).
        let stop = Arc::new(tokio::sync::Notify::new());
        tokio::spawn(driver.run(stop));
        Ok(MultihopPacketSink::from_arc(session, Some(handle))
            .with_close_rtt_observer(self.close_rtt_recorder(exit.exit_ed25519_pubkey)))
    }

    /// Starts the PRIVILEGED TUN datapath over a multihop tunnel to `exit`: opens
    /// a kernel TUN device named `tun_name`, installs the split-default routing,
    /// the OS killswitch and the DNS push, and forwards raw IP packets between the
    /// device and the sealed tunnel. This is the one-call entry for full-OS
    /// capture, the privileged analogue of [`Self::start_proxy`].
    ///
    /// The routing (`warrenguard_route_split`), killswitch
    /// (`warrenguard_killswitch_os`) and DNS push are the single, real-exit-proven
    /// home shared with the app-scope system-VPN; this method composes
    /// their RAII guards plus the device bring-up and the per-OS carrier escape.
    /// It also reuses [`Self::connect_multihop`], `warren_tun::device::open_tun`,
    /// `warren_net::tun_channels` and `warren_net::forward_bidirectional`.
    ///
    /// The datapath is brought up and PROVEN to forward (an in-tunnel DNS probe to
    /// the exit resolver) BEFORE the fail-closed killswitch is armed and before this
    /// returns Ok: a datapath that never comes up fails OPEN (host left as found),
    /// never fail-closed on a dead tunnel.
    ///
    /// EXPERIMENTAL, Unix-only (Linux + macOS), requires root / `CAP_NET_ADMIN`.
    /// Behind the `experimental-tun` feature.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] if the tunnel handshake fails, or [`SdkError::Tun`]
    /// if the device cannot be opened or the routing / killswitch / DNS cannot be
    /// applied (a v6-dialed exit is also rejected here). On any setup failure the
    /// guards installed so far revert on drop, so a partial setup never strands the
    /// host fail-closed or with a captured route.
    #[cfg(all(unix, feature = "experimental-tun"))]
    pub async fn start_tun_multihop(
        &self,
        exit: &VerifiedExit,
        tun_name: &str,
    ) -> Result<TunDatapathHandle, SdkError> {
        use std::net::IpAddr;
        use warrenguard_killswitch_os::KillswitchBackend;
        use warrenguard_route_split::platform_net::{PlatformNet, current_platform};

        let exit_ip = exit.endpoint.ip();
        // The split-default routing keys on the exit's IPv4 endpoint (macOS exits
        // are dialed over v4); a v6-dialed exit is not supported on this path.
        let IpAddr::V4(exit_ip_v4) = exit_ip else {
            return Err(SdkError::Tun(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "the privileged TUN datapath dials the exit over IPv4 only",
            )));
        };

        // Resolve the per-OS carrier escape BEFORE dialing (macOS resolves the
        // physical gateway now, while `route get default` still sees it and not
        // the split-default capture).
        //
        // Linux: tag the carrier's QUIC socket `SO_MARK = WARREN_TUNNEL_FWMARK`
        // (Port Fail / TunnelCrack ServerIP fix); the split installs the matching
        // `fwmark lookup main` rule so only the marked socket escapes.
        //
        // macOS: do NOT bind the carrier (`IP_BOUND_IF` black-holes egress on
        // multi-interface hosts); the unbound carrier escapes via a
        // `<exit>/32` physical host route instead,
        // matching the app's proven macOS model. The bind-preferred + egress-guard
        // revert (a live QUIC socket rebind) belongs to a separate datapath change:
        // it needs an engine endpoint-rebind seam and its own connection-migration
        // validation, so it is not wired here.
        #[cfg(target_os = "macos")]
        let (socket_bypass, phys_gateway): (Option<SocketBypass>, String) = (
            None,
            crate::tun_setup::discover_physical_gateway_macos().map_err(SdkError::Tun)?,
        );
        #[cfg(target_os = "linux")]
        let socket_bypass: Option<SocketBypass> = Some(socket_bypass_from_ifindex(0));
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let socket_bypass: Option<SocketBypass> = {
            return Err(SdkError::Tun(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "the privileged TUN datapath is implemented for Linux and macOS only",
            )));
        };

        let sink = self
            .connect_multihop_with_bypass(exit, socket_bypass)
            .await?;
        let session = sink.session();
        let ipv4 = session.assigned_ipv4();
        let ipv6 = session.assigned_ipv6();
        let mtu = u16::try_from(session.max_inner_payload())
            .unwrap_or(warrenguard_config::TUNNEL_INITIAL_MTU);
        let device = warren_tun::device::open_tun(tun_name).map_err(SdkError::Tun)?;
        // The kernel assigns the interface name on macOS (the requested `tun_name`
        // may be empty), so read it back; on Linux the name is what we asked for.
        #[cfg(target_os = "macos")]
        let dev_name = device.name().map_err(SdkError::Tun)?;
        #[cfg(not(target_os = "macos"))]
        let dev_name = tun_name.to_owned();

        // Bring the device up + address it BEFORE routing (a fresh TUN is down).
        crate::tun_setup::configure_interface(&dev_name, ipv4, ipv6, mtu).map_err(SdkError::Tun)?;

        // Bring the datapath up and PROVE it forwards BEFORE arming the killswitch.
        // Arming fail-closed before the datapath is proven emits Connected on a
        // datapath that never came up and strands the whole host behind the pf
        // anchor with a dead tunnel. Order: split
        // capture -> carrier escape -> DNS -> forward -> verify egress -> only then
        // the killswitch. Every guard here is RAII: on any failure before the
        // killswitch, the guards installed so far revert on their drops and no
        // killswitch is left behind, so a broken setup fails OPEN (host left as
        // found) instead of fail-closed on a tunnel that carries no traffic.

        // Split-default capture, single-homed in the engine route-split.
        let route_guard = current_platform()
            .install_default_route_split(Some(exit_ip_v4), &dev_name)
            .await
            .map_err(|e| SdkError::Tun(std::io::Error::other(format!("route split: {e}"))))?;

        // macOS: the unbound carrier's escape from the `/1` capture. This MUST come
        // AFTER the split: the engine route-split is built for the socket-keyed
        // (IP_BOUND_IF) bypass and its install deletes any `<exit>` host route as a
        // stale destination-keyed leftover. This macOS path deliberately does not
        // bind the carrier (`IP_BOUND_IF` black-holes egress on multi-interface hosts),
        // so it needs the `<exit>/32` escape instead; adding it after the split lets
        // the more-specific host route win and keeps the QUIC carrier off the tunnel
        // (before the split deleted it, the carrier looped into its own tunnel and
        // downlink was zero).
        #[cfg(target_os = "macos")]
        let carrier_route = {
            crate::tun_setup::add_carrier_host_route_macos(exit_ip, &phys_gateway)
                .map_err(SdkError::Tun)?;
            CarrierHostRoute { exit_ip }
        };

        // DNS push: point the system resolver at the in-tunnel gateway so lookups
        // travel the tunnel, not a now-unreachable LAN resolver.
        let dns_guard = current_platform()
            .install_dns_push(&[TUNNEL_GATEWAY_IP])
            .await
            .map_err(|e| SdkError::Tun(std::io::Error::other(format!("dns push: {e}"))))?;

        // Start forwarding so the device actually carries traffic, then verify.
        let (tun_sink, bridge) =
            warren_net::tun_channels(device, warren_tun::Framing::for_target_os(), mtu);
        let driver = tokio::spawn(bridge.run());
        let pump = tokio::spawn(warren_net::forward_bidirectional(tun_sink, sink));

        // Verify the tunnel forwards end to end, then (and only then) arm the
        // killswitch. On a dead verdict or a killswitch error the helper aborts the
        // forwarding tasks and returns Err; `route_guard`, `dns_guard` and the macOS
        // `carrier_route` revert on their drops here, so the host fails open.
        let killswitch = arm_killswitch_on_verified_egress(
            verify_tunnel_egress,
            move || async move {
                KsBackend::install_with(&build_killswitch_opts(exit_ip, &dev_name, socket_bypass))
                    .await
                    .map_err(|e| SdkError::Tun(std::io::Error::other(format!("killswitch: {e}"))))
            },
            || {
                driver.abort();
                pump.abort();
            },
        )
        .await?;

        Ok(TunDatapathHandle {
            driver,
            pump,
            route_guard,
            dns_guard,
            #[cfg(target_os = "macos")]
            carrier_route,
            killswitch,
        })
    }

    /// Starts the non-root proxy datapath over a multihop tunnel to `exit`. Same
    /// shape as [`Self::start_proxy`] but every packet is HPKE-sealed, so it
    /// works against production exits.
    ///
    /// # Errors
    ///
    /// [`SdkError::ExitDnsDisabled`] if the exit runs no DNS forwarder and no
    /// resolver override is set, [`SdkError::Multihop`] from the tunnel, or
    /// [`SdkError::Proxy`] if the local listener cannot bind.
    pub async fn start_proxy(
        &self,
        circuit: &Circuit,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<ProxyHandle, SdkError> {
        let exit = circuit.dialed_exit();
        ensure_dns_reachable(exit.dns_disabled, cfg)?;
        let sink = self.connect_multihop(exit).await?;
        // Capture the session's counters before the sink moves into the engine, so
        // the handle can expose live metrics for the datapath's lifetime.
        let metrics = sink.metrics();
        let (local_ip, prefix, gateway, ipv6) = addressing_from_session(sink.session());
        let mut handle = serve_proxy_over_sink(sink, local_ip, prefix, gateway, ipv6, cfg).await?;
        handle.metrics = Some(metrics);
        Ok(handle)
    }

    /// Opens `n` (>= 1) multihop sessions to `exit` and bonds them into one
    /// [`warren_net::BondedPacketSink`]: outbound packets stripe across members,
    /// inbound packets merge. Every member uses this client's identity, so a real
    /// exit's sticky allocator assigns the bundle ONE tunnel IP. Lifts the single-
    /// connection bandwidth ceiling. Validate against a real exit before relying on
    /// the bundle's sticky-IP coherence.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] if any member fails to establish.
    pub async fn connect_multihop_bonded(
        &self,
        exit: &VerifiedExit,
        n: usize,
    ) -> Result<warren_net::BondedPacketSink, SdkError> {
        let mut sinks = Vec::with_capacity(n.max(1));
        for _ in 0..n.max(1) {
            sinks.push(self.connect_multihop(exit).await?);
        }
        Ok(warren_net::BondedPacketSink::new(sinks))
    }

    /// Starts the non-root proxy datapath over a bonded set of `n` multihop
    /// sessions to `exit` (see [`Self::connect_multihop_bonded`]). Same shape as
    /// [`Self::start_proxy`] but traffic is striped across `n` tunnels.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] from establishing a member, [`SdkError::ExitDnsDisabled`]
    /// per [`Self::start_proxy`], or [`SdkError::Proxy`] on a bind failure.
    pub async fn start_proxy_bonded(
        &self,
        circuit: &Circuit,
        n: usize,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<ProxyHandle, SdkError> {
        let exit = circuit.dialed_exit();
        ensure_dns_reachable(exit.dns_disabled, cfg)?;
        let n = n.max(1);
        let mut sinks = Vec::with_capacity(n);
        for _ in 0..n {
            sinks.push(self.connect_multihop(exit).await?);
        }
        // All members share the exit's sticky assignment; read it from the first,
        // and expose that member's metrics on the handle.
        let (local_ip, prefix, gateway, ipv6) = addressing_from_session(sinks[0].session());
        let metrics = sinks[0].metrics();
        let bond = warren_net::BondedPacketSink::new(sinks);
        let mut handle = serve_proxy_over_sink(bond, local_ip, prefix, gateway, ipv6, cfg).await?;
        handle.metrics = Some(metrics);
        Ok(handle)
    }

    /// Starts a *self-healing* multihop proxy datapath: it binds the local
    /// SOCKS5 (and optional HTTP CONNECT) listeners once, then keeps a sealed
    /// tunnel to `exit` up across drops, rebuilding the netstack from a freshly
    /// fetched `IpAssign` on each reconnect while the app-facing proxy address
    /// stays stable. Observe progress via [`SupervisedProxyHandle::watch_state`].
    ///
    /// Unlike [`Self::start_proxy`], the returned handle stays valid
    /// across reconnects: the app keeps pointing at the same proxy address and the
    /// datapath transparently re-establishes. Reconnection targets the same
    /// `exit`; the first attempt's failure is surfaced (the handle reports
    /// [`ConnectionState::Reconnecting`]) but does not error the call. For
    /// resilience to a permanently-unreachable exit, see
    /// [`Self::start_proxy_supervised_failover`].
    ///
    /// # Errors
    ///
    /// [`SdkError::ExitDnsDisabled`] if the exit runs no DNS forwarder and no
    /// resolver override is set, or [`SdkError::Proxy`] if a local listener cannot
    /// bind. Tunnel establishment happens in the background, so connect failures
    /// surface as state, not here.
    pub async fn start_proxy_supervised(
        &self,
        circuit: &Circuit,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<SupervisedProxyHandle, SdkError> {
        let exit = circuit.dialed_exit().clone();
        ensure_dns_reachable(exit.dns_disabled, cfg)?;
        let signing = self.signing.clone();
        let auto_local_ip = self.auto_local_ip;
        let wants_ipv6 = self.wants_ipv6;
        let transport_config = self.transport_config.clone();
        let rtt_cache = Arc::clone(&self.rtt_cache);
        self.spawn_supervised(
            cfg,
            move || {
                let signing = signing.clone();
                let exit = exit.clone();
                let transport_config = transport_config.clone();
                let rtt_cache = Arc::clone(&rtt_cache);
                async move {
                    establish_multihop(
                        signing,
                        &exit,
                        auto_local_ip,
                        wants_ipv6,
                        transport_config,
                        rtt_cache,
                    )
                    .await
                }
            },
            // Single pinned exit: a drain has nowhere to rotate, the proactive
            // reconnect re-dials it (the ambient relay-list refresh excludes it).
            || {},
        )
        .await
    }

    /// Self-healing multihop proxy with exit FAILOVER: same stable-listener,
    /// self-rebuilding datapath as [`Self::start_proxy_supervised`], but
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
    pub async fn start_proxy_supervised_failover(
        &self,
        circuits: &[Circuit],
        cfg: &warren_net::ProxyConfig,
    ) -> Result<SupervisedProxyHandle, SdkError> {
        if circuits.is_empty() {
            return Err(SdkError::NoMultihopExit);
        }
        let exits: Vec<VerifiedExit> = circuits.iter().map(|c| c.dialed_exit().clone()).collect();
        // Without a DNS override, an exit that runs no in-tunnel forwarder
        // (`dns_disabled`) cannot resolve names, so drop such exits from the
        // rotation: otherwise failover could silently land on one and break name
        // resolution. With an override every exit can resolve, so keep them all.
        let exits = dns_capable_candidates(&exits, cfg.dns_server.is_some());
        if exits.is_empty() {
            return Err(SdkError::ExitDnsDisabled);
        }
        let signing = self.signing.clone();
        let auto_local_ip = self.auto_local_ip;
        let wants_ipv6 = self.wants_ipv6;
        let transport_config = self.transport_config.clone();
        // Shared cursor: advanced on a failed attempt (so a working exit is kept
        // and a broken one is rotated past) AND on a drain advisory (ADR 36: the
        // current exit is healthy but leaving, so rotate past it directly instead
        // of waiting for its hard-close to produce the `Err` that rotates).
        let cursor = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let drain_cursor = Arc::clone(&cursor);
        // Durable avoidance on top of the cursor: an exit that failed to
        // establish (and, once the reserve-then-switch gate is live, one that
        // conflicted with a pinned port) stays out of rotation for the TTL,
        // instead of being retried after one full cursor wrap.
        let avoid = Arc::new(std::sync::Mutex::new(
            // Keyed by the raw exit id bytes (`VerifiedExit::exit_id`).
            crate::portfollow::AvoidSet::<[u8; 16]>::default(),
        ));
        let rtt_cache = Arc::clone(&self.rtt_cache);
        self.spawn_supervised(
            cfg,
            move || {
                let signing = signing.clone();
                let exits = exits.clone();
                let cursor = Arc::clone(&cursor);
                let avoid = Arc::clone(&avoid);
                let transport_config = transport_config.clone();
                let rtt_cache = Arc::clone(&rtt_cache);
                async move {
                    let idx = {
                        let avoid = avoid.lock().expect("avoid-set lock poisoned");
                        let ids: Vec<_> = exits.iter().map(|e| e.exit_id).collect();
                        crate::portfollow::next_candidate(
                            cursor.load(Ordering::Relaxed),
                            &ids,
                            &*avoid,
                        )
                    };
                    match establish_multihop(
                        signing,
                        &exits[idx],
                        auto_local_ip,
                        wants_ipv6,
                        transport_config,
                        rtt_cache,
                    )
                    .await
                    {
                        Ok(tunnel) => {
                            cursor.store(idx, Ordering::Relaxed);
                            Ok(tunnel)
                        }
                        Err(e) => {
                            avoid
                                .lock()
                                .expect("avoid-set lock poisoned")
                                .insert(exits[idx].exit_id);
                            cursor.store(idx.wrapping_add(1), Ordering::Relaxed);
                            Err(e)
                        }
                    }
                }
            },
            move || {
                drain_cursor.fetch_add(1, Ordering::Relaxed);
            },
        )
        .await
    }

    /// Binds the stable proxy listeners, spawns the supervisor over `connect`, and
    /// returns the [`SupervisedProxyHandle`]. Shared by the single-exit and
    /// failover supervised datapaths; only the (re)connect closure differs.
    async fn spawn_supervised<F, Fut, D>(
        &self,
        cfg: &warren_net::ProxyConfig,
        connect: F,
        on_drain: D,
    ) -> Result<SupervisedProxyHandle, SdkError>
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<EstablishedTunnel<MultihopPacketSink>, SdkError>>
            + Send,
        D: Fn() + Send + 'static,
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
        let (forwarder_tx, forwarder_rx) = tokio::sync::watch::channel(None);
        let (migration_tx, migration_rx) = tokio::sync::watch::channel(None);
        let (fatal_tx, fatal_rx) = tokio::sync::watch::channel(None);
        let dns_server = cfg.dns_server;
        let task = tokio::spawn(async move {
            supervise_proxy(
                socks_listener,
                http_listener,
                dns_server,
                crate::supervisor::SupervisorOutputs {
                    state_tx,
                    forwarder_tx,
                    migration_tx,
                    fatal_tx,
                    egress_probe: true,
                },
                crate::supervisor::EpochGuards {
                    // Reserve-then-switch is OFF by default: the pre-migrate
                    // gate needs the candidate pre-flight (NAT-PMP reservation
                    // over the target exit) that activates with the
                    // transactional-migration rollout; until then a drain
                    // migrates unconditionally.
                    pre_migrate: None,
                    // Network-change migration: a moved default path
                    // (handover, renumbering) redials immediately instead of
                    // riding the dead session into idle timeout.
                    network_watch: Some(crate::supervisor::NetworkWatch::system()),
                },
                connect,
                on_drain,
            )
            .await;
        });

        Ok(SupervisedProxyHandle {
            local_addr,
            http_addr,
            state_rx,
            forwarder_rx,
            migration_rx,
            fatal_rx,
            task,
        })
    }
}

#[cfg(feature = "reqwest-transport")]
fn warren_api_default_base() -> String {
    crate::product::API_URL.to_owned()
}

#[cfg(not(feature = "reqwest-transport"))]
fn warren_api_default_base() -> String {
    String::new()
}

/// The failover candidates that can resolve DNS over the tunnel: with a
/// `dns_server` override every exit qualifies, otherwise only exits that run the
/// in-tunnel forwarder (`!dns_disabled`). Keeps failover from rotating onto an
/// exit that would silently break name resolution (the per-rotation analogue of
/// [`ensure_dns_reachable`]).
pub(crate) fn dns_capable_candidates(
    exits: &[VerifiedExit],
    has_dns_override: bool,
) -> Vec<VerifiedExit> {
    if has_dns_override {
        exits.to_vec()
    } else {
        exits.iter().filter(|e| !e.dns_disabled).cloned().collect()
    }
}

/// Fails closed when an exit runs no DNS forwarder and the caller supplied no
/// override resolver: starting the datapath anyway would leave every name-based
/// connection silently unresolvable. (In proxy mode lookups never touch the host
/// resolver, so this is a fail-fast usability guard, not a leak fix; the leak
/// concern is the privileged TUN backend's, which is deferred.)
pub(crate) fn ensure_dns_reachable(
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
/// How the multihop DAITA defense is armed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaitaMode {
    /// No defense requested.
    Off,
    /// Default: advertise support, the exit samples and returns the machine
    /// (the production-proven negotiated model).
    Negotiated,
    /// Explicit override: client-side unilateral pick of a named machine.
    LocalPick(String),
}

/// Resolves the arming mode from the builder switches. A named machine
/// implies the override; plain `.daita()` negotiates.
pub(crate) fn daita_mode(daita: bool, machine: Option<&str>) -> DaitaMode {
    match (daita, machine) {
        (false, _) => DaitaMode::Off,
        (true, None) => DaitaMode::Negotiated,
        (true, Some(name)) => DaitaMode::LocalPick(name.to_owned()),
    }
}

pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The ONE wiring of a measured path RTT into the client store, shared by
/// every datapath (client connects and the supervised reconnect loop).
/// Best effort: a poisoned lock is silently skipped (the store is an
/// optimisation, never load-bearing).
pub(crate) fn record_rtt_in(
    cache: &Arc<Mutex<RttCache>>,
    endpoint_id: [u8; 32],
    rtt: std::time::Duration,
) {
    let rtt_ms = u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX);
    if let Ok(mut cache) = cache.lock() {
        cache.record(endpoint_id, rtt_ms, now_unix_secs());
    }
}

/// Sink observer recording the session's parting RTT under `endpoint_id`
/// when the datapath drops, so a long session's final measurement reaches
/// the store, not just the connect-time one.
pub(crate) fn close_rtt_recorder_for(
    cache: &Arc<Mutex<RttCache>>,
    endpoint_id: [u8; 32],
) -> warren_net::CloseRttObserver {
    let cache = Arc::clone(cache);
    Box::new(move |rtt_ms| {
        if let Ok(mut cache) = cache.lock() {
            cache.record(endpoint_id, rtt_ms, now_unix_secs());
        }
    })
}

/// The Linux carrier-socket bypass given the physical interface index (unused on
/// Linux: the escape is keyed on the fwmark, not the interface), delegating to the
/// engine's single picker so the SDK never re-derives the `SO_MARK` mechanism.
/// macOS deliberately uses no socket bypass (the `IP_BOUND_IF` bind
/// black-holes egress on multi-interface hosts); its carrier
/// escapes via a `<exit>/32` host route instead (see [`crate::tun_setup`]).
#[cfg(all(feature = "experimental-tun", target_os = "linux"))]
fn socket_bypass_from_ifindex(ifindex: u32) -> SocketBypass {
    warrenguard_route_split::socket_bypass::tunnel_socket_bypass(ifindex)
}

/// Builds the killswitch options the privileged datapath installs (single-homed
/// in `warrenguard-killswitch-os`). The carrier accept keys on the Linux socket
/// mark when the carrier is bound (Port Fail / TunnelCrack ServerIP fix), and
/// falls back to the legacy destination accept when there is no bind (macOS,
/// where the unbound carrier escapes via the `<exit>/32` route). Shared with the
/// tests so they pin the rendered Home A ruleset against the real construction.
#[cfg(all(unix, feature = "experimental-tun"))]
fn build_killswitch_opts(
    exit_ip: std::net::IpAddr,
    dev: &str,
    socket_bypass: Option<SocketBypass>,
) -> warrenguard_killswitch_os::KillswitchOpts {
    warrenguard_killswitch_os::KillswitchOpts {
        exit_addrs: vec![exit_ip],
        tun_name: dev.to_owned(),
        allow_lan: false,
        allow_dhcp: false,
        socket_mark: socket_bypass.and_then(|b| b.fwmark()),
        phys_iface: None,
    }
}

/// Arms the fail-closed killswitch ONLY once `verify` has proven the datapath
/// forwards, and never otherwise. On a failed verification, or a killswitch
/// install error, it runs `abort` (tearing down the forwarding tasks) and returns
/// the error WITHOUT a killswitch, so a datapath that never comes up fails OPEN,
/// leaving the host as found rather than stranded behind a fail-closed anchor with
/// a dead tunnel (arming before egress is verified strands the host exactly that
/// way). Generic over the killswitch type so this ordering invariant is unit
/// tested with fakes: `start_tun_multihop` itself needs a real device + privilege.
#[cfg(all(unix, feature = "experimental-tun"))]
async fn arm_killswitch_on_verified_egress<K, VFut, AFut>(
    verify: impl FnOnce() -> VFut,
    arm: impl FnOnce() -> AFut,
    abort: impl FnOnce(),
) -> Result<K, SdkError>
where
    VFut: std::future::Future<Output = Result<(), SdkError>>,
    AFut: std::future::Future<Output = Result<K, SdkError>>,
{
    if let Err(e) = verify().await {
        abort();
        return Err(e);
    }
    match arm().await {
        Ok(killswitch) => Ok(killswitch),
        Err(e) => {
            abort();
            Err(e)
        }
    }
}

/// Total wall-clock budget for [`verify_tunnel_egress`]: a freshly dialled circuit
/// can take a beat to forward its first datagrams, so retry within this window.
#[cfg(all(unix, feature = "experimental-tun"))]
const TUN_EGRESS_VERIFY_BUDGET: std::time::Duration = std::time::Duration::from_secs(12);
/// Gap between egress-verification attempts within the budget.
#[cfg(all(unix, feature = "experimental-tun"))]
const TUN_EGRESS_VERIFY_RETRY_GAP: std::time::Duration = std::time::Duration::from_millis(500);
/// Per-attempt wait for an in-tunnel DNS answer (two sends inside).
#[cfg(all(unix, feature = "experimental-tun"))]
const TUN_EGRESS_VERIFY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Retransmit offset of the second datagram in one attempt, so a single lost UDP
/// packet does not fail the attempt.
#[cfg(all(unix, feature = "experimental-tun"))]
const TUN_EGRESS_VERIFY_RETRANSMIT: std::time::Duration = std::time::Duration::from_millis(1500);
/// Name the verification resolves: Warren infrastructure, queried against Warren's
/// own exit resolver, so no third party learns anything.
#[cfg(all(unix, feature = "experimental-tun"))]
const TUN_EGRESS_VERIFY_QNAME: &str = "warrenbrowse.com";

/// Proves the freshly brought-up TUN datapath actually forwards, by resolving a
/// name through the in-tunnel gateway resolver ([`TUNNEL_GATEWAY_IP`]). The
/// gateway is reachable only across the new device (its point-to-point peer, and
/// the `/1` split capture), so a genuine matching DNS answer proves the whole
/// chain: device up + addressed, routes captured, and the exit decapsulating and
/// forwarding. Retried over [`TUN_EGRESS_VERIFY_BUDGET`].
///
/// Strict on purpose, unlike the periodic liveness
/// [`warren_transport::egress_probe::probe_gateway_dns`] which reports inconclusive
/// local errors as alive: this gates arming the killswitch, so a bind/connect/send
/// failure or no answer is "not proven" and must fail open.
///
/// # Errors
///
/// [`SdkError::Tun`] if no in-tunnel DNS answer arrives within the budget.
#[cfg(all(unix, feature = "experimental-tun"))]
async fn verify_tunnel_egress() -> Result<(), SdkError> {
    let gateway = SocketAddr::new(std::net::IpAddr::V4(TUNNEL_GATEWAY_IP), 53);
    let deadline = tokio::time::Instant::now() + TUN_EGRESS_VERIFY_BUDGET;
    loop {
        if probe_gateway_dns_strict(gateway).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(SdkError::Tun(std::io::Error::other(
                "tunnel egress not verified: no in-tunnel DNS answer, the datapath \
                 is not forwarding",
            )));
        }
        tokio::time::sleep(TUN_EGRESS_VERIFY_RETRY_GAP).await;
    }
}

/// One strict in-tunnel DNS round trip to `gateway`: `true` only on a genuine
/// matching answer. A local socket error (bind/connect/send) or a timeout is
/// `false` (not proven), because a false positive here would arm the killswitch on
/// a dead datapath.
#[cfg(all(unix, feature = "experimental-tun"))]
async fn probe_gateway_dns_strict(gateway: SocketAddr) -> bool {
    use warren_transport::egress_probe::{build_dns_query, is_matching_response};

    let sock = match tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    if sock.connect(gateway).await.is_err() {
        return false;
    }
    let txid = next_probe_txid();
    let query = build_dns_query(txid, TUN_EGRESS_VERIFY_QNAME);
    if sock.send(&query).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + TUN_EGRESS_VERIFY_PROBE_TIMEOUT;
    let retransmit = tokio::time::sleep(TUN_EGRESS_VERIFY_RETRANSMIT);
    tokio::pin!(retransmit);
    let mut retransmitted = false;
    loop {
        tokio::select! {
            () = &mut retransmit, if !retransmitted => {
                retransmitted = true;
                let _ = sock.send(&query).await;
            }
            recv = sock.recv(&mut buf) => match recv {
                Ok(n) if is_matching_response(&buf[..n], txid) => return true,
                Ok(_) => {} // unrelated datagram, keep reading
                Err(_) => return false,
            },
            () = tokio::time::sleep_until(deadline) => return false,
        }
    }
}

/// A per-probe DNS transaction id. Seedless is fine: each probe uses a fresh
/// ephemeral source port, so a stale datagram from a prior probe never reaches
/// this socket; the id only guards against an unrelated in-flight answer within
/// one probe.
#[cfg(all(unix, feature = "experimental-tun"))]
fn next_probe_txid() -> u16 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed) as u16
}

/// macOS: RAII owner of the carrier host-route escape (`<exit>/32` via the
/// physical gateway). Its `Drop` removes the route, so it is torn down whether
/// `start_tun_multihop` returns early on a later setup failure or the datapath
/// handle is dropped.
#[cfg(all(unix, feature = "experimental-tun", target_os = "macos"))]
struct CarrierHostRoute {
    exit_ip: std::net::IpAddr,
}

#[cfg(all(unix, feature = "experimental-tun", target_os = "macos"))]
impl std::fmt::Debug for CarrierHostRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarrierHostRoute").finish_non_exhaustive()
    }
}

#[cfg(all(unix, feature = "experimental-tun", target_os = "macos"))]
impl Drop for CarrierHostRoute {
    fn drop(&mut self) {
        crate::tun_setup::del_carrier_host_route_macos(self.exit_ip);
    }
}

/// The OS killswitch backend the datapath installs (pf sub-anchor on macOS, nft
/// table on Linux). Single-homed in `warrenguard-killswitch-os`.
#[cfg(all(unix, feature = "experimental-tun", target_os = "macos"))]
type KsBackend = warrenguard_killswitch_os::MacosKillswitch;
#[cfg(all(unix, feature = "experimental-tun", target_os = "linux"))]
type KsBackend = warrenguard_killswitch_os::LinuxKillswitch;

/// Handle to a running privileged TUN datapath (from
/// [`WarrenClient::start_tun_multihop`]). Dropping it stops the datapath: both
/// background tasks are aborted (closing the device and the tunnel) and the
/// routing / DNS / killswitch guards revert on their own field drops, declared so
/// the killswitch (fail-closed) is torn down last.
///
/// EXPERIMENTAL, Unix-only, behind the `experimental-tun` feature.
#[cfg(all(unix, feature = "experimental-tun"))]
// The routing / DNS / carrier-route / killswitch guards are held ONLY for their
// `Drop` teardown (never read by name), which the dead-code lint cannot see; the
// field order is the load-bearing teardown order, so they must stay owned fields.
#[allow(dead_code)]
pub struct TunDatapathHandle {
    driver: tokio::task::JoinHandle<std::io::Result<()>>,
    pump: tokio::task::JoinHandle<Result<(), warren_net::NetError>>,
    // Reverts the split-default `/1` capture on drop (physical default resumes).
    route_guard: Option<warrenguard_route_split::platform_net::RouteSplitGuard>,
    // Restores the system resolvers on drop.
    dns_guard: Option<warrenguard_route_split::platform_net::DnsPushGuard>,
    // macOS carrier `<exit>/32` escape, removed on drop (dropped before the
    // killswitch so the host stays fail-closed until teardown finishes).
    #[cfg(target_os = "macos")]
    carrier_route: CarrierHostRoute,
    // Removes the OS killswitch LAST: fail-closed until every other guard is gone.
    killswitch: KsBackend,
}

// The routing / DNS guards are not `Debug`, so render only a stable name.
#[cfg(all(unix, feature = "experimental-tun"))]
impl std::fmt::Debug for TunDatapathHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDatapathHandle").finish_non_exhaustive()
    }
}

#[cfg(all(unix, feature = "experimental-tun"))]
impl Drop for TunDatapathHandle {
    fn drop(&mut self) {
        // Abort the datapath tasks (closes the device + tunnel). The routing, DNS,
        // carrier-route and killswitch guards then revert on their field drops
        // (declaration order), leaving the host as found. Best-effort throughout.
        self.driver.abort();
        self.pump.abort();
    }
}

// The privileged TUN datapath's Port Fail wiring: the SDK composes the single
// Home A stack (route-split picker + killswitch-os) rather than a private
// plan/apply. These pin that composition; the end-to-end datapath itself is
// validated rooted against a real device.
#[cfg(all(test, unix, feature = "experimental-tun"))]
mod portfail_tests {
    use super::*;
    use std::net::IpAddr;

    const EXIT: &str = "203.0.113.9";

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_bypass_delegates_to_the_shared_route_split_picker() {
        // Anti-regrowth pin: the SDK must NOT re-derive its own Linux
        // carrier bypass; it delegates to the engine's single picker. If a future
        // change re-open-codes a private SDK picker that drifts from the engine's,
        // this equality breaks and this test goes red.
        for idx in [0_u32, 1, 7, 42, 65535] {
            assert_eq!(
                socket_bypass_from_ifindex(idx),
                warrenguard_route_split::socket_bypass::tunnel_socket_bypass(idx),
                "the SDK carrier bypass must stay identical to the shared \
                 warrenguard_route_split picker (no private re-derivation)"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn killswitch_opts_key_the_carrier_accept_on_the_socket_mark_on_linux() {
        // The SDK's own opts, rendered by the Home A killswitch: the
        // carrier accept must key on the socket mark, never the exit destination.
        // A regression to the destination accept (the Port Fail leak) puts
        // `ip daddr <exit>` back and drops the `meta mark` rule -> red.
        let exit: IpAddr = EXIT.parse().unwrap();
        let bypass = Some(socket_bypass_from_ifindex(0));
        let opts = build_killswitch_opts(exit, "warren0", bypass);
        let ruleset = warrenguard_killswitch_os::build_linux_ruleset(&opts);
        let mark = warrenguard_route_split::socket_bypass::tunnel_socket_bypass(0)
            .fwmark()
            .expect("the linux picker is a fwmark bypass");
        assert!(
            ruleset.contains(&format!("meta mark {mark:#x} accept")),
            "the SDK killswitch must accept the carrier socket mark (Port Fail \
             fix), got:\n{ruleset}"
        );
        assert!(
            !ruleset.contains(&format!("ip daddr {EXIT}")),
            "the per-exit destination accept (the leak) must NOT be present:\n{ruleset}"
        );
        assert!(ruleset.contains("policy drop;"), "fail-closed preserved");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn killswitch_opts_render_a_failclosed_pf_subanchor_on_macos() {
        // macOS composes the Home A pf sub-anchor killswitch (not a private plan):
        // the SDK's opts must render a valid, non-empty ruleset. With no carrier
        // bind, the accept stays destination-based (socket_mark None); the unbound
        // carrier's leak-free escape is the `<exit>/32` route pinned in tun_setup.
        let exit: IpAddr = EXIT.parse().unwrap();
        let opts = build_killswitch_opts(exit, "utun7", None);
        assert!(
            opts.socket_mark.is_none(),
            "macOS uses no carrier bind, so the killswitch keeps the destination accept"
        );
        let rules = warrenguard_killswitch_os::build_pf_rules(&opts)
            .expect("the SDK opts must render a valid pf ruleset");
        assert!(
            !rules.is_empty(),
            "the pf sub-anchor killswitch must install rules (fail-closed)"
        );
    }

    // A stand-in killswitch: the ordering invariant is exercised without a real
    // pf/nft install (which needs privilege and a device).
    #[derive(Debug, PartialEq)]
    struct FakeKs;

    #[tokio::test]
    async fn arms_the_killswitch_only_once_egress_is_verified() {
        let armed = std::cell::Cell::new(false);
        let aborted = std::cell::Cell::new(false);
        let ks: FakeKs = arm_killswitch_on_verified_egress(
            || async { Ok(()) },
            || async {
                armed.set(true);
                Ok(FakeKs)
            },
            || aborted.set(true),
        )
        .await
        .expect("a verified datapath must arm the killswitch and connect");
        assert_eq!(ks, FakeKs);
        assert!(
            armed.get(),
            "the killswitch must be armed once egress is proven"
        );
        assert!(
            !aborted.get(),
            "a healthy setup must not tear the forwarding datapath down"
        );
    }

    #[tokio::test]
    async fn never_arms_the_killswitch_when_egress_is_not_verified() {
        // Arming the killswitch on a datapath that never forwarded would strand
        // the host fail-closed with a dead tunnel. It must fail OPEN instead: NO
        // killswitch, and the forwarding tasks torn down.
        let armed = std::cell::Cell::new(false);
        let aborted = std::cell::Cell::new(false);
        let err = arm_killswitch_on_verified_egress::<FakeKs, _, _>(
            || async {
                Err(SdkError::Tun(std::io::Error::other(
                    "datapath not forwarding",
                )))
            },
            || async {
                armed.set(true);
                Ok(FakeKs)
            },
            || aborted.set(true),
        )
        .await
        .expect_err("an unverified datapath must not connect");
        assert!(matches!(err, SdkError::Tun(_)));
        assert!(
            !armed.get(),
            "the killswitch must NEVER engage on an unverified datapath (fail open)"
        );
        assert!(
            aborted.get(),
            "the forwarding datapath must be torn down when egress is not proven"
        );
    }

    #[tokio::test]
    async fn tears_down_and_fails_open_when_the_killswitch_install_fails() {
        // Egress is proven but the killswitch itself cannot install: still abort the
        // forwarding tasks and surface the error, leaving no killswitch behind.
        let aborted = std::cell::Cell::new(false);
        let err = arm_killswitch_on_verified_egress::<FakeKs, _, _>(
            || async { Ok(()) },
            || async { Err(SdkError::Tun(std::io::Error::other("pf busy"))) },
            || aborted.set(true),
        )
        .await
        .expect_err("a killswitch install failure must fail the connect");
        assert!(matches!(err, SdkError::Tun(_)));
        assert!(
            aborted.get(),
            "a failed killswitch install must tear the datapath down"
        );
    }
}
