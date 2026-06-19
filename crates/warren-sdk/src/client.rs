use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use warren_api::{HttpTransport, WarrenApiClient};
use warren_discovery::{
    ExitSelector, VerifiedExit, verify_multihop_directory, verify_signed_relay_list,
};
use warren_identity::WarrenIdentity;
use warren_net::{MultihopPacketSink, QuicPacketSink};
use warren_transport::{ClientTunnel, ConnectionState, MultihopClientTunnel};

#[cfg(feature = "reqwest-transport")]
use warren_api::ReqwestTransport;

use crate::error::{BuildError, SdkError};
use crate::proxy::{
    ProxyHandle, TUNNEL_GATEWAY, TUNNEL_PREFIX, addressing_from_session, serve_proxy_over_sink,
};
use crate::supervisor::{
    EstablishedTunnel, SupervisedProxyHandle, establish_multihop, supervise_proxy,
};

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

    /// Enables DAITA on multihop tunnels: the client pads its own uplink with
    /// cover traffic scheduled by a machine picked uniformly from the curated
    /// [`DaitaPool`](warren_daita::DaitaPool) (the exit pads the downlink
    /// independently). Off by default. Only affects multihop connects.
    #[must_use]
    pub fn daita(mut self) -> Self {
        self.daita = true;
        self
    }

    /// Like [`daita`](Self::daita) but pins the uplink defense to a named curated
    /// machine (`netflow`, `tamaraw`, `front`, `interspace_server`,
    /// `scrambler_server`) instead of a random pick. Useful for deterministic
    /// behaviour in tests and ops debugging.
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
    /// Anti-rollback floor: highest signed-list `generation` trusted so far.
    pub(crate) generation_store: Arc<dyn GenerationStore>,
    /// Anti-rollback floor for the multihop directory (separate sequence).
    pub(crate) multihop_generation_store: Arc<dyn GenerationStore>,
    /// Trust-on-first-use pin store, when enabled.
    pub(crate) server_key_store: Option<Arc<dyn ServerKeyStore>>,
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
    pub async fn connect_tunnel(
        &self,
        exit: &warren_discovery::Relay,
    ) -> Result<QuicPacketSink, SdkError> {
        let addr: SocketAddr = *exit.addrs().first().ok_or(SdkError::NoExitAddress)?;
        let mut tunnel = ClientTunnel::new(self.signing.clone());
        if self.auto_local_ip {
            tunnel = tunnel.with_auto_local_ip();
        }
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
        exit: &warren_discovery::Relay,
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
        Ok(verified.exits)
    }

    /// Establishes a multihop tunnel to `exit` (the handshake real exits require:
    /// an HPKE-sealed setup frame, not a bare `Setup`) and returns the sealed
    /// packet plane.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] if the handshake, policy gate, or datapath fails.
    /// When DAITA is enabled (see [`WarrenClientBuilder::daita`]):
    /// [`SdkError::UnknownDaitaMachine`] if a named machine is not in the pool,
    /// [`SdkError::EmptyDaitaPool`] if the pool is empty, or
    /// [`SdkError::DaitaConfig`] if the maybenot framework rejects the config.
    pub async fn connect_multihop(
        &self,
        exit: &VerifiedExit,
    ) -> Result<MultihopPacketSink, SdkError> {
        let mut tunnel = MultihopClientTunnel::new(self.signing.clone());
        if self.auto_local_ip {
            tunnel = tunnel.with_auto_local_ip();
        }
        if self.wants_ipv6 {
            tunnel = tunnel.with_ipv6(true);
        }
        let session = tunnel
            .connect(
                exit.exit_ed25519_pubkey,
                exit.exit_x25519_multihop_pubkey,
                exit.exit_id,
                exit.endpoint,
            )
            .await?;
        if !self.daita {
            return Ok(MultihopPacketSink::new(session));
        }
        // DAITA on: pick the uplink machine, build the driver over a shared
        // session, and spawn its padding loop. The loop self-terminates when the
        // tunnel closes (a cover send then errors), so no explicit stop is needed.
        let pool = warren_daita::DaitaPool::default_pool();
        let cfg = match &self.daita_machine {
            Some(name) => pool
                .pick_named_os(name)
                .ok_or_else(|| SdkError::UnknownDaitaMachine { name: name.clone() })?,
            None => pool.pick_os().ok_or(SdkError::EmptyDaitaPool)?,
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
        Ok(MultihopPacketSink::from_arc(session, Some(handle)))
    }

    /// Starts the PRIVILEGED TUN datapath over a multihop tunnel to `exit`:
    /// opens a kernel TUN device named `tun_name`, applies the split-default
    /// routing and the killswitch, and forwards raw IP packets between the device
    /// and the sealed tunnel. This is the one-call entry for full-OS capture, the
    /// privileged analogue of [`Self::start_proxy_multihop`].
    ///
    /// EXPERIMENTAL, Unix-only, requires root / `CAP_NET_ADMIN`, and is NOT YET
    /// validated against a real exit (per CLAUDE.md that needs a real device +
    /// privilege; it cannot be exercised from a headless CI). Behind the
    /// `experimental-tun` feature. It composes already-tested pieces:
    /// [`Self::connect_multihop`], `warren_tun::device::open_tun`, the
    /// routing/killswitch applier, `warren_net::tun_channels` +
    /// `TunBridge::run`, and `warren_net::forward_bidirectional`.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] if the tunnel handshake fails, or [`SdkError::Tun`]
    /// if the device cannot be opened or the routing/killswitch cannot be applied.
    #[cfg(all(unix, feature = "experimental-tun"))]
    pub async fn start_tun_multihop(
        &self,
        exit: &VerifiedExit,
        tun_name: &str,
    ) -> Result<TunDatapathHandle, SdkError> {
        use warren_tun::{RoutingPlan, TunConfig};

        let sink = self.connect_multihop(exit).await?;
        let session = sink.session();
        let ipv4 = session.assigned_ipv4();
        // /32 host address on the tunnel; the split-default routes capture the
        // rest. v6 is added only when the exit assigned one.
        let mtu = u16::try_from(session.max_inner_payload()).unwrap_or(1280);
        let device = warren_tun::device::open_tun(tun_name).map_err(SdkError::Tun)?;
        // The kernel assigns the interface name on macOS (the requested `tun_name`
        // may be empty), so read it back; on Linux the name is what we asked for.
        #[cfg(target_os = "macos")]
        let dev_name = device.name().map_err(SdkError::Tun)?;
        #[cfg(not(target_os = "macos"))]
        let dev_name = tun_name.to_owned();

        let config = TunConfig {
            name: dev_name.clone(),
            mtu,
            ipv4: (ipv4, 32),
            ipv6: session.assigned_ipv6().map(|v6| (v6, 128)),
            exit_endpoint: exit.endpoint,
            dns: vec![std::net::Ipv4Addr::new(10, 66, 0, 1).into()],
        };

        let gateway = warren_tun::gateway::discover_default_gateway().map_err(SdkError::Tun)?;
        // Bring the device up + address it BEFORE routing (a fresh TUN is down).
        warren_tun::apply::configure_interface(&config).map_err(SdkError::Tun)?;
        let routing = RoutingPlan::split_default(&config);
        // Fail-safe: if routing or the killswitch fails mid-setup, revert what was
        // applied before returning, so a partial setup never strands the host with
        // a captured default route or a closed killswitch and no handle to undo it.
        if let Err(e) = warren_tun::apply::apply_routing(&routing, &dev_name, gateway) {
            warren_tun::apply::revert_routing(&routing, &dev_name, gateway);
            return Err(SdkError::Tun(e));
        }
        if let Err(e) = warren_tun::apply::apply_killswitch(&config) {
            warren_tun::apply::revert_routing(&routing, &dev_name, gateway);
            let _ = warren_tun::apply::teardown_killswitch();
            return Err(SdkError::Tun(e));
        }
        // Push the exit resolvers and route EVERY query through the tunnel link.
        // Without this, the split-default capture above still leaves DNS going to
        // the host's previous resolver (the R4 leak). Fail-safe like the steps
        // before it: undo DNS, routing and the killswitch if the push fails.
        if let Err(e) = warren_tun::apply::apply_dns(&config) {
            warren_tun::apply::revert_dns(&config);
            warren_tun::apply::revert_routing(&routing, &dev_name, gateway);
            let _ = warren_tun::apply::teardown_killswitch();
            return Err(SdkError::Tun(e));
        }

        let (tun_sink, bridge) =
            warren_net::tun_channels(device, warren_tun::Framing::for_target_os(), config.mtu);
        let driver = tokio::spawn(bridge.run());
        let pump = tokio::spawn(warren_net::forward_bidirectional(tun_sink, sink));
        Ok(TunDatapathHandle {
            driver,
            pump,
            routing,
            config,
            gateway,
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
    pub async fn start_proxy_multihop(
        &self,
        exit: &VerifiedExit,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<ProxyHandle, SdkError> {
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
    /// [`Self::start_proxy_multihop`] but traffic is striped across `n` tunnels.
    ///
    /// # Errors
    ///
    /// [`SdkError::Multihop`] from establishing a member, [`SdkError::ExitDnsDisabled`]
    /// per [`Self::start_proxy_multihop`], or [`SdkError::Proxy`] on a bind failure.
    pub async fn start_proxy_multihop_bonded(
        &self,
        exit: &VerifiedExit,
        n: usize,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<ProxyHandle, SdkError> {
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
    /// [`SdkError::ExitDnsDisabled`] if the exit runs no DNS forwarder and no
    /// resolver override is set, or [`SdkError::Proxy`] if a local listener cannot
    /// bind. Tunnel establishment happens in the background, so connect failures
    /// surface as state, not here.
    pub async fn start_proxy_multihop_supervised(
        &self,
        exit: &VerifiedExit,
        cfg: &warren_net::ProxyConfig,
    ) -> Result<SupervisedProxyHandle, SdkError> {
        ensure_dns_reachable(exit.dns_disabled, cfg)?;
        let signing = self.signing.clone();
        let exit = exit.clone();
        let auto_local_ip = self.auto_local_ip;
        let wants_ipv6 = self.wants_ipv6;
        self.spawn_supervised(cfg, move || {
            let signing = signing.clone();
            let exit = exit.clone();
            async move { establish_multihop(signing, &exit, auto_local_ip, wants_ipv6).await }
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
        // Without a DNS override, an exit that runs no in-tunnel forwarder
        // (`dns_disabled`) cannot resolve names, so drop such exits from the
        // rotation: otherwise failover could silently land on one and break name
        // resolution. With an override every exit can resolve, so keep them all.
        let exits = dns_capable_candidates(exits, cfg.dns_server.is_some());
        if exits.is_empty() {
            return Err(SdkError::ExitDnsDisabled);
        }
        let signing = self.signing.clone();
        let auto_local_ip = self.auto_local_ip;
        let wants_ipv6 = self.wants_ipv6;
        // Shared cursor: advanced only on a failed attempt, so a working exit is
        // kept (stable egress) and a broken one is rotated past on the next try.
        let cursor = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        self.spawn_supervised(cfg, move || {
            let signing = signing.clone();
            let exits = exits.clone();
            let cursor = Arc::clone(&cursor);
            async move {
                let idx = cursor.load(Ordering::Relaxed) % exits.len();
                match establish_multihop(signing, &exits[idx], auto_local_ip, wants_ipv6).await {
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
        let (forwarder_tx, forwarder_rx) = tokio::sync::watch::channel(None);
        let dns_server = cfg.dns_server;
        let task = tokio::spawn(async move {
            supervise_proxy(
                socks_listener,
                http_listener,
                dns_server,
                state_tx,
                forwarder_tx,
                connect,
            )
            .await;
        });

        Ok(SupervisedProxyHandle {
            local_addr,
            http_addr,
            state_rx,
            forwarder_rx,
            task,
        })
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
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Handle to a running privileged TUN datapath (from
/// [`WarrenClient::start_tun_multihop`]). Dropping it stops the datapath: both
/// background tasks are aborted, which closes the device and the tunnel.
///
/// EXPERIMENTAL, Unix-only, behind the `experimental-tun` feature.
#[cfg(all(unix, feature = "experimental-tun"))]
#[derive(Debug)]
pub struct TunDatapathHandle {
    driver: tokio::task::JoinHandle<std::io::Result<()>>,
    pump: tokio::task::JoinHandle<Result<(), warren_net::NetError>>,
    routing: warren_tun::RoutingPlan,
    config: warren_tun::TunConfig,
    gateway: std::net::IpAddr,
}

#[cfg(all(unix, feature = "experimental-tun"))]
impl Drop for TunDatapathHandle {
    fn drop(&mut self) {
        // Stop the datapath tasks (closes the device + tunnel), then restore the
        // routing table and drop the killswitch so the host is left as found.
        // Best-effort: a route/table already gone on teardown is not an error.
        self.driver.abort();
        self.pump.abort();
        warren_tun::apply::revert_dns(&self.config);
        warren_tun::apply::revert_routing(&self.routing, &self.config.name, self.gateway);
        let _ = warren_tun::apply::teardown_killswitch();
    }
}
