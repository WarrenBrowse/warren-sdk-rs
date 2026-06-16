use warren_api::ClientError;
use warren_discovery::{DirectoryError, SelectorError, SignedError};
use warren_transport::{MultihopError, TunnelError};

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
    /// The privileged TUN datapath could not be set up (device open, routing or
    /// killswitch application). EXPERIMENTAL, only from `start_tun_multihop`.
    #[error("tun datapath setup failed")]
    Tun(#[source] std::io::Error),
    /// DAITA was enabled with a named machine that is not in the curated pool.
    /// The machine name is a public protocol label, not identity material.
    #[error("unknown DAITA machine: {name}")]
    UnknownDaitaMachine {
        /// The requested machine name (a curated-pool label).
        name: String,
    },
    /// DAITA was enabled but the curated machine pool was empty (should not
    /// happen with the built-in pool; surfaced rather than panicking).
    #[error("the DAITA machine pool is empty")]
    EmptyDaitaPool,
    /// DAITA was enabled but the maybenot framework rejected the configuration.
    #[error("DAITA framework configuration failed")]
    DaitaConfig(#[source] warren_daita::DaitaError),
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
