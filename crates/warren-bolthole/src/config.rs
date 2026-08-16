//! Environment-first configuration of the gateway.
//!
//! Parsing is pure: the environment, the file reader and the file-mode reader
//! are injected, so every refusal below is unit-tested without touching the
//! process environment or the filesystem. The knobs shared with the other
//! headless daemon come from [`warren_headless::env`]; what is here is the
//! gateway's own.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ip_network::IpNetwork;
use warren_bolthole_core::{
    CONTROL_RANGE_END, CONTROL_RANGE_START, DEFAULT_HANDSHAKE_RATE, NatConfig, PeerPlan,
    TUNNEL_GATEWAY_V4,
};
use warren_headless::env::{self, CircuitKind, ConfigError, ExitFilter};
use warren_headless::forward::{ForwardConfig, parse_forward};
use warren_sdk::transport::SocketBypass;
use zeroize::Zeroizing;

/// The gateway's own health port, distinct from the proxy's 9999 so both
/// daemons run on one host without either operator changing anything.
pub const DEFAULT_HEALTH_LISTEN: &str = "127.0.0.1:9998";
/// Where peers send their datagrams by default: nothing but this host.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:51820";
/// The interface MTU written into every client configuration. The IPv6
/// minimum, so every v6 flow fits once the tunnel budget reaches 1280, and it
/// leaves QUIC its own floor inside the peer.
pub const DEFAULT_CLIENT_MTU: u16 = 1280;
/// The largest MTU `/status` ever recommends: above it the tunnel budget stops
/// being the binding constraint and the peer's own path becomes one.
pub const MAX_CLIENT_MTU: u16 = 1420;
/// The smallest MTU a peer configuration may carry: the IPv6 minimum, under
/// which a stock host fragments rather than shrinking its packets, and this
/// gateway drops fragments.
pub const MIN_CLIENT_MTU: u16 = 1280;
/// How long the tunnel has to reach `Connected` before startup gives up.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 90;

/// Why the environment did not resolve to a runnable gateway.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GatewayConfigError {
    /// A shared knob was missing or malformed.
    #[error(transparent)]
    Env(#[from] ConfigError),
    /// A non-loopback bind was asked for without the explicit opt-in.
    #[error(
        "WARREN_BOLTHOLE_LISTEN binds an address other than loopback: set WARREN_BOLTHOLE_LAN=1 to accept it. \
         A LAN-bound gateway is reachable by every device on that network, and any of them holding a client \
         configuration rides this account's Warren session: one assigned address at the exit, one abuse \
         identity, one device slot, shared bandwidth and no per-peer accounting. \
         Warren's QUIC transport and its obfuscation begin AT this gateway: the hop between a stock client \
         and the gateway is ordinary WireGuard, recognisable to DPI, so a gateway reachable across the \
         internet gives up Warren's censorship resistance for that leg"
    )]
    LanNotAllowed,
    /// The gateway configuration file is readable by more than its owner.
    #[error(
        "the gateway configuration file must be mode 0600: it holds the gateway private key and every \
         peer's preshared key"
    )]
    ConfPermissions,
    /// The peer address plan is unusable.
    #[error("invalid peer subnet")]
    Plan(#[from] warren_bolthole_core::PlanError),
    /// An explicit endpoint that no peer on the LAN could ever reach.
    #[error(
        "WARREN_BOLTHOLE_ENDPOINT is a loopback address while WARREN_BOLTHOLE_LAN=1: no other device can \
         reach it, so every client configuration written with it would be dead on arrival"
    )]
    LoopbackEndpoint,
    /// The forwarded port would collide with the gateway's control plane.
    #[error(
        "WARREN_PORT_FORWARD_INTERNAL_PORT is inside the range this gateway reserves for its own \
         in-tunnel control plane ({CONTROL_RANGE_START}-{CONTROL_RANGE_END})"
    )]
    ForwardPortReserved,
    /// The forward target is not a peer.
    #[error(
        "WARREN_PORT_FORWARD_TARGET must be a peer address inside the peer subnet: inbound traffic is \
         delivered by cryptokey routing, and this gateway has no other way to reach it"
    )]
    ForwardTargetNotAPeer,
    /// No forward target was named.
    #[error(
        "WARREN_PORT_FORWARD_TARGET is required: unlike the proxy, this gateway relays nothing itself, \
         it delivers to a peer"
    )]
    ForwardTargetMissing,
    /// The MTU written into client configurations is unusable.
    #[error(
        "WARREN_BOLTHOLE_CLIENT_MTU must be between {MIN_CLIENT_MTU} and {MAX_CLIENT_MTU}: under the \
         IPv6 minimum a peer fragments rather than shrinking its packets and this gateway drops \
         fragments, and above it the tunnel stops being the binding constraint while the peer's \
         own path becomes one"
    )]
    ClientMtu,
    /// The state directory could not be resolved from the environment.
    #[error("could not resolve a state directory: set WARREN_BOLTHOLE_STATE_DIR")]
    NoStateDir,
}

/// Everything the gateway reads from its environment.
pub struct GatewayEnv {
    /// The account's BIP39 recovery phrase, absent for the subcommands that
    /// only write files. Zeroized on drop; never logged.
    pub mnemonic: Option<Zeroizing<String>>,
    /// Override for the API base URL; `None` uses the compiled default.
    pub api_base: Option<String>,
    /// Override for the relay-list signing key pin.
    pub server_pubkey_hex: Option<String>,
    /// Circuit shape dialed for every candidate.
    pub circuit: CircuitKind,
    /// Exit constraints in priority order.
    pub exit_filters: Vec<ExitFilter>,
    /// Budget for the tunnel to reach `Connected` at startup.
    pub connect_timeout: Duration,
    /// One UDP bind per entry: a wildcard socket answers from a route-chosen
    /// source that a peer's `Endpoint` may not match.
    pub listen: Vec<SocketAddr>,
    /// Whether the operator accepted a gateway reachable off this host.
    pub lan: bool,
    /// The endpoint written into client configurations, when the operator set
    /// one explicitly.
    pub endpoint: Option<SocketAddr>,
    /// How many peers a first run generates.
    pub peers: u32,
    /// Where the gateway keeps its configuration and the client files.
    pub state_dir: PathBuf,
    /// The gateway-side configuration file.
    pub conf_path: PathBuf,
    /// Where peers are numbered.
    pub plan: PeerPlan,
    /// Whether to ask the exit for an IPv6 assignment.
    pub ipv6: bool,
    /// The `MTU` line written into client configurations.
    pub client_mtu: u16,
    /// Whether peers may reach each other.
    pub peer_isolation: bool,
    /// Threshold of the shared cookie limiter.
    pub handshake_rate: u64,
    /// Local liveness endpoint; `None` disables it.
    pub health_listen: Option<SocketAddr>,
    /// Whether `/peers` is served.
    pub health_peers: bool,
    /// The resolver written into client configurations; `None` writes no line.
    pub dns_server: Option<IpAddr>,
    /// True when the peers resolve somewhere other than the exit forwarder,
    /// which lets an exit that runs no forwarder stay in the rotation.
    pub dns_override: bool,
    /// Optional tunnel-side port forward.
    pub forward: Option<ForwardConfig>,
    /// The NAT's ranges, caps and timeouts.
    pub nat: NatConfig,
    /// Marks or binds the carrier socket, so a peer on this host whose default
    /// route points into the gateway cannot capture the datapath's own QUIC
    /// datagrams.
    pub socket_bypass: Option<SocketBypass>,
}

impl std::fmt::Debug for GatewayEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual impl: the mnemonic must never reach a log through {:?}.
        f.debug_struct("GatewayEnv")
            .field("mnemonic", &"<redacted>")
            .field("api_base", &self.api_base)
            .field("circuit", &self.circuit)
            .field("exit_filters", &self.exit_filters)
            .field("listen", &self.listen.len())
            .field("lan", &self.lan)
            .field("peers", &self.peers)
            .field("ipv6", &self.ipv6)
            .field("client_mtu", &self.client_mtu)
            .field("peer_isolation", &self.peer_isolation)
            .field("health_listen", &self.health_listen)
            .field("forward", &self.forward)
            .finish_non_exhaustive()
    }
}

impl GatewayEnv {
    /// The recovery phrase, for the paths that dial a tunnel.
    ///
    /// # Errors
    ///
    /// [`ConfigError::MissingMnemonic`] when neither variable was set.
    pub fn require_mnemonic(&self) -> Result<&Zeroizing<String>, ConfigError> {
        self.mnemonic.as_ref().ok_or(ConfigError::MissingMnemonic)
    }

    /// Where the client configurations are written.
    #[must_use]
    pub fn clients_dir(&self) -> PathBuf {
        self.state_dir.join("clients")
    }
}

/// Resolves the gateway configuration.
///
/// `mode_of` returns a file's unix mode when it exists, so the 0600 rule is
/// testable without a filesystem; `is_root` decides the default state
/// directory. Both are injected for the same reason the readers are.
///
/// # Errors
///
/// See [`GatewayConfigError`].
pub fn load(
    get: impl Fn(&str) -> Option<String>,
    read_file: impl Fn(&Path) -> std::io::Result<String>,
    mode_of: impl Fn(&Path) -> Option<u32>,
    is_root: bool,
) -> Result<GatewayEnv, GatewayConfigError> {
    let mnemonic = env::read_secret(&get, &read_file, "WARREN_MNEMONIC")?;
    let circuit = env::parse_circuit(get("WARREN_CIRCUIT").as_deref())?;
    let exit_filters = env::parse_exit_filters(get("WARREN_EXITS").as_deref().unwrap_or_default())?;
    let connect_timeout =
        env::parse_connect_timeout(get("WARREN_CONNECT_TIMEOUT"), DEFAULT_CONNECT_TIMEOUT_SECS)?;

    let lan = parse_flag(&get, "WARREN_BOLTHOLE_LAN", false)?;
    let listen = parse_listen(get("WARREN_BOLTHOLE_LISTEN"))?;
    if !lan && listen.iter().any(|a| !a.ip().is_loopback()) {
        return Err(GatewayConfigError::LanNotAllowed);
    }

    let endpoint =
        env::parse_optional_addr(get("WARREN_BOLTHOLE_ENDPOINT"), "WARREN_BOLTHOLE_ENDPOINT")?;
    if lan && endpoint.is_some_and(|e| e.ip().is_loopback()) {
        return Err(GatewayConfigError::LoopbackEndpoint);
    }

    let state_dir = match get("WARREN_BOLTHOLE_STATE_DIR").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => default_state_dir(&get, is_root)?,
    };
    let conf_path = match get("WARREN_BOLTHOLE_CONF").filter(|v| !v.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => state_dir.join("bolthole.conf"),
    };
    // A file nobody has written yet has no mode to refuse; a first run creates
    // it 0600 itself.
    if cfg!(unix)
        && let Some(mode) = mode_of(&conf_path)
        && mode & 0o077 != 0
    {
        return Err(GatewayConfigError::ConfPermissions);
    }

    let plan = PeerPlan::new(
        parse_network(&get, "WARREN_BOLTHOLE_PEER_SUBNET", "10.67.0.0/24")?,
        parse_network(
            &get,
            "WARREN_BOLTHOLE_PEER_SUBNET_V6",
            "fd77:6172:7265::/64",
        )?,
    )?;

    let health_listen =
        env::parse_health_listen(get("WARREN_HEALTH_LISTEN"), DEFAULT_HEALTH_LISTEN)?;

    // The default resolver is the exit's own forwarder, which is what makes an
    // exit that runs none unusable; any other value is the operator saying
    // their peers resolve elsewhere, so such an exit stays in the rotation.
    let (dns_server, dns_override) = match get("WARREN_DNS_SERVER") {
        None => (Some(IpAddr::V4(TUNNEL_GATEWAY_V4)), false),
        Some(v) if env::is_off(&v) => (None, true),
        Some(v) => {
            let addr = v.parse::<IpAddr>().map_err(|_| ConfigError::Invalid {
                var: "WARREN_DNS_SERVER",
                expected: "an IP address, or off",
            })?;
            let override_ = addr != IpAddr::V4(TUNNEL_GATEWAY_V4);
            (Some(addr), override_)
        }
    };

    let client_mtu = parse_number(&get, "WARREN_BOLTHOLE_CLIENT_MTU", DEFAULT_CLIENT_MTU)?;
    if !(MIN_CLIENT_MTU..=MAX_CLIENT_MTU).contains(&client_mtu) {
        return Err(GatewayConfigError::ClientMtu);
    }

    let forward = parse_gateway_forward(&get, &plan)?;

    Ok(GatewayEnv {
        mnemonic,
        api_base: get("WARREN_API_URL").filter(|v| !v.is_empty()),
        server_pubkey_hex: get(warren_sdk::product::SERVER_PUBKEY_HEX_ENV)
            .filter(|v| !v.is_empty()),
        circuit,
        exit_filters,
        connect_timeout,
        listen,
        lan,
        endpoint,
        peers: parse_number(&get, "WARREN_BOLTHOLE_PEERS", 1)?,
        state_dir,
        conf_path,
        plan,
        ipv6: parse_flag(&get, "WARREN_BOLTHOLE_IPV6", true)?,
        client_mtu,
        peer_isolation: parse_flag(&get, "WARREN_BOLTHOLE_PEER_ISOLATION", true)?,
        handshake_rate: parse_number(
            &get,
            "WARREN_BOLTHOLE_HANDSHAKE_RATE",
            DEFAULT_HANDSHAKE_RATE,
        )?,
        health_listen,
        health_peers: parse_flag(&get, "WARREN_BOLTHOLE_HEALTH_PEERS", true)?,
        dns_server,
        dns_override,
        forward,
        nat: parse_nat(&get)?,
        socket_bypass: parse_bypass(&get)?,
    })
}

/// What the `healthcheck` subcommand should probe.
///
/// # Errors
///
/// [`ConfigError::Invalid`] when the value is neither an off spelling nor an
/// `ip:port`.
pub fn healthcheck_target(raw: Option<String>) -> Result<Option<SocketAddr>, ConfigError> {
    env::healthcheck_target(raw, DEFAULT_HEALTH_LISTEN)
}

/// Parses the comma-separated bind list. One socket per entry.
fn parse_listen(raw: Option<String>) -> Result<Vec<SocketAddr>, ConfigError> {
    let raw = raw.filter(|v| !v.trim().is_empty());
    let raw = raw.as_deref().unwrap_or(DEFAULT_LISTEN);
    raw.split(',')
        .map(|item| env::parse_addr(item.trim(), "WARREN_BOLTHOLE_LISTEN"))
        .collect()
}

fn parse_flag(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match get(var).filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => Err(ConfigError::Invalid {
            var,
            expected: "0 or 1",
        }),
    }
}

fn parse_number<T: std::str::FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: T,
) -> Result<T, ConfigError> {
    match get(var).filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => v.parse::<T>().map_err(|_| ConfigError::Invalid {
            var,
            expected: "a number",
        }),
    }
}

fn parse_seconds(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: Duration,
) -> Result<Duration, ConfigError> {
    match get(var).filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => Ok(Duration::from_secs(v.parse::<u64>().map_err(|_| {
            ConfigError::Invalid {
                var,
                expected: "a number of seconds",
            }
        })?)),
    }
}

fn parse_network(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: &str,
) -> Result<IpNetwork, ConfigError> {
    let raw = get(var).filter(|v| !v.is_empty());
    let raw = raw.as_deref().unwrap_or(default);
    raw.parse::<IpNetwork>().map_err(|_| ConfigError::Invalid {
        var,
        expected: "a network in CIDR notation",
    })
}

fn parse_nat(get: &impl Fn(&str) -> Option<String>) -> Result<NatConfig, ConfigError> {
    let d = NatConfig::default();
    Ok(NatConfig {
        per_peer_mappings: parse_number(
            get,
            "WARREN_BOLTHOLE_NAT_PER_PEER_MAPPINGS",
            d.per_peer_mappings,
        )?,
        per_peer_identifiers: parse_number(
            get,
            "WARREN_BOLTHOLE_NAT_PER_PEER_IDENTIFIERS",
            d.per_peer_identifiers,
        )?,
        udp_initial: parse_seconds(
            get,
            "WARREN_BOLTHOLE_NAT_UDP_INITIAL_TIMEOUT",
            d.udp_initial,
        )?,
        udp_established: parse_seconds(get, "WARREN_BOLTHOLE_NAT_UDP_TIMEOUT", d.udp_established)?,
        tcp_syn: parse_seconds(get, "WARREN_BOLTHOLE_NAT_TCP_SYN_TIMEOUT", d.tcp_syn)?,
        tcp_established: parse_seconds(get, "WARREN_BOLTHOLE_NAT_TCP_TIMEOUT", d.tcp_established)?,
        tcp_closing: parse_seconds(
            get,
            "WARREN_BOLTHOLE_NAT_TCP_CLOSING_TIMEOUT",
            d.tcp_closing,
        )?,
        icmp: parse_seconds(get, "WARREN_BOLTHOLE_NAT_ICMP_TIMEOUT", d.icmp)?,
        ..d
    })
}

/// The carrier-socket escape, spelled per platform because the mechanism is:
/// a firewall mark on Linux, an interface bind on macOS and Windows.
fn parse_bypass(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<SocketBypass>, ConfigError> {
    if let Some(mark) = get("WARREN_BOLTHOLE_FWMARK").filter(|v| !v.is_empty()) {
        let mark = parse_u32(&mark).ok_or(ConfigError::Invalid {
            var: "WARREN_BOLTHOLE_FWMARK",
            expected: "a firewall mark (decimal, or 0x-prefixed hex)",
        })?;
        return Ok(Some(SocketBypass::Fwmark(mark)));
    }
    if let Some(index) = get("WARREN_BOLTHOLE_BIND_IF").filter(|v| !v.is_empty()) {
        let index = index.parse::<u32>().map_err(|_| ConfigError::Invalid {
            var: "WARREN_BOLTHOLE_BIND_IF",
            expected: "an interface index",
        })?;
        return Ok(Some(if cfg!(windows) {
            SocketBypass::UnicastIf(index)
        } else {
            SocketBypass::BoundIf(index)
        }));
    }
    Ok(None)
}

fn parse_u32(raw: &str) -> Option<u32> {
    match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => raw.parse::<u32>().ok(),
    }
}

/// The forward, with the two rules that only apply to a gateway: the target is
/// a peer, and the internal port stays out of the control range.
fn parse_gateway_forward(
    get: &impl Fn(&str) -> Option<String>,
    plan: &PeerPlan,
) -> Result<Option<ForwardConfig>, GatewayConfigError> {
    let Some(fwd) = parse_forward(get)? else {
        return Ok(None);
    };
    if (CONTROL_RANGE_START..=CONTROL_RANGE_END).contains(&fwd.internal_port) {
        return Err(GatewayConfigError::ForwardPortReserved);
    }
    let target = fwd.target.ok_or(GatewayConfigError::ForwardTargetMissing)?;
    if !plan.contains(target.ip()) || plan.is_gateway(target.ip()) {
        return Err(GatewayConfigError::ForwardTargetNotAPeer);
    }
    Ok(Some(ForwardConfig {
        proto: fwd.proto,
        internal_port: fwd.internal_port,
        target,
        up_command: fwd.up_command,
        down_command: fwd.down_command,
        status_file: fwd.status_file,
    }))
}

/// Where a gateway keeps its state when the operator names no directory: a
/// system path when it runs as root (a service), the user's own private data
/// directory otherwise.
fn default_state_dir(
    get: &impl Fn(&str) -> Option<String>,
    is_root: bool,
) -> Result<PathBuf, GatewayConfigError> {
    if cfg!(unix) && is_root {
        return Ok(PathBuf::from("/var/lib/warren-bolthole"));
    }
    if cfg!(windows) {
        return get("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(|dir| PathBuf::from(dir).join("warren-bolthole"))
            .ok_or(GatewayConfigError::NoStateDir);
    }
    if let Some(xdg) = get("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("warren-bolthole"));
    }
    let home = get("HOME")
        .filter(|v| !v.is_empty())
        .ok_or(GatewayConfigError::NoStateDir)?;
    let home = PathBuf::from(home);
    Ok(if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Application Support")
            .join("warren-bolthole")
    } else {
        home.join(".local").join("state").join("warren-bolthole")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn no_file(_: &Path) -> std::io::Result<String> {
        Err(std::io::Error::other("no file expected in this test"))
    }

    fn no_mode(_: &Path) -> Option<u32> {
        None
    }

    /// The minimum every test needs: a state dir (so no platform lookup runs)
    /// and whatever the case under test adds.
    fn with(pairs: &[(&str, &str)]) -> Result<GatewayEnv, GatewayConfigError> {
        let mut all = vec![
            ("WARREN_MNEMONIC", "abandon ability able"),
            ("WARREN_BOLTHOLE_STATE_DIR", "/tmp/bolthole-state"),
        ];
        all.extend_from_slice(pairs);
        load(env(&all), no_file, no_mode, false)
    }

    #[test]
    fn a_minimal_environment_binds_loopback_and_takes_every_default() {
        let cfg = with(&[]).expect("a mnemonic and a state dir are enough");
        assert_eq!(cfg.listen, vec![DEFAULT_LISTEN.parse().unwrap()]);
        assert!(!cfg.lan);
        assert_eq!(cfg.peers, 1);
        assert_eq!(cfg.client_mtu, 1280);
        assert!(
            cfg.peer_isolation,
            "peers must not reach each other by default"
        );
        assert!(cfg.ipv6);
        assert_eq!(cfg.handshake_rate, DEFAULT_HANDSHAKE_RATE);
        assert_eq!(
            cfg.health_listen,
            Some("127.0.0.1:9998".parse().unwrap()),
            "the gateway takes its own port so it can run beside the proxy"
        );
        assert!(cfg.health_peers);
        assert_eq!(cfg.dns_server, Some(IpAddr::V4(TUNNEL_GATEWAY_V4)));
        assert!(!cfg.dns_override, "the default resolver is the exit's own");
        assert_eq!(
            cfg.conf_path,
            PathBuf::from("/tmp/bolthole-state/bolthole.conf")
        );
        assert_eq!(cfg.plan, PeerPlan::default());
        assert!(cfg.forward.is_none());
        assert!(cfg.socket_bypass.is_none());
    }

    /// A gateway on a LAN address is reachable by every device there, and the
    /// leg between a stock client and it is ordinary WireGuard. Both facts are
    /// in the refusal, because the refusal is where an operator reads them.
    #[test]
    fn a_lan_bind_is_refused_until_the_operator_opts_in() {
        let err = with(&[("WARREN_BOLTHOLE_LISTEN", "0.0.0.0:51820")])
            .expect_err("a non-loopback bind must refuse");
        let message = err.to_string();
        assert!(matches!(err, GatewayConfigError::LanNotAllowed));
        assert!(
            message.contains("every device on that network"),
            "the refusal must say who can reach it: {message}"
        );
        assert!(
            message.contains("obfuscation begin AT this gateway"),
            "the refusal must carry the obfuscation boundary: {message}"
        );

        let cfg = with(&[
            ("WARREN_BOLTHOLE_LISTEN", "0.0.0.0:51820"),
            ("WARREN_BOLTHOLE_LAN", "1"),
        ])
        .expect("the opt-in accepts it");
        assert!(cfg.lan);
    }

    #[test]
    fn several_binds_become_several_sockets() {
        let cfg = with(&[
            ("WARREN_BOLTHOLE_LISTEN", "127.0.0.1:51820, 127.0.0.2:51821"),
            ("WARREN_BOLTHOLE_LAN", "0"),
        ])
        .expect("two loopback binds need no opt-in");
        assert_eq!(
            cfg.listen,
            vec![
                "127.0.0.1:51820".parse().unwrap(),
                "127.0.0.2:51821".parse().unwrap()
            ]
        );
        assert!(matches!(
            with(&[("WARREN_BOLTHOLE_LISTEN", "51820")]),
            Err(GatewayConfigError::Env(ConfigError::Invalid {
                var: "WARREN_BOLTHOLE_LISTEN",
                ..
            }))
        ));
    }

    /// The file holds the gateway private key and every peer's preshared key,
    /// so a mode any other local account can read is a refusal, not a warning.
    #[cfg(unix)]
    #[test]
    fn a_group_readable_configuration_file_is_refused() {
        let readable = |_: &Path| Some(0o640);
        let err = load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("WARREN_BOLTHOLE_STATE_DIR", "/tmp/bolthole-state"),
            ]),
            no_file,
            readable,
            false,
        )
        .expect_err("0640 must refuse");
        assert!(matches!(err, GatewayConfigError::ConfPermissions));

        let private = |_: &Path| Some(0o600);
        load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("WARREN_BOLTHOLE_STATE_DIR", "/tmp/bolthole-state"),
            ]),
            no_file,
            private,
            false,
        )
        .expect("0600 is what the gateway writes itself");
    }

    /// The exit assigns from one engine-wide pool, so a peer plan that meets
    /// it would give two different hosts the same address inside one gateway.
    #[test]
    fn a_peer_subnet_that_meets_the_tunnel_pool_is_refused() {
        for subnet in ["10.66.0.0/24", "10.66.0.0/16", "10.0.0.0/8"] {
            let err = with(&[("WARREN_BOLTHOLE_PEER_SUBNET", subnet)])
                .unwrap_err()
                .to_string();
            assert!(err.contains("peer subnet"), "{subnet}: {err}");
        }
        with(&[("WARREN_BOLTHOLE_PEER_SUBNET", "192.168.9.0/24")])
            .expect("a subnet clear of the pool is accepted");
    }

    #[test]
    fn a_loopback_endpoint_on_a_lan_gateway_is_refused() {
        let err = with(&[
            ("WARREN_BOLTHOLE_LAN", "1"),
            ("WARREN_BOLTHOLE_LISTEN", "0.0.0.0:51820"),
            ("WARREN_BOLTHOLE_ENDPOINT", "127.0.0.1:51820"),
        ])
        .expect_err("no other device could reach that endpoint");
        assert!(matches!(err, GatewayConfigError::LoopbackEndpoint));
    }

    /// The control range carries this gateway's own NAT-PMP and egress-probe
    /// flows, so a forward landing there would shadow them.
    #[test]
    fn a_forward_inside_the_control_range_is_refused() {
        let err = with(&[
            ("WARREN_PORT_FORWARD_INTERNAL_PORT", "61001"),
            ("WARREN_PORT_FORWARD_TARGET", "10.67.0.2:8080"),
        ])
        .expect_err("the control range is reserved");
        assert!(matches!(err, GatewayConfigError::ForwardPortReserved));
    }

    #[test]
    fn a_forward_target_outside_the_peer_subnet_is_refused() {
        for target in ["127.0.0.1:8080", "10.66.0.2:8080", "10.67.0.1:8080"] {
            let err = with(&[
                ("WARREN_PORT_FORWARD_INTERNAL_PORT", "8080"),
                ("WARREN_PORT_FORWARD_TARGET", target),
            ])
            .expect_err("only a peer can receive a forward");
            assert!(
                matches!(err, GatewayConfigError::ForwardTargetNotAPeer),
                "{target}: {err}"
            );
        }
        let err = with(&[("WARREN_PORT_FORWARD_INTERNAL_PORT", "8080")])
            .expect_err("a gateway relays nothing itself");
        assert!(matches!(err, GatewayConfigError::ForwardTargetMissing));

        let cfg = with(&[
            ("WARREN_PORT_FORWARD_INTERNAL_PORT", "8080"),
            ("WARREN_PORT_FORWARD_TARGET", "10.67.0.2:8080"),
        ])
        .expect("a peer target is accepted");
        assert_eq!(
            cfg.forward.unwrap().target,
            "10.67.0.2:8080".parse().unwrap()
        );
    }

    /// The same rule as the proxy's: the exit's own forwarder is the default,
    /// and naming any other resolver says the peers resolve elsewhere, which
    /// keeps a forwarder-less exit in the rotation.
    #[test]
    fn only_a_resolver_other_than_the_exits_own_is_an_override() {
        let cfg = with(&[("WARREN_DNS_SERVER", "10.66.0.1")]).unwrap();
        assert!(!cfg.dns_override);
        let cfg = with(&[("WARREN_DNS_SERVER", "9.9.9.9")]).unwrap();
        assert!(cfg.dns_override);
        assert_eq!(cfg.dns_server, Some("9.9.9.9".parse().unwrap()));
        let cfg = with(&[("WARREN_DNS_SERVER", "off")]).unwrap();
        assert_eq!(cfg.dns_server, None, "off writes no DNS line at all");
        assert!(
            cfg.dns_override,
            "with no resolver written, the peers bring their own"
        );
        assert!(with(&[("WARREN_DNS_SERVER", "nameserver")]).is_err());
    }

    #[test]
    fn the_carrier_escape_is_spelled_per_platform() {
        let cfg = with(&[("WARREN_BOLTHOLE_FWMARK", "0x1234")]).unwrap();
        assert_eq!(cfg.socket_bypass, Some(SocketBypass::Fwmark(0x1234)));
        let cfg = with(&[("WARREN_BOLTHOLE_FWMARK", "4660")]).unwrap();
        assert_eq!(cfg.socket_bypass, Some(SocketBypass::Fwmark(4660)));
        let cfg = with(&[("WARREN_BOLTHOLE_BIND_IF", "7")]).unwrap();
        let expected = if cfg!(windows) {
            SocketBypass::UnicastIf(7)
        } else {
            SocketBypass::BoundIf(7)
        };
        assert_eq!(cfg.socket_bypass, Some(expected));
        assert!(with(&[("WARREN_BOLTHOLE_FWMARK", "mark")]).is_err());
        assert!(with(&[("WARREN_BOLTHOLE_BIND_IF", "eth0")]).is_err());
    }

    #[test]
    fn the_nat_timeouts_are_operator_tunable_and_refuse_junk() {
        let cfg = with(&[
            ("WARREN_BOLTHOLE_NAT_UDP_TIMEOUT", "45"),
            ("WARREN_BOLTHOLE_NAT_TCP_TIMEOUT", "600"),
            ("WARREN_BOLTHOLE_NAT_PER_PEER_MAPPINGS", "128"),
        ])
        .unwrap();
        assert_eq!(cfg.nat.udp_established, Duration::from_secs(45));
        assert_eq!(cfg.nat.tcp_established, Duration::from_secs(600));
        assert_eq!(cfg.nat.per_peer_mappings, 128);
        assert_eq!(
            cfg.nat.udp_initial,
            NatConfig::default().udp_initial,
            "an untouched knob keeps the RFC floor"
        );
        assert!(with(&[("WARREN_BOLTHOLE_NAT_ICMP_TIMEOUT", "a while")]).is_err());
    }

    #[test]
    fn flags_take_1_and_0_and_refuse_anything_else() {
        assert!(!with(&[("WARREN_BOLTHOLE_IPV6", "0")]).unwrap().ipv6);
        assert!(
            !with(&[("WARREN_BOLTHOLE_PEER_ISOLATION", "false")])
                .unwrap()
                .peer_isolation
        );
        assert!(
            !with(&[("WARREN_BOLTHOLE_HEALTH_PEERS", "0")])
                .unwrap()
                .health_peers
        );
        assert!(matches!(
            with(&[("WARREN_BOLTHOLE_IPV6", "yes")]),
            Err(GatewayConfigError::Env(ConfigError::Invalid {
                var: "WARREN_BOLTHOLE_IPV6",
                ..
            }))
        ));
    }

    /// The value reaches the peers' own configurations, the gate's budget
    /// target and the sink's payload cap, so a value no peer could use is a
    /// refusal at load rather than a gateway that never opens its gate.
    #[test]
    fn a_client_mtu_outside_what_a_peer_can_use_is_refused() {
        for mtu in ["0", "68", "1279", "1421", "9000"] {
            let err = with(&[("WARREN_BOLTHOLE_CLIENT_MTU", mtu)])
                .expect_err("{mtu} is not a usable client MTU");
            assert!(matches!(err, GatewayConfigError::ClientMtu), "{mtu}: {err}");
            let message = err.to_string();
            assert!(
                message.contains("1280") && message.contains("1420"),
                "{message}"
            );
        }
        for mtu in ["1280", "1380", "1420"] {
            assert_eq!(
                with(&[("WARREN_BOLTHOLE_CLIENT_MTU", mtu)])
                    .expect("a usable MTU")
                    .client_mtu,
                mtu.parse::<u16>().expect("a number")
            );
        }
        assert!(with(&[("WARREN_BOLTHOLE_CLIENT_MTU", "large")]).is_err());
    }

    /// The knobs an operator turns when the defaults do not fit their network.
    #[test]
    fn the_peer_plan_the_limiter_and_the_configuration_path_follow_their_knobs() {
        let cfg = with(&[
            ("WARREN_BOLTHOLE_CONF", "/etc/warren/gateway.conf"),
            ("WARREN_BOLTHOLE_PEER_SUBNET", "192.168.9.0/24"),
            ("WARREN_BOLTHOLE_PEER_SUBNET_V6", "fd00:dead:beef::/64"),
            ("WARREN_BOLTHOLE_HANDSHAKE_RATE", "40"),
        ])
        .expect("every knob is usable");
        assert_eq!(cfg.conf_path, PathBuf::from("/etc/warren/gateway.conf"));
        assert_eq!(cfg.handshake_rate, 40);
        assert_eq!(
            cfg.plan.address_for(2).expect("the first peer"),
            (
                "192.168.9.2".parse().expect("a literal address"),
                "fd00:dead:beef::2".parse().expect("a literal address")
            )
        );
        assert!(with(&[("WARREN_BOLTHOLE_PEER_SUBNET_V6", "fd00:dead:beef::")]).is_err());
        assert!(with(&[("WARREN_BOLTHOLE_HANDSHAKE_RATE", "many")]).is_err());
    }

    /// The subcommands that only write files never touch the network, so the
    /// recovery phrase is required where a tunnel is dialed and nowhere else.
    #[test]
    fn the_recovery_phrase_is_required_only_where_a_tunnel_is_dialed() {
        let cfg = load(
            env(&[("WARREN_BOLTHOLE_STATE_DIR", "/tmp/bolthole-state")]),
            no_file,
            no_mode,
            false,
        )
        .expect("provisioning needs no account");
        assert!(cfg.require_mnemonic().is_err());
        assert!(with(&[]).unwrap().require_mnemonic().is_ok());
    }

    #[test]
    fn debug_never_prints_the_mnemonic() {
        let cfg = with(&[("WARREN_MNEMONIC", "correct horse battery staple")]).unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("correct horse"), "mnemonic leaked: {debug}");
        assert!(debug.contains("<redacted>"));
    }

    #[cfg(unix)]
    #[test]
    fn a_service_running_as_root_keeps_its_state_under_var_lib() {
        let cfg = load(env(&[("WARREN_MNEMONIC", "m")]), no_file, no_mode, true)
            .expect("root needs no HOME");
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/warren-bolthole"));
        assert_eq!(
            cfg.clients_dir(),
            PathBuf::from("/var/lib/warren-bolthole/clients")
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn a_user_gateway_follows_the_xdg_state_home() {
        let cfg = load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("XDG_STATE_HOME", "/home/u/.state"),
            ]),
            no_file,
            no_mode,
            false,
        )
        .unwrap();
        assert_eq!(
            cfg.state_dir,
            PathBuf::from("/home/u/.state/warren-bolthole")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_user_gateway_on_macos_lands_in_application_support() {
        let cfg = load(
            env(&[("WARREN_MNEMONIC", "m"), ("HOME", "/Users/u")]),
            no_file,
            no_mode,
            false,
        )
        .unwrap();
        assert_eq!(
            cfg.state_dir,
            PathBuf::from("/Users/u/Library/Application Support/warren-bolthole")
        );
    }

    #[test]
    fn a_health_endpoint_can_be_turned_off_and_the_probe_agrees() {
        let cfg = with(&[("WARREN_HEALTH_LISTEN", "off")]).unwrap();
        assert_eq!(cfg.health_listen, None);
        assert_eq!(healthcheck_target(Some("off".to_owned())).unwrap(), None);
        assert_eq!(
            healthcheck_target(None).unwrap(),
            Some(DEFAULT_HEALTH_LISTEN.parse().unwrap())
        );
    }
}
