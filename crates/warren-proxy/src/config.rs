//! Environment-first configuration.
//!
//! Every knob is an env var so the same binary configures identically under
//! Docker, systemd, launchd or a plain shell. Parsing is pure (the reader is
//! injected), so every rule here is unit-tested without touching the process
//! environment.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

/// Which circuit shape to dial for every candidate exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitKind {
    /// Client to exit directly (the default: lowest latency).
    Single,
    /// Entry relay then exit (the entry never sees payload, the exit never
    /// sees the client address).
    Multi,
}

/// One exit constraint: a country code, optionally narrowed to a city.
/// Compared case-insensitively against the verified directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitFilter {
    /// ISO 3166-1 alpha-2 country code, lowercased at parse time.
    pub country: String,
    /// City name, lowercased at parse time.
    pub city: Option<String>,
}

/// Transport to forward for [`ForwardConfig`].
///
/// One transport per daemon. The exit allocates each proto independently: a
/// NAT-PMP request with no explicit suggestion can never land on a port whose
/// other proto slot is live, so asking for TCP and UDP would map two different
/// public ports, of which the daemon can only ever announce one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardProto {
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
}

/// Tunnel-side port forward: the exit maps a public port and inbound
/// connections are relayed to `target` on the local host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardConfig {
    /// Transport(s) to map.
    pub proto: ForwardProto,
    /// Tunnel-side internal port requested from the exit.
    pub internal_port: u16,
    /// Local socket inbound connections are relayed to.
    pub target: SocketAddr,
    /// Command run (via `sh -c`) each time a public port is granted;
    /// `{{PORT}}` is substituted.
    pub up_command: Option<String>,
    /// Command run when the granted port is replaced or on shutdown.
    pub down_command: Option<String>,
    /// File the granted public port is written to (one decimal line).
    pub status_file: Option<PathBuf>,
}

/// Full daemon configuration, resolved from the environment.
pub struct Config {
    /// The account's BIP39 recovery phrase. Zeroized on drop; never logged.
    pub mnemonic: Zeroizing<String>,
    /// Override for the API base URL (`WARREN_API_URL`); `None` uses the
    /// channel default compiled into the SDK.
    pub api_base: Option<String>,
    /// Override for the relay-list signing key pin
    /// (`WARREN_SERVER_PUBKEY_HEX`); `None` uses the compiled pin.
    pub server_pubkey_hex: Option<String>,
    /// Circuit shape dialed for every candidate.
    pub circuit: CircuitKind,
    /// Exit constraints in priority order; empty means every exit, directory
    /// order.
    pub exit_filters: Vec<ExitFilter>,
    /// SOCKS5 listener address.
    pub socks_listen: SocketAddr,
    /// Optional HTTP CONNECT listener address.
    pub http_listen: Option<SocketAddr>,
    /// DNS resolver queried over the tunnel; `None` uses the exit's gateway
    /// forwarder.
    pub dns_server: Option<Ipv4Addr>,
    /// Local liveness endpoint (`/healthz`, `/state`, `/port`); `None`
    /// disables it.
    pub health_listen: Option<SocketAddr>,
    /// Budget for the tunnel to reach `Connected` at startup. The first-egress
    /// probe that follows carries its own budget, so it is not bounded by this.
    pub connect_timeout: Duration,
    /// Optional tunnel-side port forward.
    pub forward: Option<ForwardConfig>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual impl: the mnemonic must never reach a log through {:?}.
        f.debug_struct("Config")
            .field("mnemonic", &"<redacted>")
            .field("api_base", &self.api_base)
            .field("circuit", &self.circuit)
            .field("exit_filters", &self.exit_filters)
            .field("socks_listen", &self.socks_listen)
            .field("http_listen", &self.http_listen)
            .field("dns_server", &self.dns_server)
            .field("health_listen", &self.health_listen)
            .field("connect_timeout", &self.connect_timeout)
            .field("forward", &self.forward)
            .finish_non_exhaustive()
    }
}

/// Why the environment did not resolve to a runnable [`Config`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Neither `WARREN_MNEMONIC` nor a readable `WARREN_MNEMONIC_FILE` was
    /// provided.
    #[error("no mnemonic: set WARREN_MNEMONIC or WARREN_MNEMONIC_FILE")]
    MissingMnemonic,
    /// A `*_FILE` secret path could not be read.
    #[error("could not read {var} path")]
    UnreadableSecretFile {
        /// The env var holding the path.
        var: &'static str,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A value did not parse as what the variable requires.
    #[error("invalid {var}: expected {expected}")]
    Invalid {
        /// The env var at fault.
        var: &'static str,
        /// What a valid value looks like.
        expected: &'static str,
    },
}

const DEFAULT_SOCKS_LISTEN: &str = "127.0.0.1:1080";
const DEFAULT_HEALTH_LISTEN: &str = "127.0.0.1:9999";
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 90;

/// Resolves the configuration from an env reader and a file reader (both
/// injected for testability; `main` passes `std::env::var` and
/// `std::fs::read_to_string`).
///
/// # Errors
///
/// See [`ConfigError`] variants.
pub fn load(
    get: impl Fn(&str) -> Option<String>,
    read_file: impl Fn(&std::path::Path) -> std::io::Result<String>,
) -> Result<Config, ConfigError> {
    let mnemonic =
        read_secret(&get, &read_file, "WARREN_MNEMONIC")?.ok_or(ConfigError::MissingMnemonic)?;

    let circuit = match get("WARREN_CIRCUIT").as_deref() {
        None | Some("single") => CircuitKind::Single,
        Some("multi") => CircuitKind::Multi,
        Some(_) => {
            return Err(ConfigError::Invalid {
                var: "WARREN_CIRCUIT",
                expected: "single or multi",
            });
        }
    };

    let exit_filters = parse_exit_filters(get("WARREN_EXITS").as_deref().unwrap_or_default())?;

    let socks_listen = parse_addr(
        get("WARREN_SOCKS_LISTEN")
            .as_deref()
            .unwrap_or(DEFAULT_SOCKS_LISTEN),
        "WARREN_SOCKS_LISTEN",
    )?;
    let http_listen = parse_optional_addr(get("WARREN_HTTP_LISTEN"), "WARREN_HTTP_LISTEN")?;
    let health_listen = match get("WARREN_HEALTH_LISTEN") {
        Some(v) if is_off(&v) => None,
        Some(v) => Some(parse_addr(&v, "WARREN_HEALTH_LISTEN")?),
        None => Some(parse_addr(DEFAULT_HEALTH_LISTEN, "WARREN_HEALTH_LISTEN")?),
    };

    let dns_server = match get("WARREN_DNS_SERVER") {
        None => None,
        Some(v) if is_off(&v) => None,
        Some(v) => Some(v.parse::<Ipv4Addr>().map_err(|_| ConfigError::Invalid {
            var: "WARREN_DNS_SERVER",
            expected: "an IPv4 address",
        })?),
    };

    let connect_timeout = match get("WARREN_CONNECT_TIMEOUT") {
        None => Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
        Some(v) => Duration::from_secs(v.parse::<u64>().map_err(|_| ConfigError::Invalid {
            var: "WARREN_CONNECT_TIMEOUT",
            expected: "a number of seconds",
        })?),
    };

    let forward = parse_forward(&get, &read_file)?;

    Ok(Config {
        mnemonic,
        api_base: get("WARREN_API_URL").filter(|v| !v.is_empty()),
        server_pubkey_hex: get(warren_sdk::product::SERVER_PUBKEY_HEX_ENV)
            .filter(|v| !v.is_empty()),
        circuit,
        exit_filters,
        socks_listen,
        http_listen,
        dns_server,
        health_listen,
        connect_timeout,
        forward,
    })
}

/// Reads `<var>` or `<var>_FILE` (the file wins), trimming trailing
/// whitespace. Returns `Ok(None)` when neither is set.
fn read_secret(
    get: &impl Fn(&str) -> Option<String>,
    read_file: &impl Fn(&std::path::Path) -> std::io::Result<String>,
    var: &'static str,
) -> Result<Option<Zeroizing<String>>, ConfigError> {
    let file_var = format!("{var}_FILE");
    if let Some(path) = get(&file_var).filter(|p| !p.is_empty()) {
        let raw = read_file(std::path::Path::new(&path)).map_err(|source| {
            ConfigError::UnreadableSecretFile {
                var: "WARREN_MNEMONIC_FILE",
                source,
            }
        })?;
        // Both buffers zeroize on drop; `raw` drops here, right after the trim.
        let raw = Zeroizing::new(raw);
        let trimmed = Zeroizing::new(raw.trim().to_owned());
        return Ok(Some(trimmed));
    }
    Ok(get(var)
        .filter(|v| !v.trim().is_empty())
        .map(|v| Zeroizing::new(v.trim().to_owned())))
}

fn is_off(v: &str) -> bool {
    v.is_empty() || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none")
}

fn parse_addr(v: &str, var: &'static str) -> Result<SocketAddr, ConfigError> {
    v.parse().map_err(|_| ConfigError::Invalid {
        var,
        expected: "an ip:port socket address",
    })
}

fn parse_optional_addr(
    v: Option<String>,
    var: &'static str,
) -> Result<Option<SocketAddr>, ConfigError> {
    match v {
        None => Ok(None),
        Some(v) if is_off(&v) => Ok(None),
        Some(v) => Ok(Some(parse_addr(&v, var)?)),
    }
}

/// Parses `WARREN_EXITS`: a comma-separated priority list of `cc` or
/// `cc/city` items (e.g. `fi, se/stockholm`). Lowercased; empty items are
/// rejected rather than silently dropped.
fn parse_exit_filters(raw: &str) -> Result<Vec<ExitFilter>, ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|item| {
            let item = item.trim().to_ascii_lowercase();
            let (country, city) = match item.split_once('/') {
                Some((c, city)) => (c.trim(), Some(city.trim())),
                None => (item.as_str(), None),
            };
            if country.len() != 2 || !country.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err(ConfigError::Invalid {
                    var: "WARREN_EXITS",
                    expected: "comma-separated cc or cc/city items (ISO 3166-1 alpha-2)",
                });
            }
            if matches!(city, Some(c) if c.is_empty()) {
                return Err(ConfigError::Invalid {
                    var: "WARREN_EXITS",
                    expected: "a city after the slash (cc/city)",
                });
            }
            Ok(ExitFilter {
                country: country.to_owned(),
                city: city.map(str::to_owned),
            })
        })
        .collect()
}

fn parse_forward(
    get: &impl Fn(&str) -> Option<String>,
    _read_file: &impl Fn(&std::path::Path) -> std::io::Result<String>,
) -> Result<Option<ForwardConfig>, ConfigError> {
    let Some(port_raw) = get("WARREN_PORT_FORWARD_INTERNAL_PORT").filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let internal_port =
        port_raw
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or(ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_INTERNAL_PORT",
                expected: "a port number (1-65535)",
            })?;

    let proto = match get("WARREN_PORT_FORWARD_PROTOCOL").as_deref() {
        None | Some("tcp") => ForwardProto::Tcp,
        Some("udp") => ForwardProto::Udp,
        // `both` is refused rather than silently half-honoured: it maps two
        // public ports (see [`ForwardProto`]), burns two of the account's five
        // forward slots, and only the TCP one could be published.
        Some(_) => {
            return Err(ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_PROTOCOL",
                expected: "tcp or udp (one transport: the exit maps each proto on its own public port)",
            });
        }
    };

    let target = match get("WARREN_PORT_FORWARD_TARGET") {
        None => SocketAddr::from(([127, 0, 0, 1], internal_port)),
        Some(v) => parse_addr(&v, "WARREN_PORT_FORWARD_TARGET")?,
    };

    Ok(Some(ForwardConfig {
        proto,
        internal_port,
        target,
        up_command: get("WARREN_PORT_FORWARD_UP_COMMAND").filter(|v| !v.is_empty()),
        down_command: get("WARREN_PORT_FORWARD_DOWN_COMMAND").filter(|v| !v.is_empty()),
        status_file: get("WARREN_PORT_FORWARD_STATUS_FILE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from),
    }))
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

    fn no_file(_: &std::path::Path) -> std::io::Result<String> {
        Err(std::io::Error::other("no file expected in this test"))
    }

    #[test]
    fn minimal_env_yields_defaults() {
        let cfg = load(env(&[("WARREN_MNEMONIC", "abandon ability able")]), no_file)
            .expect("minimal env must load");
        assert_eq!(cfg.socks_listen, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(cfg.http_listen, None);
        assert_eq!(
            cfg.health_listen,
            Some("127.0.0.1:9999".parse().unwrap()),
            "health endpoint defaults on: orchestrators need it"
        );
        assert_eq!(cfg.circuit, CircuitKind::Single);
        assert!(cfg.exit_filters.is_empty());
        assert_eq!(cfg.connect_timeout, Duration::from_secs(90));
        assert!(cfg.forward.is_none());
        assert_eq!(cfg.mnemonic.as_str(), "abandon ability able");
    }

    #[test]
    fn missing_mnemonic_is_refused() {
        let err = load(env(&[]), no_file).expect_err("no mnemonic must refuse");
        assert!(matches!(err, ConfigError::MissingMnemonic));
    }

    #[test]
    fn mnemonic_file_wins_over_env_and_is_trimmed() {
        let read = |_: &std::path::Path| Ok("from file\n".to_owned());
        let cfg = load(
            env(&[
                ("WARREN_MNEMONIC", "from env"),
                ("WARREN_MNEMONIC_FILE", "/run/secrets/m"),
            ]),
            read,
        )
        .expect("file secret must load");
        assert_eq!(cfg.mnemonic.as_str(), "from file");
    }

    #[test]
    fn unreadable_mnemonic_file_is_an_error_not_a_fallback() {
        let err = load(
            env(&[
                ("WARREN_MNEMONIC", "from env"),
                ("WARREN_MNEMONIC_FILE", "/nope"),
            ]),
            no_file,
        )
        .expect_err("a broken secret file must never fall back to the env");
        assert!(matches!(err, ConfigError::UnreadableSecretFile { .. }));
    }

    #[test]
    fn debug_never_prints_the_mnemonic() {
        let cfg = load(
            env(&[("WARREN_MNEMONIC", "correct horse battery staple")]),
            no_file,
        )
        .unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("correct horse"), "mnemonic leaked: {debug}");
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn exit_filters_parse_priority_list() {
        let cfg = load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("WARREN_EXITS", "FI, se/Stockholm"),
            ]),
            no_file,
        )
        .unwrap();
        assert_eq!(
            cfg.exit_filters,
            vec![
                ExitFilter {
                    country: "fi".into(),
                    city: None
                },
                ExitFilter {
                    country: "se".into(),
                    city: Some("stockholm".into())
                },
            ]
        );
    }

    #[test]
    fn bad_exit_filter_is_refused() {
        let err = load(
            env(&[("WARREN_MNEMONIC", "m"), ("WARREN_EXITS", "finland")]),
            no_file,
        )
        .expect_err("a non alpha-2 code must refuse");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "WARREN_EXITS",
                ..
            }
        ));
    }

    #[test]
    fn listeners_parse_and_health_can_be_disabled() {
        let cfg = load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("WARREN_SOCKS_LISTEN", "0.0.0.0:1080"),
                ("WARREN_HTTP_LISTEN", "0.0.0.0:8888"),
                ("WARREN_HEALTH_LISTEN", "off"),
            ]),
            no_file,
        )
        .unwrap();
        assert_eq!(cfg.socks_listen, "0.0.0.0:1080".parse().unwrap());
        assert_eq!(cfg.http_listen, Some("0.0.0.0:8888".parse().unwrap()));
        assert_eq!(cfg.health_listen, None);
    }

    #[test]
    fn invalid_listen_addr_is_refused() {
        let err = load(
            env(&[("WARREN_MNEMONIC", "m"), ("WARREN_SOCKS_LISTEN", "1080")]),
            no_file,
        )
        .expect_err("a bare port must refuse (ambiguous bind)");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "WARREN_SOCKS_LISTEN",
                ..
            }
        ));
    }

    #[test]
    fn circuit_multi_and_invalid() {
        let cfg = load(
            env(&[("WARREN_MNEMONIC", "m"), ("WARREN_CIRCUIT", "multi")]),
            no_file,
        )
        .unwrap();
        assert_eq!(cfg.circuit, CircuitKind::Multi);
        let err = load(
            env(&[("WARREN_MNEMONIC", "m"), ("WARREN_CIRCUIT", "double")]),
            no_file,
        )
        .expect_err("unknown circuit kind must refuse");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "WARREN_CIRCUIT",
                ..
            }
        ));
    }

    #[test]
    fn forward_defaults_target_to_loopback_internal_port() {
        let cfg = load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("WARREN_PORT_FORWARD_INTERNAL_PORT", "56881"),
                ("WARREN_PORT_FORWARD_UP_COMMAND", "echo {{PORT}}"),
            ]),
            no_file,
        )
        .unwrap();
        let fwd = cfg.forward.expect("forward must be enabled");
        assert_eq!(fwd.internal_port, 56881);
        assert_eq!(fwd.proto, ForwardProto::Tcp);
        assert_eq!(fwd.target, "127.0.0.1:56881".parse().unwrap());
        assert_eq!(fwd.up_command.as_deref(), Some("echo {{PORT}}"));
        assert_eq!(fwd.down_command, None);
    }

    #[test]
    fn forward_port_zero_is_refused() {
        let err = load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("WARREN_PORT_FORWARD_INTERNAL_PORT", "0"),
            ]),
            no_file,
        )
        .expect_err("port 0 must refuse");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_INTERNAL_PORT",
                ..
            }
        ));
    }

    #[test]
    fn forward_protocol_parses_all_variants() {
        for (raw, want) in [("tcp", ForwardProto::Tcp), ("udp", ForwardProto::Udp)] {
            let cfg = load(
                env(&[
                    ("WARREN_MNEMONIC", "m"),
                    ("WARREN_PORT_FORWARD_INTERNAL_PORT", "56881"),
                    ("WARREN_PORT_FORWARD_PROTOCOL", raw),
                ]),
                no_file,
            )
            .unwrap();
            assert_eq!(cfg.forward.unwrap().proto, want, "protocol {raw}");
        }
    }

    /// The exit maps TCP and UDP on two different public ports, and the daemon
    /// publishes one port, so accepting `both` announced a port whose UDP half
    /// was dead. Refused at parse time rather than half-honoured.
    #[test]
    fn forward_protocol_both_is_refused() {
        let err = load(
            env(&[
                ("WARREN_MNEMONIC", "m"),
                ("WARREN_PORT_FORWARD_INTERNAL_PORT", "56881"),
                ("WARREN_PORT_FORWARD_PROTOCOL", "both"),
            ]),
            no_file,
        )
        .expect_err("both maps two public ports and must not be accepted");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_PROTOCOL",
                ..
            }
        ));
    }
}
