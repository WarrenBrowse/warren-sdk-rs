//! Environment-first configuration.
//!
//! Every knob is an env var so the same binary configures identically under
//! Docker, systemd, launchd or a plain shell. Parsing is pure (the reader is
//! injected), so every rule here is unit-tested without touching the process
//! environment. The knobs shared with the other headless daemon live in
//! [`warren_headless::env`]; what is here is the proxy's own.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use warren_headless::env::{
    self, CircuitKind, ConfigError, ExitFilter, is_off, parse_addr, parse_optional_addr,
};
use warren_headless::forward::{ForwardConfig, parse_forward};
use zeroize::Zeroizing;

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

const DEFAULT_SOCKS_LISTEN: &str = "127.0.0.1:1080";
/// The proxy's own health port. The gateway takes 9998, so both daemons run on
/// one host without either operator changing anything.
pub const DEFAULT_HEALTH_LISTEN: &str = "127.0.0.1:9999";
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
    let mnemonic = env::read_secret(&get, &read_file, "WARREN_MNEMONIC")?
        .ok_or(ConfigError::MissingMnemonic)?;

    let circuit = env::parse_circuit(get("WARREN_CIRCUIT").as_deref())?;
    let exit_filters = env::parse_exit_filters(get("WARREN_EXITS").as_deref().unwrap_or_default())?;

    let socks_listen = parse_addr(
        get("WARREN_SOCKS_LISTEN")
            .as_deref()
            .unwrap_or(DEFAULT_SOCKS_LISTEN),
        "WARREN_SOCKS_LISTEN",
    )?;
    let http_listen = parse_optional_addr(get("WARREN_HTTP_LISTEN"), "WARREN_HTTP_LISTEN")?;
    let health_listen =
        env::parse_health_listen(get("WARREN_HEALTH_LISTEN"), DEFAULT_HEALTH_LISTEN)?;

    let dns_server = match get("WARREN_DNS_SERVER") {
        None => None,
        Some(v) if is_off(&v) => None,
        Some(v) => Some(v.parse::<Ipv4Addr>().map_err(|_| ConfigError::Invalid {
            var: "WARREN_DNS_SERVER",
            expected: "an IPv4 address",
        })?),
    };

    let connect_timeout =
        env::parse_connect_timeout(get("WARREN_CONNECT_TIMEOUT"), DEFAULT_CONNECT_TIMEOUT_SECS)?;

    // The proxy relays inbound connections itself, so an unset target means
    // "the same port on this host", which is what a sibling container in the
    // same network namespace expects.
    let forward = parse_forward(&get)?.map(|fwd| ForwardConfig {
        proto: fwd.proto,
        internal_port: fwd.internal_port,
        target: fwd
            .target
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], fwd.internal_port))),
        up_command: fwd.up_command,
        down_command: fwd.down_command,
        status_file: fwd.status_file,
    });

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

/// What the `healthcheck` subcommand should probe, resolved from the raw
/// `WARREN_HEALTH_LISTEN` value: `None` when the endpoint is disabled, so the
/// probe reports the container healthy instead of hunting an address nobody
/// bound.
///
/// # Errors
///
/// [`ConfigError::Invalid`] when the value is neither an off spelling nor an
/// `ip:port`.
pub fn healthcheck_target(raw: Option<String>) -> Result<Option<SocketAddr>, ConfigError> {
    env::healthcheck_target(raw, DEFAULT_HEALTH_LISTEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use warren_headless::forward::ForwardProto;

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

    /// The daemon and the `healthcheck` subcommand read the same variable, so a
    /// spelling that disables the endpoint for one and not the other marks a
    /// container unhealthy for as long as it runs.
    #[test]
    fn the_healthcheck_target_agrees_with_the_daemon_on_every_off_spelling() {
        for raw in ["", "off", "OFF", "none", "NONE"] {
            let cfg = load(
                env(&[("WARREN_MNEMONIC", "m"), ("WARREN_HEALTH_LISTEN", raw)]),
                no_file,
            )
            .expect("an off spelling is valid configuration");
            assert_eq!(cfg.health_listen, None, "{raw:?} must disable the endpoint");
            assert_eq!(
                healthcheck_target(Some(raw.to_owned())).expect("an off spelling is not an error"),
                None,
                "{raw:?} disables the endpoint, so there is nothing to probe"
            );
        }
    }

    #[test]
    fn the_healthcheck_target_follows_the_daemon_default_and_refuses_junk() {
        assert_eq!(
            healthcheck_target(None).expect("the default is a valid address"),
            Some(DEFAULT_HEALTH_LISTEN.parse().unwrap()),
            "with the variable unset the probe must reach where the daemon binds"
        );
        assert_eq!(
            healthcheck_target(Some("127.0.0.1:19999".to_owned())).unwrap(),
            Some("127.0.0.1:19999".parse().unwrap())
        );
        assert!(matches!(
            healthcheck_target(Some("1080".to_owned())),
            Err(ConfigError::Invalid {
                var: "WARREN_HEALTH_LISTEN",
                ..
            })
        ));
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

    /// Two independent mappings land on two different public ports and the
    /// daemon publishes one, so accepting `both` announced a port whose UDP
    /// half was dead. Refused at parse time rather than half-honoured.
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
