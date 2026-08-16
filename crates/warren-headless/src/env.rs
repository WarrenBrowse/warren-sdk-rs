//! Environment-first configuration primitives.
//!
//! Every knob is an env var so the same binary configures identically under
//! Docker, systemd, launchd or a plain shell. Parsing is pure (the readers are
//! injected), so every rule here is unit-tested without touching the process
//! environment.

use std::net::SocketAddr;
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

/// Why the environment did not resolve to a runnable configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Neither `WARREN_MNEMONIC` nor a readable `WARREN_MNEMONIC_FILE` was
    /// provided.
    #[error("no mnemonic: set WARREN_MNEMONIC or WARREN_MNEMONIC_FILE")]
    MissingMnemonic,
    /// A `*_FILE` secret path could not be read.
    #[error("could not read {var}_FILE path")]
    UnreadableSecretFile {
        /// The env var whose `_FILE` variant is at fault.
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

/// Reads `<var>` or `<var>_FILE` (the file wins), trimming trailing
/// whitespace. Returns `Ok(None)` when neither is set.
///
/// # Errors
///
/// [`ConfigError::UnreadableSecretFile`] when the `_FILE` path is set and
/// cannot be read. A broken secret file never falls back to the plain
/// variable: that would run the daemon under whatever stale value the
/// environment still carried.
pub fn read_secret(
    get: &impl Fn(&str) -> Option<String>,
    read_file: &impl Fn(&std::path::Path) -> std::io::Result<String>,
    var: &'static str,
) -> Result<Option<Zeroizing<String>>, ConfigError> {
    let file_var = format!("{var}_FILE");
    if let Some(path) = get(&file_var).filter(|p| !p.is_empty()) {
        let raw = read_file(std::path::Path::new(&path))
            .map_err(|source| ConfigError::UnreadableSecretFile { var, source })?;
        // Both buffers zeroize on drop; `raw` drops here, right after the trim.
        let raw = Zeroizing::new(raw);
        let trimmed = Zeroizing::new(raw.trim().to_owned());
        return Ok(Some(trimmed));
    }
    Ok(get(var)
        .filter(|v| !v.trim().is_empty())
        .map(|v| Zeroizing::new(v.trim().to_owned())))
}

/// Whether a value spells "this knob is deliberately disabled" (empty, `off`
/// or `none`, in any case).
#[must_use]
pub fn is_off(v: &str) -> bool {
    v.is_empty() || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none")
}

/// Parses an `ip:port` socket address.
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming `var`.
pub fn parse_addr(v: &str, var: &'static str) -> Result<SocketAddr, ConfigError> {
    v.parse().map_err(|_| ConfigError::Invalid {
        var,
        expected: "an ip:port socket address",
    })
}

/// Parses an optional `ip:port`, where an off spelling means "not bound".
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming `var`.
pub fn parse_optional_addr(
    v: Option<String>,
    var: &'static str,
) -> Result<Option<SocketAddr>, ConfigError> {
    match v {
        None => Ok(None),
        Some(v) if is_off(&v) => Ok(None),
        Some(v) => Ok(Some(parse_addr(&v, var)?)),
    }
}

/// Parses `WARREN_CIRCUIT`.
///
/// # Errors
///
/// [`ConfigError::Invalid`] for anything but `single` or `multi`.
pub fn parse_circuit(raw: Option<&str>) -> Result<CircuitKind, ConfigError> {
    match raw {
        None | Some("single") => Ok(CircuitKind::Single),
        Some("multi") => Ok(CircuitKind::Multi),
        Some(_) => Err(ConfigError::Invalid {
            var: "WARREN_CIRCUIT",
            expected: "single or multi",
        }),
    }
}

/// Parses `WARREN_EXITS`: a comma-separated priority list of `cc` or
/// `cc/city` items (e.g. `fi, se/stockholm`). Lowercased; empty items are
/// rejected rather than silently dropped.
///
/// # Errors
///
/// [`ConfigError::Invalid`] for a code that is not alpha-2, or an empty city.
pub fn parse_exit_filters(raw: &str) -> Result<Vec<ExitFilter>, ConfigError> {
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

/// Parses `WARREN_HEALTH_LISTEN` against the daemon's own default, where an
/// off spelling disables the endpoint.
///
/// # Errors
///
/// [`ConfigError::Invalid`] for a value that is neither an off spelling nor an
/// `ip:port`.
pub fn parse_health_listen(
    raw: Option<String>,
    default: &str,
) -> Result<Option<SocketAddr>, ConfigError> {
    match raw {
        Some(v) if is_off(&v) => Ok(None),
        Some(v) => Ok(Some(parse_addr(&v, "WARREN_HEALTH_LISTEN")?)),
        None => Ok(Some(parse_addr(default, "WARREN_HEALTH_LISTEN")?)),
    }
}

/// What the `healthcheck` subcommand should probe, resolved from the raw
/// `WARREN_HEALTH_LISTEN` value: `None` when the endpoint is disabled, so the
/// probe reports the container healthy instead of hunting an address nobody
/// bound. Shares [`is_off`] and the default with [`parse_health_listen`],
/// which is the point: the two must never disagree.
///
/// # Errors
///
/// [`ConfigError::Invalid`] when the value is neither an off spelling nor an
/// `ip:port`.
pub fn healthcheck_target(
    raw: Option<String>,
    default: &str,
) -> Result<Option<SocketAddr>, ConfigError> {
    parse_health_listen(raw, default)
}

/// Parses `WARREN_CONNECT_TIMEOUT` (a number of seconds) against a default.
///
/// # Errors
///
/// [`ConfigError::Invalid`] for anything that is not a number of seconds.
pub fn parse_connect_timeout(raw: Option<String>, default: u64) -> Result<Duration, ConfigError> {
    match raw {
        None => Ok(Duration::from_secs(default)),
        Some(v) => Ok(Duration::from_secs(v.parse::<u64>().map_err(|_| {
            ConfigError::Invalid {
                var: "WARREN_CONNECT_TIMEOUT",
                expected: "a number of seconds",
            }
        })?)),
    }
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
    fn a_secret_file_wins_over_the_plain_variable_and_is_trimmed() {
        let read = |_: &std::path::Path| Ok("from file\n".to_owned());
        let secret = read_secret(
            &env(&[
                ("WARREN_MNEMONIC", "from env"),
                ("WARREN_MNEMONIC_FILE", "/run/secrets/m"),
            ]),
            &read,
            "WARREN_MNEMONIC",
        )
        .expect("the file secret loads")
        .expect("a secret was set");
        assert_eq!(secret.as_str(), "from file");
    }

    /// Falling back to the environment would run the daemon under whatever
    /// stale value was still exported, which is the opposite of what mounting
    /// a secret file asks for.
    #[test]
    fn an_unreadable_secret_file_is_an_error_not_a_fallback() {
        let err = read_secret(
            &env(&[
                ("WARREN_MNEMONIC", "from env"),
                ("WARREN_MNEMONIC_FILE", "/nope"),
            ]),
            &no_file,
            "WARREN_MNEMONIC",
        )
        .expect_err("a broken secret file must refuse");
        assert!(matches!(
            err,
            ConfigError::UnreadableSecretFile {
                var: "WARREN_MNEMONIC",
                ..
            }
        ));
        assert_eq!(err.to_string(), "could not read WARREN_MNEMONIC_FILE path");
    }

    #[test]
    fn an_unset_and_a_blank_secret_are_both_absent() {
        for pairs in [vec![], vec![("WARREN_MNEMONIC", "   ")]] {
            let secret =
                read_secret(&env(&pairs), &no_file, "WARREN_MNEMONIC").expect("not an error");
            assert!(secret.is_none(), "{pairs:?} carries no secret");
        }
    }

    #[test]
    fn off_spellings_are_recognised_in_any_case() {
        for raw in ["", "off", "OFF", "none", "NONE", "None"] {
            assert!(is_off(raw), "{raw:?} disables a knob");
        }
        for raw in ["0", "127.0.0.1:9999", "no"] {
            assert!(!is_off(raw), "{raw:?} is a value, not an off spelling");
        }
    }

    #[test]
    fn a_bare_port_is_refused_because_the_bind_would_be_ambiguous() {
        let err = parse_addr("1080", "WARREN_SOCKS_LISTEN").expect_err("a bare port must refuse");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "WARREN_SOCKS_LISTEN",
                ..
            }
        ));
        assert_eq!(
            parse_addr("127.0.0.1:1080", "WARREN_SOCKS_LISTEN").unwrap(),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn an_optional_address_is_absent_when_unset_or_off() {
        assert_eq!(parse_optional_addr(None, "X").unwrap(), None);
        assert_eq!(parse_optional_addr(Some("off".into()), "X").unwrap(), None);
        assert_eq!(
            parse_optional_addr(Some("0.0.0.0:8888".into()), "X").unwrap(),
            Some("0.0.0.0:8888".parse().unwrap())
        );
    }

    #[test]
    fn circuit_kinds_parse_and_an_unknown_one_refuses() {
        assert_eq!(parse_circuit(None).unwrap(), CircuitKind::Single);
        assert_eq!(parse_circuit(Some("single")).unwrap(), CircuitKind::Single);
        assert_eq!(parse_circuit(Some("multi")).unwrap(), CircuitKind::Multi);
        assert!(matches!(
            parse_circuit(Some("double")),
            Err(ConfigError::Invalid {
                var: "WARREN_CIRCUIT",
                ..
            })
        ));
    }

    #[test]
    fn exit_filters_parse_a_priority_list_case_insensitively() {
        assert_eq!(
            parse_exit_filters("FI, se/Stockholm").unwrap(),
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
        assert!(parse_exit_filters("  ").unwrap().is_empty());
    }

    #[test]
    fn a_filter_that_is_not_alpha_2_or_has_no_city_refuses() {
        for raw in ["finland", "fi/", "f", "fi,,se"] {
            assert!(
                matches!(
                    parse_exit_filters(raw),
                    Err(ConfigError::Invalid {
                        var: "WARREN_EXITS",
                        ..
                    })
                ),
                "{raw:?} must refuse rather than be silently dropped"
            );
        }
    }

    /// The daemon and the `healthcheck` subcommand read the same variable, so
    /// a spelling that disables the endpoint for one and not the other marks a
    /// container unhealthy for as long as it runs.
    #[test]
    fn the_healthcheck_target_agrees_with_the_daemon_on_every_off_spelling() {
        for raw in ["", "off", "OFF", "none", "NONE"] {
            assert_eq!(
                parse_health_listen(Some(raw.to_owned()), "127.0.0.1:9999").unwrap(),
                None
            );
            assert_eq!(
                healthcheck_target(Some(raw.to_owned()), "127.0.0.1:9999").unwrap(),
                None,
                "{raw:?} disables the endpoint, so there is nothing to probe"
            );
        }
    }

    #[test]
    fn the_health_default_is_the_callers_and_junk_refuses() {
        assert_eq!(
            parse_health_listen(None, "127.0.0.1:9998").unwrap(),
            Some("127.0.0.1:9998".parse().unwrap()),
            "each daemon brings its own default port"
        );
        assert!(matches!(
            healthcheck_target(Some("9999".to_owned()), "127.0.0.1:9999"),
            Err(ConfigError::Invalid {
                var: "WARREN_HEALTH_LISTEN",
                ..
            })
        ));
    }

    #[test]
    fn the_connect_timeout_falls_back_to_the_default_and_refuses_junk() {
        assert_eq!(
            parse_connect_timeout(None, 90).unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_connect_timeout(Some("5".into()), 90).unwrap(),
            Duration::from_secs(5)
        );
        assert!(matches!(
            parse_connect_timeout(Some("soon".into()), 90),
            Err(ConfigError::Invalid {
                var: "WARREN_CONNECT_TIMEOUT",
                ..
            })
        ));
    }
}
