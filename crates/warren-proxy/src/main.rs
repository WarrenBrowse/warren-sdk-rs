//! `warren-proxy`: headless Warren proxy daemon. See the crate docs
//! ([`warren_proxy`]) and `README.md` for the env contract.

use std::process::ExitCode;

const USAGE: &str = "\
warren-proxy: a headless Warren endpoint serving SOCKS5 and HTTP CONNECT over a supervised tunnel.

    warren-proxy                 serve (the default)
    warren-proxy healthcheck     probe the running daemon's /healthz
    warren-proxy --version       print the build this binary came from

Every knob is an environment variable; see README.md next to this crate.
";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Serve,
    Healthcheck,
    Help,
    Version,
}

/// What `--version` prints, and the first line the daemon logs. The release
/// pipeline refuses a tag whose version differs from this crate's manifest, so
/// this string names the release the binary came from.
fn version_line() -> String {
    format!("warren-proxy {}", env!("CARGO_PKG_VERSION"))
}

fn parse_command(args: &[String]) -> Result<Command, String> {
    let mut rest = args.iter().map(String::as_str);
    let Some(first) = rest.next() else {
        return Ok(Command::Serve);
    };
    let command = match first {
        "healthcheck" => Command::Healthcheck,
        "help" | "--help" | "-h" => Command::Help,
        "version" | "--version" | "-V" => Command::Version,
        other => {
            return Err(format!(
                "{other} is not a command; every knob is an environment variable, see --help"
            ));
        }
    };
    match rest.next() {
        Some(extra) => Err(format!("{first} takes no argument, got {extra}")),
        None => Ok(command),
    }
}

/// `warren-proxy healthcheck`: probe the running daemon's `/healthz` and
/// exit 0/1, so a container HEALTHCHECK needs no shell and no wget.
fn healthcheck() -> ExitCode {
    let addr = match warren_proxy::config::healthcheck_target(
        std::env::var("WARREN_HEALTH_LISTEN").ok(),
    ) {
        // The operator turned the endpoint off, so there is nothing to assert
        // and reporting unhealthy would be reporting on their own choice.
        Ok(None) => {
            println!("warren-proxy: health endpoint disabled, nothing to probe");
            return ExitCode::SUCCESS;
        }
        Ok(Some(addr)) => addr,
        Err(err) => {
            eprintln!("warren-proxy: {err}");
            return ExitCode::from(1);
        }
    };
    match warren_headless::health::probe_healthz(addr) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("warren-proxy: unhealthy");
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("warren-proxy: health endpoint unreachable: {err}");
            ExitCode::from(1)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_command(&args) {
        Ok(Command::Serve) => {}
        Ok(Command::Healthcheck) => return healthcheck(),
        Ok(Command::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Command::Version) => {
            println!("{}", version_line());
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("warren-proxy: {message}");
            return ExitCode::from(1);
        }
    }
    // Before the recovery phrase is read: a core dump taken after it is in
    // memory carries it, and no zeroize-on-drop helps against that.
    if !warren_headless::disable_core_dumps() {
        eprintln!("warren-proxy: could not disable core dumps on this host");
    }
    let config =
        match warren_proxy::config::load(|k| std::env::var(k).ok(), |p| std::fs::read_to_string(p))
        {
            Ok(config) => config,
            Err(err) => {
                eprintln!("warren-proxy: {err}");
                return ExitCode::from(1);
            }
        };
    match warren_proxy::run::run(config).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("warren-proxy: {err:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        let owned: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        parse_command(&owned)
    }

    #[test]
    fn no_argument_serves_and_the_two_words_it_takes_are_recognised() {
        assert_eq!(parse(&[]).expect("the default"), Command::Serve);
        assert_eq!(
            parse(&["healthcheck"]).expect("a probe"),
            Command::Healthcheck
        );
        assert_eq!(parse(&["--help"]).expect("usage"), Command::Help);
        assert_eq!(parse(&["--version"]).expect("long flag"), Command::Version);
        assert_eq!(parse(&["-V"]).expect("short flag"), Command::Version);
    }

    /// The daemon reads its whole configuration from the environment, so an
    /// argument it does not know is a misunderstanding: starting the tunnel
    /// anyway would silently ignore what the operator asked for.
    #[test]
    fn an_argument_the_daemon_does_not_take_is_refused() {
        let err = parse(&["--socks-port=1080"]).expect_err("an unknown flag");
        assert!(err.contains("--socks-port=1080"), "{err}");
        let err = parse(&["healthcheck", "now"]).expect_err("a trailing word");
        assert!(err.contains("now"), "{err}");
    }

    #[test]
    fn the_version_line_names_the_binary_then_a_semver_triple() {
        let line = version_line();
        let (name, version) = line.split_once(' ').expect("a name then a version");
        assert_eq!(name, "warren-proxy");
        assert_eq!(version.split('.').count(), 3, "{version} is not a triple");
        assert!(
            version.split('.').all(|part| !part.is_empty()),
            "{version} has an empty component"
        );
    }
}
