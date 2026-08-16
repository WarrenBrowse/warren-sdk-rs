//! `warren-bolthole`: the Warren local gateway. The env contract is the table in
//! `README.md`, next to this crate's `Cargo.toml`.

use std::path::Path;
use std::process::ExitCode;

use ip_network::IpNetwork;
use warren_bolthole::admin;
use warren_bolthole::config::GatewayEnv;
use warren_bolthole::provision::{self, InitOptions, PeerOptions};

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run,
    Init(InitOptions),
    AddPeer(String, PeerOptions),
    RemovePeer(String),
    Show(String, bool),
    Reload,
    ResetPeer(String),
    Healthcheck,
    Help,
    Version,
}

const USAGE: &str = "\
warren-bolthole: a local gateway that carries stock WireGuard-protocol clients through a Warren exit.

    warren-bolthole [run]                      serve (the default; first run provisions)
    warren-bolthole init [OPTIONS]             generate the gateway and its peers
    warren-bolthole add-peer LABEL [OPTIONS]   add one peer and write its files
    warren-bolthole remove-peer LABEL          revoke one peer
    warren-bolthole show LABEL [--qr]          print a peer's client configuration
    warren-bolthole reload                     apply the configuration file to the running daemon
    warren-bolthole reset-peer LABEL           rebuild one peer's session (a device whose clock jumped)
    warren-bolthole healthcheck                probe the running daemon's /healthz
    warren-bolthole --version                  print the build this binary came from

Options for init and add-peer:
    --peers N            how many peers init generates (init only)
    --label NAME         name a peer, repeatable (init only)
    --lan-exclude CIDR   keep a prefix outside the tunnel, repeatable (that prefix is unprotected)
    --no-v6              write v4-only lines, for a host whose kernel has IPv6 disabled
    --force              move an existing configuration aside instead of refusing (init only)

Every other knob is an environment variable; see the README.
\"WireGuard\" is a registered trademark of Jason A. Donenfeld.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("warren-bolthole: {message}");
            return ExitCode::from(1);
        }
    };
    if matches!(command, Command::Help) {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if matches!(command, Command::Version) {
        println!("{}", version_line());
        return ExitCode::SUCCESS;
    }
    if matches!(command, Command::Healthcheck) {
        return healthcheck();
    }
    // Before the recovery phrase and the peers' key material are in memory: a
    // core dump carries all of it, and zeroize-on-drop does not help against a
    // dump taken while the process is alive.
    if !warren_headless::disable_core_dumps() {
        eprintln!("warren-bolthole: could not disable core dumps on this host");
    }
    let env = match load_env() {
        Ok(env) => env,
        Err(message) => {
            eprintln!("warren-bolthole: {message}");
            return ExitCode::from(1);
        }
    };
    match command {
        Command::Run => run(env),
        Command::Init(options) => provisioning(|| {
            let out = provision::init(&env, &options)?;
            println!(
                "warren-bolthole: {} peer(s) written to {}",
                out.written.len(),
                out.clients_dir.display()
            );
            for label in &out.written {
                println!("  warren-bolthole show {}", label.as_str());
            }
            apply_to_daemon(&env);
            Ok(())
        }),
        Command::AddPeer(label, options) => provisioning(|| {
            let out = provision::add_peer(&env, &label, &options)?;
            println!(
                "warren-bolthole: peer written to {}",
                out.clients_dir.display()
            );
            println!("  warren-bolthole show {label}");
            apply_to_daemon(&env);
            Ok(())
        }),
        Command::RemovePeer(label) => provisioning(|| {
            provision::remove_peer(&env, &label)?;
            println!("warren-bolthole: {label} revoked");
            if !apply_to_daemon(&env) {
                // A revoked device keeps its session until a daemon applies
                // the file, so the operator has to be told when none did.
                println!(
                    "warren-bolthole: a running daemon keeps that peer's session until it \
                          reloads ({RELOAD_HINT}) or restarts"
                );
            }
            Ok(())
        }),
        Command::Show(label, qr) => provisioning(|| show(&env, &label, qr)),
        Command::Reload => admin_call(&env, "/admin/reload"),
        Command::ResetPeer(label) => admin_call(&env, &format!("/admin/reset-peer/{label}")),
        Command::Healthcheck | Command::Help | Command::Version => {
            unreachable!("handled above")
        }
    }
}

/// `warren-bolthole run`, on its own runtime so the provisioning subcommands
/// start no reactor at all.
fn run(env: GatewayEnv) -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("warren-bolthole: could not start the runtime: {err}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(warren_bolthole::run::run(env)) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("warren-bolthole: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn provisioning(body: impl FnOnce() -> Result<(), provision::ProvisionError>) -> ExitCode {
    match body() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("warren-bolthole: {err}");
            ExitCode::from(1)
        }
    }
}

fn show(env: &GatewayEnv, label: &str, qr: bool) -> Result<(), provision::ProvisionError> {
    if qr {
        println!(
            "warren-bolthole: this QR carries the peer's private key and preshared key. \
             Show it on a trusted screen only."
        );
        print!("{}", *provision::show_qr(env, label)?);
        return Ok(());
    }
    print!("{}", *provision::show(env, label)?);
    Ok(())
}

/// Calls one admin route on the running daemon and reports what it answered.
fn admin_call(env: &GatewayEnv, path: &str) -> ExitCode {
    match admin_request(env, path) {
        Ok(message) => {
            print!("warren-bolthole: {message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("warren-bolthole: {message}");
            ExitCode::from(1)
        }
    }
}

/// Tells the running daemon to apply the file that was just edited, and says
/// what happened: an operator who edited a credential needs to know whether it
/// is live. Answers whether a daemon took it.
fn apply_to_daemon(env: &GatewayEnv) -> bool {
    // No token means no daemon has ever run against this state directory,
    // which is the ordinary case right after a first `init`: there is nothing
    // to tell and nothing to reload.
    if admin::read_token(env).is_err() {
        return false;
    }
    match admin_request(env, "/admin/reload") {
        Ok(message) => {
            print!("warren-bolthole: {message}");
            true
        }
        Err(message) => {
            eprintln!("warren-bolthole: {message}");
            false
        }
    }
}

/// One admin request, with the message an operator should read.
fn admin_request(env: &GatewayEnv, path: &str) -> Result<String, String> {
    let Some(addr) = health_target()? else {
        return Err(format!(
            "the health endpoint is off, so no admin route is served: reload with {RELOAD_HINT}"
        ));
    };
    let token = admin::read_token(env).map_err(|err| err.to_string())?;
    let reply = admin::post(addr, path, &token)
        .map_err(|_| "no daemon answered on the health endpoint".to_owned())?;
    let body = reply.body.trim().to_owned();
    if reply.status == 200 {
        Ok(format!("{body}\n"))
    } else {
        Err(format!("the daemon refused it ({}): {body}", reply.status))
    }
}

/// What an operator does when no admin route can be reached.
#[cfg(unix)]
const RELOAD_HINT: &str = "SIGHUP";
#[cfg(not(unix))]
const RELOAD_HINT: &str = "a restart, the only way on this platform";

fn health_target() -> Result<Option<std::net::SocketAddr>, String> {
    warren_bolthole::config::healthcheck_target(std::env::var("WARREN_HEALTH_LISTEN").ok())
        .map_err(|err| err.to_string())
}

/// `warren-bolthole healthcheck`: probe the running daemon and exit 0/1, so a
/// container HEALTHCHECK needs no shell and no wget.
fn healthcheck() -> ExitCode {
    let addr = match warren_bolthole::config::healthcheck_target(
        std::env::var("WARREN_HEALTH_LISTEN").ok(),
    ) {
        // The operator turned the endpoint off, so there is nothing to assert
        // and reporting unhealthy would be reporting on their own choice.
        Ok(None) => {
            println!("warren-bolthole: health endpoint disabled, nothing to probe");
            return ExitCode::SUCCESS;
        }
        Ok(Some(addr)) => addr,
        Err(err) => {
            eprintln!("warren-bolthole: {err}");
            return ExitCode::from(1);
        }
    };
    match warren_headless::health::probe_healthz(addr) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("warren-bolthole: unhealthy");
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("warren-bolthole: health endpoint unreachable: {err}");
            ExitCode::from(1)
        }
    }
}

fn load_env() -> Result<GatewayEnv, String> {
    warren_bolthole::config::load(
        |k| std::env::var(k).ok(),
        |p: &Path| std::fs::read_to_string(p),
        file_mode,
        warren_headless::is_root(),
    )
    .map_err(|err| err.to_string())
}

/// The unix mode of a file that exists, so the 0600 rule can be checked
/// without the config module touching the filesystem.
fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).ok().map(|m| m.mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Parses the command line. Everything else is an environment variable, which
/// is what makes one container image configure identically everywhere.
/// What `--version` prints, and the first line the daemon logs. The release
/// pipeline refuses a tag whose version differs from this crate's manifest, so
/// this string names the release the binary came from.
fn version_line() -> String {
    format!("warren-bolthole {}", env!("CARGO_PKG_VERSION"))
}

fn parse_command(args: &[String]) -> Result<Command, String> {
    let mut rest = args.iter().map(String::as_str);
    let Some(first) = rest.next() else {
        return Ok(Command::Run);
    };
    match first {
        "run" => match rest.next() {
            // The daemon takes its whole configuration from the environment,
            // so an argument here is a misunderstanding worth naming rather
            // than a flag to ignore.
            Some(extra) => Err(format!("run takes no argument, got {extra}")),
            None => Ok(Command::Run),
        },
        "healthcheck" => Ok(Command::Healthcheck),
        "reload" => match rest.next() {
            Some(extra) => Err(format!("reload takes no argument, got {extra}")),
            None => Ok(Command::Reload),
        },
        "reset-peer" => {
            let label = rest.next().ok_or("reset-peer needs a label")?.to_owned();
            match rest.next() {
                Some(extra) => Err(format!("reset-peer takes one label, got {extra}")),
                None => Ok(Command::ResetPeer(label)),
            }
        }
        "help" | "--help" | "-h" => Ok(Command::Help),
        "version" | "--version" | "-V" => Ok(Command::Version),
        "init" => Ok(Command::Init(parse_init(rest)?)),
        "add-peer" => {
            let label = rest.next().ok_or("add-peer needs a label")?.to_owned();
            Ok(Command::AddPeer(label, parse_peer_options(rest)?))
        }
        "remove-peer" => {
            let label = rest.next().ok_or("remove-peer needs a label")?.to_owned();
            match rest.next() {
                Some(extra) => Err(format!("remove-peer takes one label, got {extra}")),
                None => Ok(Command::RemovePeer(label)),
            }
        }
        "show" => {
            let mut label = None;
            let mut qr = false;
            for arg in rest {
                match arg {
                    "--qr" => qr = true,
                    other if label.is_some() => {
                        return Err(format!("show takes one label, got {other}"));
                    }
                    other => label = Some(other.to_owned()),
                }
            }
            Ok(Command::Show(label.ok_or("show needs a label")?, qr))
        }
        other if other.starts_with('-') => Err(format!("unknown option {other}")),
        other => Err(format!("unknown subcommand {other}")),
    }
}

fn parse_init<'a>(args: impl Iterator<Item = &'a str>) -> Result<InitOptions, String> {
    let mut options = InitOptions::default();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg {
            "--peers" => {
                let raw = args.next().ok_or("--peers needs a number")?;
                options.peers = Some(raw.parse().map_err(|_| "--peers needs a number")?);
            }
            "--label" => options
                .labels
                .push(args.next().ok_or("--label needs a name")?.to_owned()),
            "--lan-exclude" => options.peer.lan_exclude.push(parse_cidr(&mut args)?),
            "--no-v6" => options.peer.no_v6 = true,
            "--force" => options.force = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(options)
}

fn parse_peer_options<'a>(args: impl Iterator<Item = &'a str>) -> Result<PeerOptions, String> {
    let mut options = PeerOptions::default();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg {
            "--lan-exclude" => options.lan_exclude.push(parse_cidr(&mut args)?),
            "--no-v6" => options.no_v6 = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(options)
}

fn parse_cidr<'a>(args: &mut impl Iterator<Item = &'a str>) -> Result<IpNetwork, String> {
    let raw = args.next().ok_or("--lan-exclude needs a CIDR prefix")?;
    raw.parse()
        .map_err(|_| format!("{raw} is not a CIDR prefix"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        let owned: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        parse_command(&owned)
    }

    /// A binary handed out as a release asset has to name its own build: the
    /// version an operator reports is the only link between a running gateway
    /// and the release that produced it.
    #[test]
    fn the_version_is_asked_for_by_flag_or_by_subcommand() {
        assert_eq!(parse(&["--version"]).expect("long flag"), Command::Version);
        assert_eq!(parse(&["-V"]).expect("short flag"), Command::Version);
        assert_eq!(parse(&["version"]).expect("subcommand"), Command::Version);
    }

    #[test]
    fn the_version_line_names_the_binary_then_a_semver_triple() {
        let line = version_line();
        let (name, version) = line.split_once(' ').expect("a name then a version");
        assert_eq!(name, "warren-bolthole");
        assert_eq!(version.split('.').count(), 3, "{version} is not a triple");
        assert!(
            version.split('.').all(|part| !part.is_empty()),
            "{version} has an empty component"
        );
    }

    #[test]
    fn no_argument_serves_and_the_write_subcommands_name_their_target() {
        assert_eq!(parse(&[]).expect("the default"), Command::Run);
        assert_eq!(parse(&["run"]).expect("explicit"), Command::Run);
        assert_eq!(parse(&["reload"]).expect("a reload"), Command::Reload);
        assert_eq!(
            parse(&["reset-peer", "phone"]).expect("a reset"),
            Command::ResetPeer("phone".to_owned())
        );
        assert_eq!(
            parse(&["show", "phone", "--qr"]).expect("a show"),
            Command::Show("phone".to_owned(), true)
        );
    }

    /// An argument a subcommand does not take is a misunderstanding: the
    /// daemon reads its whole configuration from the environment, so silently
    /// ignoring one would run something other than what was asked.
    #[test]
    fn an_argument_a_subcommand_does_not_take_is_refused() {
        for args in [
            vec!["run", "--peers", "3"],
            vec!["reload", "now"],
            vec!["reset-peer", "phone", "again"],
            vec!["remove-peer", "phone", "too"],
            vec!["show", "phone", "tv"],
            vec!["init", "--nope"],
            vec!["add-peer", "phone", "--nope"],
            vec!["fly"],
            vec!["--nope"],
        ] {
            let err = parse(&args).expect_err("must name the argument at fault");
            assert!(args.iter().any(|arg| err.contains(arg)), "{args:?}: {err}");
        }
        assert!(parse(&["reset-peer"]).is_err(), "a label is required");
        assert!(parse(&["show", "--qr"]).is_err(), "a label is required");
    }
}
