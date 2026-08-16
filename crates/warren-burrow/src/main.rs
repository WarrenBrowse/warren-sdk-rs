//! `warren-burrow`: the Warren local gateway. See the crate docs
//! ([`warren_burrow`]) and `README.md` for the env contract.

use std::path::Path;
use std::process::ExitCode;

use ip_network::IpNetwork;
use warren_burrow::admin;
use warren_burrow::config::GatewayEnv;
use warren_burrow::provision::{self, InitOptions, PeerOptions};

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
}

const USAGE: &str = "\
warren-burrow: a local gateway that carries stock WireGuard-protocol clients through a Warren exit.

    warren-burrow [run]                      serve (the default; first run provisions)
    warren-burrow init [OPTIONS]             generate the gateway and its peers
    warren-burrow add-peer LABEL [OPTIONS]   add one peer and write its files
    warren-burrow remove-peer LABEL          revoke one peer
    warren-burrow show LABEL [--qr]          print a peer's client configuration
    warren-burrow reload                     apply the configuration file to the running daemon
    warren-burrow reset-peer LABEL           rebuild one peer's session (a device whose clock jumped)
    warren-burrow healthcheck                probe the running daemon's /healthz

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
            eprintln!("warren-burrow: {message}");
            return ExitCode::from(1);
        }
    };
    if matches!(command, Command::Help) {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if matches!(command, Command::Healthcheck) {
        return healthcheck();
    }
    // Before the recovery phrase and the peers' key material are in memory: a
    // core dump carries all of it, and zeroize-on-drop does not help against a
    // dump taken while the process is alive.
    if !warren_headless::disable_core_dumps() {
        eprintln!("warren-burrow: could not disable core dumps on this host");
    }
    let env = match load_env() {
        Ok(env) => env,
        Err(message) => {
            eprintln!("warren-burrow: {message}");
            return ExitCode::from(1);
        }
    };
    match command {
        Command::Run => run(env),
        Command::Init(options) => provisioning(|| {
            let out = provision::init(&env, &options)?;
            println!(
                "warren-burrow: {} peer(s) written to {}",
                out.written.len(),
                out.clients_dir.display()
            );
            for label in &out.written {
                println!("  warren-burrow show {}", label.as_str());
            }
            Ok(())
        }),
        Command::AddPeer(label, options) => provisioning(|| {
            let out = provision::add_peer(&env, &label, &options)?;
            println!(
                "warren-burrow: peer written to {}",
                out.clients_dir.display()
            );
            println!("  warren-burrow show {label}");
            apply_to_daemon(&env);
            Ok(())
        }),
        Command::RemovePeer(label) => provisioning(|| {
            provision::remove_peer(&env, &label)?;
            println!("warren-burrow: {label} revoked");
            apply_to_daemon(&env);
            Ok(())
        }),
        Command::Show(label, qr) => provisioning(|| show(&env, &label, qr)),
        Command::Reload => admin_call(&env, "/admin/reload"),
        Command::ResetPeer(label) => admin_call(&env, &format!("/admin/reset-peer/{label}")),
        Command::Healthcheck | Command::Help => unreachable!("handled above"),
    }
}

/// `warren-burrow run`, on its own runtime so the provisioning subcommands
/// start no reactor at all.
fn run(env: GatewayEnv) -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("warren-burrow: could not start the runtime: {err}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(warren_burrow::run::run(env)) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("warren-burrow: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn provisioning(body: impl FnOnce() -> Result<(), provision::ProvisionError>) -> ExitCode {
    match body() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("warren-burrow: {err}");
            ExitCode::from(1)
        }
    }
}

fn show(env: &GatewayEnv, label: &str, qr: bool) -> Result<(), provision::ProvisionError> {
    if qr {
        #[cfg(feature = "qr")]
        {
            println!(
                "warren-burrow: this QR carries the peer's private key and preshared key. \
                 Show it on a trusted screen only."
            );
            print!("{}", *provision::show_qr(env, label)?);
            return Ok(());
        }
        #[cfg(not(feature = "qr"))]
        {
            eprintln!(
                "warren-burrow: this build carries no QR renderer (build with --features qr)"
            );
        }
    }
    print!("{}", *provision::show(env, label)?);
    Ok(())
}

/// Calls one admin route on the running daemon and reports what it answered.
fn admin_call(env: &GatewayEnv, path: &str) -> ExitCode {
    match admin_request(env, path) {
        Ok(message) => {
            print!("warren-burrow: {message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("warren-burrow: {message}");
            ExitCode::from(1)
        }
    }
}

/// Tells the running daemon to apply the file that was just edited, and says
/// what happened either way: an operator who edited a credential needs to know
/// whether it is live.
fn apply_to_daemon(env: &GatewayEnv) {
    match admin_request(env, "/admin/reload") {
        Ok(message) => print!("warren-burrow: {message}"),
        Err(message) => eprintln!("warren-burrow: {message}"),
    }
}

/// One admin request, with the message an operator should read.
fn admin_request(env: &GatewayEnv, path: &str) -> Result<String, String> {
    let Some(addr) = health_target()? else {
        return Err(format!(
            "the health endpoint is off, so no admin route is served: {}",
            RELOAD_WITHOUT_ENDPOINT
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
const RELOAD_WITHOUT_ENDPOINT: &str = "send SIGHUP to the daemon instead";
#[cfg(not(unix))]
const RELOAD_WITHOUT_ENDPOINT: &str = "restart the daemon to apply it";

fn health_target() -> Result<Option<std::net::SocketAddr>, String> {
    warren_burrow::config::healthcheck_target(std::env::var("WARREN_HEALTH_LISTEN").ok())
        .map_err(|err| err.to_string())
}

/// `warren-burrow healthcheck`: probe the running daemon and exit 0/1, so a
/// container HEALTHCHECK needs no shell and no wget.
fn healthcheck() -> ExitCode {
    let addr =
        match warren_burrow::config::healthcheck_target(std::env::var("WARREN_HEALTH_LISTEN").ok())
        {
            // The operator turned the endpoint off, so there is nothing to assert
            // and reporting unhealthy would be reporting on their own choice.
            Ok(None) => {
                println!("warren-burrow: health endpoint disabled, nothing to probe");
                return ExitCode::SUCCESS;
            }
            Ok(Some(addr)) => addr,
            Err(err) => {
                eprintln!("warren-burrow: {err}");
                return ExitCode::from(1);
            }
        };
    match warren_headless::health::probe_healthz(addr) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("warren-burrow: unhealthy");
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("warren-burrow: health endpoint unreachable: {err}");
            ExitCode::from(1)
        }
    }
}

fn load_env() -> Result<GatewayEnv, String> {
    warren_burrow::config::load(
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
