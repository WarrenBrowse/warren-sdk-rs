//! `warren-burrow`: the Warren local gateway. See the crate docs
//! ([`warren_burrow`]) and `README.md` for the env contract.

use std::path::Path;
use std::process::ExitCode;

use ip_network::IpNetwork;
use warren_burrow::config::GatewayEnv;
use warren_burrow::provision::{self, InitOptions, PeerOptions};

/// What the command line asked for.
enum Command {
    Run,
    Init(InitOptions),
    AddPeer(String, PeerOptions),
    RemovePeer(String),
    Show(String, bool),
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
            Ok(())
        }),
        Command::RemovePeer(label) => provisioning(|| {
            provision::remove_peer(&env, &label)?;
            println!("warren-burrow: {label} revoked; reload or restart the daemon to apply it");
            Ok(())
        }),
        Command::Show(label, qr) => provisioning(|| show(&env, &label, qr)),
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
        "run" => Ok(Command::Run),
        "healthcheck" => Ok(Command::Healthcheck),
        "help" | "--help" | "-h" => Ok(Command::Help),
        "init" => Ok(Command::Init(parse_init(rest)?)),
        "add-peer" => {
            let label = rest.next().ok_or("add-peer needs a label")?.to_owned();
            Ok(Command::AddPeer(label, parse_peer_options(rest)?))
        }
        "remove-peer" => {
            let label = rest.next().ok_or("remove-peer needs a label")?.to_owned();
            Ok(Command::RemovePeer(label))
        }
        "show" => {
            let mut label = None;
            let mut qr = false;
            for arg in rest {
                match arg {
                    "--qr" => qr = true,
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
