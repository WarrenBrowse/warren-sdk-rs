//! Daemon orchestration: build the client, pick candidates, run the
//! supervised failover datapath, publish health, forward ports, and exit
//! cleanly on signals.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use tokio::sync::watch;
use warren_sdk::discovery::VerifiedExit;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{MapProto, ProxyConfig};
use warren_sdk::socks_egress::{FIRST_EGRESS_VERIFY, verify_first_egress};
use warren_sdk::{
    Circuit, ConnectionState, SupervisedForwardedPort, SupervisedProxyHandle, WarrenClient,
};

use crate::config::{CircuitKind, Config, ForwardConfig, ForwardProto};
use crate::{health, hooks, select};

fn log(msg: &str) {
    println!("warren-proxy: {msg}");
}

/// Runs the daemon until a signal or a terminal failure; returns the process
/// exit code (0 clean shutdown, 1 startup failure, 2 the supervisor gave up).
///
/// # Errors
///
/// Startup errors (API unreachable, no matching exit, bind failure) are
/// returned; after the datapath is up, failures translate into the exit code.
pub async fn run(config: Config) -> anyhow::Result<i32> {
    let identity = WarrenIdentity::from_mnemonic(config.mnemonic.trim())
        .context("the recovery phrase must be 12 or 24 BIP39 words")?;
    log(&format!("account: {}", identity.address()));

    let mut builder = WarrenClient::builder()
        .identity(identity)
        .server_pubkey_pin(
            config
                .server_pubkey_hex
                .as_deref()
                .unwrap_or(warren_sdk::product::SERVER_PUBKEY_HEX),
        );
    if let Some(base) = &config.api_base {
        builder = builder.api_base(base.clone());
    }
    let client = builder.build().context("client construction failed")?;

    let candidates = candidate_circuits(&client, &config).await?;
    log(&format!(
        "{} candidate exit(s), circuit {:?}",
        candidates.len(),
        config.circuit
    ));

    let proxy_cfg = ProxyConfig {
        socks5: config.socks_listen,
        http: config.http_listen,
        dns_server: config.dns_server,
    };
    let handle = client
        .start_proxy_supervised_failover(&candidates, &proxy_cfg)
        .await
        .context("starting the supervised datapath failed")?;
    log(&format!("SOCKS5 listening on {}", handle.local_addr()));
    if let Some(http) = handle.http_addr() {
        log(&format!("HTTP CONNECT listening on {http}"));
    }

    let egress_verified = Arc::new(AtomicBool::new(false));
    let (port_tx, port_rx) = watch::channel(None::<u16>);

    if let Some(listen) = config.health_listen {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding the health endpoint on {listen}"))?;
        log(&format!("health endpoint on http://{listen}/healthz"));
        let view = health::HealthView {
            state_rx: handle.watch_state(),
            egress_verified: Arc::clone(&egress_verified),
            port_rx: port_rx.clone(),
        };
        tokio::spawn(health::serve(listener, view));
    }

    wait_until_connected(&handle, config.connect_timeout)
        .await
        .context("the tunnel never reached Connected")?;

    let probe_addr = probe_address(handle.local_addr());
    verify_first_egress(probe_addr, FIRST_EGRESS_VERIFY)
        .await
        .map_err(|e| anyhow::anyhow!("first egress verification failed: {e:?}"))?;
    egress_verified.store(true, Ordering::Relaxed);
    log("tunnel up, egress verified");

    let _forward: Option<SupervisedForwardedPort> = config
        .forward
        .as_ref()
        .map(|fwd| start_forward(&handle, fwd, port_tx));

    let code = supervise(&handle, &config, &port_rx).await;
    handle.shutdown();
    Ok(code)
}

/// Fetches both signed views, cross-checks them, applies the user's filters.
async fn candidate_circuits(
    client: &warren_sdk::DefaultClient,
    config: &Config,
) -> anyhow::Result<Vec<Circuit>> {
    let selector = client
        .fetch_exits()
        .await
        .context("fetching the signed relay list failed")?;
    let directory = client
        .fetch_multihop_directory()
        .await
        .context("fetching the multihop directory failed")?;

    // Trust the intersection only: an exit present in the directory but
    // absent from the pinned relay list (or the reverse) is not dialed.
    let cross_checked: Vec<VerifiedExit> = directory
        .into_iter()
        .filter(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .collect();

    let ordered = select::order_exits(
        cross_checked,
        &config.exit_filters,
        |e| e.country.clone(),
        |e| e.city.clone(),
    );
    anyhow::ensure!(
        !ordered.is_empty(),
        "no exit matches WARREN_EXITS (or the directory and relay list do not intersect)"
    );
    for e in &ordered {
        log(&format!("  candidate: {} / {}", e.country, e.city));
    }
    Ok(ordered
        .into_iter()
        .map(|exit| match config.circuit {
            CircuitKind::Single => Circuit::SingleHop(exit),
            CircuitKind::Multi => Circuit::MultiHop(exit),
        })
        .collect())
}

async fn wait_until_connected(
    handle: &SupervisedProxyHandle,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let mut state_rx = handle.watch_state();
    tokio::time::timeout(timeout, async {
        loop {
            if *state_rx.borrow_and_update() == ConnectionState::Connected {
                return Ok(());
            }
            if state_rx.changed().await.is_err() {
                anyhow::bail!("the supervisor ended before reaching Connected");
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out after {timeout:?}"))?
}

/// The SOCKS listener may be bound on an unspecified address (containers);
/// the local egress probe then dials loopback on the same port.
fn probe_address(bound: SocketAddr) -> SocketAddr {
    if bound.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port())
    } else {
        bound
    }
}

/// Starts the configured forward and the watcher that keeps the status file
/// and the up/down hooks in sync with the granted public port.
///
/// One transport, one mapping, one published port: the exit picks each proto's
/// public port independently, so a second leg would be reachable on a port the
/// daemon never announces (see [`ForwardProto`]).
fn start_forward(
    handle: &SupervisedProxyHandle,
    fwd: &ForwardConfig,
    port_tx: watch::Sender<Option<u16>>,
) -> SupervisedForwardedPort {
    let proto = match fwd.proto {
        ForwardProto::Tcp => MapProto::Tcp,
        ForwardProto::Udp => MapProto::Udp,
    };
    let forward = handle.forward_port(proto, fwd.internal_port, fwd.target);
    log(&format!(
        "port forward requested: internal {} -> {} ({:?})",
        fwd.internal_port, fwd.target, fwd.proto
    ));

    let mut external_rx = forward.watch_external_port();
    let fwd = fwd.clone();
    tokio::spawn(async move {
        let mut last: Option<u16> = None;
        loop {
            let current = *external_rx.borrow_and_update();
            if current != last {
                apply_port_change(&ShellHooks, &fwd, last, current).await;
                // Published after the hooks have run, so a reader that sees a
                // port knows the up command already fired for it.
                let _ = port_tx.send(current);
                last = current;
            }
            if external_rx.changed().await.is_err() {
                return;
            }
        }
    });
    forward
}

/// Waits for a signal or a terminal supervisor failure.
async fn supervise(
    handle: &SupervisedProxyHandle,
    config: &Config,
    port_rx: &watch::Receiver<Option<u16>>,
) -> i32 {
    let mut state_rx = handle.watch_state();
    let failed = async {
        loop {
            if *state_rx.borrow_and_update() == ConnectionState::Failed {
                return;
            }
            if state_rx.changed().await.is_err() {
                return;
            }
        }
    };
    let signals = wait_for_signal();
    tokio::select! {
        () = failed => {
            eprintln!("warren-proxy: the supervisor gave up (every candidate failed)");
            2
        }
        () = signals => {
            log("signal received, shutting down");
            // The live port comes from the watch channel the forward watcher
            // publishes, never from the status file: the file is optional, and
            // reading it there skipped the down hook for everyone who had not
            // configured one.
            run_shutdown_hook(&ShellHooks, config.forward.as_ref(), *port_rx.borrow()).await;
            0
        }
    }
}

/// Where a hook actually runs. Injected so the orchestration below (which hook
/// fires, for which port, in which order) is tested by observing calls rather
/// than by spawning a shell, whose syntax and quoting differ per platform.
pub(crate) trait HookSink {
    async fn run(&self, command: &str, port: u16, label: &str);
}

/// The production sink: the platform's shell, under the hook timeout.
pub(crate) struct ShellHooks;

impl HookSink for ShellHooks {
    async fn run(&self, command: &str, port: u16, label: &str) {
        hooks::run_hook(command, port, label).await;
    }
}

/// Runs the down command once at shutdown, when a port was actually granted.
async fn run_shutdown_hook<H: HookSink>(
    sink: &H,
    forward: Option<&ForwardConfig>,
    port: Option<u16>,
) {
    if let Some(fwd) = forward
        && let Some(cmd) = &fwd.down_command
        && let Some(port) = port
    {
        sink.run(cmd, port, "down").await;
    }
}

/// Reacts to the exit granting a different public port: retire the old one,
/// publish the new one, then announce it. Split out of the watcher loop so the
/// ordering is testable without a live tunnel.
async fn apply_port_change<H: HookSink>(
    sink: &H,
    fwd: &ForwardConfig,
    previous: Option<u16>,
    current: Option<u16>,
) {
    if let Some(old) = previous
        && let Some(cmd) = &fwd.down_command
    {
        sink.run(cmd, old, "down").await;
    }
    let Some(port) = current else { return };
    log(&format!("public port granted: {port}"));
    if let Some(path) = &fwd.status_file
        && let Err(err) = hooks::write_status_file(path, port).await
    {
        eprintln!("warren-proxy: writing the port status file failed: {err}");
    }
    if let Some(cmd) = &fwd.up_command {
        sink.run(cmd, port, "up").await;
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(term) => term,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ForwardProto;

    /// A unique scratch path per test, so the suite stays parallel-safe.
    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("warren-proxy-run-{}-{name}", std::process::id()))
    }

    /// Records what the orchestration asked for, instead of running it. The
    /// shell itself is covered once, in the hooks module.
    #[derive(Default)]
    struct Recorder {
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl Recorder {
        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .expect("test mutex is never poisoned")
                .clone()
        }
    }

    impl HookSink for Recorder {
        async fn run(&self, command: &str, port: u16, label: &str) {
            self.calls
                .lock()
                .expect("test mutex is never poisoned")
                .push(format!("{label}:{port}:{command}"));
        }
    }

    fn forward(status_file: Option<std::path::PathBuf>) -> ForwardConfig {
        ForwardConfig {
            proto: ForwardProto::Tcp,
            internal_port: 56881,
            target: "127.0.0.1:56881".parse().expect("valid literal address"),
            up_command: Some("up {{PORT}}".to_owned()),
            down_command: Some("down {{PORT}}".to_owned()),
            status_file,
        }
    }

    #[tokio::test]
    async fn the_shutdown_hook_runs_without_a_status_file() {
        let sink = Recorder::default();
        let fwd = forward(None);

        run_shutdown_hook(&sink, Some(&fwd), Some(49587)).await;

        assert_eq!(
            sink.calls(),
            vec!["down:49587:down {{PORT}}".to_owned()],
            "the down command must fire on the granted port even with no status file configured"
        );
    }

    #[tokio::test]
    async fn the_shutdown_hook_is_skipped_when_no_port_was_granted() {
        let sink = Recorder::default();
        let fwd = forward(None);

        run_shutdown_hook(&sink, Some(&fwd), None).await;

        assert!(
            sink.calls().is_empty(),
            "with no port granted there is nothing to retire, so the hook must not run"
        );
    }

    #[tokio::test]
    async fn a_new_grant_writes_the_status_file_and_fires_the_up_hook() {
        let status = scratch("grant-status");
        let _ = std::fs::remove_file(&status);
        let sink = Recorder::default();
        let fwd = forward(Some(status.clone()));

        apply_port_change(&sink, &fwd, None, Some(58364)).await;

        assert_eq!(
            std::fs::read_to_string(&status).expect("status file written"),
            "58364\n"
        );
        assert_eq!(sink.calls(), vec!["up:58364:up {{PORT}}".to_owned()]);
        let _ = std::fs::remove_file(&status);
    }

    #[tokio::test]
    async fn a_replaced_port_retires_the_old_one_before_announcing_the_new() {
        let sink = Recorder::default();
        let fwd = forward(None);

        apply_port_change(&sink, &fwd, Some(49587), Some(58364)).await;

        assert_eq!(
            sink.calls(),
            vec![
                "down:49587:down {{PORT}}".to_owned(),
                "up:58364:up {{PORT}}".to_owned(),
            ],
            "the old port must be retired before the new one is announced"
        );
    }

    #[test]
    fn probe_address_maps_unspecified_to_loopback() {
        assert_eq!(
            probe_address("0.0.0.0:1080".parse().unwrap()),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            probe_address("127.0.0.1:1080".parse().unwrap()),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            probe_address("[::]:1080".parse().unwrap()),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap(),
            "v6 unspecified also probes over loopback v4"
        );
    }
}
