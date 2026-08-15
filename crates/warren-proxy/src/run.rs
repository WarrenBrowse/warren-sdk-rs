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
use warren_sdk::socks_egress::{FIRST_EGRESS_RECHECK, FIRST_EGRESS_VERIFY, verify_first_egress};
use warren_sdk::transport::FatalCause;
use warren_sdk::{
    Circuit, ConnectionState, SupervisedForwardedPort, SupervisedProxyHandle, WarrenClient,
};

use crate::config::{CircuitKind, Config, ForwardConfig, ForwardProto};
use crate::{health, hooks, select};

fn log(msg: &str) {
    println!("warren-proxy: {msg}");
}

/// The startup account line. The SS58 address is the paying account's
/// identifier and this daemon's stdout is the container log (shipped to
/// whatever aggregator the host runs), so only the short prefix the app's UI
/// shows ever reaches it, per the shared no-log rule.
fn account_line(address: &str) -> String {
    let prefix: String = address.chars().take(8).collect();
    format!("account {prefix}...")
}

/// Runs the daemon until a signal or a terminal failure; returns the process
/// exit code (0 clean shutdown, 1 startup failure, 2 a terminal control-plane
/// refusal). There is no code for "every candidate exit failed": a transient
/// failure never stops the supervisor, it keeps rotating and retrying.
///
/// # Errors
///
/// Startup errors (API unreachable, no matching exit, bind failure) are
/// returned; after the datapath is up, failures translate into the exit code.
pub async fn run(config: Config) -> anyhow::Result<i32> {
    let identity = WarrenIdentity::from_mnemonic(config.mnemonic.trim())
        .context("the recovery phrase must be 12 or 24 BIP39 words")?;
    log(&account_line(&identity.address()));

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

    tokio::spawn(track_egress_across_epochs(
        handle.watch_state(),
        Arc::clone(&egress_verified),
        move || async move {
            verify_first_egress(probe_addr, FIRST_EGRESS_RECHECK)
                .await
                .is_ok()
        },
    ));

    let forward: Option<SupervisedForwardedPort> = config
        .forward
        .as_ref()
        .map(|fwd| start_forward(&handle, fwd, port_tx));

    let code = match supervise(&handle).await {
        Stop::Signal => {
            log("signal received, shutting down");
            // The live port comes from the watch channel the forward watcher
            // publishes, never from the status file: the file is optional, and
            // reading it there skipped the down hook for everyone who had not
            // configured one.
            retire_forward_state(&ShellHooks, config.forward.as_ref(), *port_rx.borrow()).await;
            // Release the lease at the exit rather than let it lapse: it runs
            // for two hours, so a restart on another internal port or protocol
            // would leave the public port stranded that long.
            if let Some(forward) = forward {
                if forward.shutdown().await {
                    log("forwarded port released at the exit");
                } else {
                    log("the forwarded port release timed out, its lease will lapse");
                }
            }
            0
        }
        Stop::Fatal(cause) => {
            eprintln!("warren-proxy: {}", fatal_line(cause));
            2
        }
    };
    handle.shutdown();
    Ok(code)
}

/// Keeps `/healthz` honest across reconnects.
///
/// The first-egress proof belongs to the epoch it was measured on, so leaving
/// `Connected` clears it and the next `Connected` has to prove egress again
/// before the endpoint reports 200. Without this an orchestrator routes traffic
/// into a rebuilt tunnel nobody has probed, on the strength of the previous
/// epoch's result.
async fn track_egress_across_epochs<R, Fut>(
    mut state_rx: watch::Receiver<ConnectionState>,
    egress_verified: Arc<AtomicBool>,
    mut recheck: R,
) where
    R: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    // The receiver arrives having seen the state its creator saw (tokio marks
    // the current version at clone time), so no transition raised before the
    // first poll is lost.
    loop {
        if state_rx.changed().await.is_err() {
            return;
        }
        if *state_rx.borrow_and_update() != ConnectionState::Connected {
            egress_verified.store(false, Ordering::Relaxed);
            continue;
        }
        // Every change that lands on Connected is re-proven, including a
        // republication of a state that never left. A watch channel coalesces,
        // so a short Reconnecting between two polls is invisible here: probing
        // once too often costs three quick connects, while trusting a state
        // this task cannot distinguish would report 200 on an unproven epoch.
        let proven = recheck().await;
        egress_verified.store(proven, Ordering::Relaxed);
        if proven {
            log("egress re-verified for the current epoch");
        } else {
            eprintln!("warren-proxy: egress is not proven on this epoch, staying unhealthy");
        }
    }
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

/// Why the daemon stopped running.
enum Stop {
    /// A signal asked it to stop.
    Signal,
    /// The supervisor stopped healing on a terminal verdict, with the cause it
    /// published (`None` if the state went terminal without one).
    Fatal(Option<FatalCause>),
}

/// Waits for a signal or a terminal supervisor failure.
async fn supervise(handle: &SupervisedProxyHandle) -> Stop {
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
    tokio::select! {
        () = failed => Stop::Fatal(handle.last_fatal()),
        () = wait_for_signal() => Stop::Signal,
    }
}

/// The operator-facing line for a terminal verdict. Carries the cause and no
/// identity material: the account is named nowhere, on any branch.
fn fatal_line(cause: Option<FatalCause>) -> String {
    let detail = match cause {
        Some(FatalCause::NotAuthorized) => {
            "the account is not authorized (no active subscription, or not enrolled at this exit)"
        }
        Some(FatalCause::DeviceLimit) => "the account already holds its maximum device count",
        Some(FatalCause::Banned) => "the account is suspended",
        Some(FatalCause::PolicyRefused) => {
            "the exit applied a policy refusal, with no reason given"
        }
        // `FatalCause` is non-exhaustive: a cause added upstream is still a
        // refusal, and saying so beats printing an opaque debug name.
        Some(_) | None => "no reason was published",
    };
    format!(
        "refused by the control plane: {detail}. Not retrying: no restart and no other exit resolves this"
    )
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

/// Retires the forward's published state at shutdown: the down command for the
/// port that was granted, then the status file, which must not outlive the
/// mapping it names.
async fn retire_forward_state<H: HookSink>(
    sink: &H,
    forward: Option<&ForwardConfig>,
    port: Option<u16>,
) {
    let Some(fwd) = forward else { return };
    if let Some(cmd) = &fwd.down_command
        && let Some(port) = port
    {
        sink.run(cmd, port, "down").await;
    }
    if let Some(path) = &fwd.status_file
        && let Err(err) = hooks::clear_status_file(path).await
    {
        eprintln!("warren-proxy: clearing the port status file failed: {err}");
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
    let Some(port) = current else {
        // The mapping is gone: a stale file would keep naming a dead public
        // port to whoever reads it (the documented sibling-container seam),
        // while `/port` already answers 404.
        if let Some(path) = &fwd.status_file
            && let Err(err) = hooks::clear_status_file(path).await
        {
            eprintln!("warren-proxy: clearing the port status file failed: {err}");
        }
        return;
    };
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
    async fn the_shutdown_down_hook_runs_without_a_status_file() {
        let sink = Recorder::default();
        let fwd = forward(None);

        retire_forward_state(&sink, Some(&fwd), Some(49587)).await;

        assert_eq!(
            sink.calls(),
            vec!["down:49587:down {{PORT}}".to_owned()],
            "the down command must fire on the granted port even with no status file configured"
        );
    }

    /// The file names a live mapping, and the mapping is released as the daemon
    /// stops, so a file left behind would announce a port to the next reader of
    /// a directory the daemon no longer owns.
    #[tokio::test]
    async fn shutdown_runs_the_down_hook_then_clears_the_status_file() {
        let status = scratch("shutdown-status");
        hooks::write_status_file(&status, 49587)
            .await
            .expect("a granted port was published");
        let sink = Recorder::default();
        let fwd = forward(Some(status.clone()));

        retire_forward_state(&sink, Some(&fwd), Some(49587)).await;

        assert_eq!(sink.calls(), vec!["down:49587:down {{PORT}}".to_owned()]);
        assert!(
            !status.exists(),
            "the status file must not survive the daemon that published it"
        );
    }

    #[tokio::test]
    async fn the_shutdown_hook_is_skipped_when_no_port_was_granted() {
        let sink = Recorder::default();
        let fwd = forward(None);

        retire_forward_state(&sink, Some(&fwd), None).await;

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

    /// The file is the documented integration seam (a sibling container reads
    /// it), so leaving it behind makes that consumer announce a port the exit
    /// no longer maps, while `/port` already answers 404.
    #[tokio::test]
    async fn a_withdrawn_grant_clears_the_status_file_after_the_down_hook() {
        let status = scratch("withdrawn-status");
        let sink = Recorder::default();
        let fwd = forward(Some(status.clone()));

        apply_port_change(&sink, &fwd, None, Some(58364)).await;
        apply_port_change(&sink, &fwd, Some(58364), None).await;

        assert!(
            !status.exists(),
            "the status file must not survive the mapping it names"
        );
        assert_eq!(
            sink.calls(),
            vec![
                "up:58364:up {{PORT}}".to_owned(),
                "down:58364:down {{PORT}}".to_owned(),
            ],
            "the down hook still runs, and runs before the file is cleared"
        );
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

    /// Polls a latch until it reads `want`, so the assertions do not race the
    /// tracker task. Bounded, so a regression fails instead of hanging.
    async fn wait_for(flag: &AtomicBool, want: bool, what: &str) {
        for _ in 0..200u32 {
            if flag.load(Ordering::Relaxed) == want {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("{what} (still {}) after 1 s", !want);
    }

    /// The egress proof belongs to the epoch it was measured on. Reporting 200
    /// again on the strength of the previous epoch's probe is what makes an
    /// orchestrator route traffic into a tunnel nobody has proven.
    #[tokio::test]
    async fn a_reconnect_clears_the_egress_proof_and_reproves_it() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let task = tokio::spawn({
            let verified = Arc::clone(&verified);
            let probes = Arc::clone(&probes);
            track_egress_across_epochs(state_rx, verified, move || {
                let probes = Arc::clone(&probes);
                async move {
                    probes.fetch_add(1, Ordering::Relaxed);
                    true
                }
            })
        });

        state_tx.send(ConnectionState::Reconnecting).unwrap();
        wait_for(
            &verified,
            false,
            "leaving Connected must clear the egress proof",
        )
        .await;
        assert_eq!(
            probes.load(Ordering::Relaxed),
            0,
            "nothing to probe while the tunnel is down"
        );

        state_tx.send(ConnectionState::Connected).unwrap();
        wait_for(
            &verified,
            true,
            "a re-proven epoch must report healthy again",
        )
        .await;
        assert_eq!(
            probes.load(Ordering::Relaxed),
            1,
            "the new epoch must be proven by its own probe"
        );
        task.abort();
    }

    /// A watch channel coalesces, so a `Reconnecting` raised and cleared
    /// between two polls of this task is invisible to it. Re-proving on every
    /// change that lands on `Connected` is what keeps that invisible epoch from
    /// being reported healthy on the previous epoch's evidence.
    #[tokio::test]
    async fn a_republished_connected_state_is_re_proven_rather_than_trusted() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let task = tokio::spawn({
            let verified = Arc::clone(&verified);
            let probes = Arc::clone(&probes);
            track_egress_across_epochs(state_rx, verified, move || {
                let probes = Arc::clone(&probes);
                async move {
                    probes.fetch_add(1, Ordering::Relaxed);
                    true
                }
            })
        });

        state_tx.send(ConnectionState::Connected).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(
            probes.load(Ordering::Relaxed),
            1,
            "a state change this task cannot interpret is re-proven, not trusted"
        );
        assert!(
            verified.load(Ordering::Relaxed),
            "and the fresh probe passed, so the endpoint stays green"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_reconnected_epoch_that_does_not_egress_stays_unhealthy() {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));

        let task = tokio::spawn({
            let verified = Arc::clone(&verified);
            track_egress_across_epochs(state_rx, verified, || async { false })
        });

        state_tx.send(ConnectionState::Reconnecting).unwrap();
        state_tx.send(ConnectionState::Connected).unwrap();
        wait_for(
            &verified,
            false,
            "an epoch whose egress probe fails must not report healthy",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !verified.load(Ordering::Relaxed),
            "a failed recheck must leave the latch clear"
        );
        task.abort();
    }

    /// Exit 2 can only ever mean a terminal verdict: every transient failure
    /// keeps healing with backoff and never reaches `Failed`. The operator
    /// needs to read which refusal it was, because no restart fixes any of
    /// them.
    #[test]
    fn the_terminal_verdict_names_the_refusal_it_stopped_on() {
        let lines = [
            (FatalCause::NotAuthorized, "not authorized"),
            (FatalCause::DeviceLimit, "device"),
            (FatalCause::Banned, "suspended"),
            (FatalCause::PolicyRefused, "policy"),
        ];
        let mut seen: Vec<String> = Vec::new();
        for (cause, needle) in lines {
            let line = fatal_line(Some(cause));
            assert!(
                line.contains(needle),
                "{cause:?} must be readable in the message, got: {line}"
            );
            assert!(
                !line.contains("every candidate"),
                "a fatal verdict is not an exhausted candidate list: {line}"
            );
            assert!(
                !seen.contains(&line),
                "each cause needs its own line: {line}"
            );
            seen.push(line);
        }
        assert!(
            fatal_line(None).contains("refused"),
            "without a published cause the refusal is still terminal"
        );
    }

    /// The SS58 address is the paying account's identifier and this daemon's
    /// stdout is the container log, so the startup line carries the prefix only.
    #[test]
    fn the_startup_account_line_carries_only_the_address_prefix() {
        let address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let line = account_line(address);
        assert_eq!(line, "account 5GrwvaEF...");
        assert!(
            !line.contains(address),
            "the full account address must never reach a log: {line}"
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
