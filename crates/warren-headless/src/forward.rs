//! Tunnel-side port forwarding: its environment, its hooks, and the stop paths
//! that retire what it published.

use std::net::SocketAddr;
use std::path::PathBuf;

use warren_sdk::ConnectionState;
use warren_sdk::transport::FatalCause;

use crate::env::ConfigError;
use crate::hooks;
use crate::log::Log;

/// Transport to forward for [`ForwardConfig`].
///
/// One transport per daemon. TCP and UDP would be two independent mappings:
/// the exit allocates each proto on its own public port (a NAT-PMP request
/// with no explicit suggestion can never land on a port whose other proto slot
/// is live), so the daemon could announce only one of the two, and the pair
/// would hold two of the exit's per-client forward slots.
///
/// The engine implements the atomic TCP+UDP pair on ONE public port under ONE
/// entitlement credential, which is what a BitTorrent client wants. The SDK
/// forward path these daemons run on does not carry that pair yet: that is
/// what refuses `both` here, and the protocol imposes no such limit.
///
/// These daemons also present no entitlement credential, so the exit applies
/// its default per-client quota rather than the account's fleet-wide slot
/// count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardProto {
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
}

/// Tunnel-side port forward: the exit maps a public port and inbound
/// connections are relayed to `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardConfig {
    /// Transport to map.
    pub proto: ForwardProto,
    /// Tunnel-side internal port requested from the exit.
    pub internal_port: u16,
    /// Where inbound connections end up: a local socket for the proxy, a peer
    /// endpoint for the gateway.
    pub target: SocketAddr,
    /// Command run (via the platform shell) each time a public port is
    /// granted; `{{PORT}}` is substituted.
    pub up_command: Option<String>,
    /// Command run when the granted port is replaced or on shutdown.
    pub down_command: Option<String>,
    /// File the granted public port is written to (one decimal line).
    pub status_file: Option<PathBuf>,
}

/// The `WARREN_PORT_FORWARD_*` family as the environment spells it, before a
/// daemon applies its own rule to the target (which differs: the proxy relays
/// to a local socket, the gateway to a peer inside its own subnet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardEnv {
    /// Transport to map.
    pub proto: ForwardProto,
    /// Tunnel-side internal port requested from the exit.
    pub internal_port: u16,
    /// `WARREN_PORT_FORWARD_TARGET`, unset when the daemon's default applies.
    pub target: Option<SocketAddr>,
    /// Command run on every grant.
    pub up_command: Option<String>,
    /// Command run when a grant is replaced or withdrawn.
    pub down_command: Option<String>,
    /// File the granted public port is written to.
    pub status_file: Option<PathBuf>,
}

/// Parses the `WARREN_PORT_FORWARD_*` family. `Ok(None)` when no internal port
/// is set, which is how forwarding stays off.
///
/// # Errors
///
/// [`ConfigError::Invalid`] for a port that is not 1-65535, an unknown
/// protocol, or a target that is not an `ip:port`.
pub fn parse_forward(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<ForwardEnv>, ConfigError> {
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
        // independent public ports (see [`ForwardProto`]), takes two of the
        // exit's per-client slots, and only one of them could be published.
        Some(_) => {
            return Err(ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_PROTOCOL",
                expected: "tcp or udp (one transport: the exit maps each proto on its own public port)",
            });
        }
    };

    let target = match get("WARREN_PORT_FORWARD_TARGET") {
        None => None,
        Some(v) => Some(crate::env::parse_addr(&v, "WARREN_PORT_FORWARD_TARGET")?),
    };

    Ok(Some(ForwardEnv {
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

/// Where a hook actually runs. Injected so the orchestration (which hook
/// fires, for which port, in which order) is tested by observing calls rather
/// than by spawning a shell, whose syntax and quoting differ per platform.
pub trait HookSink {
    /// Runs `command` for `port`, labelled `up` or `down`.
    fn run(&self, command: &str, port: u16, label: &str) -> impl std::future::Future<Output = ()>;
}

/// The production sink: the platform's shell, under the hook timeout.
#[derive(Debug, Clone, Copy)]
pub struct ShellHooks(pub Log);

impl HookSink for ShellHooks {
    async fn run(&self, command: &str, port: u16, label: &str) {
        hooks::run_hook(self.0, command, port, label).await;
    }
}

/// Reacts to the exit granting a different public port: retire the old one,
/// publish the new one, then announce it. Split out of the watcher loop so the
/// ordering is testable without a live tunnel.
pub async fn apply_port_change<H: HookSink>(
    log: Log,
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
            log.error(&format!("clearing the port status file failed: {err}"));
        }
        return;
    };
    log.info(&format!("public port granted: {port}"));
    if let Some(path) = &fwd.status_file
        && let Err(err) = hooks::write_status_file(path, port).await
    {
        log.error(&format!("writing the port status file failed: {err}"));
    }
    if let Some(cmd) = &fwd.up_command {
        sink.run(cmd, port, "up").await;
    }
}

/// Retires the forward's published state at shutdown: the down command for the
/// port that was granted, then the status file, which must not outlive the
/// mapping it names.
pub async fn retire_forward_state<H: HookSink>(
    log: Log,
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
        log.error(&format!("clearing the port status file failed: {err}"));
    }
}

/// Why the daemon stopped running.
#[derive(Debug)]
pub enum Stop {
    /// A signal asked it to stop.
    Signal,
    /// The supervisor stopped healing on a terminal verdict, with the cause it
    /// published (`None` if the state went terminal without one).
    Fatal(Option<FatalCause>),
}

/// Waits for a stop signal or a terminal supervisor failure.
pub async fn wait_for_stop(
    mut state_rx: tokio::sync::watch::Receiver<ConnectionState>,
    last_fatal: impl Fn() -> Option<FatalCause>,
) -> Stop {
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
        () = failed => Stop::Fatal(last_fatal()),
        () = crate::signals::wait_for_signal() => Stop::Signal,
    }
}

/// Announces why the daemon is stopping, retires the forward's published
/// state, and returns the process exit code.
///
/// Every stop path retires, because every stop path leaves the same thing
/// behind: a down hook that has not run and a status file naming a public port
/// the exit no longer maps. Leaving the terminal path to the forward watcher
/// raced the process exit and truncated a hook slower than the failing redial.
pub async fn conclude<H: HookSink>(
    log: Log,
    sink: &H,
    stop: Stop,
    forward: Option<&ForwardConfig>,
    port: Option<u16>,
) -> i32 {
    let code = match stop {
        Stop::Signal => {
            log.info("signal received, shutting down");
            0
        }
        Stop::Fatal(cause) => {
            log.error(&fatal_line(cause));
            2
        }
    };
    retire_forward_state(log, sink, forward, port).await;
    code
}

/// The operator-facing line for a terminal verdict. Carries the cause and no
/// identity material: the account is named nowhere, on any branch.
#[must_use]
pub fn fatal_line(cause: Option<FatalCause>) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const LOG: Log = Log("warren-headless-test");

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    /// A unique scratch path per test, so the suite stays parallel-safe.
    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("warren-headless-fwd-{}-{name}", std::process::id()))
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

    #[test]
    fn forwarding_is_off_until_an_internal_port_is_set() {
        assert!(parse_forward(&env(&[])).unwrap().is_none());
        let parsed = parse_forward(&env(&[
            ("WARREN_PORT_FORWARD_INTERNAL_PORT", "56881"),
            ("WARREN_PORT_FORWARD_UP_COMMAND", "echo {{PORT}}"),
        ]))
        .unwrap()
        .expect("an internal port turns forwarding on");
        assert_eq!(parsed.internal_port, 56881);
        assert_eq!(parsed.proto, ForwardProto::Tcp);
        assert_eq!(parsed.target, None, "the daemon applies its own default");
        assert_eq!(parsed.up_command.as_deref(), Some("echo {{PORT}}"));
        assert_eq!(parsed.down_command, None);
    }

    #[test]
    fn forward_port_zero_is_refused() {
        assert!(matches!(
            parse_forward(&env(&[("WARREN_PORT_FORWARD_INTERNAL_PORT", "0")])),
            Err(ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_INTERNAL_PORT",
                ..
            })
        ));
    }

    #[test]
    fn forward_protocol_parses_all_variants() {
        for (raw, want) in [("tcp", ForwardProto::Tcp), ("udp", ForwardProto::Udp)] {
            let parsed = parse_forward(&env(&[
                ("WARREN_PORT_FORWARD_INTERNAL_PORT", "56881"),
                ("WARREN_PORT_FORWARD_PROTOCOL", raw),
            ]))
            .unwrap()
            .unwrap();
            assert_eq!(parsed.proto, want, "protocol {raw}");
        }
    }

    /// Two independent mappings land on two different public ports and the
    /// daemon publishes one, so accepting `both` announced a port whose UDP
    /// half was dead. Refused at parse time rather than half-honoured.
    #[test]
    fn forward_protocol_both_is_refused() {
        assert!(matches!(
            parse_forward(&env(&[
                ("WARREN_PORT_FORWARD_INTERNAL_PORT", "56881"),
                ("WARREN_PORT_FORWARD_PROTOCOL", "both"),
            ])),
            Err(ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_PROTOCOL",
                ..
            })
        ));
    }

    #[test]
    fn a_target_that_is_not_a_socket_address_is_refused() {
        assert!(matches!(
            parse_forward(&env(&[
                ("WARREN_PORT_FORWARD_INTERNAL_PORT", "56881"),
                ("WARREN_PORT_FORWARD_TARGET", "10.67.0.2"),
            ])),
            Err(ConfigError::Invalid {
                var: "WARREN_PORT_FORWARD_TARGET",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn the_shutdown_down_hook_runs_without_a_status_file() {
        let sink = Recorder::default();
        let fwd = forward(None);

        retire_forward_state(LOG, &sink, Some(&fwd), Some(49587)).await;

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

        retire_forward_state(LOG, &sink, Some(&fwd), Some(49587)).await;

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

        retire_forward_state(LOG, &sink, Some(&fwd), None).await;

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

        apply_port_change(LOG, &sink, &fwd, None, Some(58364)).await;

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

        apply_port_change(LOG, &sink, &fwd, None, Some(58364)).await;
        apply_port_change(LOG, &sink, &fwd, Some(58364), None).await;

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

        apply_port_change(LOG, &sink, &fwd, Some(49587), Some(58364)).await;

        assert_eq!(
            sink.calls(),
            vec![
                "down:49587:down {{PORT}}".to_owned(),
                "up:58364:up {{PORT}}".to_owned(),
            ],
            "the old port must be retired before the new one is announced"
        );
    }

    /// A terminal verdict leaves exactly what a signal leaves: a down hook
    /// that has not run and a status file naming a public port the exit no
    /// longer maps. The forward watcher would clear it, but on this path it is
    /// racing the process exit, so a hook slower than the failing redial is
    /// truncated mid-run.
    #[tokio::test]
    async fn every_stop_path_retires_the_published_state_and_maps_its_exit_code() {
        for (name, stop, want_code) in [
            ("signal", Stop::Signal, 0),
            ("fatal", Stop::Fatal(Some(FatalCause::NotAuthorized)), 2),
        ] {
            let status = scratch(&format!("conclude-{name}"));
            hooks::write_status_file(&status, 49587)
                .await
                .expect("a granted port was published");
            let sink = Recorder::default();
            let fwd = forward(Some(status.clone()));

            let code = conclude(LOG, &sink, stop, Some(&fwd), Some(49587)).await;

            assert_eq!(code, want_code, "{name} must exit {want_code}");
            assert_eq!(
                sink.calls(),
                vec!["down:49587:down {{PORT}}".to_owned()],
                "the down command must fire on the {name} path"
            );
            assert!(
                !status.exists(),
                "the status file must not survive the {name} path"
            );
        }
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

    /// The supervisor reaching `Failed` is the only thing that ends the daemon
    /// on its own, and the cause it latched has to survive into the exit code.
    #[tokio::test]
    async fn a_terminal_state_stops_the_daemon_with_its_cause() {
        let (state_tx, state_rx) = watch_connected();
        state_tx.send(ConnectionState::Failed).unwrap();
        let stop = wait_for_stop(state_rx, || Some(FatalCause::Banned)).await;
        assert!(matches!(stop, Stop::Fatal(Some(FatalCause::Banned))));
    }

    #[tokio::test]
    async fn a_healthy_supervisor_never_stops_the_daemon() {
        let (state_tx, state_rx) = watch_connected();
        let waiting = tokio::spawn(wait_for_stop(state_rx, || None));
        state_tx.send(ConnectionState::Reconnecting).unwrap();
        state_tx.send(ConnectionState::Connected).unwrap();
        let quiet =
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut { waiting }).await;
        assert!(
            quiet.is_err(),
            "reconnecting is what the supervisor is for, so it must not end the daemon"
        );
    }

    fn watch_connected() -> (
        tokio::sync::watch::Sender<ConnectionState>,
        tokio::sync::watch::Receiver<ConnectionState>,
    ) {
        tokio::sync::watch::channel(ConnectionState::Connected)
    }
}
