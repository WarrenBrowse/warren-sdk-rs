//! Port-forward command hooks, the gluetun `VPN_PORT_FORWARDING_UP_COMMAND`
//! shape: a user command run through the platform's shell with `{{PORT}}`
//! substituted.

use std::path::Path;
use std::time::Duration;

/// How long a user hook may run before it is killed. The hook runs on the
/// shutdown path and ahead of the next port change, so one that never returns
/// would hold the daemon open past its signal and stall every later grant.
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// What running a hook produced. Returned so callers and tests can observe the
/// outcome; the daemon itself only logs it, because a broken hook must never
/// take the tunnel down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookOutcome {
    /// The command exited zero.
    Succeeded,
    /// The command ran and exited non-zero.
    Failed,
    /// The command could not be spawned, or could not be waited on.
    SpawnFailed,
    /// The command outlived its budget and was killed.
    TimedOut,
}

/// Substitutes every `{{PORT}}` occurrence with the granted public port.
#[must_use]
pub fn substitute_port(command: &str, port: u16) -> String {
    command.replace("{{PORT}}", &port.to_string())
}

/// Secrets that must not reach a hook. A child inherits this process's
/// environment, so an operator who passes the recovery phrase in
/// `WARREN_MNEMONIC` would otherwise hand it to every hook command and to
/// everything that command spawns, where it is readable in
/// `/proc/<pid>/environ`. The daemon cannot scrub its own environment
/// (`std::env::remove_var` is unsafe under edition 2024, and this workspace
/// forbids unsafe), so the strip happens per child, which is where it matters.
const SECRET_ENV: [&str; 2] = ["WARREN_MNEMONIC", "WARREN_MNEMONIC_FILE"];

/// How long the hook's process group is given between its SIGTERM and its
/// SIGKILL: enough for a shell trap to undo what the hook did, short enough
/// that a stop is not held up by a hook that ignores the polite signal.
#[cfg(unix)]
const KILL_GRACE: Duration = Duration::from_millis(500);

/// A hook is an operator-written command line, so it runs under the platform's
/// own shell rather than being parsed here. Without this the whole feature is
/// dead on Windows, where there is no `sh`.
fn shell_command(resolved: &str) -> tokio::process::Command {
    #[cfg(windows)]
    let mut command = {
        let mut command = tokio::process::Command::new("cmd");
        command.arg("/C").arg(resolved);
        command
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg(resolved);
        // Own process group, so the timeout below can reach everything the
        // hook spawned. Without it a backgrounded child outlives the budget,
        // and in the container image (the daemon is PID 1, no init) it is
        // never reaped either.
        command.process_group(0);
        command
    };
    for name in SECRET_ENV {
        command.env_remove(name);
    }
    command
}

/// Kills a hook that outlived its budget, and everything it spawned.
///
/// Unix signals the process GROUP the child leads: `Child::kill` reaches the
/// shell alone, which leaves the descendants that actually hold the forwarded
/// port open. SIGTERM first so a hook with a trap can undo its own work, then
/// SIGKILL for the rest.
#[cfg(unix)]
async fn kill_hook(child: &mut tokio::process::Child) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(Pid::from_raw);
    let Some(group) = group else {
        // Already reaped: nothing to signal, and no group id left to trust.
        let _ = child.kill().await;
        return;
    };
    let _ = killpg(group, Signal::SIGTERM);
    let reaped = tokio::time::timeout(KILL_GRACE, child.wait()).await.is_ok();
    // Unconditional, even once the leader is gone: a descendant that ignores
    // SIGTERM keeps the group (and the port) alive, and the escalation is the
    // only thing that ends it.
    let _ = killpg(group, Signal::SIGKILL);
    if !reaped {
        let _ = child.kill().await;
    }
}

/// Windows has no process groups to signal here, so the child alone is killed.
#[cfg(not(unix))]
async fn kill_hook(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
}

/// Runs a hook command through the platform's shell under [`HOOK_TIMEOUT`].
pub async fn run_hook(command: &str, port: u16, label: &str) -> HookOutcome {
    run_hook_with_timeout(command, port, label, HOOK_TIMEOUT).await
}

/// Runs a hook command through the platform's shell, killing it past `timeout`.
pub async fn run_hook_with_timeout(
    command: &str,
    port: u16,
    label: &str,
    timeout: Duration,
) -> HookOutcome {
    let resolved = substitute_port(command, port);
    let mut child = match shell_command(&resolved).spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("warren-proxy: port-forward {label} command failed to spawn: {err}");
            return HookOutcome::SpawnFailed;
        }
    };
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) if status.success() => {
            println!("warren-proxy: port-forward {label} command ok (port {port})");
            HookOutcome::Succeeded
        }
        Ok(Ok(status)) => {
            eprintln!("warren-proxy: port-forward {label} command exited with {status}");
            HookOutcome::Failed
        }
        Ok(Err(err)) => {
            eprintln!("warren-proxy: port-forward {label} command could not be waited on: {err}");
            HookOutcome::SpawnFailed
        }
        Err(_) => {
            kill_hook(&mut child).await;
            eprintln!(
                "warren-proxy: port-forward {label} command exceeded {timeout:?} and was killed"
            );
            HookOutcome::TimedOut
        }
    }
}

/// Writes the granted port to the status file (atomic rename), creating the
/// parent directory if needed.
pub async fn write_status_file(path: &Path, port: u16) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, format!("{port}\n")).await?;
    tokio::fs::rename(&tmp, path).await
}

/// Clears the status file when the mapping is gone, so a consumer reading it
/// stops announcing a port the exit no longer maps. A file that was never
/// written is not an error.
pub async fn clear_status_file(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn substitutes_every_port_occurrence() {
        assert_eq!(
            substitute_port("curl -d '{\"p\":{{PORT}}}' x && echo {{PORT}}", 51820),
            "curl -d '{\"p\":51820}' x && echo 51820"
        );
    }

    #[test]
    fn command_without_placeholder_is_unchanged() {
        assert_eq!(substitute_port("echo done", 1), "echo done");
    }

    /// A hook that outlives any sane timeout. `sleep` is not a cmd builtin, so
    /// Windows gets the usual `ping` idiom; both forms need no quoting and no
    /// redirection, which is what keeps this test portable.
    fn never_returns() -> &'static str {
        if cfg!(windows) {
            "ping -n 31 127.0.0.1"
        } else {
            "sleep 30"
        }
    }

    /// The one test that exercises the real shell. It observes the child's exit
    /// code rather than a file it writes: `exit N` is spelled identically in sh
    /// and cmd, while every file-writing form differs in quoting, in line
    /// endings, and (in cmd) in whether a digit before `>` is read as a stream
    /// handle. The orchestration around hooks is tested in `run`, against a
    /// recording sink.
    #[tokio::test]
    async fn the_substituted_port_reaches_the_shell() {
        assert_eq!(
            run_hook("exit {{PORT}}", 0, "up").await,
            HookOutcome::Succeeded,
            "a hook substituted to `exit 0` must be reported as success"
        );
        assert_eq!(
            run_hook("exit {{PORT}}", 3, "up").await,
            HookOutcome::Failed,
            "the port must reach the shell: substituted to `exit 3` this must fail"
        );
    }

    /// Asserted on the spawn configuration rather than by reading the child's
    /// environment back, so it holds on every platform without a shell idiom.
    #[test]
    fn the_recovery_phrase_is_stripped_from_a_hook_child() {
        let command = shell_command("anything");
        let removed: Vec<String> = command
            .as_std()
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        assert!(
            removed.contains(&"WARREN_MNEMONIC".to_owned()),
            "a hook must never inherit the recovery phrase, removed: {removed:?}"
        );
        assert!(
            removed.contains(&"WARREN_MNEMONIC_FILE".to_owned()),
            "a hook must not be handed the secret's path either, removed: {removed:?}"
        );
    }

    #[tokio::test]
    async fn a_failing_hook_is_reported_and_does_not_panic() {
        assert_eq!(run_hook("exit 3", 1, "up").await, HookOutcome::Failed);
    }

    #[tokio::test]
    async fn clearing_the_status_file_is_idempotent() {
        let path = std::env::temp_dir().join(format!("warren-proxy-clear-{}", std::process::id()));
        write_status_file(&path, 51820).await.expect("write");
        clear_status_file(&path).await.expect("first clear");
        assert!(!path.exists());
        clear_status_file(&path)
            .await
            .expect("a file that was never written is not an error");
    }

    #[tokio::test]
    async fn a_hanging_hook_is_killed_by_its_timeout() {
        let started = std::time::Instant::now();
        let outcome =
            run_hook_with_timeout(never_returns(), 1, "down", Duration::from_millis(200)).await;
        assert_eq!(
            outcome,
            HookOutcome::TimedOut,
            "a hook that never returns must be killed, not awaited forever"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout must cut the wait short, took {:?}",
            started.elapsed()
        );
    }

    /// A hook is an operator's shell line, so what it backgrounds is what
    /// actually holds the port open. In the image the daemon is PID 1 with no
    /// init, so a descendant that outlives the budget is never reaped either.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_hooks_own_children_are_killed_with_it() {
        let marker =
            std::env::temp_dir().join(format!("warren-proxy-orphan-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        // The descendant writes late enough that the kill (budget, then the
        // SIGTERM/SIGKILL grace) has room to finish first on a loaded or
        // emulated CI runner, and the wait below outlasts the write.
        let command = format!(
            "sh -c 'sleep 3; echo survived > {}' & sleep 30",
            marker.display()
        );

        let outcome = run_hook_with_timeout(&command, 1, "up", Duration::from_millis(200)).await;

        assert_eq!(outcome, HookOutcome::TimedOut);
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            !marker.exists(),
            "what the hook started must die with it, not outlive the budget"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[tokio::test]
    async fn status_file_is_written_atomically_with_parent_dirs() {
        let dir = std::env::temp_dir().join(format!("warren-proxy-test-{}", std::process::id()));
        let path = dir.join("nested").join("forwarded_port");
        write_status_file(&path, 55555).await.expect("write");
        let content = tokio::fs::read_to_string(&path).await.expect("read back");
        assert_eq!(content, "55555\n");
        assert!(
            !path.with_extension("tmp").exists(),
            "tmp file must be renamed away"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
