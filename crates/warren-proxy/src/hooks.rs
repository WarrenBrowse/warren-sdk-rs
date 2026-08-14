//! Port-forward command hooks, the gluetun `VPN_PORT_FORWARDING_UP_COMMAND`
//! shape: a user command run through `sh -c` with `{{PORT}}` substituted.

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

/// Runs a hook command through `sh -c` under [`HOOK_TIMEOUT`].
pub async fn run_hook(command: &str, port: u16, label: &str) -> HookOutcome {
    run_hook_with_timeout(command, port, label, HOOK_TIMEOUT).await
}

/// Runs a hook command through `sh -c`, killing it past `timeout`.
pub async fn run_hook_with_timeout(
    command: &str,
    port: u16,
    label: &str,
    timeout: Duration,
) -> HookOutcome {
    let resolved = substitute_port(command, port);
    let mut child = match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&resolved)
        .spawn()
    {
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
            let _ = child.kill().await;
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

#[cfg(test)]
mod tests {
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

    /// A unique scratch path per test, so the suite stays parallel-safe.
    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("warren-proxy-hook-{}-{name}", std::process::id()))
    }

    #[tokio::test]
    async fn a_successful_hook_runs_the_substituted_command() {
        let marker = scratch("ok");
        let _ = std::fs::remove_file(&marker);
        let outcome = run_hook(
            &format!("printf %s {{{{PORT}}}} > {}", marker.display()),
            51820,
            "up",
        )
        .await;
        assert_eq!(outcome, HookOutcome::Succeeded);
        assert_eq!(
            std::fs::read_to_string(&marker).expect("marker written"),
            "51820",
            "the hook must receive the granted port, substituted"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[tokio::test]
    async fn a_failing_hook_is_reported_and_does_not_panic() {
        assert_eq!(run_hook("exit 3", 1, "up").await, HookOutcome::Failed);
    }

    #[tokio::test]
    async fn a_hanging_hook_is_killed_by_its_timeout() {
        let started = std::time::Instant::now();
        let outcome =
            run_hook_with_timeout("sleep 30", 1, "down", Duration::from_millis(200)).await;
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
