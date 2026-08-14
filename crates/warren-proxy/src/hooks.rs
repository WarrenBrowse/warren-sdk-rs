//! Port-forward command hooks, the gluetun `VPN_PORT_FORWARDING_UP_COMMAND`
//! shape: a user command run through `sh -c` with `{{PORT}}` substituted.

use std::path::Path;

/// Substitutes every `{{PORT}}` occurrence with the granted public port.
#[must_use]
pub fn substitute_port(command: &str, port: u16) -> String {
    command.replace("{{PORT}}", &port.to_string())
}

/// Runs a hook command through `sh -c`, logging failure without killing the
/// daemon: a broken hook must not take the tunnel down.
pub async fn run_hook(command: &str, port: u16, label: &str) {
    let resolved = substitute_port(command, port);
    match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&resolved)
        .status()
        .await
    {
        Ok(status) if status.success() => {
            println!("warren-proxy: port-forward {label} command ok (port {port})");
        }
        Ok(status) => {
            eprintln!("warren-proxy: port-forward {label} command exited with {status}");
        }
        Err(err) => {
            eprintln!("warren-proxy: port-forward {label} command failed to spawn: {err}");
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
