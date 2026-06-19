//! Privileged applier: runs the routing and killswitch plans (Linux).
//!
//! EXPERIMENTAL, requires root / `CAP_NET_ADMIN`, NOT YET REAL-EXIT VALIDATED.
//! Compiled only under the `experimental-tun` feature. The argv it runs come from
//! [`crate::plan`] (pure and unit-tested); this module is the thin process glue
//! that executes them, which can only be exercised with privilege.
//!
//! Shelling out to `ip`/`nft` (rather than linking a netlink crate) keeps the
//! default build dependency-free; the commands are the testable contract.

use std::io::{self, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::plan::{KillswitchPlan, RoutingPlan, TunConfig};

/// Runs `argv`, optionally feeding `stdin`, and maps a non-zero exit to an error.
///
/// # Errors
///
/// The spawn error, or [`io::ErrorKind::Other`] if the command exits non-zero.
fn run(argv: &[String], stdin: Option<&str>) -> io::Result<()> {
    // Guard the slice index: a caller passing an empty argv is a bug, but it must
    // surface as a recoverable error, not a panic mid-teardown.
    let program = argv
        .first()
        .ok_or_else(|| io::Error::other("empty command argv"))?;
    let mut cmd = Command::new(program);
    cmd.args(&argv[1..]);
    // Discard the child's stdout/stderr: success/failure is read from the exit
    // status, and inheriting a parent pipe that is no longer drained would kill
    // the child with SIGPIPE when it writes (for example pfctl warnings).
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn()?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no stdin pipe"))?
            .write_all(input.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{program} exited with {status}")))
    }
}

/// Runs `argv` and returns its captured stdout, mapping a non-zero exit to an
/// error. Used for the read-only pf snapshot commands (`pfctl -s info`/`-sr`).
///
/// # Errors
///
/// The spawn error, or [`io::ErrorKind::Other`] if the command exits non-zero.
#[cfg(target_os = "macos")]
fn run_capture(argv: &[String]) -> io::Result<String> {
    let program = argv
        .first()
        .ok_or_else(|| io::Error::other("empty command argv"))?;
    let out = Command::new(program)
        .args(&argv[1..])
        .stderr(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{program} exited with {}",
            out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Where the pre-apply pf snapshot is saved so teardown can restore it. Kept in
/// root-owned `/var/run` (not world-writable `/tmp`): the killswitch only runs
/// as root, and a non-root-writable directory denies a symlink-swap on the path.
#[cfg(target_os = "macos")]
fn pf_backup_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/run/warren-killswitch-pf-backup.conf")
}

/// Configures the TUN interface BEFORE routing: assigns the tunnel address(es),
/// sets the MTU, and brings the link up (a freshly opened device is down and
/// unaddressed, so routes via it do nothing until this runs).
///
/// # Errors
///
/// The first `ip` invocation that fails.
pub fn configure_interface(config: &TunConfig) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let cmds = config.interface_up_commands_macos();
    #[cfg(not(target_os = "macos"))]
    let cmds = config.interface_up_commands();
    for argv in cmds {
        run(&argv, None)?;
    }
    Ok(())
}

/// Applies `plan` to the `dev` device, pinning the exit carrier route to
/// `physical_gateway` (the pre-existing default gateway on the physical link).
///
/// # Errors
///
/// The first `ip route` invocation that fails.
pub fn apply_routing(plan: &RoutingPlan, dev: &str, physical_gateway: IpAddr) -> io::Result<()> {
    // Fail closed on an address-family mismatch: pinning a v6 exit to a v4
    // next-hop (or vice-versa) is rejected by the kernel and would otherwise
    // leave the routing table half-applied (some routes in, the exit pin not).
    if !plan.gateway_family_matches(physical_gateway) {
        return Err(io::Error::other(
            "physical gateway address family does not match the exit endpoint",
        ));
    }
    #[cfg(target_os = "macos")]
    let cmds = plan.to_macos_commands(dev, physical_gateway, "add");
    #[cfg(not(target_os = "macos"))]
    let cmds = plan.to_ip_commands(dev, physical_gateway);
    for argv in cmds {
        run(&argv, None)?;
    }
    Ok(())
}

/// Loads the killswitch ruleset (`nft -f -`), failing closed.
///
/// # Errors
///
/// If `nft` cannot be run or rejects the ruleset.
pub fn apply_killswitch(config: &TunConfig) -> io::Result<()> {
    apply_killswitch_impl(config)
}

#[cfg(target_os = "macos")]
fn apply_killswitch_impl(config: &TunConfig) -> io::Result<()> {
    // Snapshot pf's prior state BEFORE touching it, so teardown restores the
    // pre-existing ruleset and enable-state instead of wiping them (the old
    // teardown ran `pfctl -F rules` + `-d`, clobbering any host firewall config
    // and fighting pf's `-E` refcount when another VPN was already running).
    //
    // Best-effort and non-fatal: the read-only `pfctl -s info`/`-sr` snapshot
    // never blocks installing the killswitch. If it fails, teardown finds no
    // backup and falls back to the old flush+disable. The killswitch rules and
    // `-E` enable below are unchanged, so this cannot weaken the active block.
    if let Ok(info) = run_capture(&KillswitchPlan::pf_show_info_argv())
        && let Ok(rules) = run_capture(&KillswitchPlan::pf_show_rules_argv())
    {
        let was_enabled = KillswitchPlan::pf_status_is_enabled(&info);
        let backup = format!("{}{}", KillswitchPlan::pf_backup_header(was_enabled), rules);
        let _ = std::fs::write(pf_backup_path(), backup);
    }
    run(
        &KillswitchPlan::pf_load_argv(),
        Some(&KillswitchPlan::pf_rules(config)),
    )?;
    run(&KillswitchPlan::pf_enable_argv(), None)
}

#[cfg(not(target_os = "macos"))]
fn apply_killswitch_impl(config: &TunConfig) -> io::Result<()> {
    run(
        &KillswitchPlan::nft_apply_argv(),
        Some(&KillswitchPlan::nftables(config).nftables),
    )
}

/// Reverts the routes [`apply_routing`] installed (best-effort: a route already
/// gone is not fatal, so individual `ip route del` failures are ignored). Pair
/// this with [`teardown_killswitch`] to fully restore the routing table on
/// datapath shutdown.
pub fn revert_routing(plan: &RoutingPlan, dev: &str, physical_gateway: IpAddr) {
    #[cfg(target_os = "macos")]
    let cmds = plan.to_macos_commands(dev, physical_gateway, "delete");
    #[cfg(not(target_os = "macos"))]
    let cmds = plan.to_teardown_commands(dev, physical_gateway);
    for argv in cmds {
        let _ = run(&argv, None);
    }
}

/// Pushes the exit-assigned DNS resolvers onto the TUN link and routes EVERY
/// query through it (Linux/systemd-resolved via `resolvectl`). This closes the
/// DNS-leak vector: once the split-default routing captures traffic, lookups
/// must not keep hitting the host's previous resolver. No-op when the exit
/// assigned no DNS.
///
/// macOS DNS push (`scutil`/`networksetup`) is not yet wired, so a macOS TUN
/// datapath still resolves via the host resolver until that lands; the routing
/// capture above is unaffected. Tracked as the remaining half of the DNS-leak
/// fix for the experimental TUN path.
///
/// # Errors
///
/// The first `resolvectl` invocation that fails.
pub fn apply_dns(config: &TunConfig) -> io::Result<()> {
    #[cfg(not(target_os = "macos"))]
    for argv in config.dns_push_commands_linux() {
        run(&argv, None)?;
    }
    #[cfg(target_os = "macos")]
    let _ = config;
    Ok(())
}

/// Reverts [`apply_dns`] (best-effort: a link already reverted is not fatal), so
/// the host resolver returns on datapath shutdown. No-op when no DNS was pushed.
pub fn revert_dns(config: &TunConfig) {
    #[cfg(not(target_os = "macos"))]
    for argv in config.dns_teardown_commands_linux() {
        let _ = run(&argv, None);
    }
    #[cfg(target_os = "macos")]
    let _ = config;
}

/// Tears the killswitch down, restoring normal output. On macOS this flushes the
/// rules and disables pf (back to the default unfiltered state); on Linux it
/// deletes the nftables table.
///
/// # Errors
///
/// If the teardown command cannot be run (a missing rule is treated as success
/// by the caller).
pub fn teardown_killswitch() -> io::Result<()> {
    teardown_killswitch_impl()
}

#[cfg(target_os = "macos")]
fn teardown_killswitch_impl() -> io::Result<()> {
    let path = pf_backup_path();
    match std::fs::read_to_string(&path) {
        Ok(backup) => {
            // Restore the captured ruleset (pfctl ignores the `#` header comment),
            // returning the host's filter rules to their pre-apply state instead
            // of flushing them to empty.
            let restore = run(
                &KillswitchPlan::pf_restore_argv(&path.to_string_lossy()),
                None,
            );
            // Only disable pf if it was OFF before we enabled it. If it was
            // already on (e.g. another VPN owns it), `pfctl -E` was
            // reference-counted, so leaving it enabled respects that owner.
            if !KillswitchPlan::parse_pf_backup_was_enabled(&backup) {
                let _ = run(&KillswitchPlan::pf_disable_argv(), None);
            }
            let _ = std::fs::remove_file(&path);
            restore
        }
        // No snapshot (it failed or never ran): fall back to the old best-effort
        // teardown rather than leaving Warren's block rules loaded.
        Err(_) => {
            let _ = run(&KillswitchPlan::pf_flush_argv(), None);
            run(&KillswitchPlan::pf_disable_argv(), None)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn teardown_killswitch_impl() -> io::Result<()> {
    run(&KillswitchPlan::nft_teardown_argv(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_rejects_an_empty_argv_without_panicking() {
        // The slice guard must turn a bug (empty argv) into a recoverable error
        // before any indexing or spawn happens.
        let err = run(&[], None).unwrap_err();
        assert!(err.to_string().contains("empty command argv"));
    }
}
