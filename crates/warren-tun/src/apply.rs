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
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
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
        Err(io::Error::other(format!(
            "{} exited with {status}",
            argv[0]
        )))
    }
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
    let _ = run(&KillswitchPlan::pf_flush_argv(), None);
    run(&KillswitchPlan::pf_disable_argv(), None)
}

#[cfg(not(target_os = "macos"))]
fn teardown_killswitch_impl() -> io::Result<()> {
    run(&KillswitchPlan::nft_teardown_argv(), None)
}
