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

use crate::plan::{KillswitchPlan, RoutingPlan};

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

/// Applies `plan` to the `dev` device, pinning the exit carrier route to
/// `physical_gateway` (the pre-existing default gateway on the physical link).
///
/// # Errors
///
/// The first `ip route` invocation that fails.
pub fn apply_routing(plan: &RoutingPlan, dev: &str, physical_gateway: IpAddr) -> io::Result<()> {
    for argv in plan.to_ip_commands(dev, physical_gateway) {
        run(&argv, None)?;
    }
    Ok(())
}

/// Loads the killswitch ruleset (`nft -f -`), failing closed.
///
/// # Errors
///
/// If `nft` cannot be run or rejects the ruleset.
pub fn apply_killswitch(plan: &KillswitchPlan) -> io::Result<()> {
    run(&KillswitchPlan::nft_apply_argv(), Some(&plan.nftables))
}

/// Tears the killswitch table down, restoring normal output.
///
/// # Errors
///
/// If `nft` cannot be run (a missing table is treated as success by the caller).
pub fn teardown_killswitch() -> io::Result<()> {
    run(&KillswitchPlan::nft_teardown_argv(), None)
}
