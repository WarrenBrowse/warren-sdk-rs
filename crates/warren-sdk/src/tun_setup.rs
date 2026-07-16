//! Privileged device setup for the experimental `start_tun_multihop` datapath.
//!
//! This is the small, genuinely SDK-specific glue that the routing/killswitch/DNS
//! single-home (`warrenguard-route-split` + `warrenguard-killswitch-os`) does not
//! cover: bringing up and addressing the freshly opened raw TUN device, and (on
//! macOS) installing the carrier host-route escape. Ported from the deleted
//! in-tree `plan`/`apply` glue (doc-94 B1). The app opens and addresses its device
//! through talpid instead, so this bring-up has no engine home; the routing,
//! killswitch and DNS policy it composes are all in the shared engine crates.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

/// Runs `argv`, mapping a non-zero exit to an error. The child's stdout/stderr
/// are discarded: success is read from the exit status, and an inherited pipe
/// that is no longer drained would kill the child with SIGPIPE when it writes.
///
/// # Errors
///
/// The spawn error, or [`io::ErrorKind::Other`] if the command exits non-zero.
fn run(argv: &[String]) -> io::Result<()> {
    // An empty argv is a caller bug, but must surface as a recoverable error
    // rather than a panic mid-setup or mid-teardown.
    let program = argv
        .first()
        .ok_or_else(|| io::Error::other("empty command argv"))?;
    let status = Command::new(program)
        .args(&argv[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{program} exited with {status}")))
    }
}

/// macOS: the `ifconfig` argv that addresses the point-to-point `utun` and brings
/// it up BEFORE routing. `utun` is point-to-point, so the peer is the in-tunnel
/// gateway (`warrenguard_config::TUNNEL_GATEWAY_IP`). Pure (no exec); unit-tested.
#[cfg(target_os = "macos")]
#[must_use]
fn interface_up_argv_macos(
    dev: &str,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
    mtu: u16,
) -> Vec<Vec<String>> {
    let gateway = warrenguard_config::TUNNEL_GATEWAY_IP;
    let mut cmds = vec![vec![
        "ifconfig".to_owned(),
        dev.to_owned(),
        "inet".to_owned(),
        ipv4.to_string(),
        gateway.to_string(),
        "mtu".to_owned(),
        mtu.to_string(),
        "up".to_owned(),
    ]];
    if let Some(v6) = ipv6 {
        cmds.push(vec![
            "ifconfig".to_owned(),
            dev.to_owned(),
            "inet6".to_owned(),
            format!("{v6}/128"),
        ]);
    }
    cmds
}

/// Linux: the `ip` argv that addresses the device, sets its MTU, and brings it up
/// BEFORE routing (a freshly opened TUN is down and unaddressed). Pure (no exec);
/// unit-tested.
#[cfg(target_os = "linux")]
#[must_use]
fn interface_up_argv_linux(
    dev: &str,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
    mtu: u16,
) -> Vec<Vec<String>> {
    let mut cmds = vec![vec![
        "ip".to_owned(),
        "addr".to_owned(),
        "add".to_owned(),
        format!("{ipv4}/32"),
        "dev".to_owned(),
        dev.to_owned(),
    ]];
    if let Some(v6) = ipv6 {
        cmds.push(vec![
            "ip".to_owned(),
            "-6".to_owned(),
            "addr".to_owned(),
            "add".to_owned(),
            format!("{v6}/128"),
            "dev".to_owned(),
            dev.to_owned(),
        ]);
    }
    cmds.push(vec![
        "ip".to_owned(),
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        dev.to_owned(),
        "mtu".to_owned(),
        mtu.to_string(),
    ]);
    cmds.push(vec![
        "ip".to_owned(),
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        dev.to_owned(),
        "up".to_owned(),
    ]);
    cmds
}

/// Bring up and address the freshly opened TUN `dev` with the exit-assigned
/// tunnel address(es) and `mtu`, BEFORE any routing is installed (a fresh device
/// is down, so routes via it do nothing until this runs).
///
/// # Errors
///
/// The first `ifconfig` (macOS) / `ip` (Linux) invocation that fails.
pub(crate) fn configure_interface(
    dev: &str,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
    mtu: u16,
) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let cmds = interface_up_argv_macos(dev, ipv4, ipv6, mtu);
    #[cfg(target_os = "linux")]
    let cmds = interface_up_argv_linux(dev, ipv4, ipv6, mtu);
    for argv in cmds {
        run(&argv)?;
    }
    Ok(())
}

/// macOS `route` argv to install the carrier host-route escape: send traffic to
/// the exit endpoint via the physical `gateway`, so the split-default `/1` capture
/// (route-split) does not loop the tunnel's own unbound carrier socket back into
/// the tunnel. Pure (no exec); unit-tested.
#[cfg(target_os = "macos")]
#[must_use]
fn carrier_route_add_argv_macos(exit_ip: IpAddr, gateway: &str) -> Vec<String> {
    vec![
        "route".to_owned(),
        "-n".to_owned(),
        "add".to_owned(),
        "-host".to_owned(),
        exit_ip.to_string(),
        gateway.to_owned(),
    ]
}

/// macOS `route` argv to delete the carrier host-route escape installed by
/// [`carrier_route_add_argv_macos`]. Pure (no exec); unit-tested.
#[cfg(target_os = "macos")]
#[must_use]
fn carrier_route_del_argv_macos(exit_ip: IpAddr) -> Vec<String> {
    vec![
        "route".to_owned(),
        "-n".to_owned(),
        "delete".to_owned(),
        "-host".to_owned(),
        exit_ip.to_string(),
    ]
}

/// macOS: discover the physical default gateway (`route -n get default`) to pin
/// the carrier host-route escape to. Resolved BEFORE the split-default capture is
/// installed (afterwards `route get default` would resolve to the tunnel).
///
/// # Errors
///
/// [`io::ErrorKind::Other`] if `route` fails or the output has no gateway.
#[cfg(target_os = "macos")]
pub(crate) fn discover_physical_gateway_macos() -> io::Result<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .stderr(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other("route -n get default failed"));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    warrenguard_route_split::default_route_split_macos::parse_default_gateway(&text)
        .ok_or_else(|| io::Error::other("no physical default gateway found"))
}

/// macOS: install the carrier host-route escape (delete any stale one first so
/// the add is idempotent after a dirty exit).
///
/// # Errors
///
/// The `route add` invocation if it fails for a reason other than a pre-existing
/// route (which is tolerated by deleting first).
#[cfg(target_os = "macos")]
pub(crate) fn add_carrier_host_route_macos(exit_ip: IpAddr, gateway: &str) -> io::Result<()> {
    let _ = run(&carrier_route_del_argv_macos(exit_ip));
    run(&carrier_route_add_argv_macos(exit_ip, gateway))
}

/// macOS: remove the carrier host-route escape. Best-effort (a route already gone
/// on teardown is not an error), so it is safe to call from `Drop`.
#[cfg(target_os = "macos")]
pub(crate) fn del_carrier_host_route_macos(exit_ip: IpAddr) {
    let _ = run(&carrier_route_del_argv_macos(exit_ip));
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::*;
    #[cfg(target_os = "macos")]
    use std::net::Ipv4Addr;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_interface_up_addresses_the_point_to_point_utun_then_up() {
        let cmds = interface_up_argv_macos("utun7", Ipv4Addr::new(10, 66, 0, 2), None, 1280);
        assert_eq!(
            cmds[0],
            vec![
                "ifconfig",
                "utun7",
                "inet",
                "10.66.0.2",
                &warrenguard_config::TUNNEL_GATEWAY_IP.to_string(),
                "mtu",
                "1280",
                "up"
            ],
            "the utun must be addressed point-to-point with the shared tunnel \
             gateway and brought up in one ifconfig line"
        );
        assert_eq!(cmds.len(), 1, "v4-only: a single ifconfig line");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_carrier_route_escape_pins_the_exit_to_the_physical_gateway() {
        // The unbound carrier socket must reach the exit via the physical
        // gateway, not the split-default `/1` capture (which would loop the
        // tunnel onto itself). The escape is a `<exit>/32` host route.
        let exit: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            carrier_route_add_argv_macos(exit, "192.168.1.1"),
            vec!["route", "-n", "add", "-host", "203.0.113.9", "192.168.1.1"]
        );
        assert_eq!(
            carrier_route_del_argv_macos(exit),
            vec!["route", "-n", "delete", "-host", "203.0.113.9"],
            "teardown deletes exactly the carrier host route, keyed on the exit IP"
        );
    }
}
