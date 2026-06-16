//! Routing and killswitch PLAN computation.
//!
//! A privileged backend must (a) steer all traffic into the TUN device without
//! losing the route to the exit itself, and (b) optionally fail closed so traffic
//! cannot leak outside the tunnel. Both are expressed here as pure data: a backend
//! computes the plan, then a privileged applier runs it. Separating the two keeps
//! the policy (the hard part to get right) testable without root.
//!
//! NOTE: this module produces the intended operations; APPLYING them needs root
//! and is feature-gated. Nothing here has been validated against a real exit.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The TUN datapath parameters a backend would install on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Device name (for example `utun7` on macOS, `warren0` on Linux).
    pub name: String,
    /// Link MTU.
    pub mtu: u16,
    /// The tunnel IPv4 address and prefix length assigned by the exit.
    pub ipv4: (Ipv4Addr, u8),
    /// The tunnel IPv6 address and prefix length, if v6 was assigned.
    pub ipv6: Option<(std::net::Ipv6Addr, u8)>,
    /// The exit's public UDP endpoint: traffic to it must keep using the physical
    /// link (otherwise the tunnel would route its own carrier packets into itself).
    pub exit_endpoint: SocketAddr,
    /// DNS servers to push (resolved over the tunnel).
    pub dns: Vec<IpAddr>,
}

/// A single routing operation in a [`RoutingPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOp {
    /// Pin the exit endpoint to the pre-existing default gateway on the physical
    /// link, so the tunnel's own carrier packets are not routed into the tunnel.
    PinExitToPhysical(IpAddr),
    /// Add a route for `cidr` via the TUN device.
    RouteViaTun {
        /// Destination network in `addr/prefix` form.
        cidr: String,
    },
}

/// The ordered routing operations that capture all traffic via the TUN device
/// without black-holing the route to the exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPlan {
    /// Operations to apply in order.
    pub ops: Vec<RouteOp>,
}

impl RoutingPlan {
    /// Computes the split-default capture plan.
    ///
    /// The default route is overridden with the classic `0.0.0.0/1` + `128.0.0.0/1`
    /// pair rather than `0.0.0.0/0`: two more-specific halves outrank the existing
    /// default without deleting it, so the carrier route to the exit (pinned
    /// first) survives. v6 uses the analogous `::/1` + `8000::/1` split when a v6
    /// address was assigned.
    #[must_use]
    pub fn split_default(config: &TunConfig) -> Self {
        let mut ops = vec![RouteOp::PinExitToPhysical(config.exit_endpoint.ip())];
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            ops.push(RouteOp::RouteViaTun {
                cidr: half.to_owned(),
            });
        }
        if config.ipv6.is_some() {
            for half in ["::/1", "8000::/1"] {
                ops.push(RouteOp::RouteViaTun {
                    cidr: half.to_owned(),
                });
            }
        }
        Self { ops }
    }

    /// Renders the plan as `ip route` argv vectors for the Linux applier, in
    /// order. `physical_gateway` is the pre-existing default gateway on the
    /// physical link (discovered at runtime) the exit carrier route pins to.
    ///
    /// This is pure (no process is run): the applier executes each argv. Kept
    /// separate so the exact commands are unit-testable without privilege.
    #[must_use]
    pub fn to_ip_commands(&self, dev: &str, physical_gateway: IpAddr) -> Vec<Vec<String>> {
        self.ops
            .iter()
            .map(|op| match op {
                RouteOp::PinExitToPhysical(ip) => {
                    let host = match ip {
                        IpAddr::V4(v4) => format!("{v4}/32"),
                        IpAddr::V6(v6) => format!("{v6}/128"),
                    };
                    vec![
                        "ip".to_owned(),
                        "route".to_owned(),
                        "replace".to_owned(),
                        host,
                        "via".to_owned(),
                        physical_gateway.to_string(),
                    ]
                }
                RouteOp::RouteViaTun { cidr } => vec![
                    "ip".to_owned(),
                    "route".to_owned(),
                    "replace".to_owned(),
                    cidr.clone(),
                    "dev".to_owned(),
                    dev.to_owned(),
                ],
            })
            .collect()
    }

    /// Renders the `ip route del` argv that REVERTS [`Self::to_ip_commands`], so
    /// the datapath restores the routing table on shutdown. Pure (no exec); the
    /// applier runs each best-effort (a missing route on teardown is not fatal).
    #[must_use]
    pub fn to_teardown_commands(&self, dev: &str, physical_gateway: IpAddr) -> Vec<Vec<String>> {
        self.ops
            .iter()
            .map(|op| match op {
                RouteOp::PinExitToPhysical(ip) => {
                    let host = match ip {
                        IpAddr::V4(v4) => format!("{v4}/32"),
                        IpAddr::V6(v6) => format!("{v6}/128"),
                    };
                    vec![
                        "ip".to_owned(),
                        "route".to_owned(),
                        "del".to_owned(),
                        host,
                        "via".to_owned(),
                        physical_gateway.to_string(),
                    ]
                }
                RouteOp::RouteViaTun { cidr } => vec![
                    "ip".to_owned(),
                    "route".to_owned(),
                    "del".to_owned(),
                    cidr.clone(),
                    "dev".to_owned(),
                    dev.to_owned(),
                ],
            })
            .collect()
    }
}

/// A killswitch ruleset: only the tunnel and the carrier path to the exit are
/// allowed out; everything else (including a v6 leak when v6 is not tunneled) is
/// dropped, so a dropped tunnel fails closed instead of leaking to the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillswitchPlan {
    /// The nftables ruleset text (Linux). Other backends render their own.
    pub nftables: String,
}

impl KillswitchPlan {
    /// Renders an nftables ruleset that drops all output except: loopback, the
    /// TUN device, and UDP to the exit endpoint on the physical link. When no v6
    /// address is tunneled, all IPv6 output is dropped (v6 leak block).
    #[must_use]
    pub fn nftables(config: &TunConfig) -> Self {
        let exit_ip = config.exit_endpoint.ip();
        let exit_port = config.exit_endpoint.port();
        let block_v6 = config.ipv6.is_none();
        let mut s = String::new();
        s.push_str("table inet warren_killswitch {\n");
        s.push_str("  chain output {\n");
        s.push_str("    type filter hook output priority 0; policy drop;\n");
        s.push_str("    oif \"lo\" accept\n");
        s.push_str(&format!("    oif \"{}\" accept\n", config.name));
        // The carrier path to the exit on the physical link (UDP / QUIC).
        match exit_ip {
            IpAddr::V4(ip) => {
                s.push_str(&format!("    ip daddr {ip} udp dport {exit_port} accept\n"))
            }
            IpAddr::V6(ip) => s.push_str(&format!(
                "    ip6 daddr {ip} udp dport {exit_port} accept\n"
            )),
        }
        if block_v6 {
            // Fail closed on v6 when the tunnel carries only v4: no v6 leak.
            s.push_str("    meta nfproto ipv6 drop\n");
        }
        s.push_str("  }\n}\n");
        Self { nftables: s }
    }

    /// The argv that loads this ruleset, reading it from stdin (`nft -f -`). The
    /// applier feeds [`Self::nftables`] to the child's stdin. Pure (no exec).
    #[must_use]
    pub fn nft_apply_argv() -> Vec<String> {
        vec!["nft".to_owned(), "-f".to_owned(), "-".to_owned()]
    }

    /// The argv that tears the ruleset down (`nft delete table inet
    /// warren_killswitch`), restoring normal output. Pure (no exec).
    #[must_use]
    pub fn nft_teardown_argv() -> Vec<String> {
        ["nft", "delete", "table", "inet", "warren_killswitch"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4_config() -> TunConfig {
        TunConfig {
            name: "warren0".to_owned(),
            mtu: 1280,
            ipv4: (Ipv4Addr::new(10, 66, 0, 2), 16),
            ipv6: None,
            exit_endpoint: "203.0.113.9:51820".parse().unwrap(),
            dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
        }
    }

    #[test]
    fn split_default_pins_the_exit_then_captures_both_halves() {
        let plan = RoutingPlan::split_default(&v4_config());
        assert_eq!(
            plan.ops[0],
            RouteOp::PinExitToPhysical(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            "the exit carrier route must be pinned FIRST, before the capture"
        );
        let cidrs: Vec<_> = plan
            .ops
            .iter()
            .filter_map(|o| match o {
                RouteOp::RouteViaTun { cidr } => Some(cidr.as_str()),
                RouteOp::PinExitToPhysical(_) => None,
            })
            .collect();
        assert_eq!(cidrs, ["0.0.0.0/1", "128.0.0.0/1"]);
    }

    #[test]
    fn split_default_adds_the_v6_halves_only_when_v6_is_assigned() {
        let mut cfg = v4_config();
        cfg.ipv6 = Some((Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 2), 64));
        let plan = RoutingPlan::split_default(&cfg);
        let cidrs: Vec<_> = plan
            .ops
            .iter()
            .filter_map(|o| match o {
                RouteOp::RouteViaTun { cidr } => Some(cidr.as_str()),
                RouteOp::PinExitToPhysical(_) => None,
            })
            .collect();
        assert_eq!(cidrs, ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
    }

    #[test]
    fn killswitch_drops_by_default_and_allows_only_lo_tun_and_the_exit() {
        let ks = KillswitchPlan::nftables(&v4_config());
        assert!(ks.nftables.contains("policy drop;"));
        assert!(ks.nftables.contains("oif \"lo\" accept"));
        assert!(ks.nftables.contains("oif \"warren0\" accept"));
        assert!(
            ks.nftables
                .contains("ip daddr 203.0.113.9 udp dport 51820 accept")
        );
    }

    #[test]
    fn routing_plan_renders_ip_route_argv_in_order() {
        let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let cmds = RoutingPlan::split_default(&v4_config()).to_ip_commands("warren0", gw);
        assert_eq!(
            cmds[0],
            vec![
                "ip",
                "route",
                "replace",
                "203.0.113.9/32",
                "via",
                "192.168.1.1"
            ],
            "the exit carrier pin is emitted first, via the physical gateway"
        );
        assert_eq!(
            cmds[1],
            vec!["ip", "route", "replace", "0.0.0.0/1", "dev", "warren0"]
        );
        assert_eq!(
            cmds[2],
            vec!["ip", "route", "replace", "128.0.0.0/1", "dev", "warren0"]
        );
        assert_eq!(cmds.len(), 3, "v4-only config emits exactly three routes");
    }

    #[test]
    fn routing_teardown_argv_reverts_each_added_route() {
        let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let plan = RoutingPlan::split_default(&v4_config());
        let down = plan.to_teardown_commands("warren0", gw);
        // Same routes as the apply, but `del` instead of `replace`.
        assert_eq!(
            down[0],
            vec!["ip", "route", "del", "203.0.113.9/32", "via", "192.168.1.1"]
        );
        assert_eq!(
            down[1],
            vec!["ip", "route", "del", "0.0.0.0/1", "dev", "warren0"]
        );
        assert_eq!(down.len(), plan.ops.len());
        // Apply uses `replace`, teardown uses `del`: symmetric op count.
        let up = plan.to_ip_commands("warren0", gw);
        assert_eq!(up.len(), down.len());
        for (u, d) in up.iter().zip(&down) {
            assert_eq!(u[1], "route");
            assert_eq!(u[2], "replace");
            assert_eq!(d[2], "del");
        }
    }

    #[test]
    fn killswitch_apply_and_teardown_argv_are_stable() {
        assert_eq!(KillswitchPlan::nft_apply_argv(), ["nft", "-f", "-"]);
        assert_eq!(
            KillswitchPlan::nft_teardown_argv(),
            ["nft", "delete", "table", "inet", "warren_killswitch"]
        );
    }

    #[test]
    fn killswitch_blocks_v6_when_v6_is_not_tunneled() {
        let v4_only = KillswitchPlan::nftables(&v4_config());
        assert!(
            v4_only.nftables.contains("meta nfproto ipv6 drop"),
            "a v4-only tunnel must fail closed on v6 to prevent a leak"
        );

        let mut dual = v4_config();
        dual.ipv6 = Some((Ipv6Addr::LOCALHOST, 64));
        let dual = KillswitchPlan::nftables(&dual);
        assert!(
            !dual.nftables.contains("meta nfproto ipv6 drop"),
            "a dual-stack tunnel must not block its own v6"
        );
    }
}
