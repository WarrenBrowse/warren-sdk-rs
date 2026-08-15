//! The peer address plan: which addresses the gateway hands its peers, and
//! which addresses it must never hand out.
//!
//! Two ranges must not collide. The tunnel pool is the engine-wide range an
//! exit assigns a Warren session from; the peer subnet is the local range the
//! gateway numbers its own WireGuard peers in. A peer numbered inside the
//! tunnel pool would make the NAT and cryptokey routing disagree about who
//! owns an address, so the overlap is refused where the plan is built rather
//! than diagnosed later from a packet that vanished.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ip_network::{IpNetwork, Ipv4Network, Ipv6Network};

/// The IPv4 range an exit assigns a Warren session from.
pub const TUNNEL_POOL_V4: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 66, 0, 0), 16);
/// The IPv6 range an exit assigns a Warren session from.
pub const TUNNEL_POOL_V6: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 0), 64);
/// The gateway and resolver address inside the tunnel pool.
pub const TUNNEL_GATEWAY_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
/// The IPv6 gateway and resolver address inside the tunnel pool.
pub const TUNNEL_GATEWAY_V6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 1);
/// Default IPv4 peer subnet.
pub const DEFAULT_PEER_SUBNET_V4: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 67, 0, 0), 24);
/// Default IPv6 peer subnet, a ULA spelling "warre" in hex.
pub const DEFAULT_PEER_SUBNET_V6: (Ipv6Addr, u8) =
    (Ipv6Addr::new(0xfd77, 0x6172, 0x7265, 0, 0, 0, 0, 0), 64);

/// Why an address plan was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// The subnet overlaps the range the exit assigns tunnel addresses from.
    #[error("peer subnet overlaps the tunnel pool")]
    TunnelPoolOverlap,
    /// An IPv6 subnet was offered where an IPv4 one belongs, or the reverse.
    #[error("peer subnet has the wrong address family")]
    WrongFamily,
    /// The subnet has no room for a gateway address and at least one peer.
    #[error("peer subnet too small")]
    SubnetTooSmall,
    /// The peer number names the network address, the gateway, or an address
    /// outside the subnet.
    #[error("peer number outside the subnet")]
    IndexOutOfRange,
}

/// True while `addr` belongs to the range an exit assigns from.
#[must_use]
pub fn is_tunnel_pool(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => in_v4(v4, TUNNEL_POOL_V4),
        IpAddr::V6(v6) => in_v6(v6, TUNNEL_POOL_V6),
    }
}

/// True while `addr` is the exit's own gateway and resolver address.
#[must_use]
pub fn is_tunnel_gateway(addr: IpAddr) -> bool {
    addr == IpAddr::V4(TUNNEL_GATEWAY_V4) || addr == IpAddr::V6(TUNNEL_GATEWAY_V6)
}

fn in_v4(addr: Ipv4Addr, (base, prefix): (Ipv4Addr, u8)) -> bool {
    let mask = mask32(prefix);
    (u32::from(addr) & mask) == (u32::from(base) & mask)
}

fn in_v6(addr: Ipv6Addr, (base, prefix): (Ipv6Addr, u8)) -> bool {
    let mask = mask128(prefix);
    (u128::from(addr) & mask) == (u128::from(base) & mask)
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Where the gateway numbers its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPlan {
    v4: Ipv4Network,
    v6: Ipv6Network,
}

impl PeerPlan {
    /// Builds a plan over one IPv4 and one IPv6 subnet.
    ///
    /// # Errors
    ///
    /// [`PlanError::WrongFamily`] when a subnet is of the wrong family,
    /// [`PlanError::TunnelPoolOverlap`] when either subnet meets the range the
    /// exit assigns from, [`PlanError::SubnetTooSmall`] when the IPv4 subnet
    /// has no room for a gateway address and a peer.
    pub fn new(v4: IpNetwork, v6: IpNetwork) -> Result<Self, PlanError> {
        let (IpNetwork::V4(v4), IpNetwork::V6(v6)) = (v4, v6) else {
            return Err(PlanError::WrongFamily);
        };
        if v4.netmask() > 30 {
            return Err(PlanError::SubnetTooSmall);
        }
        if overlaps_v4(v4, TUNNEL_POOL_V4) {
            return Err(PlanError::TunnelPoolOverlap);
        }
        if overlaps_v6(v6, TUNNEL_POOL_V6) {
            return Err(PlanError::TunnelPoolOverlap);
        }
        Ok(Self { v4, v6 })
    }

    /// The IPv4 subnet peers are numbered in.
    #[must_use]
    pub fn subnet_v4(&self) -> Ipv4Network {
        self.v4
    }

    /// The IPv6 subnet peers are numbered in.
    #[must_use]
    pub fn subnet_v6(&self) -> Ipv6Network {
        self.v6
    }

    /// The gateway's own address inside the IPv4 peer subnet.
    #[must_use]
    pub fn gateway_v4(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.v4.network_address()) | 1)
    }

    /// The gateway's own address inside the IPv6 peer subnet.
    #[must_use]
    pub fn gateway_v6(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.v6.network_address()) | 1)
    }

    /// The pair of addresses peer number `index` is given.
    ///
    /// # Errors
    ///
    /// [`PlanError::IndexOutOfRange`] for the network address, the gateway
    /// address, or anything past the end of the subnet.
    pub fn address_for(&self, index: u32) -> Result<(Ipv4Addr, Ipv6Addr), PlanError> {
        let host_bits = 32 - u32::from(self.v4.netmask());
        let last = if host_bits >= 32 {
            u32::MAX
        } else {
            (1u32 << host_bits) - 1
        };
        if index < 2 || index >= last {
            return Err(PlanError::IndexOutOfRange);
        }
        Ok((
            Ipv4Addr::from(u32::from(self.v4.network_address()) | index),
            Ipv6Addr::from(u128::from(self.v6.network_address()) | u128::from(index)),
        ))
    }

    /// True while `addr` belongs to either peer subnet.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.v4.contains(v4),
            IpAddr::V6(v6) => self.v6.contains(v6),
        }
    }

    /// True while `addr` is one of the gateway's own peer-subnet addresses.
    #[must_use]
    pub fn is_gateway(&self, addr: IpAddr) -> bool {
        addr == IpAddr::V4(self.gateway_v4()) || addr == IpAddr::V6(self.gateway_v6())
    }
}

impl Default for PeerPlan {
    fn default() -> Self {
        let v4 = Ipv4Network::new(DEFAULT_PEER_SUBNET_V4.0, DEFAULT_PEER_SUBNET_V4.1)
            .expect("the default IPv4 peer subnet is a valid network");
        let v6 = Ipv6Network::new(DEFAULT_PEER_SUBNET_V6.0, DEFAULT_PEER_SUBNET_V6.1)
            .expect("the default IPv6 peer subnet is a valid network");
        Self { v4, v6 }
    }
}

fn overlaps_v4(net: Ipv4Network, other: (Ipv4Addr, u8)) -> bool {
    // Two prefixes overlap when one contains the other's base, whichever is
    // the shorter: a supernet of the pool is as much of a collision as a
    // subnet of it.
    in_v4(net.network_address(), other) || in_v4(other.0, (net.network_address(), net.netmask()))
}

fn overlaps_v6(net: Ipv6Network, other: (Ipv6Addr, u8)) -> bool {
    in_v6(net.network_address(), other) || in_v6(other.0, (net.network_address(), net.netmask()))
}

/// The whole address space with `exclude` cut out of it, as the list a peer
/// writes in its `AllowedIPs`.
///
/// A client that excludes its own LAN keeps reaching it directly; every other
/// destination still enters the tunnel. An excluded prefix is unprotected,
/// which is why the generated README says so next to the list.
#[must_use]
pub fn complement(exclude: &[IpNetwork]) -> Vec<IpNetwork> {
    let mut v4: Vec<(u32, u8)> = vec![(0, 0)];
    let mut v6: Vec<(u128, u8)> = vec![(0, 0)];
    for network in exclude {
        match network {
            IpNetwork::V4(net) => {
                v4 = subtract32(&v4, u32::from(net.network_address()), net.netmask());
            }
            IpNetwork::V6(net) => {
                v6 = subtract128(&v6, u128::from(net.network_address()), net.netmask());
            }
        }
    }
    let mut out = Vec::with_capacity(v4.len() + v6.len());
    v4.sort_unstable();
    v6.sort_unstable();
    for (base, prefix) in v4 {
        if let Ok(net) = Ipv4Network::new(Ipv4Addr::from(base), prefix) {
            out.push(IpNetwork::V4(net));
        }
    }
    for (base, prefix) in v6 {
        if let Ok(net) = Ipv6Network::new(Ipv6Addr::from(base), prefix) {
            out.push(IpNetwork::V6(net));
        }
    }
    out
}

fn subtract32(networks: &[(u32, u8)], base: u32, prefix: u8) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    for &(net_base, net_prefix) in networks {
        if net_prefix > prefix || (base & mask32(net_prefix)) != net_base {
            // Disjoint from the exclusion, or entirely inside it.
            if !(net_prefix >= prefix && (net_base & mask32(prefix)) == (base & mask32(prefix))) {
                out.push((net_base, net_prefix));
            }
            continue;
        }
        for length in (net_prefix + 1)..=prefix {
            let sibling = (base & mask32(length)) ^ (1u32 << (32 - length));
            out.push((sibling, length));
        }
    }
    out
}

fn subtract128(networks: &[(u128, u8)], base: u128, prefix: u8) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    for &(net_base, net_prefix) in networks {
        if net_prefix > prefix || (base & mask128(net_prefix)) != net_base {
            if !(net_prefix >= prefix && (net_base & mask128(prefix)) == (base & mask128(prefix))) {
                out.push((net_base, net_prefix));
            }
            continue;
        }
        for length in (net_prefix + 1)..=prefix {
            let sibling = (base & mask128(length)) ^ (1u128 << (128 - length));
            out.push((sibling, length));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr as _;

    fn net(value: &str) -> IpNetwork {
        IpNetwork::from_str(value).expect("a network literal")
    }

    #[test]
    fn numbers_every_peer_from_the_second_address_of_each_subnet() {
        let plan = PeerPlan::default();
        assert_eq!(plan.gateway_v4(), Ipv4Addr::new(10, 67, 0, 1));
        assert_eq!(
            plan.gateway_v6(),
            Ipv6Addr::from_str("fd77:6172:7265::1").unwrap()
        );
        assert_eq!(
            plan.address_for(2).unwrap(),
            (
                Ipv4Addr::new(10, 67, 0, 2),
                Ipv6Addr::from_str("fd77:6172:7265::2").unwrap()
            )
        );
        assert_eq!(
            plan.address_for(254).unwrap().0,
            Ipv4Addr::new(10, 67, 0, 254)
        );
    }

    #[test]
    fn refuses_an_index_that_is_not_a_peer_address() {
        let plan = PeerPlan::default();
        for index in [0, 1, 255, 256] {
            assert_eq!(
                plan.address_for(index).unwrap_err(),
                PlanError::IndexOutOfRange,
                "index {index}"
            );
        }
    }

    #[test]
    fn refuses_a_peer_subnet_that_overlaps_the_tunnel_pool() {
        let default_v6 = PeerPlan::default().subnet_v6();
        assert_eq!(
            PeerPlan::new(net("10.66.5.0/24"), IpNetwork::V6(default_v6)).unwrap_err(),
            PlanError::TunnelPoolOverlap
        );
        // A supernet of the pool overlaps it just as much as a subnet does.
        assert_eq!(
            PeerPlan::new(net("10.0.0.0/8"), IpNetwork::V6(default_v6)).unwrap_err(),
            PlanError::TunnelPoolOverlap
        );
        let default_v4 = PeerPlan::default().subnet_v4();
        assert_eq!(
            PeerPlan::new(IpNetwork::V4(default_v4), net("fdcc:f:1::/96")).unwrap_err(),
            PlanError::TunnelPoolOverlap
        );
    }

    #[test]
    fn refuses_a_subnet_of_the_wrong_family_or_with_no_room_for_a_peer() {
        let default_v6 = IpNetwork::V6(PeerPlan::default().subnet_v6());
        let default_v4 = IpNetwork::V4(PeerPlan::default().subnet_v4());
        assert_eq!(
            PeerPlan::new(default_v6, default_v6).unwrap_err(),
            PlanError::WrongFamily
        );
        assert_eq!(
            PeerPlan::new(default_v4, default_v4).unwrap_err(),
            PlanError::WrongFamily
        );
        assert_eq!(
            PeerPlan::new(net("10.67.0.0/31"), default_v6).unwrap_err(),
            PlanError::SubnetTooSmall
        );
    }

    #[test]
    fn knows_which_addresses_belong_to_the_plan_and_to_the_tunnel() {
        let plan = PeerPlan::default();
        assert!(plan.contains(IpAddr::V4(Ipv4Addr::new(10, 67, 0, 9))));
        assert!(!plan.contains(IpAddr::V4(Ipv4Addr::new(10, 68, 0, 9))));
        assert!(plan.is_gateway(IpAddr::V4(Ipv4Addr::new(10, 67, 0, 1))));
        assert!(!plan.is_gateway(IpAddr::V4(Ipv4Addr::new(10, 67, 0, 2))));
        assert!(is_tunnel_pool(IpAddr::V4(Ipv4Addr::new(10, 66, 3, 4))));
        assert!(is_tunnel_pool(IpAddr::V6(
            Ipv6Addr::from_str("fdcc:f:1::1").unwrap()
        )));
        assert!(!is_tunnel_pool(IpAddr::V4(Ipv4Addr::new(10, 67, 0, 2))));
    }

    #[test]
    fn covers_the_whole_space_except_the_excluded_lan() {
        let excluded = net("192.168.1.0/24");
        let complement = complement(&[excluded]);

        for network in &complement {
            assert!(
                !network.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))),
                "{network} still carries the excluded LAN"
            );
        }
        for covered in [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)),
            IpAddr::V6(Ipv6Addr::from_str("2001:4860:4860::8888").unwrap()),
        ] {
            assert!(
                complement.iter().any(|network| network.contains(covered)),
                "{covered:?} is routed nowhere"
            );
        }
        // The v6 half is untouched by a v4 exclusion, so it stays one route.
        assert_eq!(
            complement
                .iter()
                .filter(|network| !network.is_ipv4())
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["::/0".to_string()]
        );
    }

    #[test]
    fn renders_the_whole_space_when_nothing_is_excluded() {
        assert_eq!(
            complement(&[])
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
        );
    }
}
