//! Exit selection query: geography and IP availability constraints.

use crate::relay::Relay;

/// Location constraint: none, by country, or by (country, city) pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LocationConstraint {
    /// No location constraint.
    #[default]
    Any,
    /// Match by ISO-3166 alpha-2 country code (case-insensitive).
    Country(String),
    /// Match by (country code, city name), both compared case-insensitively.
    City {
        /// ISO-3166 alpha-2 country code.
        country_code: String,
        /// City name (free form).
        city: String,
    },
}

/// IP availability required at selection time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IpAvailability {
    /// Client has both v4 and v6: any relay is fine.
    #[default]
    Both,
    /// Client has v4 only: exclude v6-only relays.
    Ipv4Only,
    /// Client has v6 only: exclude v4-only relays.
    Ipv6Only,
}

/// Composite exit selection query.
#[derive(Debug, Clone, Default)]
pub struct ExitQuery {
    location: LocationConstraint,
    ip_availability: IpAvailability,
    require_ipv6_egress: bool,
    require_port_forward: bool,
}

impl ExitQuery {
    /// Query without any constraint.
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Shorthand for a country constraint.
    #[must_use]
    pub fn country(code: impl Into<String>) -> Self {
        Self::any().with_location(LocationConstraint::Country(code.into()))
    }

    /// Adds a location constraint.
    #[must_use]
    pub fn with_location(mut self, location: LocationConstraint) -> Self {
        self.location = location;
        self
    }

    /// Adds an IP availability constraint.
    #[must_use]
    pub fn with_ip_availability(mut self, ip: IpAvailability) -> Self {
        self.ip_availability = ip;
        self
    }

    /// Requires exits with attested IPv6 egress.
    #[must_use]
    pub fn with_require_ipv6_egress(mut self, require: bool) -> Self {
        self.require_ipv6_egress = require;
        self
    }

    /// Requires exits that advertise an enabled NAT-PMP port-forwarding gateway
    /// (doc 79). Set this when the app wants port forwarding so the selector
    /// only returns capable exits, rather than picking one that would refuse
    /// the mapping. An unknown (legacy roster) or explicitly-disabled exit is
    /// excluded.
    #[must_use]
    pub fn with_require_port_forward(mut self, require: bool) -> Self {
        self.require_port_forward = require;
        self
    }

    /// `true` if `relay` satisfies every constraint.
    #[must_use]
    pub(crate) fn matches(&self, relay: &Relay) -> bool {
        if !relay.is_active() {
            return false;
        }
        if !location_matches(&self.location, relay) {
            return false;
        }
        if !ip_matches(self.ip_availability, relay) {
            return false;
        }
        if self.require_ipv6_egress && !relay.ipv6_egress() {
            return false;
        }
        if self.require_port_forward && !relay.supports_port_forward() {
            return false;
        }
        true
    }
}

fn location_matches(constraint: &LocationConstraint, relay: &Relay) -> bool {
    match constraint {
        LocationConstraint::Any => true,
        LocationConstraint::Country(cc) => relay.location().country_code().eq_ignore_ascii_case(cc),
        LocationConstraint::City { country_code, city } => {
            relay
                .location()
                .country_code()
                .eq_ignore_ascii_case(country_code)
                && relay.location().city().eq_ignore_ascii_case(city)
        }
    }
}

fn ip_matches(ip: IpAvailability, relay: &Relay) -> bool {
    match ip {
        IpAvailability::Both => relay.has_ipv4() || relay.has_ipv6(),
        IpAvailability::Ipv4Only => relay.has_ipv4(),
        IpAvailability::Ipv6Only => relay.has_ipv6(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit_id::ExitId;
    use crate::relay::{Location, Relay};
    use std::net::SocketAddr;

    fn relay_with(addrs: &[&str], active: bool) -> Relay {
        let addrs = addrs.iter().map(|a| a.parse::<SocketAddr>().unwrap());
        Relay::new(
            [0xab; 32],
            ExitId::from_bytes([0xcd; 16]),
            addrs.collect(),
            Location::new("RO", "Bucharest"),
            100,
            active,
        )
    }

    #[test]
    fn ip_availability_filters_by_family() {
        let v4 = relay_with(&["127.0.0.1:443"], true);
        let v6 = relay_with(&["[2001:db8::1]:443"], true);
        let dual = relay_with(&["127.0.0.1:443", "[2001:db8::1]:443"], true);

        assert!(ExitQuery::any().matches(&v4));
        assert!(ExitQuery::any().matches(&v6));

        let v4_only = ExitQuery::any().with_ip_availability(IpAvailability::Ipv4Only);
        assert!(v4_only.matches(&v4));
        assert!(!v4_only.matches(&v6), "v6-only relay must be excluded");
        assert!(v4_only.matches(&dual));

        let v6_only = ExitQuery::any().with_ip_availability(IpAvailability::Ipv6Only);
        assert!(!v6_only.matches(&v4), "v4-only relay must be excluded");
        assert!(v6_only.matches(&v6));
        assert!(v6_only.matches(&dual));
    }

    #[test]
    fn inactive_relay_never_matches() {
        let inactive = relay_with(&["127.0.0.1:443"], false);
        assert!(!ExitQuery::any().matches(&inactive));
    }

    #[test]
    fn require_ipv6_egress_excludes_non_egressing_relays() {
        let no_egress = relay_with(&["[2001:db8::1]:443"], true);
        let egress = relay_with(&["[2001:db8::1]:443"], true).with_ipv6_egress(true);

        let q = ExitQuery::any().with_require_ipv6_egress(true);
        assert!(!q.matches(&no_egress));
        assert!(q.matches(&egress));
        // Without the requirement, both pass.
        assert!(ExitQuery::any().matches(&no_egress));
    }

    #[test]
    fn require_port_forward_excludes_non_capable_and_unknown_relays() {
        // doc 79: when the app requests port forwarding, the selector must only
        // return exits that explicitly advertise an enabled NAT-PMP gateway. An
        // exit with no flag (legacy roster, unknown) or an explicitly-disabled
        // one must be excluded, so the app never lands on an exit that would
        // refuse the mapping.
        let unknown = relay_with(&["127.0.0.1:443"], true);
        let disabled = relay_with(&["127.0.0.1:443"], true).with_port_forward(Some(false));
        let capable = relay_with(&["127.0.0.1:443"], true).with_port_forward(Some(true));

        let q = ExitQuery::any().with_require_port_forward(true);
        assert!(!q.matches(&unknown), "unknown capability must be excluded");
        assert!(!q.matches(&disabled), "disabled NAT-PMP must be excluded");
        assert!(q.matches(&capable), "enabled NAT-PMP must match");
        // Without the requirement, all three pass.
        assert!(ExitQuery::any().matches(&unknown));
        assert!(ExitQuery::any().matches(&disabled));
    }

    #[test]
    fn location_constraint_matches_country_and_city_case_insensitively() {
        let relay = relay_with(&["127.0.0.1:443"], true);
        assert!(ExitQuery::country("ro").matches(&relay));
        assert!(!ExitQuery::country("de").matches(&relay));
        let city = ExitQuery::any().with_location(LocationConstraint::City {
            country_code: "RO".to_owned(),
            city: "bucharest".to_owned(),
        });
        assert!(city.matches(&relay));
        let wrong_city = ExitQuery::any().with_location(LocationConstraint::City {
            country_code: "RO".to_owned(),
            city: "Cluj".to_owned(),
        });
        assert!(!wrong_city.matches(&relay));
    }

    #[test]
    fn relay_accessors_reflect_construction() {
        let relay = relay_with(&["127.0.0.1:443", "[2001:db8::1]:443"], true);
        assert_eq!(relay.endpoint_id(), [0xab; 32]);
        assert_eq!(relay.exit_id(), ExitId::from_bytes([0xcd; 16]));
        assert_eq!(relay.weight(), 100);
        assert!(relay.is_active());
        assert!(relay.has_ipv4());
        assert!(relay.has_ipv6());
        assert!(!relay.ipv6_egress());
        assert_eq!(relay.location().country_code(), "RO");
        assert_eq!(relay.location().city(), "Bucharest");
        assert_eq!(relay.addrs().len(), 2);
        // doc 79: NAT-PMP capability defaults to unknown, and unknown is not a
        // supported exit for the gate.
        assert_eq!(relay.port_forward(), None);
        assert!(!relay.supports_port_forward(), "unknown is not supported");
        assert!(
            relay.with_port_forward(Some(true)).supports_port_forward(),
            "an enabled NAT-PMP exit is supported"
        );
    }
}
