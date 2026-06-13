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
