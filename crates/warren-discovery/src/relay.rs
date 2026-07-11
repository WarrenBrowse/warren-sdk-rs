//! Resolved relay types: a verified, parsed exit ready for selection.

use std::net::SocketAddr;

use crate::exit_id::ExitId;

/// Declared geolocation of a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    country_code: String,
    city: String,
}

impl Location {
    /// Builds a location from a country code and a city name.
    #[must_use]
    pub fn new(country_code: impl Into<String>, city: impl Into<String>) -> Self {
        Self {
            country_code: country_code.into(),
            city: city.into(),
        }
    }

    /// ISO 3166-1 alpha-2 country code.
    #[must_use]
    pub fn country_code(&self) -> &str {
        &self.country_code
    }

    /// City name (free form).
    #[must_use]
    pub fn city(&self) -> &str {
        &self.city
    }
}

/// A resolved Warren exit: identity, dialable addresses, and selection metadata.
///
/// `weight == 0` disables the relay for weighted selection even when active.
#[derive(Debug, Clone)]
pub struct Relay {
    endpoint_id: [u8; 32],
    exit_id: ExitId,
    addrs: Vec<SocketAddr>,
    location: Location,
    weight: u64,
    active: bool,
    ipv6_egress: bool,
    cover_domain: Option<String>,
    port_forward: Option<bool>,
}

impl Relay {
    /// Builds a relay. `ipv6_egress` defaults to `false` via [`Self::new`];
    /// use [`Self::with_ipv6_egress`] to set it.
    #[must_use]
    pub fn new(
        endpoint_id: [u8; 32],
        exit_id: ExitId,
        addrs: Vec<SocketAddr>,
        location: Location,
        weight: u64,
        active: bool,
    ) -> Self {
        Self {
            endpoint_id,
            exit_id,
            addrs,
            location,
            weight,
            active,
            ipv6_egress: false,
            cover_domain: None,
            port_forward: None,
        }
    }

    /// Sets the attested IPv6 egress capability.
    #[must_use]
    pub fn with_ipv6_egress(mut self, ipv6_egress: bool) -> Self {
        self.ipv6_egress = ipv6_egress;
        self
    }

    /// Sets the v6 X.509 cover-domain SNI advertised for this exit (wg-0005).
    #[must_use]
    pub fn with_cover_domain(mut self, cover_domain: Option<String>) -> Self {
        self.cover_domain = cover_domain;
        self
    }

    /// Sets the exit's NAT-PMP port-forwarding capability (doc 79): `Some(true)`
    /// if it runs an enabled gateway, `Some(false)` if explicitly disabled,
    /// `None` if the roster carried no flag (unknown). The SDK only offers or
    /// prefers port forwarding when this is `Some(true)`.
    #[must_use]
    pub fn with_port_forward(mut self, port_forward: Option<bool>) -> Self {
        self.port_forward = port_forward;
        self
    }

    /// Ed25519 identity of the exit (32-byte pubkey).
    #[must_use]
    pub fn endpoint_id(&self) -> [u8; 32] {
        self.endpoint_id
    }

    /// Stable operator-assigned identifier (survives key rotation).
    #[must_use]
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Dialable exit UDP socket addresses.
    #[must_use]
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Declared relay geolocation.
    #[must_use]
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Relative weight for random selection.
    #[must_use]
    pub fn weight(&self) -> u64 {
        self.weight
    }

    /// `true` if the relay is marked active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// `true` if at least one address is IPv4.
    #[must_use]
    pub fn has_ipv4(&self) -> bool {
        self.addrs.iter().any(SocketAddr::is_ipv4)
    }

    /// `true` if at least one address is IPv6.
    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.addrs.iter().any(SocketAddr::is_ipv6)
    }

    /// `true` if the exit advertises working IPv6 egress (it can route in-tunnel
    /// client traffic to the IPv6 internet). Orthogonal to [`Self::has_ipv6`].
    #[must_use]
    pub fn ipv6_egress(&self) -> bool {
        self.ipv6_egress
    }

    /// The v6 X.509 cover-domain SNI for this exit, if the roster advertises
    /// one (wg-0005). `None` means dial in RPK mode.
    #[must_use]
    pub fn cover_domain(&self) -> Option<&str> {
        self.cover_domain.as_deref()
    }

    /// The exit's NAT-PMP port-forwarding capability (doc 79): `Some(true)` if
    /// it runs an enabled gateway, `Some(false)` if explicitly disabled, `None`
    /// if the roster carried no flag (unknown).
    #[must_use]
    pub fn port_forward(&self) -> Option<bool> {
        self.port_forward
    }

    /// `true` only when the exit explicitly advertises an enabled NAT-PMP
    /// gateway. The SDK gates the port-forwarding feature on this: an unknown
    /// (`None`, legacy roster) or explicitly-disabled (`Some(false)`) exit is
    /// treated as not supporting it.
    #[must_use]
    pub fn supports_port_forward(&self) -> bool {
        self.port_forward == Some(true)
    }
}

/// A list of resolved relays.
#[derive(Debug, Clone, Default)]
pub struct RelayList {
    relays: Vec<Relay>,
}

impl RelayList {
    /// Builds a list from a vector of relays.
    #[must_use]
    pub fn new(relays: Vec<Relay>) -> Self {
        Self { relays }
    }

    /// Immutable slice of relays.
    #[must_use]
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    /// Total number of relays (including inactive).
    #[must_use]
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// `true` if the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }
}
