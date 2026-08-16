//! The gateway configuration file and the artifacts it generates.
//!
//! The file is the shape every WireGuard user already knows, parsed here by
//! hand: a configuration format is not worth a dependency, and a hand parser
//! is what lets the file stay readable by `wg-quick` while carrying the one
//! thing WireGuard has no field for, the operator's label for a device, in a
//! comment it ignores.
//!
//! Key material never leaves this module as a plain `String`: every rendered
//! artifact is a `Zeroizing<String>` because each one carries a peer's private
//! key, and each one is a bearer credential for the operator's subscription.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr as _;

use ip_network::IpNetwork;
use zeroize::Zeroizing;

use crate::keys::{GatewayKey, KeyError, PeerPublicKey, PresharedKey};
use crate::peer::{LabelError, PeerLabel};
use crate::plan::{PeerPlan, complement, overlaps_tunnel_pool};

/// Why a configuration file was refused.
///
/// Every variant names the rule that refused, never the value that broke it:
/// the file holds key material and addresses, and a refusal is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfError {
    /// A line is neither a section header, a comment, nor `key = value`, or a
    /// setting appeared before any section.
    #[error("configuration line cannot be read")]
    Syntax,
    /// A key could not be decoded.
    #[error("configuration carries an unreadable key")]
    Key(#[source] KeyError),
    /// A label could not be validated.
    #[error("configuration carries an unusable peer label")]
    Label(#[source] LabelError),
    /// An `AllowedIPs` entry is not a CIDR prefix.
    #[error("configuration carries an unreadable network")]
    Network,
    /// The `[Interface]` section carries no `PrivateKey`.
    #[error("no gateway private key")]
    MissingPrivateKey,
    /// A `[Peer]` section carries no `PublicKey`.
    #[error("peer without a public key")]
    MissingPublicKey,
    /// A `[Peer]` section carries no `AllowedIPs`, so nothing would ever be
    /// routed to it and it could source anything.
    #[error("peer without allowed IPs")]
    MissingAllowedIps,
    /// Two peers claim addresses that overlap, so no owner is unambiguous.
    #[error("two peers claim overlapping allowed IPs")]
    OverlappingAllowedIps,
    /// A peer claims an address the exit assigns tunnel sessions from.
    #[error("peer claims an address of the tunnel pool")]
    TunnelPoolAllowedIps,
    /// A peer claims the gateway's own address inside the peer subnet.
    #[error("peer claims the gateway's own address")]
    GatewayAddressAllowedIps,
    /// Two peers carry the same static public key.
    #[error("two peers share one public key")]
    DuplicatePeerKey,
    /// Two peers carry the same label.
    #[error("two peers share one label")]
    DuplicateLabel,
    /// The gateway has no session index left to number a peer with. Reusing
    /// one would demux a stranger's data packet onto a live peer, so the
    /// configuration is refused instead.
    #[error("more peers than the index space holds")]
    TooManyPeers,
}

/// One peer as the gateway configuration declares it.
pub struct PeerConf {
    /// The operator's name for the device.
    pub label: PeerLabel,
    /// The peer's static public key.
    pub public: PeerPublicKey,
    /// The optional symmetric key mixed into the handshake.
    pub psk: Option<PresharedKey>,
    /// What the peer may source from, and what is routed to it.
    pub allowed: Vec<IpNetwork>,
}

impl std::fmt::Debug for PeerConf {
    // The label is the only handle that may be rendered; keys and addresses
    // are identity material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConf")
            .field("label", &self.label)
            .field("networks", &self.allowed.len())
            .finish()
    }
}

/// The gateway's own configuration.
pub struct GatewayConf {
    /// The gateway's static key pair.
    pub key: GatewayKey,
    /// Every peer, in file order.
    pub peers: Vec<PeerConf>,
}

impl GatewayConf {
    /// Checks the rules that hold whatever the deployment's plan is.
    ///
    /// Parsing already runs these; a configuration built in memory (a reload
    /// assembled by the admin path) has not been through the parser.
    ///
    /// # Errors
    ///
    /// A [`ConfError`] naming the rule that refused.
    pub fn validate(&self) -> Result<(), ConfError> {
        check_peers(&self.peers)
    }

    /// Checks the rules that need the deployment's address plan.
    ///
    /// # Errors
    ///
    /// [`ConfError::GatewayAddressAllowedIps`] when a peer claims the
    /// gateway's own address inside the peer subnet.
    pub fn check_against(&self, plan: &PeerPlan) -> Result<(), ConfError> {
        for peer in &self.peers {
            for network in &peer.allowed {
                if network.contains(IpAddr::V4(plan.gateway_v4()))
                    || network.contains(IpAddr::V6(plan.gateway_v6()))
                {
                    return Err(ConfError::GatewayAddressAllowedIps);
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for GatewayConf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayConf")
            .field("peers", &self.peers.len())
            .finish()
    }
}

/// Reads a gateway configuration file.
///
/// `text` carries the gateway's private key and every peer's preshared key in
/// clear, so the caller reads the file into a buffer it wipes (a
/// [`Zeroizing`] `String`, which derefs to `&str`) rather than a plain `String`
/// it drops. Everything this module renders back out is already zeroized.
///
/// # Errors
///
/// A [`ConfError`] naming the rule that refused. Nothing is returned
/// partially: a file with one bad peer is a bad file, because starting with a
/// silently dropped peer is how a device stops working with no diagnosis.
pub fn parse_gateway_conf(text: &str) -> Result<GatewayConf, ConfError> {
    let mut key: Option<GatewayKey> = None;
    let mut peers: Vec<PeerConf> = Vec::new();
    let mut section = Section::None;
    let mut pending: Option<PendingPeer> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#').or_else(|| line.strip_prefix(';')) {
            // The one comment with a meaning: the label wg-quick has no field
            // for. Anything else is the operator's own note.
            if let Some((name, value)) = split_setting(comment.trim())
                && name.eq_ignore_ascii_case("label")
                && let Some(peer) = pending.as_mut()
            {
                peer.label = Some(PeerLabel::new(value).map_err(ConfError::Label)?);
            }
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if let Some(peer) = pending.take() {
                peers.push(peer.finish()?);
            }
            section = match header.trim().to_ascii_lowercase().as_str() {
                "interface" => Section::Interface,
                "peer" => {
                    pending = Some(PendingPeer::default());
                    Section::Peer
                }
                _ => return Err(ConfError::Syntax),
            };
            continue;
        }
        let (name, value) = split_setting(line).ok_or(ConfError::Syntax)?;
        match (section, name.to_ascii_lowercase().as_str()) {
            (Section::Interface, "privatekey") => {
                key = Some(GatewayKey::from_base64(value).map_err(ConfError::Key)?);
            }
            // ListenPort, Address, MTU and the rest belong to the shell's own
            // configuration, not to the responder; they are accepted so an
            // operator can keep one file, and ignored.
            (Section::Interface, _) => {}
            (Section::Peer, field) => {
                let peer = pending.as_mut().ok_or(ConfError::Syntax)?;
                match field {
                    "publickey" => {
                        peer.public =
                            Some(PeerPublicKey::from_base64(value).map_err(ConfError::Key)?);
                    }
                    "presharedkey" => {
                        peer.psk = Some(PresharedKey::from_base64(value).map_err(ConfError::Key)?);
                    }
                    "allowedips" => {
                        for entry in value.split(',') {
                            let entry = entry.trim();
                            if entry.is_empty() {
                                continue;
                            }
                            peer.allowed
                                .push(IpNetwork::from_str(entry).map_err(|_| ConfError::Network)?);
                        }
                    }
                    _ => {}
                }
            }
            (Section::None, _) => return Err(ConfError::Syntax),
        }
    }
    if let Some(peer) = pending.take() {
        peers.push(peer.finish()?);
    }

    for (position, peer) in peers.iter_mut().enumerate() {
        if peer.label.as_str().is_empty() {
            peer.label =
                PeerLabel::new(&format!("peer{}", position + 1)).map_err(ConfError::Label)?;
        }
    }
    check_peers(&peers)?;

    Ok(GatewayConf {
        key: key.ok_or(ConfError::MissingPrivateKey)?,
        peers,
    })
}

fn check_peers(peers: &[PeerConf]) -> Result<(), ConfError> {
    // Every rule below is a property of the peer, not of one of its networks,
    // so none of them may be nested inside the walk over `allowed`: a peer
    // that claims nothing would then be examined by nothing, and a duplicate
    // key would demux two devices onto one session.
    for peer in peers {
        if peer.allowed.is_empty() {
            return Err(ConfError::MissingAllowedIps);
        }
        for network in &peer.allowed {
            if overlaps_tunnel_pool(*network) {
                return Err(ConfError::TunnelPoolAllowedIps);
            }
        }
    }
    for (position, peer) in peers.iter().enumerate() {
        for other in peers.iter().skip(position + 1) {
            if other.public == peer.public {
                return Err(ConfError::DuplicatePeerKey);
            }
            if other.label == peer.label {
                return Err(ConfError::DuplicateLabel);
            }
            // Cryptokey routing resolves an address by longest match, so an
            // address covered by two peers has no owner the NAT and the router
            // would agree on.
            for network in &peer.allowed {
                if other
                    .allowed
                    .iter()
                    .any(|candidate| overlaps(*candidate, *network))
                {
                    return Err(ConfError::OverlappingAllowedIps);
                }
            }
        }
    }
    Ok(())
}

fn overlaps(left: IpNetwork, right: IpNetwork) -> bool {
    left.contains(right.network_address()) || right.contains(left.network_address())
}

fn split_setting(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name, value.trim()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Default)]
struct PendingPeer {
    label: Option<PeerLabel>,
    public: Option<PeerPublicKey>,
    psk: Option<PresharedKey>,
    allowed: Vec<IpNetwork>,
}

impl PendingPeer {
    fn finish(self) -> Result<PeerConf, ConfError> {
        let public = self.public.ok_or(ConfError::MissingPublicKey)?;
        if self.allowed.is_empty() {
            return Err(ConfError::MissingAllowedIps);
        }
        Ok(PeerConf {
            // An empty label is the marker for "number it by position", which
            // needs the whole file to have been read.
            label: self.label.unwrap_or(PeerLabel::EMPTY),
            public,
            psk: self.psk,
            allowed: self.allowed,
        })
    }
}

/// Renders a gateway configuration file.
#[must_use]
pub fn render_gateway_conf(conf: &GatewayConf) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    let _ = writeln!(out, "[Interface]");
    let _ = writeln!(out, "PrivateKey = {}", *conf.key.to_base64_zeroizing());
    for peer in &conf.peers {
        let _ = writeln!(out);
        let _ = writeln!(out, "[Peer]");
        let _ = writeln!(out, "# label = {}", peer.label);
        let _ = writeln!(out, "PublicKey = {}", peer.public.to_base64());
        if let Some(psk) = &peer.psk {
            let _ = writeln!(out, "PresharedKey = {}", *psk.to_base64_zeroizing());
        }
        let _ = writeln!(out, "AllowedIPs = {}", join_networks(&peer.allowed));
    }
    out
}

fn join_networks(networks: &[IpNetwork]) -> String {
    networks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Everything one peer needs to reach this gateway.
pub struct ClientConf {
    /// The operator's name for the device.
    pub label: PeerLabel,
    /// The peer's own private key, base64.
    pub private_key: Zeroizing<String>,
    /// The peer's address inside the IPv4 peer subnet.
    pub address_v4: Ipv4Addr,
    /// The peer's address inside the IPv6 peer subnet, absent only for a host
    /// whose kernel has IPv6 disabled entirely.
    pub address_v6: Option<Ipv6Addr>,
    /// The gateway's public key.
    pub gateway_public: PeerPublicKey,
    /// The symmetric key mixed into this peer's handshake.
    pub psk: PresharedKey,
    /// Where the peer sends its datagrams.
    pub endpoint: SocketAddr,
    /// The resolver written into the config, absent when the operator turned
    /// it off.
    pub dns: Option<IpAddr>,
    /// The interface MTU the peer is told to use.
    pub mtu: u16,
    /// How often the peer sends a keepalive, which is what holds open the NAT
    /// between the peer and the gateway.
    pub keepalive: u16,
    /// Prefixes the peer keeps reaching directly, outside the tunnel.
    pub lan_exclude: Vec<IpNetwork>,
}

impl ClientConf {
    /// What the peer routes into the tunnel.
    ///
    /// The whole space by default, in both families whatever the exit
    /// currently offers: a peer that routed only IPv4 would keep its own
    /// native IPv6 default route and send every AAAA-resolved connection
    /// outside the tunnel, under its own address.
    #[must_use]
    pub fn allowed_ips(&self) -> Vec<IpNetwork> {
        let mut networks = if self.lan_exclude.is_empty() {
            complement(&[])
        } else {
            complement(&self.lan_exclude)
        };
        if self.address_v6.is_none() {
            networks.retain(IpNetwork::is_ipv4);
        }
        networks
    }
}

impl std::fmt::Debug for ClientConf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConf")
            .field("label", &self.label)
            .finish()
    }
}

/// Renders the configuration a stock WireGuard client reads.
#[must_use]
pub fn render_client_conf(conf: &ClientConf) -> Zeroizing<String> {
    let mut addresses = format!("{}/32", conf.address_v4);
    if let Some(v6) = conf.address_v6 {
        let _ = write!(addresses, ", {v6}/128");
    }

    let mut out = Zeroizing::new(String::new());
    let _ = writeln!(out, "[Interface]");
    let _ = writeln!(out, "PrivateKey = {}", *conf.private_key);
    let _ = writeln!(out, "Address = {addresses}");
    if let Some(dns) = conf.dns {
        let _ = writeln!(out, "DNS = {dns}");
    }
    let _ = writeln!(out, "MTU = {}", conf.mtu);
    let _ = writeln!(out);
    let _ = writeln!(out, "[Peer]");
    let _ = writeln!(out, "PublicKey = {}", conf.gateway_public.to_base64());
    let _ = writeln!(out, "PresharedKey = {}", *conf.psk.to_base64_zeroizing());
    let _ = writeln!(out, "AllowedIPs = {}", join_networks(&conf.allowed_ips()));
    let _ = writeln!(out, "Endpoint = {}", conf.endpoint);
    let _ = writeln!(out, "PersistentKeepalive = {}", conf.keepalive);
    out
}

/// Renders the environment snippet gluetun reads.
///
/// gluetun's own INI reader takes only the two keys and the addresses out of a
/// `.conf` file: it ignores `MTU`, `DNS`, `AllowedIPs` and
/// `PersistentKeepalive`. A gateway peer left at gluetun's defaults would run
/// with MTU 0 (its own probing, through this gateway) and no keepalive (the
/// NAT in front of it ages out and inbound traffic dies), so both are set
/// here, in the environment, where gluetun does read them.
#[must_use]
pub fn render_gluetun_env(conf: &ClientConf) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    let _ = writeln!(out, "VPN_SERVICE_PROVIDER=custom");
    let _ = writeln!(out, "VPN_TYPE=wireguard");
    // gluetun parses this as an address, never as a name.
    let _ = writeln!(out, "WIREGUARD_ENDPOINT_IP={}", conf.endpoint.ip());
    let _ = writeln!(out, "WIREGUARD_ENDPOINT_PORT={}", conf.endpoint.port());
    let _ = writeln!(
        out,
        "WIREGUARD_PUBLIC_KEY={}",
        conf.gateway_public.to_base64()
    );
    let _ = writeln!(out, "WIREGUARD_PRIVATE_KEY={}", *conf.private_key);
    let _ = writeln!(
        out,
        "WIREGUARD_PRESHARED_KEY={}",
        *conf.psk.to_base64_zeroizing()
    );
    let _ = writeln!(out, "WIREGUARD_ADDRESSES={}/32", conf.address_v4);
    let _ = writeln!(out, "WIREGUARD_MTU={}", conf.mtu);
    let _ = writeln!(
        out,
        "WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL={}s",
        conf.keepalive
    );
    if let Some(v6) = conf.address_v6 {
        let _ = writeln!(
            out,
            "# WIREGUARD_ADDRESSES stays v4 only: gluetun refuses to start with an IPv6 interface"
        );
        let _ = writeln!(
            out,
            "# address unless the container network has IPv6 routes. On such a network, add"
        );
        let _ = writeln!(out, "# {v6}/128 to the list above.");
    }
    let _ = writeln!(
        out,
        "# WIREGUARD_ALLOWED_IPS is left at gluetun's default (0.0.0.0/0,::/0, filtered per"
    );
    let _ = writeln!(
        out,
        "# IPv6 support): its own firewall drops v6 when unsupported, so nothing leaks."
    );
    if let Some(dns) = conf.dns {
        let _ = writeln!(
            out,
            "# gluetun's DNS over TLS works through the tunnel. To use the exit resolver instead:"
        );
        let _ = writeln!(out, "# DNS_UPSTREAM_RESOLVER_TYPE=plain");
        let _ = writeln!(out, "# DNS_UPSTREAM_PLAIN_ADDRESSES={dns}:53");
        let _ = writeln!(
            out,
            "# gluetun then warns that the address is private and suggests FIREWALL_OUTBOUND_SUBNETS."
        );
        let _ = writeln!(
            out,
            "# Ignore that advice: {dns} lives on the far side of the tunnel and must not be"
        );
        let _ = writeln!(out, "# in FIREWALL_OUTBOUND_SUBNETS.");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const PEER_PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const PEER_PUBLIC: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const PSK: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    const GATEWAY_PUBLIC: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";

    fn two_peer_file() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {PEER_PRIVATE}\n\
             ListenPort = 51820\n\
             \n\
             [Peer]\n\
             # label = livingroom-tv\n\
             PublicKey = {PEER_PUBLIC}\n\
             PresharedKey = {PSK}\n\
             AllowedIPs = 10.67.0.2/32, fd77:6172:7265::2/128\n\
             \n\
             ; a comment in the other spelling\n\
             [Peer]\n\
             # label = nas\n\
             PublicKey = {GATEWAY_PUBLIC}\n\
             AllowedIPs = 10.67.0.3/32\n"
        )
    }

    fn client() -> ClientConf {
        ClientConf {
            label: PeerLabel::new("peer1").unwrap(),
            private_key: Zeroizing::new(PEER_PRIVATE.to_owned()),
            address_v4: Ipv4Addr::new(10, 67, 0, 2),
            address_v6: Some(Ipv6Addr::from_str("fd77:6172:7265::2").unwrap()),
            gateway_public: PeerPublicKey::from_base64(GATEWAY_PUBLIC).unwrap(),
            psk: PresharedKey::from_base64(PSK).unwrap(),
            endpoint: SocketAddr::from_str("192.168.1.10:51820").unwrap(),
            dns: Some(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))),
            mtu: 1280,
            keepalive: 25,
            lan_exclude: Vec::new(),
        }
    }

    #[test]
    fn parses_a_two_peer_file() {
        let conf = parse_gateway_conf(&two_peer_file()).expect("a well formed file");
        assert_eq!(*conf.key.to_base64_zeroizing(), PEER_PRIVATE);
        assert_eq!(conf.peers.len(), 2);

        let first = &conf.peers[0];
        assert_eq!(first.label.as_str(), "livingroom-tv");
        assert_eq!(first.public.to_base64(), PEER_PUBLIC);
        assert_eq!(
            first
                .psk
                .as_ref()
                .map(|psk| (*psk.to_base64_zeroizing()).clone()),
            Some(PSK.to_owned())
        );
        assert_eq!(
            first
                .allowed
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["10.67.0.2/32", "fd77:6172:7265::2/128"]
        );

        let second = &conf.peers[1];
        assert_eq!(second.label.as_str(), "nas");
        assert!(second.psk.is_none());
    }

    #[test]
    fn refuses_a_file_with_no_gateway_key() {
        let text =
            "[Peer]\nPublicKey = ".to_owned() + PEER_PUBLIC + "\nAllowedIPs = 10.67.0.2/32\n";
        assert_eq!(
            parse_gateway_conf(&text).unwrap_err(),
            ConfError::MissingPrivateKey
        );
    }

    #[test]
    fn refuses_a_peer_without_allowed_ips() {
        let text = format!(
            "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n[Peer]\nPublicKey = {PEER_PUBLIC}\n"
        );
        assert_eq!(
            parse_gateway_conf(&text).unwrap_err(),
            ConfError::MissingAllowedIps
        );
    }

    #[test]
    fn refuses_a_peer_without_a_public_key() {
        let text = format!(
            "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n[Peer]\nAllowedIPs = 10.67.0.2/32\n"
        );
        assert_eq!(
            parse_gateway_conf(&text).unwrap_err(),
            ConfError::MissingPublicKey
        );
    }

    #[test]
    fn refuses_two_peers_that_claim_the_same_address() {
        let text = format!(
            "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n\
             [Peer]\n# label = a\nPublicKey = {PEER_PUBLIC}\nAllowedIPs = 10.67.0.0/24\n\n\
             [Peer]\n# label = b\nPublicKey = {GATEWAY_PUBLIC}\nAllowedIPs = 10.67.0.3/32\n"
        );
        assert_eq!(
            parse_gateway_conf(&text).unwrap_err(),
            ConfError::OverlappingAllowedIps
        );
    }

    #[test]
    fn refuses_a_peer_that_claims_a_tunnel_address() {
        let text = format!(
            "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n\
             [Peer]\n# label = a\nPublicKey = {PEER_PUBLIC}\nAllowedIPs = 10.66.0.2/32\n"
        );
        assert_eq!(
            parse_gateway_conf(&text).unwrap_err(),
            ConfError::TunnelPoolAllowedIps
        );
    }

    #[test]
    fn refuses_every_prefix_that_meets_the_tunnel_pool() {
        // A supernet of the pool claims every address inside it just as much
        // as a host route does, and it is the shape that escaped the first
        // check: the prefix's own base sits outside the pool.
        for claim in [
            "10.66.0.2/32",
            "10.66.0.0/16",
            "10.0.0.0/8",
            "0.0.0.0/0",
            "fdcc:f:1::/64",
            "fdcc::/16",
            "::/0",
        ] {
            let text = format!(
                "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n\
                 [Peer]\n# label = a\nPublicKey = {PEER_PUBLIC}\nAllowedIPs = {claim}\n"
            );
            assert_eq!(
                parse_gateway_conf(&text).unwrap_err(),
                ConfError::TunnelPoolAllowedIps,
                "{claim} was accepted"
            );
        }
    }

    #[test]
    fn validate_refuses_a_peer_built_in_memory_without_allowed_ips() {
        let conf = GatewayConf {
            key: GatewayKey::from_base64(PEER_PRIVATE).expect("a valid key"),
            peers: vec![PeerConf {
                label: PeerLabel::new("a").expect("a valid label"),
                public: PeerPublicKey::from_base64(PEER_PUBLIC).expect("a valid key"),
                psk: None,
                allowed: Vec::new(),
            }],
        };
        assert_eq!(conf.validate().unwrap_err(), ConfError::MissingAllowedIps);
    }

    #[test]
    fn validate_refuses_two_peers_sharing_a_key_when_the_first_claims_nothing() {
        // Every per-peer rule used to live inside the loop over the peer's own
        // networks, so a peer with no network was never examined at all and
        // the duplicate key demuxed both devices onto one session.
        let conf = GatewayConf {
            key: GatewayKey::from_base64(PEER_PRIVATE).expect("a valid key"),
            peers: vec![
                PeerConf {
                    label: PeerLabel::new("a").expect("a valid label"),
                    public: PeerPublicKey::from_base64(PEER_PUBLIC).expect("a valid key"),
                    psk: None,
                    allowed: Vec::new(),
                },
                PeerConf {
                    label: PeerLabel::new("b").expect("a valid label"),
                    public: PeerPublicKey::from_base64(PEER_PUBLIC).expect("a valid key"),
                    psk: None,
                    allowed: vec![IpNetwork::from_str("10.67.0.3/32").expect("a valid network")],
                },
            ],
        };
        assert!(matches!(
            conf.validate().unwrap_err(),
            ConfError::MissingAllowedIps | ConfError::DuplicatePeerKey
        ));
    }

    #[test]
    fn refuses_a_peer_that_claims_the_gateway_own_address() {
        let text = format!(
            "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n\
             [Peer]\n# label = a\nPublicKey = {PEER_PUBLIC}\nAllowedIPs = 10.67.0.1/32\n"
        );
        let conf = parse_gateway_conf(&text).expect("the plan is not part of parsing");
        assert_eq!(
            conf.check_against(&PeerPlan::default()).unwrap_err(),
            ConfError::GatewayAddressAllowedIps
        );
    }

    #[test]
    fn refuses_two_peers_with_the_same_key_or_the_same_label() {
        let same_key = format!(
            "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n\
             [Peer]\n# label = a\nPublicKey = {PEER_PUBLIC}\nAllowedIPs = 10.67.0.2/32\n\n\
             [Peer]\n# label = b\nPublicKey = {PEER_PUBLIC}\nAllowedIPs = 10.67.0.3/32\n"
        );
        assert_eq!(
            parse_gateway_conf(&same_key).unwrap_err(),
            ConfError::DuplicatePeerKey
        );
        let same_label = format!(
            "[Interface]\nPrivateKey = {PEER_PRIVATE}\n\n\
             [Peer]\n# label = a\nPublicKey = {PEER_PUBLIC}\nAllowedIPs = 10.67.0.2/32\n\n\
             [Peer]\n# label = a\nPublicKey = {GATEWAY_PUBLIC}\nAllowedIPs = 10.67.0.3/32\n"
        );
        assert_eq!(
            parse_gateway_conf(&same_label).unwrap_err(),
            ConfError::DuplicateLabel
        );
    }

    #[test]
    fn refuses_a_line_it_cannot_read() {
        let text = format!("[Interface]\nPrivateKey = {PEER_PRIVATE}\nthis is not a setting\n");
        assert_eq!(parse_gateway_conf(&text).unwrap_err(), ConfError::Syntax);
        let text = format!("PrivateKey = {PEER_PRIVATE}\n");
        assert_eq!(parse_gateway_conf(&text).unwrap_err(), ConfError::Syntax);
        let text = "[Interface]\nPrivateKey = not-a-key\n".to_owned();
        assert_eq!(
            parse_gateway_conf(&text).unwrap_err(),
            ConfError::Key(KeyError::BadEncoding)
        );
    }

    #[test]
    fn renders_a_gateway_file_it_can_read_back() {
        let conf = parse_gateway_conf(&two_peer_file()).expect("a well formed file");
        let rendered = render_gateway_conf(&conf);
        assert_eq!(
            *rendered,
            format!(
                "[Interface]\n\
                 PrivateKey = {PEER_PRIVATE}\n\
                 \n\
                 [Peer]\n\
                 # label = livingroom-tv\n\
                 PublicKey = {PEER_PUBLIC}\n\
                 PresharedKey = {PSK}\n\
                 AllowedIPs = 10.67.0.2/32, fd77:6172:7265::2/128\n\
                 \n\
                 [Peer]\n\
                 # label = nas\n\
                 PublicKey = {GATEWAY_PUBLIC}\n\
                 AllowedIPs = 10.67.0.3/32\n"
            )
        );
        let round_trip = parse_gateway_conf(&rendered).expect("what we render, we parse");
        assert_eq!(round_trip.peers.len(), 2);
        assert_eq!(round_trip.peers[0].label.as_str(), "livingroom-tv");
    }

    #[test]
    fn renders_a_client_config_that_routes_every_family_into_the_tunnel() {
        assert_eq!(
            *render_client_conf(&client()),
            format!(
                "[Interface]\n\
                 PrivateKey = {PEER_PRIVATE}\n\
                 Address = 10.67.0.2/32, fd77:6172:7265::2/128\n\
                 DNS = 10.66.0.1\n\
                 MTU = 1280\n\
                 \n\
                 [Peer]\n\
                 PublicKey = {GATEWAY_PUBLIC}\n\
                 PresharedKey = {PSK}\n\
                 AllowedIPs = 0.0.0.0/0, ::/0\n\
                 Endpoint = 192.168.1.10:51820\n\
                 PersistentKeepalive = 25\n"
            )
        );
    }

    #[test]
    fn renders_no_resolver_line_when_the_operator_turned_it_off() {
        let mut conf = client();
        conf.dns = None;
        assert!(!render_client_conf(&conf).as_str().contains("DNS"));
    }

    #[test]
    fn renders_a_v4_only_client_config_for_a_host_without_ipv6() {
        let mut conf = client();
        conf.address_v6 = None;
        let rendered = render_client_conf(&conf);
        let rendered = rendered.as_str();
        assert!(rendered.contains("Address = 10.67.0.2/32\n"), "{rendered}");
        assert!(rendered.contains("AllowedIPs = 0.0.0.0/0\n"), "{rendered}");
        assert!(!rendered.contains("::/0"), "{rendered}");
    }

    #[test]
    fn renders_the_complement_of_an_excluded_lan() {
        let mut conf = client();
        conf.lan_exclude = vec![IpNetwork::from_str("192.168.1.0/24").unwrap()];
        let rendered = render_client_conf(&conf);
        let line = rendered
            .lines()
            .find(|line| line.starts_with("AllowedIPs = "))
            .expect("an AllowedIPs line");
        assert!(!line.contains("0.0.0.0/0"), "{line}");
        assert!(line.contains("::/0"), "{line}");
        assert!(line.contains("192.168.0.0/24"), "{line}");
        assert!(!line.contains(" 192.168.1.0/24"), "{line}");
    }

    #[test]
    fn renders_the_gluetun_snippet_with_the_variables_gluetun_actually_reads() {
        assert_eq!(
            *render_gluetun_env(&client()),
            format!(
                "VPN_SERVICE_PROVIDER=custom\n\
                 VPN_TYPE=wireguard\n\
                 WIREGUARD_ENDPOINT_IP=192.168.1.10\n\
                 WIREGUARD_ENDPOINT_PORT=51820\n\
                 WIREGUARD_PUBLIC_KEY={GATEWAY_PUBLIC}\n\
                 WIREGUARD_PRIVATE_KEY={PEER_PRIVATE}\n\
                 WIREGUARD_PRESHARED_KEY={PSK}\n\
                 WIREGUARD_ADDRESSES=10.67.0.2/32\n\
                 WIREGUARD_MTU=1280\n\
                 WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL=25s\n\
                 # WIREGUARD_ADDRESSES stays v4 only: gluetun refuses to start with an IPv6 interface\n\
                 # address unless the container network has IPv6 routes. On such a network, add\n\
                 # fd77:6172:7265::2/128 to the list above.\n\
                 # WIREGUARD_ALLOWED_IPS is left at gluetun's default (0.0.0.0/0,::/0, filtered per\n\
                 # IPv6 support): its own firewall drops v6 when unsupported, so nothing leaks.\n\
                 # gluetun's DNS over TLS works through the tunnel. To use the exit resolver instead:\n\
                 # DNS_UPSTREAM_RESOLVER_TYPE=plain\n\
                 # DNS_UPSTREAM_PLAIN_ADDRESSES=10.66.0.1:53\n\
                 # gluetun then warns that the address is private and suggests FIREWALL_OUTBOUND_SUBNETS.\n\
                 # Ignore that advice: 10.66.0.1 lives on the far side of the tunnel and must not be\n\
                 # in FIREWALL_OUTBOUND_SUBNETS.\n"
            )
        );
    }

    #[test]
    fn renders_no_key_material_when_a_client_config_is_printed() {
        let conf = client();
        let rendered = format!("{conf:?}");
        assert!(!rendered.contains(PEER_PRIVATE), "{rendered}");
        assert!(!rendered.contains(PSK), "{rendered}");
        assert!(!rendered.contains(GATEWAY_PUBLIC), "{rendered}");
        assert!(rendered.contains("peer1"), "{rendered}");
    }
}
