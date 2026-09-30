//! Whether the host's own route already exits through a local Warren tunnel.
//!
//! A proxy datapath that runs beside a system-wide Warren tunnel (the desktop app,
//! connected) should stand aside instead of stacking a second tunnel on top: the
//! system tunnel already carries every flow of the host, and its kill switch does
//! not let a second client reach the relay the two share, so the proxy's own
//! tunnel dies and every client pointed at it stalls (2026-09-29, a browser behind
//! the extension's helper stalled on `ERR_TUNNEL_CONNECTION_FAILED` for as long as
//! the app stayed connected).
//!
//! [`watch_host_route`] publishes the verdict as the [`HostRoute`] the host uses,
//! or `None`. Only a route whose source address belongs to a local tunnel
//! interface (up, point-to-point) is ever a candidate: an address on a physical
//! card is refused before any check, because a gateway on the LAN that itself
//! exits through Warren would pass the check, and the proxy would then hand it
//! every flow in clear. A candidate becomes the verdict once a check sent over
//! that interface is answered as coming from a Warren exit, and the verdict is
//! withdrawn the moment the route changes, before any new check: a stale verdict
//! must never outlive the tunnel that proved it.

use std::future::Future;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::time::Duration;

use tokio::time::Instant;

/// How often the route is read. A read is a local route and interface lookup, no
/// packet leaves the host.
pub(crate) const ROUTE_POLL: Duration = Duration::from_secs(1);
/// How often a standing verdict is confirmed with a fresh check.
pub(crate) const RECHECK_WARREN: Duration = Duration::from_secs(30);
/// How long a tunnel route the check refused waits before it is asked again. A
/// new route is asked at once, so this only bounds the traffic of a tunnel that
/// never changes.
pub(crate) const RECHECK_REFUSED: Duration = Duration::from_secs(300);

/// The host's route toward the internet, when it leaves through a local tunnel
/// interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostRoute {
    /// The route's source address, which the tunnel interface holds.
    pub(crate) source: Ipv4Addr,
    /// The tunnel interface's index.
    pub(crate) interface: NonZeroU32,
    /// The tunnel interface's name.
    pub(crate) name: String,
}

/// Where the system Warren tunnel the host routes through comes out, as the
/// API's check placed the request it received over that tunnel.
///
/// Named for display only: the check that proved the route is what protects,
/// and a system tunnel that moves to another exit is renamed at the next
/// recheck, up to [`RECHECK_WARREN`] later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SystemExit {
    /// The exit's country, ISO 3166-1 alpha-2, upper-case, when the check
    /// named a well-formed one.
    pub country: Option<String>,
    /// The exit's city, when the check named one.
    pub city: Option<String>,
}

/// The longest city name kept from a check.
const MAX_CITY_CHARS: usize = 64;

impl SystemExit {
    /// The exit as a check named it. The answer is only as trusted as its TLS
    /// session and is rendered to the member, so anything that is not a
    /// two-letter country is dropped, and the city loses its control
    /// characters and is capped.
    #[must_use]
    pub fn new(country: Option<&str>, city: Option<&str>) -> Self {
        let country = country
            .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
            .map(str::to_ascii_uppercase);
        let city = city
            .map(|c| {
                c.chars()
                    .filter(|ch| !ch.is_control())
                    .take(MAX_CITY_CHARS)
                    .collect::<String>()
                    .trim()
                    .to_owned()
            })
            .filter(|c| !c.is_empty());
        Self { country, city }
    }
}

/// One IPv4 address of one interface, as far as [`tunnel_route`] needs it.
#[derive(Debug, Clone)]
pub(crate) struct InterfaceAddress {
    pub(crate) name: String,
    pub(crate) index: Option<u32>,
    pub(crate) address: Ipv4Addr,
    pub(crate) up: bool,
    pub(crate) point_to_point: bool,
}

/// The route leaving from `source`, when an up, point-to-point interface holds
/// that address and the address comes from Warren's own tunnel pool.
///
/// Point-to-point rules out a physical card, whose traffic a LAN gateway could
/// route through a Warren tunnel of its own and so pass the check. The pool rules
/// out any other tunnel whose far end exits through Warren (a Tailscale exit
/// node, a WireGuard link to a subscribed router): its peer would pass the check
/// too, and then see every flow.
pub(crate) fn tunnel_route(
    source: Ipv4Addr,
    interfaces: impl IntoIterator<Item = InterfaceAddress>,
) -> Option<HostRoute> {
    if !in_warren_pool(source) {
        return None;
    }
    interfaces
        .into_iter()
        .find(|i| i.address == source)
        .filter(|i| i.up && i.point_to_point)
        .and_then(|i| {
            Some(HostRoute {
                source,
                interface: NonZeroU32::new(i.index?)?,
                name: i.name,
            })
        })
}

/// Whether `address` belongs to the pool Warren exits assign tunnel addresses from.
fn in_warren_pool(address: Ipv4Addr) -> bool {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(warrenguard_config::TUNNEL_POOL_PREFIX))
        .unwrap_or(0);
    u32::from(address) & mask == u32::from(warrenguard_config::TUNNEL_POOL_NETWORK) & mask
}

/// The host route, as the watcher needs to read it.
pub(crate) trait HostRouteIo: Send + Sync + 'static {
    /// The host's route toward the internet when it leaves through a local
    /// tunnel interface, else `None`.
    fn route(&self) -> Option<HostRoute>;

    /// The Warren exit a check sent over `route` reached the API from, or
    /// `None` when it did not come from a Warren exit's egress. Any failure
    /// answers `None`.
    fn warren_exit<'a>(
        &'a self,
        route: &'a HostRoute,
    ) -> Pin<Box<dyn Future<Output = Option<SystemExit>> + Send + 'a>>;
}

/// Publishes on `tx` a host route proven to exit through Warren, or `None`,
/// until every receiver is gone, and on `exit_tx` where that route comes out.
/// The exit is published before the route it belongs to and cleared after it,
/// so a reader that sees a route always finds its exit.
pub(crate) async fn watch_host_route<I: HostRouteIo>(
    io: I,
    tx: tokio::sync::watch::Sender<Option<HostRoute>>,
    exit_tx: tokio::sync::watch::Sender<Option<SystemExit>>,
) {
    let withdraw = || {
        tx.send_replace(None);
        exit_tx.send_replace(None);
    };
    let mut verdict: Option<(HostRoute, Instant)> = None;
    let mut refused: Option<(HostRoute, Instant)> = None;
    while !tx.is_closed() {
        let route = io.route();
        if let Some((proven, at)) = verdict.take() {
            if route.as_ref() != Some(&proven) {
                withdraw();
            } else if at.elapsed() >= RECHECK_WARREN {
                if let Some(exit) = confirmed(&io, &proven).await {
                    exit_tx.send_if_modified(|current| {
                        let moved = current.as_ref() != Some(&exit);
                        *current = Some(exit);
                        moved
                    });
                    verdict = Some((proven, Instant::now()));
                } else {
                    withdraw();
                }
            } else {
                verdict = Some((proven, at));
            }
        }
        if verdict.is_none()
            && let Some(candidate) = route
        {
            let due = refused
                .as_ref()
                .is_none_or(|(r, at)| *r != candidate || at.elapsed() >= RECHECK_REFUSED);
            if due {
                if let Some(exit) = confirmed(&io, &candidate).await {
                    exit_tx.send_replace(Some(exit));
                    tx.send_replace(Some(candidate.clone()));
                    verdict = Some((candidate, Instant::now()));
                    refused = None;
                } else {
                    refused = Some((candidate, Instant::now()));
                }
            }
        }
        tokio::time::sleep(ROUTE_POLL).await;
    }
}

/// How a socket is carried inside the tunnel `route` leaves by: bound to its
/// interface on macOS (`IP_BOUND_IF`) and Windows (`IP_UNICAST_IF`). `None` on
/// Linux, whose routing already sends every socket but the system tunnel's own
/// into that tunnel, and elsewhere.
fn bypass_into(route: &HostRoute) -> Option<warren_transport::SocketBypass> {
    let index = route.interface.get();
    if cfg!(target_os = "macos") {
        Some(warren_transport::SocketBypass::BoundIf(index))
    } else if cfg!(windows) {
        Some(warren_transport::SocketBypass::UnicastIf(index))
    } else {
        None
    }
}

/// The binding that carries a socket inside the system Warren tunnel the host
/// routes through right now, or `None` when it routes through none. Read by
/// the proxy's own tunnel when it migrates: its relay is one the system
/// tunnel's kill switch admits only the system tunnel to, so a fresh socket
/// following the routing table would be refused, and one inside the system
/// tunnel reaches it. The session is encrypted end to end whatever carries
/// it, so no check of the tunnel's exit is needed for this.
pub(crate) fn system_tunnel_bypass() -> Option<warren_transport::SocketBypass> {
    bypass_into(&tunnel_route(route_source()?, interface_addresses())?)
}

/// Any global address: [`SystemHostRoute::route`] only asks the routing table
/// which source it would use toward it, nothing is sent.
const ROUTE_PROBE: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
/// How long the check may take.
#[cfg(feature = "reqwest-transport")]
const CHECK_TIMEOUT: Duration = Duration::from_secs(6);

/// The real host route: the routing table's source address, the interface that
/// holds it, and the API's unsigned `GET /v1/check` sent over that interface.
/// Unsigned on purpose, so the check carries no identity: it only asks where the
/// request came from.
#[cfg(feature = "reqwest-transport")]
pub(crate) struct SystemHostRoute {
    check_url: String,
}

#[cfg(feature = "reqwest-transport")]
impl SystemHostRoute {
    pub(crate) fn new(api_base: &str) -> Self {
        Self {
            check_url: format!("{}/v1/check", api_base.trim_end_matches('/')),
        }
    }
}

/// The IPv4 source the routing table picks toward the internet.
fn route_source() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(ROUTE_PROBE).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Every IPv4 address of every interface of the host.
#[cfg(unix)]
fn interface_addresses() -> Vec<InterfaceAddress> {
    use nix::net::if_::InterfaceFlags;
    let Ok(addresses) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    addresses
        .filter_map(|a| {
            let address = a.address.as_ref()?.as_sockaddr_in()?.ip();
            Some(InterfaceAddress {
                index: nix::net::if_::if_nametoindex(a.interface_name.as_str()).ok(),
                up: a.flags.contains(InterfaceFlags::IFF_UP),
                point_to_point: a.flags.contains(InterfaceFlags::IFF_POINTOPOINT),
                name: a.interface_name,
                address,
            })
        })
        .collect()
}

/// The GUID the Warren desktop app always creates its Windows tunnel adapter
/// with (warren-app `talpid-tunnel` `ADAPTER_GUID`, kept stable so Windows does
/// not see a new network on every connect). Inherited from Mullvad, whose own
/// adapter carries it too: a Mullvad tunnel can pass this and the pool test,
/// and it is the API check (`is_exit`) that refuses it.
const WARREN_ADAPTER_GUID: &str = "{AFE43773-E1F8-4EBB-8536-576AB86AFE9A}";

/// Whether an adapter is a Wintun tunnel of the Warren app's lineage, by the
/// GUID Windows names it with. Windows reports no point-to-point flag for a
/// Wintun adapter and has tunnel-typed adapters of its own (Teredo, IP-HTTPS,
/// 6to4), so neither the flag nor the type can stand in for this; creating an
/// adapter with a chosen GUID takes administrator rights.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_warren_adapter(adapter_name: &str) -> bool {
    adapter_name.eq_ignore_ascii_case(WARREN_ADAPTER_GUID)
}

/// Every IPv4 address of every adapter of the host. Only the Warren app's own
/// adapter counts as a tunnel.
#[cfg(windows)]
fn interface_addresses() -> Vec<InterfaceAddress> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    interfaces
        .into_iter()
        .filter_map(|i| {
            let if_addrs::IfAddr::V4(v4) = &i.addr else {
                return None;
            };
            Some(InterfaceAddress {
                address: v4.ip,
                index: i.index,
                up: i.is_oper_up(),
                point_to_point: is_warren_adapter(&i.adapter_name),
                name: i.name,
            })
        })
        .collect()
}

/// No interface is read elsewhere, so no verdict is ever given there.
#[cfg(not(any(unix, windows)))]
fn interface_addresses() -> Vec<InterfaceAddress> {
    Vec::new()
}

#[cfg(feature = "reqwest-transport")]
impl HostRouteIo for SystemHostRoute {
    /// Only where the tunnel interface can be told from a physical card:
    /// macOS and Linux by their point-to-point flag, Windows by the Warren
    /// app's adapter GUID. Elsewhere no verdict is ever given, and the proxy
    /// keeps its own tunnel.
    fn route(&self) -> Option<HostRoute> {
        if cfg!(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows"
        ))) {
            return None;
        }
        tunnel_route(route_source()?, interface_addresses())
    }

    fn warren_exit<'a>(
        &'a self,
        route: &'a HostRoute,
    ) -> Pin<Box<dyn Future<Output = Option<SystemExit>> + Send + 'a>> {
        #[derive(serde::Deserialize)]
        struct Check {
            #[serde(default)]
            is_exit: bool,
            #[serde(default)]
            exit_country: Option<String>,
            #[serde(default)]
            exit_city: Option<String>,
        }
        Box::pin(async move {
            let builder = reqwest::Client::builder()
                .local_address(std::net::IpAddr::V4(route.source))
                .timeout(CHECK_TIMEOUT);
            // Windows has no per-socket interface option here; its strong host
            // model sends a socket bound to the adapter's address out of that
            // adapter only.
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let builder = builder.interface(&route.name);
            let client = builder.build().ok()?;
            let response = client.get(&self.check_url).send().await.ok()?;
            let check = response.json::<Check>().await.ok()?;
            check
                .is_exit
                .then(|| SystemExit::new(check.exit_country.as_deref(), check.exit_city.as_deref()))
        })
    }
}

/// The exit a check over `route` placed it at, when that says Warren AND the
/// host still routes through it once the answer is in: a route that moved
/// during the check proves nothing.
async fn confirmed<I: HostRouteIo>(io: &I, route: &HostRoute) -> Option<SystemExit> {
    let exit = io.warren_exit(route).await?;
    (io.route().as_ref() == Some(route)).then_some(exit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    const PHYSICAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 12);
    const SYSTEM_TUNNEL: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 79);

    fn tunnel(source: Ipv4Addr) -> HostRoute {
        HostRoute {
            source,
            interface: NonZeroU32::new(14).expect("non-zero"),
            name: "utun14".into(),
        }
    }

    fn address(name: &str, address: Ipv4Addr, up: bool, point_to_point: bool) -> InterfaceAddress {
        InterfaceAddress {
            name: name.into(),
            index: Some(7),
            address,
            up,
            point_to_point,
        }
    }

    #[test]
    fn a_source_held_by_an_up_point_to_point_interface_is_a_tunnel_route() {
        let route = tunnel_route(
            SYSTEM_TUNNEL,
            [
                address("en0", PHYSICAL, true, false),
                address("utun14", SYSTEM_TUNNEL, true, true),
            ],
        )
        .expect("a tunnel route");

        assert_eq!(route.source, SYSTEM_TUNNEL);
        assert_eq!(route.interface.get(), 7);
        assert_eq!(route.name, "utun14");
    }

    /// A LAN gateway that exits through Warren of its own would pass the check
    /// for the physical address: that address must never even be a candidate.
    #[test]
    fn a_source_on_a_physical_card_is_never_a_tunnel_route() {
        let interfaces = [
            address("en0", PHYSICAL, true, false),
            address("utun14", SYSTEM_TUNNEL, true, true),
        ];

        assert_eq!(tunnel_route(PHYSICAL, interfaces), None);
    }

    /// Any tunnel whose far end happens to exit through Warren would pass the
    /// check (a Tailscale exit node, a WireGuard link to a router with its own
    /// subscription), and its peer would see every flow: only an address from
    /// Warren's own tunnel pool is ever a candidate.
    #[test]
    fn a_tunnel_outside_the_warren_pool_is_never_a_tunnel_route() {
        let tailscale = Ipv4Addr::new(100, 106, 181, 5);
        let wireguard = Ipv4Addr::new(10, 8, 0, 2);

        assert_eq!(
            tunnel_route(tailscale, [address("utun12", tailscale, true, true)]),
            None
        );
        assert_eq!(
            tunnel_route(wireguard, [address("utun9", wireguard, true, true)]),
            None
        );
    }

    /// Windows reports no point-to-point flag for a Wintun adapter, and has
    /// tunnel-typed adapters of its own (Teredo, IP-HTTPS, 6to4): only the
    /// adapter GUID of the app's lineage is a candidate.
    #[test]
    fn a_check_answer_is_kept_only_in_a_shape_the_popup_can_show() {
        assert_eq!(
            SystemExit::new(Some("fi"), Some("Helsinki")),
            helsinki(),
            "the country is upper-cased"
        );
        let hostile = SystemExit::new(Some("FIN"), Some("Hel\u{1b}[31msinki\n"));
        assert_eq!(hostile.country, None, "not a two-letter country");
        assert_eq!(hostile.city.as_deref(), Some("Hel[31msinki"));
        assert_eq!(
            SystemExit::new(None, Some(&"x".repeat(500)))
                .city
                .map(|c| c.chars().count()),
            Some(MAX_CITY_CHARS)
        );
        assert_eq!(
            SystemExit::new(Some("F1"), Some(" \t ")),
            SystemExit::default()
        );
    }

    #[test]
    fn only_the_warren_app_adapter_is_a_windows_tunnel() {
        assert!(is_warren_adapter("{AFE43773-E1F8-4EBB-8536-576AB86AFE9A}"));
        assert!(is_warren_adapter("{afe43773-e1f8-4ebb-8536-576ab86afe9a}"));
        for other in [
            "{93123211-9629-4E04-82F0-EA2E4F221468}",
            "{E287C945-01BC-4B45-AF7E-FF150F2BFBF2}",
            "AFE43773-E1F8-4EBB-8536-576AB86AFE9A",
            "",
        ] {
            assert!(!is_warren_adapter(other), "{other}");
        }
    }

    #[test]
    fn a_socket_is_carried_inside_the_system_tunnel_by_binding_its_interface() {
        let bypass = bypass_into(&tunnel(SYSTEM_TUNNEL));
        if cfg!(target_os = "macos") {
            assert_eq!(bypass, Some(warren_transport::SocketBypass::BoundIf(14)));
        } else if cfg!(windows) {
            assert_eq!(bypass, Some(warren_transport::SocketBypass::UnicastIf(14)));
        } else {
            assert_eq!(bypass, None, "routing already carries it there");
        }
    }

    #[test]
    fn a_down_tunnel_or_an_address_nobody_holds_is_no_route() {
        assert_eq!(
            tunnel_route(
                SYSTEM_TUNNEL,
                [address("utun14", SYSTEM_TUNNEL, false, true)]
            ),
            None
        );
        assert_eq!(
            tunnel_route(SYSTEM_TUNNEL, [address("en0", PHYSICAL, true, false)]),
            None
        );
    }

    #[derive(Default)]
    struct Fake {
        route: Mutex<Option<HostRoute>>,
        warren: Mutex<Vec<Ipv4Addr>>,
        exit: Mutex<SystemExit>,
        checks: Mutex<Vec<Ipv4Addr>>,
    }

    #[derive(Clone)]
    struct Io(Arc<Fake>);

    impl HostRouteIo for Io {
        fn route(&self) -> Option<HostRoute> {
            self.0.route.lock().unwrap().clone()
        }

        fn warren_exit<'a>(
            &'a self,
            route: &'a HostRoute,
        ) -> Pin<Box<dyn Future<Output = Option<SystemExit>> + Send + 'a>> {
            self.0.checks.lock().unwrap().push(route.source);
            let answer = self
                .0
                .warren
                .lock()
                .unwrap()
                .contains(&route.source)
                .then(|| self.0.exit.lock().unwrap().clone());
            Box::pin(async move { answer })
        }
    }

    fn helsinki() -> SystemExit {
        SystemExit {
            country: Some("FI".into()),
            city: Some("Helsinki".into()),
        }
    }

    fn start(fake: &Arc<Fake>) -> tokio::sync::watch::Receiver<Option<HostRoute>> {
        start_with_exit(fake).0
    }

    fn start_with_exit(
        fake: &Arc<Fake>,
    ) -> (
        tokio::sync::watch::Receiver<Option<HostRoute>>,
        tokio::sync::watch::Receiver<Option<SystemExit>>,
    ) {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let (exit_tx, exit_rx) = tokio::sync::watch::channel(None);
        tokio::spawn(watch_host_route(Io(Arc::clone(fake)), tx, exit_tx));
        (rx, exit_rx)
    }

    fn route(fake: &Fake, route: Option<HostRoute>) {
        *fake.route.lock().unwrap() = route;
    }

    async fn settle() {
        tokio::time::sleep(ROUTE_POLL * 2).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_route_the_check_places_at_a_warren_exit_is_published() {
        let fake = Arc::new(Fake::default());
        route(&fake, Some(tunnel(SYSTEM_TUNNEL)));
        fake.warren.lock().unwrap().push(SYSTEM_TUNNEL);

        let rx = start(&fake);
        settle().await;

        assert_eq!(*rx.borrow(), Some(tunnel(SYSTEM_TUNNEL)));
    }

    /// What the extension shows while its helper stands aside: the exit the
    /// member's traffic actually leaves by, which is the app's, never the one
    /// the helper would have picked.
    #[tokio::test(start_paused = true)]
    async fn the_exit_of_a_verdict_is_published_with_it_and_cleared_with_it() {
        let fake = Arc::new(Fake::default());
        route(&fake, Some(tunnel(SYSTEM_TUNNEL)));
        fake.warren.lock().unwrap().push(SYSTEM_TUNNEL);
        *fake.exit.lock().unwrap() = helsinki();

        let (rx, exit_rx) = start_with_exit(&fake);
        settle().await;
        assert_eq!(*rx.borrow(), Some(tunnel(SYSTEM_TUNNEL)));
        assert_eq!(*exit_rx.borrow(), Some(helsinki()));

        let stockholm = SystemExit {
            country: Some("SE".into()),
            city: Some("Stockholm".into()),
        };
        *fake.exit.lock().unwrap() = stockholm.clone();
        tokio::time::sleep(RECHECK_WARREN + ROUTE_POLL * 2).await;
        assert_eq!(
            *exit_rx.borrow(),
            Some(stockholm),
            "the app moved to another exit: the recheck says so"
        );

        route(&fake, None);
        tokio::time::sleep(ROUTE_POLL + Duration::from_millis(10)).await;
        assert_eq!(*rx.borrow(), None);
        assert_eq!(*exit_rx.borrow(), None, "no exit outlives its route");
    }

    #[tokio::test(start_paused = true)]
    async fn a_route_the_check_does_not_place_at_a_warren_exit_is_never_published() {
        let fake = Arc::new(Fake::default());
        route(&fake, Some(tunnel(SYSTEM_TUNNEL)));

        let rx = start(&fake);
        settle().await;

        assert_eq!(*rx.borrow(), None);
    }

    /// Off a tunnel there is nothing to ask: no check leaves the host's real
    /// address, which would tell the network the host runs Warren.
    #[tokio::test(start_paused = true)]
    async fn no_check_is_sent_while_the_route_leaves_by_no_tunnel() {
        let fake = Arc::new(Fake::default());

        let rx = start(&fake);
        tokio::time::sleep(ROUTE_POLL * 10).await;

        assert_eq!(*rx.borrow(), None);
        assert!(fake.checks.lock().unwrap().is_empty());
    }

    /// The whole safety of standing aside: the verdict dies with the route that
    /// proved it, at the next read of the route, without waiting for any check.
    #[tokio::test(start_paused = true)]
    async fn the_verdict_is_withdrawn_as_soon_as_the_route_leaves_its_tunnel() {
        let fake = Arc::new(Fake::default());
        route(&fake, Some(tunnel(SYSTEM_TUNNEL)));
        fake.warren.lock().unwrap().push(SYSTEM_TUNNEL);
        let rx = start(&fake);
        settle().await;
        assert_eq!(*rx.borrow(), Some(tunnel(SYSTEM_TUNNEL)));
        let checks_before = fake.checks.lock().unwrap().len();

        route(&fake, None);
        tokio::time::sleep(ROUTE_POLL + Duration::from_millis(10)).await;

        assert_eq!(*rx.borrow(), None);
        assert_eq!(
            fake.checks.lock().unwrap().len(),
            checks_before,
            "the withdrawal may not wait on any check"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_verdict_the_recheck_no_longer_confirms_is_withdrawn() {
        let fake = Arc::new(Fake::default());
        route(&fake, Some(tunnel(SYSTEM_TUNNEL)));
        fake.warren.lock().unwrap().push(SYSTEM_TUNNEL);
        let rx = start(&fake);
        settle().await;
        assert_eq!(*rx.borrow(), Some(tunnel(SYSTEM_TUNNEL)));

        fake.warren.lock().unwrap().clear();
        tokio::time::sleep(RECHECK_WARREN + ROUTE_POLL * 2).await;

        assert_eq!(*rx.borrow(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_tunnel_is_checked_at_once_and_a_refused_one_is_not_hammered() {
        let other = Ipv4Addr::new(10, 66, 3, 7);
        let fake = Arc::new(Fake::default());
        route(&fake, Some(tunnel(other)));
        let rx = start(&fake);
        tokio::time::sleep(ROUTE_POLL * 30).await;
        assert_eq!(
            fake.checks.lock().unwrap().len(),
            1,
            "one check for a tunnel that never changes, within the refused recheck"
        );

        fake.warren.lock().unwrap().push(SYSTEM_TUNNEL);
        route(&fake, Some(tunnel(SYSTEM_TUNNEL)));
        tokio::time::sleep(ROUTE_POLL * 2).await;

        assert_eq!(
            *rx.borrow(),
            Some(tunnel(SYSTEM_TUNNEL)),
            "the connect is noticed within a poll"
        );
    }

    /// Answers every request with `body` as JSON, and records the peer address.
    #[cfg(all(unix, feature = "reqwest-transport"))]
    async fn check_server(body: &'static str) -> (String, Arc<Mutex<Vec<std::net::IpAddr>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&peers);
        tokio::spawn(async move {
            while let Ok((mut stream, peer)) = listener.accept().await {
                seen.lock().unwrap().push(peer.ip());
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            }
        });
        (base, peers)
    }

    #[cfg(all(unix, feature = "reqwest-transport"))]
    fn loopback_route() -> HostRoute {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        HostRoute {
            source: Ipv4Addr::LOCALHOST,
            interface: NonZeroU32::new(nix::net::if_::if_nametoindex(name).expect("loopback"))
                .expect("non-zero"),
            name: name.into(),
        }
    }

    #[cfg(all(unix, feature = "reqwest-transport"))]
    #[tokio::test]
    async fn the_system_check_reads_the_verdict_over_the_given_route() {
        let (warren, peers) = check_server(
            r#"{"ip":"37.27.217.153","is_exit":true,"exit_country":"FI","exit_city":"Helsinki"}"#,
        )
        .await;
        let (plain, _) = check_server(r#"{"ip":"192.0.2.9","is_exit":false}"#).await;
        let route = loopback_route();

        assert_eq!(
            SystemHostRoute::new(&warren).warren_exit(&route).await,
            Some(helsinki())
        );
        assert_eq!(
            peers.lock().unwrap().as_slice(),
            &[std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "the check leaves from the source it vouches for"
        );
        assert_eq!(SystemHostRoute::new(&plain).warren_exit(&route).await, None);
    }

    #[cfg(all(unix, feature = "reqwest-transport"))]
    #[tokio::test]
    async fn a_check_that_cannot_be_sent_over_the_route_is_not_warren() {
        let (warren, peers) = check_server(r#"{"is_exit":true}"#).await;
        let gone = HostRoute {
            source: Ipv4Addr::new(192, 0, 2, 1),
            ..loopback_route()
        };

        let verdict = SystemHostRoute::new(&warren).warren_exit(&gone).await;

        assert_eq!(
            verdict, None,
            "a source the host does not hold proves nothing"
        );
        assert!(peers.lock().unwrap().is_empty());
    }

    /// The real thing, run by hand on a host whose Warren desktop app is
    /// connected (the Windows proof of the stand-aside):
    /// `cargo test -p warren-sdk --lib live_system_route -- --ignored --nocapture`,
    /// with `WARREN_LIVE_API` naming the app's API when it is not the build's.
    #[cfg(feature = "reqwest-transport")]
    #[tokio::test]
    #[ignore = "needs the Warren desktop app connected on this host"]
    async fn live_system_route_is_found_checked_and_carries_a_bound_flow() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use warren_net::proxy::Connector;
        let api =
            std::env::var("WARREN_LIVE_API").unwrap_or_else(|_| crate::product::API_URL.into());
        let io = SystemHostRoute::new(&api);

        let route = io
            .route()
            .expect("the host routes through the Warren app's tunnel adapter");
        let exit = io
            .warren_exit(&route)
            .await
            .expect("a check over that adapter is placed at a Warren exit");
        println!(
            "tunnel interface {} exits in {:?}",
            route.name, exit.country
        );

        let connector = warren_net::BoundHostConnector::new(
            route.source,
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(warrenguard_config::TUNNEL_GATEWAY_IP),
                53,
            ),
        )
        .on_interface(route.interface);
        let mut stream = connector
            .connect(warren_net::socks5::Target::Domain("example.com".into(), 80))
            .await
            .expect("a flow bound to the adapter resolves and connects");
        stream
            .write_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut head = [0u8; 12];
        stream.read_exact(&mut head).await.expect("read");
        assert!(head.starts_with(b"HTTP/1.1 "), "{head:?}");
    }

    /// On a host whose route leaves by a physical card (every CI runner, and a
    /// Mac without the app), the system route is no tunnel route.
    #[cfg(all(unix, feature = "reqwest-transport"))]
    #[test]
    fn the_system_route_is_only_ever_a_route_this_host_holds_on_a_tunnel() {
        let Some(route) = SystemHostRoute::new("http://unused").route() else {
            return;
        };
        let holder = interface_addresses()
            .into_iter()
            .find(|i| i.address == route.source)
            .expect("the host holds the route's source");
        assert!(holder.point_to_point && holder.up);
    }
}
