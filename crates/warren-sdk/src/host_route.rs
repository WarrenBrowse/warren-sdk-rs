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

    /// Whether a check sent over `route` reached the API from a Warren exit's
    /// egress. Any failure answers `false`.
    fn exits_through_warren<'a>(
        &'a self,
        route: &'a HostRoute,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// Publishes on `tx` a host route proven to exit through Warren, or `None`,
/// until every receiver is gone.
pub(crate) async fn watch_host_route<I: HostRouteIo>(
    io: I,
    tx: tokio::sync::watch::Sender<Option<HostRoute>>,
) {
    let mut verdict: Option<(HostRoute, Instant)> = None;
    let mut refused: Option<(HostRoute, Instant)> = None;
    while !tx.is_closed() {
        let route = io.route();
        if let Some((proven, at)) = verdict.take() {
            if route.as_ref() != Some(&proven) {
                tx.send_replace(None);
            } else if at.elapsed() >= RECHECK_WARREN {
                if confirmed(&io, &proven).await {
                    verdict = Some((proven, Instant::now()));
                } else {
                    tx.send_replace(None);
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
                if confirmed(&io, &candidate).await {
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

/// No interface is read off Unix, so no verdict is ever given there.
#[cfg(not(unix))]
fn interface_addresses() -> Vec<InterfaceAddress> {
    Vec::new()
}

#[cfg(feature = "reqwest-transport")]
impl HostRouteIo for SystemHostRoute {
    /// Windows is left out until a Warren tunnel adapter there is proven to
    /// report as point-to-point: without that proof no verdict is ever given, and
    /// the proxy keeps its own tunnel.
    fn route(&self) -> Option<HostRoute> {
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            return None;
        }
        tunnel_route(route_source()?, interface_addresses())
    }

    fn exits_through_warren<'a>(
        &'a self,
        route: &'a HostRoute,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        #[derive(serde::Deserialize)]
        struct Check {
            #[serde(default)]
            is_exit: bool,
        }
        Box::pin(async move {
            let builder = reqwest::Client::builder()
                .local_address(std::net::IpAddr::V4(route.source))
                .timeout(CHECK_TIMEOUT);
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let builder = builder.interface(&route.name);
            let Ok(client) = builder.build() else {
                return false;
            };
            let Ok(response) = client.get(&self.check_url).send().await else {
                return false;
            };
            response
                .json::<Check>()
                .await
                .is_ok_and(|check| check.is_exit)
        })
    }
}

/// A check over `route` says Warren AND the host still routes through it once
/// the answer is in: a route that moved during the check proves nothing.
async fn confirmed<I: HostRouteIo>(io: &I, route: &HostRoute) -> bool {
    io.exits_through_warren(route).await && io.route().as_ref() == Some(route)
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
        checks: Mutex<Vec<Ipv4Addr>>,
    }

    #[derive(Clone)]
    struct Io(Arc<Fake>);

    impl HostRouteIo for Io {
        fn route(&self) -> Option<HostRoute> {
            self.0.route.lock().unwrap().clone()
        }

        fn exits_through_warren<'a>(
            &'a self,
            route: &'a HostRoute,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            self.0.checks.lock().unwrap().push(route.source);
            let answer = self.0.warren.lock().unwrap().contains(&route.source);
            Box::pin(async move { answer })
        }
    }

    fn start(fake: &Arc<Fake>) -> tokio::sync::watch::Receiver<Option<HostRoute>> {
        let (tx, rx) = tokio::sync::watch::channel(None);
        tokio::spawn(watch_host_route(Io(Arc::clone(fake)), tx));
        rx
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
        let (warren, peers) = check_server(r#"{"ip":"37.27.217.153","is_exit":true}"#).await;
        let (plain, _) = check_server(r#"{"ip":"192.0.2.9","is_exit":false}"#).await;
        let route = loopback_route();

        assert!(
            SystemHostRoute::new(&warren)
                .exits_through_warren(&route)
                .await
        );
        assert_eq!(
            peers.lock().unwrap().as_slice(),
            &[std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "the check leaves from the source it vouches for"
        );
        assert!(
            !SystemHostRoute::new(&plain)
                .exits_through_warren(&route)
                .await
        );
    }

    #[cfg(all(unix, feature = "reqwest-transport"))]
    #[tokio::test]
    async fn a_check_that_cannot_be_sent_over_the_route_is_not_warren() {
        let (warren, peers) = check_server(r#"{"is_exit":true}"#).await;
        let gone = HostRoute {
            source: Ipv4Addr::new(192, 0, 2, 1),
            ..loopback_route()
        };

        let verdict = SystemHostRoute::new(&warren)
            .exits_through_warren(&gone)
            .await;

        assert!(!verdict, "a source the host does not hold proves nothing");
        assert!(peers.lock().unwrap().is_empty());
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
