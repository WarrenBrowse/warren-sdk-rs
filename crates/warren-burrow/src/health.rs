//! The gateway's own health routes, on top of the shared three.
//!
//! Both routes are rendered from one snapshot, and neither carries a key, an
//! endpoint address or anything that names the account: an operator running
//! this on a NAS reads it from a browser on the same network, and a peer's
//! remote address is the one thing a VPN exists to keep out of reach.

use std::sync::Arc;

use warren_burrow_core::{PeerStatus, V6State};
use warren_headless::health::{ExtraRoutes, Request, RouteReply};
use warren_sdk::ConnectionState;
use warren_sdk::EpochEnd;

use crate::admin::Admin;
use crate::device::{GatewayDevice, GatewaySnapshot, drop_class};

/// What `/status` reads besides the device's own snapshot.
#[derive(Clone)]
pub struct GatewayHealth {
    device: GatewayDevice,
    started: std::time::Instant,
    state_rx: tokio::sync::watch::Receiver<ConnectionState>,
    epoch_end_rx: tokio::sync::watch::Receiver<Option<EpochEnd>>,
    port_rx: tokio::sync::watch::Receiver<Option<u16>>,
    client_mtu: u16,
    max_client_mtu: u16,
    peers_route: bool,
    /// The write surface, when this daemon serves one.
    admin: Option<Arc<Admin>>,
}

impl std::fmt::Debug for GatewayHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayHealth")
            .field("peers_route", &self.peers_route)
            .finish()
    }
}

impl GatewayHealth {
    /// Wires the routes to the device and the supervised handle's watches.
    #[must_use]
    pub fn new(
        device: GatewayDevice,
        state_rx: tokio::sync::watch::Receiver<ConnectionState>,
        epoch_end_rx: tokio::sync::watch::Receiver<Option<EpochEnd>>,
        port_rx: tokio::sync::watch::Receiver<Option<u16>>,
        client_mtu: u16,
        max_client_mtu: u16,
        peers_route: bool,
    ) -> Self {
        Self {
            device,
            started: std::time::Instant::now(),
            state_rx,
            epoch_end_rx,
            port_rx,
            client_mtu,
            max_client_mtu,
            peers_route,
            admin: None,
        }
    }

    /// The same routes, plus the admin surface guarded by its bearer token.
    #[must_use]
    pub fn with_admin(mut self, admin: Admin) -> Self {
        self.admin = Some(Arc::new(admin));
        self
    }

    /// Behind an [`Arc`], as the shared health view holds it.
    #[must_use]
    pub fn shared(self) -> Arc<dyn ExtraRoutes> {
        Arc::new(self)
    }

    fn status(&self) -> String {
        let snapshot = self.device.snapshot();
        let state = *self.state_rx.borrow();
        let epoch_end = self
            .epoch_end_rx
            .borrow()
            .map(|end| format!("{:?}", end.cause));
        let recommended = recommended_client_mtu(snapshot.inner_budget, self.max_client_mtu);
        let mut out = String::new();
        out.push_str("{\n");
        push_field(&mut out, "state", &json_string(&format!("{state:?}")));
        push_field(
            &mut out,
            "uptime_secs",
            &self.started.elapsed().as_secs().to_string(),
        );
        push_field(
            &mut out,
            "last_epoch_end",
            &epoch_end.map_or_else(|| "null".to_owned(), |cause| json_string(&cause)),
        );
        push_field(&mut out, "epoch", &snapshot.generation.to_string());
        push_field(
            &mut out,
            "gate",
            &json_string(if snapshot.gate_open { "open" } else { "closed" }),
        );
        push_field(
            &mut out,
            "inner_budget",
            &snapshot
                .inner_budget
                .map_or_else(|| "null".to_owned(), |b| b.to_string()),
        );
        push_field(
            &mut out,
            "recommended_client_mtu",
            &recommended.map_or_else(|| "null".to_owned(), |m| m.to_string()),
        );
        push_field(&mut out, "client_mtu", &self.client_mtu.to_string());
        push_field(&mut out, "ipv6", &json_string(&v6_line(&snapshot)));
        push_field(
            &mut out,
            "peers_configured",
            &snapshot.peers.len().to_string(),
        );
        push_field(
            &mut out,
            "peers_with_session",
            &snapshot.peers_with_session.to_string(),
        );
        push_field(&mut out, "nat_mappings", &snapshot.nat_mappings.to_string());
        push_field(
            &mut out,
            "granted_port",
            &self
                .port_rx
                .borrow()
                .map_or_else(|| "null".to_owned(), |p| p.to_string()),
        );
        out.push_str("  \"drops\": {\n");
        let drops = drop_counters(&snapshot);
        for (index, (name, value)) in drops.iter().enumerate() {
            let comma = if index + 1 == drops.len() { "" } else { "," };
            out.push_str(&format!("    {}: {value}{comma}\n", json_string(name)));
        }
        out.push_str("  }\n}\n");
        out
    }

    fn peers(&self) -> String {
        let snapshot = self.device.snapshot();
        let mut out = String::from("[\n");
        for (index, peer) in snapshot.peers.iter().enumerate() {
            let comma = if index + 1 == snapshot.peers.len() {
                ""
            } else {
                ","
            };
            out.push_str(&render_peer(peer));
            out.push_str(comma);
            out.push('\n');
        }
        out.push_str("]\n");
        out
    }
}

impl ExtraRoutes for GatewayHealth {
    fn render(&self, request: &Request<'_>) -> Option<RouteReply> {
        if let Some(reply) = self.admin.as_ref().and_then(|admin| admin.render(request)) {
            return Some(reply);
        }
        match request.path {
            "/status" => Some(RouteReply::json(200, self.status())),
            "/peers" if self.peers_route => Some(RouteReply::json(200, self.peers())),
            // Turned off on a shared host: the labels and per-device counters
            // are the operator's business, and the shared table's 404 is the
            // truthful answer for a route this daemon does not serve.
            _ => None,
        }
    }
}

/// The largest MTU a peer configuration should carry on the current path.
///
/// A peer packet rides the tunnel as it is, so anything above the live inner
/// budget depends on the MSS clamp (TCP) or on the reflected Packet Too Big
/// (UDP) to get through. Above `max` the tunnel stops being the binding
/// constraint, so the recommendation stops there.
#[must_use]
pub fn recommended_client_mtu(inner_budget: Option<usize>, max: u16) -> Option<u16> {
    let budget = inner_budget?;
    Some(u16::try_from(budget).unwrap_or(u16::MAX).min(max))
}

fn v6_line(snapshot: &GatewaySnapshot) -> String {
    match snapshot.ipv6 {
        V6State::Available => "available".to_owned(),
        V6State::NoAssignment => "unavailable (exit)".to_owned(),
        V6State::BudgetTooSmall => format!(
            "withdrawn (budget {} < {})",
            snapshot.inner_budget.unwrap_or(0),
            crate::device::IPV6_MIN_MTU
        ),
        // `V6State` is non-exhaustive: a state added later is still not one an
        // operator should read as working IPv6.
        _ => "unavailable".to_owned(),
    }
}

/// Every drop class, by name, from the three places that count one.
fn drop_counters(snapshot: &GatewaySnapshot) -> Vec<(&'static str, u64)> {
    let r = &snapshot.responder;
    let n = &snapshot.nat;
    let d = &snapshot.device;
    vec![
        (
            "handshake_refused_gate_closed",
            r.handshake_refused_gate_closed,
        ),
        ("gate_closed", r.dropped_gate_closed),
        ("source_rate_limited", r.source_rate_limited),
        ("unknown_peer", r.unknown_peer),
        ("unknown_index", r.unknown_index),
        ("auth_failed", r.auth_failed),
        ("replayed", r.replayed),
        ("spoofed_source", r.spoofed_source),
        ("link_local_source", r.link_local_source),
        ("malformed", r.malformed),
        ("oversize", r.oversize),
        ("non_unicast", r.non_unicast),
        ("self_destination", r.self_destination),
        ("peer_isolation", r.peer_isolation),
        ("unowned_peer_address", r.unowned_peer_address),
        ("pool_destination", r.pool_destination),
        ("private_destination", r.private_destination),
        ("v6_unavailable", r.v6_unavailable),
        ("v6_budget", r.v6_budget),
        ("no_route", r.no_route),
        ("nat_source_not_owned", n.source_not_owned),
        ("nat_no_mapping", n.no_mapping),
        ("nat_port_exhausted", n.port_exhausted),
        ("nat_peer_cap", n.peer_cap),
        ("nat_fragment", n.fragment),
        ("nat_v6_extension_header", n.v6_extension_header),
        ("nat_unsupported_protocol", n.unsupported_protocol),
        ("nat_malformed", n.malformed),
        ("nat_family_unavailable", n.family_unavailable),
        ("uplink_queue_full", d.uplink_queue_full),
        ("uplink_stale_flushed", d.uplink_stale_flushed),
        ("stale_epoch_send", d.stale_epoch_send),
        ("socket_send_failed", d.socket_send_failed),
        ("egress_queue_full", d.egress_queue_full),
        ("downlink_unroutable", d.downlink_unroutable),
    ]
}

fn render_peer(peer: &PeerStatus) -> String {
    let allowed: Vec<String> = peer
        .allowed_ips
        .iter()
        .map(|n| json_string(&format!("{}/{}", n.network_address(), n.netmask())))
        .collect();
    format!(
        "  {{\"label\": {}, \"session\": {}, \"last_handshake_secs\": {}, \"endpoint_seen\": {}, \
         \"rx_bytes\": {}, \"tx_bytes\": {}, \"deferred\": {}, \"drops\": {}, \
         \"last_drop\": {}, \"allowed_ips\": [{}]}}",
        json_string(peer.label.as_str()),
        peer.has_session,
        peer.last_handshake_secs
            .map_or_else(|| "null".to_owned(), |s| s.to_string()),
        // The address itself is never rendered: it is the one thing about a
        // peer that identifies a person's location.
        peer.endpoint_seen,
        peer.stats.rx_bytes,
        peer.stats.tx_bytes,
        peer.stats.deferred,
        peer.stats.drops,
        peer.last_drop
            .map_or_else(|| "null".to_owned(), |r| json_string(drop_class(r))),
        allowed.join(", ")
    )
}

fn push_field(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!("  {}: {value},\n", json_string(name)));
}

/// A JSON string. The values rendered here are labels, state names and drop
/// classes, so escaping the two characters JSON forbids raw is enough.
fn json_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use ip_network::IpNetwork;
    use warren_burrow_core::{
        GatewayConf, GatewayKey, PeerConf, PeerLabel, PeerPlan, PeerPublicKey, PresharedKey,
    };

    use crate::device::{GatewayDevice, GatewayOptions};
    use crate::socket::DatagramSocket;

    /// What a browser or a probe sends: a plain read.
    fn get(path: &str) -> Request<'_> {
        Request {
            method: "GET",
            path,
            authorization: None,
        }
    }

    async fn routes(peers_route: bool) -> GatewayHealth {
        let sockets: Vec<Arc<dyn DatagramSocket>> =
            crate::socket::bind_all(&["127.0.0.1:0".parse().unwrap()])
                .await
                .unwrap();
        let plan = PeerPlan::default();
        let (v4, v6) = plan.address_for(2).unwrap();
        let conf = GatewayConf {
            key: GatewayKey::generate(),
            peers: vec![PeerConf {
                label: PeerLabel::new("livingroom-tv").unwrap(),
                public: PeerPublicKey::from_bytes([7u8; 32]),
                psk: Some(PresharedKey::generate()),
                allowed: vec![
                    IpNetwork::new(std::net::IpAddr::V4(v4), 32).unwrap(),
                    IpNetwork::new(std::net::IpAddr::V6(v6), 128).unwrap(),
                ],
            }],
        };
        let device =
            GatewayDevice::new(&conf, plan, &GatewayOptions::default(), sockets).expect("a device");
        let (_s, state_rx) = tokio::sync::watch::channel(ConnectionState::Connected);
        let (_e, epoch_rx) = tokio::sync::watch::channel(None);
        let (_p, port_rx) = tokio::sync::watch::channel(Some(49587));
        std::mem::forget((_s, _e, _p));
        GatewayHealth::new(device, state_rx, epoch_rx, port_rx, 1280, 1420, peers_route)
    }

    #[tokio::test]
    async fn status_reports_the_epoch_the_budget_and_every_drop_class() {
        let health = routes(true).await;
        let reply = health.render(&get("/status")).expect("the route is served");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.content_type, "application/json");
        let body = reply.body;
        assert!(body.contains("\"state\": \"Connected\""), "{body}");
        assert!(body.contains("\"gate\": \"closed\""), "{body}");
        assert!(body.contains("\"epoch\": 0"), "{body}");
        assert!(body.contains("\"inner_budget\": null"), "{body}");
        assert!(body.contains("\"recommended_client_mtu\": null"), "{body}");
        assert!(body.contains("\"client_mtu\": 1280"), "{body}");
        assert!(body.contains("\"peers_configured\": 1"), "{body}");
        assert!(body.contains("\"peers_with_session\": 0"), "{body}");
        assert!(body.contains("\"granted_port\": 49587"), "{body}");
        assert!(body.contains("\"spoofed_source\": 0"), "{body}");
        assert!(body.contains("\"link_local_source\": 0"), "{body}");
        assert!(body.contains("\"nat_source_not_owned\": 0"), "{body}");
        assert!(body.contains("\"stale_epoch_send\": 0"), "{body}");
    }

    /// The operator's own labels and per-device counters have no business on a
    /// shared host, so the route disappears rather than answering empty.
    #[tokio::test]
    async fn the_peers_route_can_be_turned_off() {
        let health = routes(true).await;
        let body = health
            .render(&get("/peers"))
            .expect("served by default")
            .body;
        assert!(body.contains("\"label\": \"livingroom-tv\""), "{body}");
        assert!(body.contains("\"session\": false"), "{body}");
        assert!(body.contains("\"endpoint_seen\": false"), "{body}");
        assert!(
            body.contains("\"allowed_ips\": [\"10.67.0.2/32\""),
            "{body}"
        );

        let health = routes(false).await;
        assert!(
            health.render(&get("/peers")).is_none(),
            "with the route off the shared table answers 404"
        );
    }

    /// A peer's remote address is what a VPN exists to keep out of reach, and
    /// its keys are the credential: neither may be rendered, on any route.
    #[tokio::test]
    async fn no_route_renders_a_key_or_a_remote_address() {
        let health = routes(true).await;
        let status = health.render(&get("/status")).unwrap().body;
        let peers = health.render(&get("/peers")).unwrap().body;
        for body in [&status, &peers] {
            assert!(!body.contains("PrivateKey"), "{body}");
            assert!(!body.contains("127.0.0.1"), "{body}");
            assert!(!body.contains("endpoint\": \""), "{body}");
        }
    }

    #[test]
    fn the_recommended_mtu_follows_the_budget_up_to_the_cap() {
        assert_eq!(recommended_client_mtu(None, 1420), None);
        assert_eq!(recommended_client_mtu(Some(1114), 1420), Some(1114));
        assert_eq!(
            recommended_client_mtu(Some(1500), 1420),
            Some(1420),
            "past the cap the tunnel is no longer the binding constraint"
        );
    }

    /// The subcommands reach these routes over the health listener, so the
    /// token, the method and the path have to survive a real socket, and a
    /// caller without the token must get nothing but a refusal.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_admin_routes_answer_over_the_health_listener_and_only_with_the_token() {
        let dir = std::env::temp_dir().join(format!(
            "warren-burrow-health-admin-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let map: std::collections::HashMap<String, String> = [(
            "WARREN_BURROW_STATE_DIR".to_owned(),
            dir.display().to_string(),
        )]
        .into_iter()
        .collect();
        let env = crate::config::load(
            move |k| map.get(k).cloned(),
            |_| Err(std::io::Error::other("no file")),
            |_| None,
            false,
        )
        .expect("a valid test environment");
        let provisioned = crate::provision::init(&env, &crate::provision::InitOptions::default())
            .expect("a provisioned gateway");
        let token = crate::admin::write_token(&env).expect("a token");

        let sockets: Vec<Arc<dyn DatagramSocket>> =
            crate::socket::bind_all(&["127.0.0.1:0".parse().unwrap()])
                .await
                .unwrap();
        let device = GatewayDevice::new(
            &provisioned.conf,
            env.plan,
            &GatewayOptions::default(),
            sockets,
        )
        .expect("a device");
        let admin = crate::admin::Admin::new(
            device.clone(),
            env.conf_path.clone(),
            env.plan,
            token.clone(),
        );
        let (state_tx, state_rx) = tokio::sync::watch::channel(ConnectionState::Connected);
        let (epoch_tx, epoch_rx) = tokio::sync::watch::channel(None);
        let (port_tx, port_rx) = tokio::sync::watch::channel(None);
        let routes = GatewayHealth::new(
            device,
            state_rx.clone(),
            epoch_rx,
            port_rx.clone(),
            1280,
            1420,
            true,
        )
        .with_admin(admin);
        let view = warren_headless::health::HealthView::new(
            state_rx,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            port_rx,
        )
        .with_routes(routes.shared());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(warren_headless::health::serve(listener, view));

        let with_token = token.clone();
        let reply = tokio::task::spawn_blocking(move || {
            crate::admin::post(addr, "/admin/reload", &with_token)
        })
        .await
        .unwrap()
        .expect("the daemon answers");
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert!(reply.body.contains("\"unchanged\": 1"), "{}", reply.body);

        let refused = tokio::task::spawn_blocking(move || {
            crate::admin::post(addr, "/admin/reset-peer/peer2", "not the token")
        })
        .await
        .unwrap()
        .expect("the daemon answers");
        assert_eq!(refused.status, 401, "{}", refused.body);

        server.abort();
        drop((state_tx, epoch_tx, port_tx));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_unknown_path_falls_through_to_the_shared_table() {
        let health = routes(true).await;
        assert!(health.render(&get("/healthz")).is_none());
        assert!(health.render(&get("/nope")).is_none());
    }
}
