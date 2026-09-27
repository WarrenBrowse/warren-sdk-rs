//! Real-exit gates of route admission by anchor (warren-core doc 107 section
//! 17): one v7 main session anchors on one exit, route sessions on the other
//! exits are admitted against that anchor without a token of their own, and a
//! timed plan then exercises the gates while every session is watched.
//!
//! Userspace only: the engine's supervisors carry the sessions and the SDK's
//! smoltcp netstack runs an HTTPS IP echo through each of them. Nothing touches
//! a TUN, a route or a resolver of this host.
//!
//! Run (beta): `WARREN_API_URL=https://api.beta.warrenbrowse.com
//! ROUTE_MNEMONIC_FILE=~/.warren/app-routing-test-wallet-2.mnemonic
//! ROUTE_MAIN=nl cargo run -p warren-sdk --example live_route_admission`
//!
//! Environment:
//!
//! - `ROUTE_MAIN`: country (or `country/city`) prefix of the main's exit.
//! - `ROUTE_ONLY`: comma list of prefixes for the route exits (default: every
//!   other exit of the directory).
//! - `ROUTE_PLAN`: comma list of `<seconds>:<action>`, seconds counted from
//!   the moment every route was dialled. Actions: `echo`, `rebind-main`,
//!   `rebind-routes`, `rebind-all` (each session moves onto a fresh UDP
//!   socket, as the migration watchdog does on a network change),
//!   `reconnect-main`, `reconnect-routes`, `reconnect-all` (the session is
//!   closed and redialled, as after a path loss), `kill-main`, `end`. Default:
//!   `0:echo,<ROUTE_KILL_DELAY_SECS>:kill-main,<+ROUTE_KILL_WAIT_SECS>:end`,
//!   the main-kill gate.
//! - `ROUTE_STATUS_SECS` (15) and `ROUTE_ECHO_SECS` (0, off): the period of
//!   the status line and of the echo through every live session.
//! - `ROUTE_LOG_LEVEL` (`info`): the engine's own events on stderr (why a
//!   session was lost, why a route was refused).
//!
//! The probe falls back to a token route as the desktop app does: a route
//! refused as legacy, `not offered`, `route limit`, `unavailable`, or dialled
//! while the anchor is unavailable, runs again under the wallet's tokens. A
//! route the exit ends while the anchor lives is redialled by anchor once the
//! anchor is bound again. After `kill-main` nothing is redialled.
//!
//! Every line carries a unix timestamp so it can be matched against the API's
//! access log. Nothing printed names a token, a serial, the anchor or the
//! wallet; exit IPs are public.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use warren_net::Connector;
use warren_net::socks5::Target;
use warren_sdk::api::{BlindingKey, ReqwestTransport, TokenManager, WarrenApiClient};
use warren_sdk::identity::{WarrenIdentity, seed_from_mnemonic};
use warrenguard_backoff::Backoff;
use warrenguard_multihop::{ExitId, RouteRejectCode};
use warrenguard_transport::IpAssignChannel;
use warrenguard_transport::multihop::{MultiHopError, RebindPolicy};
use warrenguard_transport::route_anchor::{
    AnchorState, RouteAnchorConfig, RouteAnchorHandle, RouteRefusal, RouteSessionAdmission,
};
use warrenguard_transport::supervisor::{
    ClientWatch, MultiHopSupervisor, SessionAdmission, SessionTokenProvider, SupervisorConfig,
    SupervisorHandle,
};
use warrenguard_wire::SessionToken;

/// Client-pinned trust anchors (the same for beta and staging).
const SERVER_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
const ROOT_PIN: &str = "33cd9279ad06d1ee884235e763b876fa70598094944bdcfb82375bd9aaa67b08";
const ECHO_HOST: &str = "api.ipify.org";

type Error = Box<dyn std::error::Error + Send + Sync>;
type Manager = TokenManager<ReqwestTransport>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn stamp() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", t.as_secs(), t.subsec_millis())
}

macro_rules! say {
    ($($arg:tt)*) => { println!("{} {}", stamp(), format!($($arg)*)) };
}

#[derive(Clone)]
struct Node {
    name: String,
    relay: Arc<warrenguard_multihop::RelayDescriptorSigned>,
    exit_id: ExitId,
    exit_x25519: [u8; 32],
    exit_mlkem: Option<Vec<u8>>,
}

/// How a session of the probe is admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Main,
    RouteByAnchor,
    RouteByToken,
}

/// One live supervisor with its watch, its IP channel and a downlink reader
/// that drains the session at all times, as a real pump does (anchor acks and
/// route ends are consumed on that read path).
struct Session {
    kind: Kind,
    watch: ClientWatch,
    handle: SupervisorHandle,
    ip: IpAssignChannel,
    run: tokio::task::JoinHandle<Result<(), MultiHopError>>,
    sink: Arc<std::sync::Mutex<Option<mpsc::Sender<Bytes>>>>,
    _reader: AbortOnDrop,
    _presence: AbortOnDrop,
}

/// A helper task that dies with the session it serves.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Slot {
    node: Node,
    session: Mutex<Option<Session>>,
}

struct Probe {
    operational: ed25519_dalek::VerifyingKey,
    manager: Arc<Manager>,
    anchor: RouteAnchorHandle,
    offers: Vec<[u8; 16]>,
    main_killed: AtomicBool,
}

impl Probe {
    fn provider(&self) -> SessionTokenProvider {
        let manager = Arc::clone(&self.manager);
        Arc::new(move || {
            manager
                .session_stack(now())
                .into_iter()
                .map(SessionToken)
                .collect()
        })
    }

    fn config(
        &self,
        node: &Node,
        ip: &IpAssignChannel,
        tokens: Option<SessionTokenProvider>,
    ) -> SupervisorConfig {
        SupervisorConfig {
            relay: Arc::clone(&node.relay),
            exit_id: node.exit_id,
            exit_x25519_multihop_pubkey: node.exit_x25519,
            exit_mlkem768_pubkey: node.exit_mlkem.clone(),
            operational_pubkey: self.operational,
            client_signing: SigningKey::generate(&mut rand::rngs::OsRng),
            bind_addr: "0.0.0.0:0".parse().expect("static addr"),
            enable_gso: false,
            use_warren_obfuscation: true,
            socket_bypass: None,
            enable_daita: false,
            idle_cover: false,
            backoff: Backoff::HANDSHAKE,
            on_reconnect: None,
            ip_assign_channel: Some(ip.clone()),
            wants_ipv6: false,
            n_connections: 1,
            pre_swap_check: None,
            on_overlap_swapped: None,
            on_dial_refused: None,
            on_path_rtt: None,
            session_token_provider: tokens,
        }
    }

    /// Starts one supervisor of `kind` on `node`.
    fn start(&self, node: &Node, kind: Kind) -> Session {
        let ip = IpAssignChannel::new();
        let tokens = match kind {
            Kind::Main | Kind::RouteByToken => Some(self.provider()),
            Kind::RouteByAnchor => None,
        };
        let (sup, watch) = MultiHopSupervisor::new(self.config(node, &ip, tokens));
        let sup = match kind {
            Kind::Main => sup
                .with_session_admission(SessionAdmission::TokensOnly)
                .with_route_anchor(self.anchor.clone()),
            Kind::RouteByToken => sup.with_session_admission(SessionAdmission::TokensOnly),
            Kind::RouteByAnchor => {
                sup.with_session_admission(SessionAdmission::Route(RouteSessionAdmission {
                    anchor: self.anchor.clone(),
                    exit_offers_routes: self.offers.contains(node.exit_id.as_bytes()),
                }))
            }
        };
        let handle = sup.handle();
        let run = tokio::spawn(sup.run());
        let sink: Arc<std::sync::Mutex<Option<mpsc::Sender<Bytes>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let reader = {
            let mut rx = watch.clone();
            let to = Arc::clone(&sink);
            tokio::spawn(async move {
                loop {
                    let current = rx.borrow_and_update().clone();
                    if let Some(bundle) = current {
                        while let Ok(p) = bundle.recv().await {
                            // Count real downlink as the supervised pump does:
                            // the one-way dead-path watch redials a session
                            // whose answerable uplink sees no real downlink.
                            if matches!(p.first().map(|b| b >> 4), Some(4 | 6)) {
                                bundle.note_real_downlink();
                            }
                            let tx = to.lock().expect("sink lock").clone();
                            if let Some(tx) = tx {
                                let _ = tx.try_send(Bytes::from(p));
                            }
                        }
                    }
                    if rx.changed().await.is_err() {
                        return;
                    }
                }
            })
        };
        // Logs every loss and return of a published session, with the gap.
        let presence = {
            let mut rx = watch.clone();
            let name = node.name.clone();
            tokio::spawn(async move {
                let mut up = rx.borrow_and_update().is_some();
                let mut since = Instant::now();
                loop {
                    if rx.changed().await.is_err() {
                        return;
                    }
                    let now_up = rx.borrow_and_update().is_some();
                    if now_up != up {
                        if now_up {
                            say!(
                                "SESSION {name} ({kind:?}) up after {:.1} s without a session",
                                since.elapsed().as_secs_f64()
                            );
                        } else {
                            say!("SESSION {name} ({kind:?}) lost its session");
                        }
                        up = now_up;
                        since = Instant::now();
                    }
                }
            })
        };
        Session {
            kind,
            watch,
            handle,
            ip,
            run,
            sink,
            _reader: AbortOnDrop(reader),
            _presence: AbortOnDrop(presence),
        }
    }
}

/// HTTPS GET of the IP echo through one session, over the SDK netstack.
async fn echo_ip(s: &Session) -> Result<String, Error> {
    let bundle = s.watch.borrow().clone().ok_or("no live session")?;
    let spec = (*s.ip.subscribe().borrow()).ok_or("no IpAssign yet")?;
    let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
    let mtu = bundle.max_inner_payload().min(1280);
    let cfg = warren_net::NetstackConfig::new(spec.assigned, spec.prefix_len, spec.gateway, mtu);
    let connector = warren_net::spawn_engine(cfg, in_rx, out_tx);
    *s.sink.lock().expect("sink lock") = Some(in_tx);
    let up = Arc::clone(&bundle);
    let writer = tokio::spawn(async move {
        while let Some(p) = out_rx.recv().await {
            let _ = up.send(&p).await;
        }
    });
    let result = async {
        let stream = connector
            .connect(Target::Domain(ECHO_HOST.to_owned(), 443))
            .await?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
        let name = rustls::pki_types::ServerName::try_from(ECHO_HOST)?;
        let mut stream = connector.connect(name, stream).await?;
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: {ECHO_HOST}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut body = Vec::new();
        let _ = stream.read_to_end(&mut body).await;
        let text = String::from_utf8_lossy(&body);
        let ip = text
            .split("\r\n\r\n")
            .nth(1)
            .map(str::trim)
            .unwrap_or_default()
            .to_owned();
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err::<String, Error>("no IP in the echo answer".into());
        }
        Ok(ip)
    }
    .await;
    *s.sink.lock().expect("sink lock") = None;
    writer.abort();
    result
}

async fn echo_slot(slot: &Slot) {
    let started = Instant::now();
    let mut last: Error = "not tried".into();
    for _ in 0..4 {
        let attempt = {
            let guard = slot.session.lock().await;
            match guard.as_ref() {
                Some(s) => tokio::time::timeout(Duration::from_secs(10), echo_ip(s))
                    .await
                    .unwrap_or_else(|_| Err("echo timed out".into())),
                None => Err("no supervisor".into()),
            }
        };
        match attempt {
            Ok(ip) => {
                say!(
                    "EGRESS {} -> {ip} ({:.1} s)",
                    slot.node.name,
                    started.elapsed().as_secs_f64()
                );
                return;
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    say!("EGRESS {} failed: {last}", slot.node.name);
}

async fn wait_session(s: &Session, budget: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < budget {
        if s.watch.borrow().is_some() && s.ip.subscribe().borrow().is_some() {
            return true;
        }
        if s.run.is_finished() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// What the app does with a route that ended, from its refusal: `Some(kind)`
/// redials it under that admission, `None` leaves it down.
fn fallback(refusal: &RouteRefusal) -> Option<Kind> {
    match refusal {
        RouteRefusal::Legacy
        | RouteRefusal::AnchorUnavailable
        | RouteRefusal::Rejected(
            RouteRejectCode::NotOffered
            | RouteRejectCode::RouteLimit
            | RouteRejectCode::Unavailable,
        ) => Some(Kind::RouteByToken),
        RouteRefusal::Ended(_) | RouteRefusal::Rejected(_) => Some(Kind::RouteByAnchor),
        _ => None,
    }
}

async fn wait_anchored(anchor: &RouteAnchorHandle, budget: Duration) -> bool {
    let mut state = anchor.state();
    tokio::time::timeout(budget, async {
        loop {
            if matches!(*state.borrow_and_update(), AnchorState::Anchored { .. }) {
                return true;
            }
            if state.changed().await.is_err() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Watches one route slot: when its supervisor ends, logs why and redials it
/// the way the app would.
async fn supervise_route(probe: Arc<Probe>, slot: Arc<Slot>) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let finished = {
            let mut guard = slot.session.lock().await;
            match guard.as_ref() {
                Some(s) if s.run.is_finished() => guard.take(),
                Some(_) => None,
                None => return,
            }
        };
        let Some(ended) = finished else { continue };
        let kind = ended.kind;
        let outcome = match ended.run.await {
            Ok(outcome) => outcome,
            Err(e) => {
                say!("ROUTE {} ({kind:?}) task failed: {e}", slot.node.name);
                return;
            }
        };
        let refusal = match &outcome {
            Err(MultiHopError::RouteRefused(r)) => Some(*r),
            _ => None,
        };
        say!(
            "ROUTE {} ({kind:?}) ended: {}",
            slot.node.name,
            match &outcome {
                Ok(()) => "clean".to_owned(),
                Err(e) => e.to_string(),
            }
        );
        if probe.main_killed.load(Ordering::SeqCst) {
            say!("ROUTE {} left down (the main was killed)", slot.node.name);
            return;
        }
        let next = match (kind, refusal) {
            (Kind::RouteByAnchor, Some(r)) => fallback(&r),
            _ => None,
        };
        let next = match next {
            Some(Kind::RouteByAnchor) => {
                if wait_anchored(&probe.anchor, Duration::from_secs(60)).await {
                    Kind::RouteByAnchor
                } else {
                    Kind::RouteByToken
                }
            }
            Some(k) => k,
            None => {
                say!("ROUTE {} left down", slot.node.name);
                return;
            }
        };
        say!("ROUTE {} redial ({next:?})", slot.node.name);
        let s = probe.start(&slot.node, next);
        let ok = wait_session(&s, Duration::from_secs(90)).await;
        say!(
            "ROUTE {} ({next:?}) {}",
            slot.node.name,
            if ok { "admitted" } else { "NOT admitted" }
        );
        *slot.session.lock().await = Some(s);
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Echo,
    RebindMain,
    RebindRoutes,
    RebindAll,
    ReconnectMain,
    ReconnectRoutes,
    ReconnectAll,
    KillMain,
    End,
}

fn parse_plan(raw: &str) -> Result<Vec<(u64, Action)>, Error> {
    let mut plan = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (at, action) = item
            .split_once(':')
            .ok_or("plan item must be <secs>:<action>")?;
        let action = match action {
            "echo" => Action::Echo,
            "rebind-main" => Action::RebindMain,
            "rebind-routes" => Action::RebindRoutes,
            "rebind-all" => Action::RebindAll,
            "reconnect-main" => Action::ReconnectMain,
            "reconnect-routes" => Action::ReconnectRoutes,
            "reconnect-all" => Action::ReconnectAll,
            "kill-main" => Action::KillMain,
            "end" => Action::End,
            other => return Err(format!("unknown plan action {other}").into()),
        };
        plan.push((at.parse()?, action));
    }
    plan.sort_by_key(|(at, _)| *at);
    Ok(plan)
}

async fn rebind(slot: &Slot) {
    let guard = slot.session.lock().await;
    let Some(bundle) = guard.as_ref().and_then(|s| s.watch.borrow().clone()) else {
        say!("REBIND {} skipped: no live session", slot.node.name);
        return;
    };
    let before = bundle.local_addr().map(|a| a.port()).unwrap_or(0);
    match bundle.rebind_wildcard(RebindPolicy::Plain) {
        Ok(()) => say!(
            "REBIND {} local port {before} -> {}",
            slot.node.name,
            bundle.local_addr().map(|a| a.port()).unwrap_or(0)
        ),
        Err(e) => say!("REBIND {} failed: {e}", slot.node.name),
    }
}

async fn reconnect(slot: &Slot) {
    let guard = slot.session.lock().await;
    match guard.as_ref() {
        Some(s) => say!(
            "RECONNECT {} forced: {}",
            slot.node.name,
            s.handle.force_reconnect()
        ),
        None => say!("RECONNECT {} skipped: no supervisor", slot.node.name),
    }
}

async fn status(main: &Slot, routes: &[Arc<Slot>], anchor: &RouteAnchorHandle, manager: &Manager) {
    let mut line = format!("anchor={:?}", *anchor.state().borrow());
    for slot in std::iter::once(main).chain(routes.iter().map(AsRef::as_ref)) {
        let guard = slot.session.lock().await;
        let state = match guard.as_ref() {
            Some(s) if s.watch.borrow().is_some() => format!("up/{:?}", s.kind),
            Some(s) => format!("down/{:?}", s.kind),
            None => "none".to_owned(),
        };
        line.push_str(&format!(" {}={state}", slot.node.name));
    }
    let epoch = manager.epoch_at(now()).unwrap_or(0);
    line.push_str(&format!(
        " epoch={epoch} stack_tokens={}",
        manager.session_stack(now()).len()
    ));
    say!("STATUS {line}");
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // The engine's own account of each session (why a session ended, why a
    // route was refused) on stderr, at `ROUTE_LOG_LEVEL` (info by default).
    let level = std::env::var("ROUTE_LOG_LEVEL")
        .ok()
        .and_then(|v| v.parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    tracing::subscriber::set_global_default(StderrLog { level })?;
    let api = std::env::var("WARREN_API_URL")?;
    let file = std::env::var("ROUTE_MNEMONIC_FILE")?;
    let phrase = zeroize::Zeroizing::new(std::fs::read_to_string(
        file.replace('~', &std::env::var("HOME")?),
    )?);
    let main_cc = std::env::var("ROUTE_MAIN")
        .unwrap_or_else(|_| "nl".to_owned())
        .to_lowercase();
    let only: Vec<String> = std::env::var("ROUTE_ONLY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let env_secs = |name: &str, default: u64| -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let status_every = env_secs("ROUTE_STATUS_SECS", 15).max(1);
    let echo_every = env_secs("ROUTE_ECHO_SECS", 0);
    let plan = match std::env::var("ROUTE_PLAN") {
        Ok(raw) => parse_plan(&raw)?,
        Err(_) => {
            let delay = env_secs("ROUTE_KILL_DELAY_SECS", 0);
            let wait = env_secs("ROUTE_KILL_WAIT_SECS", 240);
            vec![
                (0, Action::Echo),
                (delay, Action::KillMain),
                (delay + wait, Action::End),
            ]
        }
    };

    // Directory with the signed relay and exit descriptors the engine dials.
    let http = reqwest::Client::new();
    let raw = http
        .get(format!("{api}/v1/multihop/directory"))
        .send()
        .await?
        .text()
        .await?;
    let dir =
        warren_discovery_core::verify_multihop_directory(&raw, Some(SERVER_PIN), Some(ROOT_PIN))?;

    // The wallet's tokens and the signed route admission block, read as the
    // client reads them (the KEM key only under a pinned server key).
    let seed = seed_from_mnemonic(phrase.trim())?;
    let manager = Arc::new(
        TokenManager::new(
            Arc::new(WarrenApiClient::new(
                api.clone(),
                WarrenIdentity::from_seed(&seed),
                ReqwestTransport::try_new()?,
            )),
            BlindingKey::session(&seed),
        )
        .with_mint_horizon(0)
        .with_server_pubkey_pins([SERVER_PIN]),
    );
    manager.refresh(now()).await?;
    let admission = manager
        .route_admission_at(now())
        .ok_or("the token directory carries no usable route_admission block")?;
    let nodes: Vec<Node> = dir
        .nodes
        .iter()
        .map(|n| Node {
            name: format!("{}/{}", n.country, n.city),
            relay: Arc::new(n.relay.clone()),
            exit_id: n.exit.exit_id,
            exit_x25519: n.exit.exit_x25519_multihop_pubkey,
            exit_mlkem: n.exit.exit_mlkem768_pubkey.clone(),
        })
        .collect();
    let offers: Vec<[u8; 16]> = nodes
        .iter()
        .map(|n| *n.exit_id.as_bytes())
        .filter(|id| admission.offers_routes(id))
        .collect();
    say!(
        "directory: {} nodes, route admission R={} with {} route-capable exits ({}), signature valid until {}",
        nodes.len(),
        admission.max_routes_per_anchor(),
        offers.len(),
        nodes
            .iter()
            .filter(|n| offers.contains(n.exit_id.as_bytes()))
            .map(|n| n.name.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        admission.valid_until()
    );
    say!(
        "tokens: epoch {} with {} tokens for this wallet",
        manager.epoch_at(now()).unwrap_or(0),
        manager.session_stack(now()).len()
    );

    // Keeps the wallet's tokens current across epochs, as the app's token
    // refresher does; only the main and token routes present them.
    {
        let manager = Arc::clone(&manager);
        tokio::spawn(async move {
            let mut last_epoch = manager.epoch_at(now());
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                if let Err(e) = manager.refresh(now()).await {
                    say!("TOKENS refresh failed: {e}");
                }
                let epoch = manager.epoch_at(now());
                if epoch != last_epoch {
                    say!(
                        "TOKENS epoch {} -> {}: {} tokens",
                        last_epoch.unwrap_or(0),
                        epoch.unwrap_or(0),
                        manager.session_stack(now()).len()
                    );
                    last_epoch = epoch;
                }
            }
        });
    }

    let main_node = nodes
        .iter()
        .find(|n| n.name.to_lowercase().starts_with(&main_cc))
        .ok_or("no main node with that prefix")?
        .clone();
    let anchor = RouteAnchorHandle::new(RouteAnchorConfig {
        kem: admission.kem().clone(),
    });
    let probe = Arc::new(Probe {
        operational: dir.operational_pubkey,
        manager: Arc::clone(&manager),
        anchor: anchor.clone(),
        offers,
        main_killed: AtomicBool::new(false),
    });
    {
        let mut state = anchor.state();
        tokio::spawn(async move {
            loop {
                let current = *state.borrow_and_update();
                say!("ANCHOR {current:?}");
                if state.changed().await.is_err() {
                    return;
                }
            }
        });
    }

    let main = Arc::new(Slot {
        node: main_node.clone(),
        session: Mutex::new(Some(probe.start(&main_node, Kind::Main))),
    });
    {
        let guard = main.session.lock().await;
        let s = guard.as_ref().expect("main just started");
        if !wait_session(s, Duration::from_secs(60)).await {
            return Err("the main session did not come up".into());
        }
    }
    say!("MAIN up on {}", main_node.name);
    if !wait_anchored(&anchor, Duration::from_secs(60)).await {
        say!("anchor not bound within 60 s: routes fall back to tokens");
    }

    let mut routes = Vec::new();
    for node in nodes.iter().filter(|n| n.exit_id != main_node.exit_id) {
        if !only.is_empty() && !only.iter().any(|p| node.name.to_lowercase().starts_with(p)) {
            continue;
        }
        let anchored = matches!(*anchor.state().borrow(), AnchorState::Anchored { .. });
        let kind = if anchored {
            Kind::RouteByAnchor
        } else {
            Kind::RouteByToken
        };
        say!(
            "ROUTE dial {} ({kind:?}, listed route-capable: {})",
            node.name,
            probe.offers.contains(node.exit_id.as_bytes())
        );
        routes.push(Arc::new(Slot {
            node: node.clone(),
            session: Mutex::new(Some(probe.start(node, kind))),
        }));
    }
    for slot in &routes {
        let ok = {
            let guard = slot.session.lock().await;
            match guard.as_ref() {
                Some(s) => wait_session(s, Duration::from_secs(90)).await,
                None => false,
            }
        };
        say!(
            "ROUTE {} {}",
            slot.node.name,
            if ok { "admitted" } else { "NOT admitted (yet)" }
        );
    }
    for slot in &routes {
        tokio::spawn(supervise_route(Arc::clone(&probe), Arc::clone(slot)));
    }

    let started = Instant::now();
    let mut next_status = 0u64;
    let mut next_echo = if echo_every > 0 { echo_every } else { u64::MAX };
    let mut plan = plan.into_iter().peekable();
    loop {
        let elapsed = started.elapsed().as_secs();
        if elapsed >= next_status {
            status(&main, &routes, &anchor, &manager).await;
            next_status = elapsed + status_every;
        }
        if elapsed >= next_echo {
            echo_all(&main, &routes).await;
            next_echo = started.elapsed().as_secs() + echo_every;
        }
        while let Some((at, action)) = plan.peek().copied() {
            if at > started.elapsed().as_secs() {
                break;
            }
            plan.next();
            say!("PLAN +{at}s {action:?}");
            match action {
                Action::Echo => echo_all(&main, &routes).await,
                Action::RebindMain => rebind(&main).await,
                Action::RebindRoutes => {
                    for r in &routes {
                        rebind(r).await;
                    }
                }
                Action::RebindAll => {
                    rebind(&main).await;
                    for r in &routes {
                        rebind(r).await;
                    }
                }
                Action::ReconnectMain => reconnect(&main).await,
                Action::ReconnectRoutes => {
                    for r in &routes {
                        reconnect(r).await;
                    }
                }
                Action::ReconnectAll => {
                    reconnect(&main).await;
                    for r in &routes {
                        reconnect(r).await;
                    }
                }
                Action::KillMain => {
                    probe.main_killed.store(true, Ordering::SeqCst);
                    if let Some(s) = main.session.lock().await.take() {
                        if let Some(b) = s.watch.borrow().clone() {
                            b.close(0, b"");
                        }
                        s.run.abort();
                    }
                    say!("MAIN killed");
                }
                Action::End => {
                    say!("END: closing every session");
                    probe.main_killed.store(true, Ordering::SeqCst);
                    for slot in routes
                        .iter()
                        .map(AsRef::as_ref)
                        .chain(std::iter::once(main.as_ref()))
                    {
                        if let Some(s) = slot.session.lock().await.take() {
                            if let Some(b) = s.watch.borrow().clone() {
                                b.close(0, b"");
                            }
                            s.run.abort();
                        }
                    }
                    // Lets the exits see the closes before the process exits.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn echo_all(main: &Slot, routes: &[Arc<Slot>]) {
    let mut all = vec![echo_slot(main)];
    for r in routes {
        all.push(echo_slot(r));
    }
    futures_join_all(all).await;
}

/// Runs the echoes concurrently without pulling in the `futures` crate.
async fn futures_join_all<F: std::future::Future<Output = ()>>(futures: Vec<F>) {
    let mut set = Vec::new();
    for f in futures {
        set.push(Box::pin(f));
    }
    let mut pending: Vec<_> = set.into_iter().map(Some).collect();
    std::future::poll_fn(|cx| {
        let mut done = true;
        for slot in &mut pending {
            if let Some(f) = slot {
                if f.as_mut().poll(cx).is_ready() {
                    *slot = None;
                } else {
                    done = false;
                }
            }
        }
        if done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
}

/// A minimal stderr subscriber for the engine's events (no span tracking),
/// so the probe needs no logging crate of its own.
struct StderrLog {
    level: tracing::Level,
}

impl tracing::Subscriber for StderrLog {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= self.level
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0.push_str(&format!(" {value:?}"));
                } else {
                    self.0.push_str(&format!(" {}={value:?}", field.name()));
                }
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let meta = event.metadata();
        eprintln!(
            "{} {} {}:{}",
            stamp(),
            meta.level(),
            meta.target(),
            fields.0
        );
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}
