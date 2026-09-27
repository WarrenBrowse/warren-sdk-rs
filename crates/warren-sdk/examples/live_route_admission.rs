//! Real-exit proof of route admission by anchor (warren-core doc 107 section
//! 17): one v7 main session anchors on one exit, route sessions on every other
//! route-capable exit are admitted against that anchor without a token of their
//! own, each egresses from its own exit, and killing the main ends the routes.
//!
//! Userspace only: the engine's supervisors carry the sessions and the SDK's
//! smoltcp netstack runs an HTTPS IP echo through each of them. Nothing touches
//! a TUN, a route or a resolver of this host.
//!
//! Run (beta): `WARREN_API_URL=https://api.beta.warrenbrowse.com
//! ROUTE_MNEMONIC_FILE=~/.warren/<wallet>.mnemonic
//! ROUTE_MAIN=nl cargo run -p warren-sdk --example live_route_admission`
//!
//! Every line carries a unix timestamp so it can be matched against the API's
//! access log. Nothing printed names a token, a serial, the anchor or the
//! wallet; exit IPs are public.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use warren_net::Connector;
use warren_net::socks5::Target;
use warren_sdk::api::{BlindingKey, ReqwestTransport, TokenManager, WarrenApiClient};
use warren_sdk::identity::{WarrenIdentity, seed_from_mnemonic};
use warrenguard_backoff::Backoff;
use warrenguard_multihop::{ExitId, RouteKemPublicKey};
use warrenguard_transport::IpAssignChannel;
use warrenguard_transport::multihop::MultiHopError;
use warrenguard_transport::route_anchor::{
    AnchorState, RouteAnchorConfig, RouteAnchorHandle, RouteSessionAdmission,
};
use warrenguard_transport::supervisor::{
    ClientWatch, MultiHopSupervisor, SessionAdmission, SessionTokenProvider, SupervisorConfig,
};
use warrenguard_wire::SessionToken;

/// Client-pinned trust anchors (the same for beta and staging).
const SERVER_PIN: &str = "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";
const ROOT_PIN: &str = "33cd9279ad06d1ee884235e763b876fa70598094944bdcfb82375bd9aaa67b08";
const ECHO_HOST: &str = "api.ipify.org";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

type Error = Box<dyn std::error::Error + Send + Sync>;

struct Node {
    name: String,
    relay: Arc<warrenguard_multihop::RelayDescriptorSigned>,
    exit_id: ExitId,
    exit_x25519: [u8; 32],
    exit_mlkem: Option<Vec<u8>>,
}

struct Running {
    name: String,
    watch: ClientWatch,
    ip: IpAssignChannel,
    run: tokio::task::JoinHandle<Result<(), MultiHopError>>,
    /// Where the downlink reader hands inner packets while an echo runs. The
    /// reader drains the session at all times, as a real pump does: anchor
    /// acks and route ends are consumed on that read path.
    sink: Arc<std::sync::Mutex<Option<mpsc::Sender<Bytes>>>>,
    _reader: tokio::task::JoinHandle<()>,
}

impl Running {
    fn start(
        name: String,
        watch: ClientWatch,
        ip: IpAssignChannel,
        run: tokio::task::JoinHandle<Result<(), MultiHopError>>,
    ) -> Self {
        let sink: Arc<std::sync::Mutex<Option<mpsc::Sender<Bytes>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let mut rx = watch.clone();
        let to = Arc::clone(&sink);
        let reader = tokio::spawn(async move {
            loop {
                let current = rx.borrow_and_update().clone();
                if let Some(bundle) = current {
                    while let Ok(p) = bundle.recv().await {
                        if let Some(tx) = to.lock().expect("sink lock").clone() {
                            let _ = tx.try_send(Bytes::from(p));
                        }
                    }
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        });
        Self {
            name,
            watch,
            ip,
            run,
            sink,
            _reader: reader,
        }
    }
}

fn config(
    node: &Node,
    operational: ed25519_dalek::VerifyingKey,
    ip: &IpAssignChannel,
    tokens: Option<SessionTokenProvider>,
) -> SupervisorConfig {
    SupervisorConfig {
        relay: Arc::clone(&node.relay),
        exit_id: node.exit_id,
        exit_x25519_multihop_pubkey: node.exit_x25519,
        exit_mlkem768_pubkey: node.exit_mlkem.clone(),
        operational_pubkey: operational,
        client_signing: SigningKey::generate(&mut rand::rngs::OsRng),
        bind_addr: "0.0.0.0:0".parse().expect("addr"),
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

/// HTTPS GET of the IP echo through one session, over the SDK netstack.
async fn echo_ip(run: &Running) -> Result<String, Error> {
    let bundle = run.watch.borrow().clone().ok_or("no live session")?;
    let spec = (*run.ip.subscribe().borrow()).ok_or("no IpAssign yet")?;
    let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
    let mtu = bundle.max_inner_payload().min(1280);
    let cfg = warren_net::NetstackConfig::new(spec.assigned, spec.prefix_len, spec.gateway, mtu);
    let connector = warren_net::spawn_engine(cfg, in_rx, out_tx);
    *run.sink.lock().expect("sink lock") = Some(in_tx);
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
        let mut s = connector.connect(name, stream).await?;
        s.write_all(
            format!("GET / HTTP/1.1\r\nHost: {ECHO_HOST}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
        let mut body = Vec::new();
        let _ = s.read_to_end(&mut body).await;
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
    *run.sink.lock().expect("sink lock") = None;
    writer.abort();
    result
}

async fn echo_with_retries(run: &Running) -> Result<String, Error> {
    let mut last: Error = "not tried".into();
    for _ in 0..6 {
        match tokio::time::timeout(Duration::from_secs(10), echo_ip(run)).await {
            Ok(Ok(ip)) => return Ok(ip),
            Ok(Err(e)) => last = e,
            Err(_) => last = "echo timed out".into(),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(last)
}

async fn wait_session(run: &Running, budget: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < budget {
        if run.watch.borrow().is_some() && run.ip.subscribe().borrow().is_some() {
            return true;
        }
        if run.run.is_finished() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let api = std::env::var("WARREN_API_URL")?;
    let file = std::env::var("ROUTE_MNEMONIC_FILE")?;
    let phrase = std::fs::read_to_string(file.replace('~', &std::env::var("HOME")?))?;
    let main_cc = std::env::var("ROUTE_MAIN").unwrap_or_else(|_| "nl".to_owned());
    let hold = Duration::from_secs(
        std::env::var("ROUTE_KILL_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(240),
    );

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
    let keys: serde_json::Value = http
        .get(format!("{api}/v1/tokens/keys"))
        .send()
        .await?
        .json()
        .await?;
    let block = keys
        .get("route_admission")
        .ok_or("the token directory carries no route_admission block")?;
    let kem_hex = block["kem_pubkey_hex"].as_str().ok_or("kem key")?;
    let mut kem = [0u8; 32];
    hex::decode_to_slice(kem_hex, &mut kem)?;
    let kem_id = u8::try_from(block["kem_key_id"].as_u64().ok_or("kem id")?)?;
    let capable: Vec<String> = block["exit_ids_hex"]
        .as_array()
        .ok_or("exit ids")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    println!(
        "{} directory: {} nodes, route_admission v{} R={} with {} route-capable exits",
        now(),
        dir.nodes.len(),
        block["version"],
        block["max_routes_per_anchor"],
        capable.len()
    );

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
    let main_node = nodes
        .iter()
        .find(|n| n.name.to_lowercase().starts_with(&main_cc.to_lowercase()))
        .ok_or("no main node in that country")?;

    // The main session's tokens: the wallet's current batch, lead first.
    let seed = seed_from_mnemonic(phrase.trim())?;
    let manager = TokenManager::new(
        Arc::new(WarrenApiClient::new(
            api.clone(),
            WarrenIdentity::from_seed(&seed),
            ReqwestTransport::try_new()?,
        )),
        BlindingKey::session(&seed),
    )
    .with_mint_horizon(0);
    manager.refresh(now()).await?;
    let batch: Vec<SessionToken> = manager
        .session_stack(now())
        .into_iter()
        .map(SessionToken)
        .collect();
    println!(
        "{} token batch of {} for the main session",
        now(),
        batch.len()
    );
    let provider: SessionTokenProvider = Arc::new(move || batch.clone());

    let anchor = RouteAnchorHandle::new(RouteAnchorConfig {
        kem: RouteKemPublicKey::new(kem_id, kem)?,
    });
    let ip = IpAssignChannel::new();
    let (sup, watch) = MultiHopSupervisor::new(config(
        main_node,
        dir.operational_pubkey,
        &ip,
        Some(provider),
    ));
    let sup = sup
        .with_session_admission(SessionAdmission::TokensOnly)
        .with_route_anchor(anchor.clone());
    let main = Running::start(main_node.name.clone(), watch, ip, tokio::spawn(sup.run()));
    if !wait_session(&main, Duration::from_secs(60)).await {
        return Err("the main session did not come up".into());
    }
    println!("{} MAIN up on {}", now(), main.name);

    let mut state = anchor.state();
    let anchored = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let AnchorState::Anchored { max_routes } = *state.borrow_and_update() {
                return Some(max_routes);
            }
            if matches!(*state.borrow(), AnchorState::Unavailable) {
                return None;
            }
            if state.changed().await.is_err() {
                return None;
            }
        }
    })
    .await;
    match anchored {
        Ok(Some(r)) => println!("{} ANCHORED (ack bound, max_routes {r})", now()),
        other => return Err(format!("{} anchor not bound: {other:?}", now()).into()),
    }

    let mut routes = Vec::new();
    for node in nodes.iter().filter(|n| n.exit_id != main_node.exit_id) {
        let offers = capable.contains(&hex::encode(node.exit_id.as_bytes()));
        let ip = IpAssignChannel::new();
        let (sup, watch) = MultiHopSupervisor::new(config(node, dir.operational_pubkey, &ip, None));
        let sup = sup.with_session_admission(SessionAdmission::Route(RouteSessionAdmission {
            anchor: anchor.clone(),
            exit_offers_routes: offers,
        }));
        println!(
            "{} ROUTE dial {} (listed route-capable: {offers})",
            now(),
            node.name
        );
        routes.push(Running::start(
            node.name.clone(),
            watch,
            ip,
            tokio::spawn(sup.run()),
        ));
    }
    for r in &routes {
        if wait_session(r, Duration::from_secs(90)).await {
            println!("{} ROUTE admitted on {}", now(), r.name);
        } else {
            println!("{} ROUTE NOT admitted on {}", now(), r.name);
        }
    }

    for r in std::iter::once(&main).chain(routes.iter()) {
        match echo_with_retries(r).await {
            Ok(ip) => println!("{} EGRESS {} -> {ip}", now(), r.name),
            Err(e) => println!("{} EGRESS {} failed: {e}", now(), r.name),
        }
    }

    // Hold the routes up for a while first (outside the API's restore window,
    // a route whose anchor is gone ends at once rather than being kept).
    let delay: u64 = std::env::var("ROUTE_KILL_DELAY_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if delay > 0 {
        tokio::time::sleep(Duration::from_secs(delay)).await;
        for r in &routes {
            println!(
                "{} ROUTE {} still up before the kill: {}",
                now(),
                r.name,
                !r.run.is_finished()
            );
        }
    }
    // Kill the main: its exit stops renewing the anchor, which expires, and
    // every route exit ends its route at its next renewal.
    let killed = Instant::now();
    if let Some(b) = main.watch.borrow().clone() {
        b.close(0, b"");
    }
    main.run.abort();
    println!("{} MAIN killed", now());
    let mut pending: Vec<&Running> = routes.iter().collect();
    while !pending.is_empty() && killed.elapsed() < hold {
        tokio::time::sleep(Duration::from_secs(1)).await;
        pending.retain(|r| {
            if r.run.is_finished() {
                println!(
                    "{} ROUTE ended on {} {:.0} s after the main was killed",
                    now(),
                    r.name,
                    killed.elapsed().as_secs_f64()
                );
                false
            } else {
                true
            }
        });
    }
    for r in &routes {
        if r.run.is_finished() {
            continue;
        }
        println!("{} ROUTE still up on {} after {:?}", now(), r.name, hold);
        r.run.abort();
    }
    for r in routes {
        if let Ok(outcome) = r.run.await {
            println!("{} ROUTE {} outcome: {:?}", now(), r.name, outcome.err());
        }
    }
    Ok(())
}
