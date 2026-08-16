//! Daemon orchestration: provision on first run, build the device, run the
//! supervised failover datapath under it, prove egress before a single packet
//! may leave toward a peer, publish health, forward a port, and exit cleanly.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use tokio::sync::watch;
// Two protocol enums meet here: the NAT's own, and the NAT-PMP client's. They
// name the same two transports and belong to different layers.
use warren_burrow_core::{GatewayConf, MapProto as NatProto, ResponderOptions};
use warren_headless::forward::{ForwardConfig, ForwardProto, ShellHooks};
use warren_headless::health::HealthView;
use warren_headless::log::Log;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::packet_egress::verify_first_egress;
use warren_sdk::socks_egress::{FIRST_EGRESS_RECHECK, FIRST_EGRESS_VERIFY};
use warren_sdk::{
    ConnectionState, PacketDatapathConfig, PortRelease, SupervisedForwardedPort,
    SupervisedPacketHandle, WarrenClient,
};

use crate::admin::{self, Admin};
use crate::config::{GatewayEnv, MAX_CLIENT_MTU};
use crate::device::{GatewayDevice, GatewayOptions};
use crate::health::GatewayHealth;
use crate::provision::{self, InitOptions};

/// Every operator-facing line this daemon writes carries its own name.
pub const LOG: Log = Log("warren-burrow");

/// How long the gate waits for the tunnel's inner budget to reach the MTU the
/// peers were configured with.
///
/// The budget converges within a few round trips of a fresh tunnel. Opening
/// before it does would let a peer measure its path against the initial,
/// smaller budget and cache that result for ten minutes; waiting forever would
/// leave a narrow but working path with a gateway that never opens, so the
/// wait is bounded and the MSS clamp plus the reflected Packet Too Big carry
/// the rest.
const BUDGET_GRACE: Duration = Duration::from_secs(2);

/// How often the tunnel's live inner budget is read.
const BUDGET_POLL: Duration = Duration::from_millis(250);

/// Runs the gateway until a signal or a terminal failure; returns the process
/// exit code (0 clean shutdown, 1 startup failure, 2 a terminal control-plane
/// refusal).
///
/// # Errors
///
/// Startup errors (an unreadable configuration, a bind failure, an API that
/// cannot be reached, no matching exit) are returned; once the datapath is up,
/// failures translate into the exit code.
pub async fn run(env: GatewayEnv) -> anyhow::Result<i32> {
    let conf = ensure_provisioned(&env)?;
    let identity = WarrenIdentity::from_mnemonic(env.require_mnemonic()?.trim())
        .context("the recovery phrase must be 12 or 24 BIP39 words")?;
    LOG.info(&warren_headless::account_line(&identity.address()));

    let device = build_device(&env, &conf).await?;
    let _tasks = device.spawn();
    for addr in device.listen_addrs() {
        LOG.info(&format!("peer listener on {addr}/udp"));
    }
    LOG.info(&format!(
        "{} peer(s) configured, gateway public key {}",
        conf.peers.len(),
        device.public_key().to_base64()
    ));

    let mut builder = WarrenClient::builder()
        .identity(identity)
        .server_pubkey_pin(
            env.server_pubkey_hex
                .as_deref()
                .unwrap_or(warren_sdk::product::SERVER_PUBKEY_HEX),
        );
    if env.ipv6 {
        builder = builder.request_ipv6();
    }
    if let Some(base) = &env.api_base {
        builder = builder.api_base(base.clone());
    }
    let client = builder.build().context("client construction failed")?;

    let candidates =
        warren_headless::candidate_circuits(&client, &env.exit_filters, env.circuit, LOG).await?;
    LOG.info(&format!(
        "{} candidate exit(s), circuit {:?}",
        candidates.len(),
        env.circuit
    ));

    let cfg = PacketDatapathConfig {
        dns_override: env.dns_override,
        socket_bypass: env.socket_bypass,
    };
    let handle = client
        .start_packet_datapath_supervised_failover(&candidates, device.clone(), &cfg)
        .await
        .context("starting the supervised datapath failed")?;

    let egress_verified = Arc::new(AtomicBool::new(false));
    let (port_tx, port_rx) = watch::channel(None::<u16>);

    if let Some(listen) = env.health_listen {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding the health endpoint on {listen}"))?;
        LOG.info(&format!("health endpoint on http://{listen}/healthz"));
        let mut routes = GatewayHealth::new(
            device.clone(),
            handle.watch_state(),
            handle.watch_epoch_end(),
            port_rx.clone(),
            env.client_mtu,
            MAX_CLIENT_MTU,
            env.health_peers,
        );
        if let Some(admin) = admin_routes(&env, &device)? {
            routes = routes.with_admin(admin);
        }
        let view = HealthView::new(
            handle.watch_state(),
            Arc::clone(&egress_verified),
            port_rx.clone(),
        )
        .with_routes(routes.shared());
        tokio::spawn(warren_headless::health::serve(listener, view));
    }

    // The tunnel's own budget, read for the gate and published on `/status`.
    tokio::spawn(sample_inner_budget(
        device.clone(),
        handle.metrics_reader(),
        BUDGET_POLL,
    ));

    // Cloned before the first proof: an epoch that ends and restarts while the
    // probe is running is invisible to a receiver cloned once it is over.
    let tracker_rx = handle.watch_state();
    let probe = egress_probe(&device, handle.watch_addressing());

    wait_until_connected(&handle, env.connect_timeout)
        .await
        .context("the tunnel never reached Connected")?;
    if !open_gate_for_current_epoch(&device, &handle, env.client_mtu, FIRST_EGRESS_VERIFY).await {
        anyhow::bail!("first egress verification failed: the gateway will not carry peer traffic");
    }
    egress_verified.store(true, Ordering::Relaxed);
    LOG.info("tunnel up, egress verified, peers admitted");

    tokio::spawn(track_gate_across_epochs(
        tracker_rx,
        device.clone(),
        Arc::clone(&egress_verified),
        env.client_mtu,
        probe,
    ));

    let forward = start_forward(&env, &device, &handle, port_tx)?;
    let mut reload = warren_headless::signals::ReloadSignal::new()
        .context("installing the reload signal handler")?;

    let stop = loop {
        let stopping =
            warren_headless::forward::wait_for_stop(handle.watch_state(), || handle.last_fatal());
        tokio::select! {
            stop = stopping => break stop,
            () = reload.recv() => reload_now(&env, &device),
        }
    };

    let granted = *port_rx.borrow();
    let code = warren_headless::forward::conclude(
        LOG,
        &ShellHooks(LOG),
        stop,
        env.forward.as_ref(),
        granted,
    )
    .await;
    // Release the lease at the exit rather than let it lapse: it runs for two
    // hours, so a restart on another internal port would leave the public port
    // stranded that long.
    if let Some(forward) = forward {
        match forward.release_and_shutdown().await {
            PortRelease::Deleted => LOG.info("forwarded port released at the exit"),
            PortRelease::NoMapping => {
                LOG.info("no live mapping to release, its lease lapses at the exit");
            }
            PortRelease::TimedOut => {
                LOG.info("the forwarded port release timed out, its lease will lapse");
            }
            // `PortRelease` is non-exhaustive: an outcome added upstream is
            // still not a proven delete.
            _ => LOG.info("the forwarded port release proved no delete, its lease may lapse"),
        }
    }
    // Nothing may reach a peer once the daemon is on its way out, and the
    // token opens nothing once there is no listener to present it to.
    device.close_gate();
    admin::forget_token(&env);
    handle.shutdown();
    Ok(code)
}

/// The admin surface, when this daemon may serve one.
///
/// It is served on a loopback health listener only: `reload` and `reset-peer`
/// change what the gateway carries, and a write surface answering the network
/// is not what a local gateway is for. A daemon that serves none leaves no
/// token behind, so the subcommands say plainly that there is nothing to talk
/// to.
fn admin_routes(env: &GatewayEnv, device: &GatewayDevice) -> anyhow::Result<Option<Admin>> {
    let loopback = env
        .health_listen
        .is_some_and(|listen| listen.ip().is_loopback());
    if !loopback {
        admin::forget_token(env);
        LOG.info(
            "admin routes are off: the health endpoint is not on loopback (reload with SIGHUP)",
        );
        return Ok(None);
    }
    let token = admin::write_token(env).context("writing the admin token")?;
    LOG.info("admin routes on /admin/reload and /admin/reset-peer/LABEL");
    Ok(Some(Admin::new(
        device.clone(),
        env.conf_path.clone(),
        env.plan,
        token,
    )))
}

/// Generates the gateway and its peers when the state directory is empty, and
/// reads the configuration in every case.
fn ensure_provisioned(env: &GatewayEnv) -> anyhow::Result<GatewayConf> {
    if !provision::is_provisioned(env) {
        let out = provision::init(env, &InitOptions::default())
            .context("provisioning the gateway on first run")?;
        let first = out
            .written
            .first()
            .map_or_else(|| "peer2".to_owned(), |l| l.as_str().to_owned());
        LOG.info(&format!(
            "first run: {} peer(s) generated, configurations written to {}",
            out.written.len(),
            out.clients_dir.display()
        ));
        LOG.info(&format!("retrieve one with: warren-burrow show {first}"));
        return Ok(out.conf);
    }
    provision::load_conf(env).context("reading the gateway configuration")
}

async fn build_device(env: &GatewayEnv, conf: &GatewayConf) -> anyhow::Result<GatewayDevice> {
    let sockets = crate::socket::bind_all(&env.listen)
        .await
        .context("binding the peer listeners")?;
    let options = GatewayOptions {
        responder: ResponderOptions {
            peer_isolation: env.peer_isolation,
            handshake_rate: env.handshake_rate,
            ..ResponderOptions::default()
        },
        nat: env.nat.clone(),
        client_mtu: env.client_mtu,
        ipv6: env.ipv6,
    };
    GatewayDevice::new(conf, env.plan, &options, sockets).context("building the gateway device")
}

/// Reads the live inner budget out of the supervised handle and hands it to
/// the device, which is what withdraws IPv6 on a path under its minimum MTU.
async fn sample_inner_budget(
    device: GatewayDevice,
    metrics: warren_sdk::MetricsReader,
    every: Duration,
) {
    loop {
        if let Some(path) = metrics.read().and_then(|m| m.path) {
            device.note_inner_budget(path.max_inner_payload as usize);
        }
        tokio::time::sleep(every).await;
    }
}

/// The probe the tracker runs on every arrival at `Connected`: a DNS query to
/// the exit resolver over the epoch's own in-tunnel control plane.
///
/// An epoch that has no addressing or no control plane yet answers `false`,
/// which is what keeps the gate shut instead of trusting a plane nobody proved.
fn egress_probe(
    device: &GatewayDevice,
    addressing_rx: watch::Receiver<Option<warren_sdk::net::EpochAddressing>>,
) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = bool> + Send>> + Send + 'static {
    let device = device.clone();
    move || {
        // Read before the future: a watch guard must never be held across an
        // await, and the pair belongs to the epoch running at this instant.
        let addressing = *addressing_rx.borrow();
        let control = device.control();
        Box::pin(async move {
            let (Some(addressing), Some(control)) = (addressing, control) else {
                return false;
            };
            verify_first_egress(&control, addressing.gateway, FIRST_EGRESS_RECHECK)
                .await
                .is_ok()
        })
    }
}

/// Proves the current epoch egresses and opens the gate for it.
///
/// Fails closed on every path: an epoch replaced while the probe was running
/// leaves the gate shut, and the next `Connected` proves itself.
async fn open_gate_for_current_epoch(
    device: &GatewayDevice,
    handle: &SupervisedPacketHandle,
    client_mtu: u16,
    options: warren_sdk::socks_egress::FirstEgressVerify,
) -> bool {
    let generation = device.generation();
    let Some(addressing) = handle.addressing() else {
        return false;
    };
    let Some(control) = device.control() else {
        return false;
    };
    if verify_first_egress(&control, addressing.gateway, options)
        .await
        .is_err()
    {
        return false;
    }
    wait_for_budget(device, client_mtu).await;
    device.open_gate_for(generation)
}

/// Waits for the tunnel's inner budget to reach the MTU the peers use, or for
/// the grace to run out.
async fn wait_for_budget(device: &GatewayDevice, client_mtu: u16) {
    let deadline = std::time::Instant::now() + BUDGET_GRACE;
    while std::time::Instant::now() < deadline {
        if device
            .inner_budget()
            .is_some_and(|budget| budget >= usize::from(client_mtu))
        {
            return;
        }
        tokio::time::sleep(BUDGET_POLL).await;
    }
}

/// Keeps the gate honest across reconnects.
///
/// The proof belongs to the epoch it was measured on, so leaving `Connected`
/// closes the gate at once (nothing authenticated may reach a peer over a
/// black hole, or that peer's own liveness detector never fires), and every
/// arrival at `Connected` proves itself again before a packet may leave.
async fn track_gate_across_epochs<P, Fut>(
    mut state_rx: watch::Receiver<ConnectionState>,
    device: GatewayDevice,
    egress_verified: Arc<AtomicBool>,
    client_mtu: u16,
    mut probe: P,
) where
    P: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    loop {
        if state_rx.changed().await.is_err() {
            // Nothing publishes epochs any more, so nothing can prove one.
            shut(&device, &egress_verified);
            return;
        }
        if *state_rx.borrow_and_update() != ConnectionState::Connected {
            shut(&device, &egress_verified);
            continue;
        }
        // Read before the probe: an epoch that replaces this one while the
        // probe runs is what `open_gate_for` refuses below.
        let generation = device.generation();
        if !probe().await {
            shut(&device, &egress_verified);
            LOG.error("egress is not proven on this epoch, peers stay refused");
            continue;
        }
        wait_for_budget(&device, client_mtu).await;
        if device.open_gate_for(generation) {
            egress_verified.store(true, Ordering::Relaxed);
            LOG.info("egress re-verified for the current epoch, peers admitted");
        } else {
            // The epoch was replaced while it was being proven; the one that
            // replaced it proves itself on its own arrival at Connected.
            shut(&device, &egress_verified);
        }
    }
}

/// Fails the gateway closed: no peer hears anything but a cookie reply, and
/// `/healthz` says so.
fn shut(device: &GatewayDevice, egress_verified: &AtomicBool) {
    device.close_gate();
    egress_verified.store(false, Ordering::Relaxed);
}

async fn wait_until_connected(
    handle: &SupervisedPacketHandle,
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut state_rx = handle.watch_state();
    tokio::time::timeout(timeout, async {
        loop {
            if *state_rx.borrow_and_update() == ConnectionState::Connected {
                return Ok(());
            }
            if state_rx.changed().await.is_err() {
                anyhow::bail!("the supervisor ended before reaching Connected");
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out after {timeout:?}"))?
}

/// Installs the pinned forward and starts the watcher that keeps the hooks and
/// the status file in sync with the granted public port.
fn start_forward(
    env: &GatewayEnv,
    device: &GatewayDevice,
    handle: &SupervisedPacketHandle,
    port_tx: watch::Sender<Option<u16>>,
) -> anyhow::Result<Option<SupervisedForwardedPort>> {
    let Some(fwd) = env.forward.as_ref() else {
        return Ok(None);
    };
    let (nat_proto, map_proto) = match fwd.proto {
        ForwardProto::Tcp => (NatProto::Tcp, warren_sdk::net::MapProto::Tcp),
        ForwardProto::Udp => (NatProto::Udp, warren_sdk::net::MapProto::Udp),
    };
    // Installed before the exit grants anything: the entry is harmless while
    // no mapping exists (nothing arrives), and reserving the port up front is
    // what keeps a peer's own flow from being handed it.
    device
        .add_static_dnat(nat_proto, fwd.internal_port, fwd.target)
        .context("pinning the forwarded port to its peer")?;
    let forward = handle.forward_port(map_proto, fwd.internal_port);
    LOG.info(&format!(
        "port forward requested: internal {} to a peer ({:?})",
        fwd.internal_port, fwd.proto
    ));

    let mut external_rx = forward.watch_external_port();
    let fwd: ForwardConfig = fwd.clone();
    tokio::spawn(async move {
        let mut last: Option<u16> = None;
        loop {
            let current = *external_rx.borrow_and_update();
            if current != last {
                warren_headless::forward::apply_port_change(
                    LOG,
                    &ShellHooks(LOG),
                    &fwd,
                    last,
                    current,
                )
                .await;
                // Published after the hooks have run, so a reader that sees a
                // port knows the up command already fired for it.
                let _ = port_tx.send(current);
                last = current;
            }
            if external_rx.changed().await.is_err() {
                return;
            }
        }
    });
    Ok(Some(forward))
}

/// Applies the configuration file as it now stands, keeping the session of
/// every peer whose key material and allowed IPs did not change.
fn reload_now(env: &GatewayEnv, device: &GatewayDevice) {
    match admin::reload(device, &env.conf_path, &env.plan) {
        Ok(report) => LOG.info(&format!(
            "reloaded: {} added, {} removed, {} rebuilt, {} untouched",
            report.added.len(),
            report.removed.len(),
            report.rebuilt.len(),
            report.unchanged
        )),
        Err(err) => LOG.error(&format!("reload refused, nothing changed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::device::GatewayOptions;
    use warren_burrow_core::{GatewayKey, PeerPlan};
    use warren_sdk::net::EpochPacketDevice as _;

    async fn empty_device() -> GatewayDevice {
        let sockets = crate::socket::bind_all(&["127.0.0.1:0".parse().unwrap()])
            .await
            .unwrap();
        let conf = GatewayConf {
            key: GatewayKey::generate(),
            peers: Vec::new(),
        };
        GatewayDevice::new(
            &conf,
            PeerPlan::default(),
            &GatewayOptions::default(),
            sockets,
        )
        .expect("a device with no peer is still a device")
    }

    /// The gate waits for the peers' own MTU so a peer measures its path
    /// against the converged budget, and gives up waiting so a permanently
    /// narrow path still ends up serving traffic.
    #[tokio::test]
    async fn the_budget_wait_ends_on_the_budget_or_on_the_grace() {
        let device = empty_device().await;
        device.note_inner_budget(1414);
        let started = std::time::Instant::now();
        wait_for_budget(&device, 1280).await;
        assert!(
            started.elapsed() < BUDGET_GRACE,
            "a budget already above the MTU must not be waited for"
        );

        let device = empty_device().await;
        device.note_inner_budget(1114);
        let started = std::time::Instant::now();
        wait_for_budget(&device, 1280).await;
        assert!(
            started.elapsed() >= BUDGET_GRACE,
            "a narrow path waits the grace out"
        );
    }

    /// One epoch of the shape the supervisor hands the device.
    fn addressing(generation: u64) -> warren_sdk::net::EpochAddressing {
        warren_sdk::net::EpochAddressing {
            epoch: warren_sdk::net::EpochId {
                exit: warren_sdk::net::ExitId::from_bytes([3u8; 16]),
                generation,
            },
            ipv4: std::net::Ipv4Addr::new(10, 66, 0, 2),
            prefix: 16,
            gateway: std::net::Ipv4Addr::new(10, 66, 0, 1),
            ipv6: None,
        }
    }

    /// Polls until `done`, so an assertion never races the tracker task.
    /// Bounded, so a regression fails instead of hanging.
    async fn wait_until(mut done: impl FnMut() -> bool, what: &str) {
        for _ in 0..400u32 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("{what}");
    }

    /// A scripted probe: it counts its runs and answers what the test says.
    fn scripted(
        answer: &Arc<AtomicBool>,
        runs: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = bool> + Send>> + Send + 'static {
        let answer = Arc::clone(answer);
        let runs = Arc::clone(runs);
        move || {
            let answer = Arc::clone(&answer);
            let runs = Arc::clone(&runs);
            Box::pin(async move {
                runs.fetch_add(1, Ordering::Relaxed);
                answer.load(Ordering::Relaxed)
            })
        }
    }

    /// The proof belongs to the epoch it was measured on: leaving `Connected`
    /// shuts the gate at once, and the epoch that comes back proves itself
    /// before a single packet may reach a peer again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_closes_the_gate_and_the_new_epoch_proves_itself_before_it_reopens() {
        let device = empty_device().await;
        let (_sink, _control) = device.begin_epoch(addressing(1));
        device.note_inner_budget(1414);
        assert!(device.open_gate_for(1));
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let answer = Arc::new(AtomicBool::new(true));
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let task = tokio::spawn(track_gate_across_epochs(
            state_rx,
            device.clone(),
            Arc::clone(&verified),
            1280,
            scripted(&answer, &runs),
        ));

        state_tx.send(ConnectionState::Reconnecting).unwrap();
        wait_until(
            || !device.snapshot().gate_open,
            "leaving Connected must close the gate at once",
        )
        .await;
        assert!(!verified.load(Ordering::Relaxed));
        assert_eq!(
            runs.load(Ordering::Relaxed),
            0,
            "there is nothing to prove while the tunnel is down"
        );

        // What the supervisor does on a redial: a fresh epoch, unproven.
        let (_next, _control) = device.begin_epoch(addressing(2));
        device.note_inner_budget(1414);
        state_tx.send(ConnectionState::Connected).unwrap();

        wait_until(
            || device.snapshot().gate_open,
            "a re-proven epoch admits peers again",
        )
        .await;
        let snapshot = device.snapshot();
        assert_eq!(
            snapshot.gate_generation, 2,
            "the gate belongs to the epoch that was proven"
        );
        assert!(verified.load(Ordering::Relaxed));
        assert_eq!(runs.load(Ordering::Relaxed), 1);
        task.abort();
    }

    /// A watch channel coalesces, so a `Reconnecting` raised and cleared
    /// between two polls is invisible here. Every change that lands on
    /// `Connected` is re-proven, and a proof that fails takes the gate with it
    /// rather than leaving peers riding a tunnel that egresses nowhere.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_republished_epoch_whose_probe_fails_loses_the_gate() {
        let device = empty_device().await;
        let (_sink, _control) = device.begin_epoch(addressing(1));
        device.note_inner_budget(1414);
        assert!(device.open_gate_for(1));
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let answer = Arc::new(AtomicBool::new(false));
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let task = tokio::spawn(track_gate_across_epochs(
            state_rx,
            device.clone(),
            Arc::clone(&verified),
            1280,
            scripted(&answer, &runs),
        ));

        state_tx.send(ConnectionState::Connected).unwrap();

        wait_until(
            || !device.snapshot().gate_open,
            "a state this task cannot interpret is re-proven, not trusted",
        )
        .await;
        assert!(!verified.load(Ordering::Relaxed));
        assert_eq!(runs.load(Ordering::Relaxed), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !device.snapshot().gate_open,
            "a failed proof leaves the gate shut"
        );
        task.abort();
    }

    /// The supervisor going away leaves the daemon with no epoch to prove, and
    /// a gate left open there would carry peer traffic into nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_supervisor_ending_shuts_the_gate() {
        let device = empty_device().await;
        let (_sink, _control) = device.begin_epoch(addressing(1));
        assert!(device.open_gate_for(1));
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
        let verified = Arc::new(AtomicBool::new(true));
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let task = tokio::spawn(track_gate_across_epochs(
            state_rx,
            device.clone(),
            Arc::clone(&verified),
            1280,
            scripted(&Arc::new(AtomicBool::new(true)), &runs),
        ));

        drop(state_tx);

        task.await.expect("the tracker ends with its publisher");
        assert!(!device.snapshot().gate_open);
        assert!(!verified.load(Ordering::Relaxed));
    }

    /// Nothing reaches a peer before an epoch has proven it egresses, and the
    /// generation is what keeps a proof from being applied to the tunnel that
    /// replaced the one it was measured on.
    #[tokio::test]
    async fn the_gate_opens_only_for_the_epoch_that_was_proven() {
        let device = empty_device().await;
        assert!(!device.snapshot().gate_open);
        assert!(
            !device.open_gate_for(7),
            "an epoch this device never served must not open the gate"
        );
        assert!(!device.snapshot().gate_open);
    }
}
