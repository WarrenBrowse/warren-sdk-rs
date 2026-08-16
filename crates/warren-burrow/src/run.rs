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
        let routes = GatewayHealth::new(
            device.clone(),
            handle.watch_state(),
            handle.watch_epoch_end(),
            port_rx.clone(),
            env.client_mtu,
            MAX_CLIENT_MTU,
            env.health_peers,
        );
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
        handle_reader(&handle),
        Arc::clone(&egress_verified),
        env.client_mtu,
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
    // Nothing may reach a peer once the daemon is on its way out.
    device.close_gate();
    handle.shutdown();
    Ok(code)
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
        ..GatewayOptions::default()
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

/// Everything the gate driver needs from the supervised handle, detached so it
/// can outlive the borrow.
#[derive(Clone)]
struct HandleReader {
    addressing_rx: watch::Receiver<Option<warren_sdk::net::EpochAddressing>>,
}

fn handle_reader(handle: &SupervisedPacketHandle) -> HandleReader {
    HandleReader {
        addressing_rx: handle.watch_addressing(),
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
async fn track_gate_across_epochs(
    mut state_rx: watch::Receiver<ConnectionState>,
    device: GatewayDevice,
    reader: HandleReader,
    egress_verified: Arc<AtomicBool>,
    client_mtu: u16,
) {
    loop {
        if state_rx.changed().await.is_err() {
            return;
        }
        if *state_rx.borrow_and_update() != ConnectionState::Connected {
            device.close_gate();
            egress_verified.store(false, Ordering::Relaxed);
            continue;
        }
        let generation = device.generation();
        let addressing = *reader.addressing_rx.borrow();
        let (Some(addressing), Some(control)) = (addressing, device.control()) else {
            continue;
        };
        let proven = verify_first_egress(&control, addressing.gateway, FIRST_EGRESS_RECHECK)
            .await
            .is_ok();
        if !proven {
            egress_verified.store(false, Ordering::Relaxed);
            LOG.error("egress is not proven on this epoch, peers stay refused");
            continue;
        }
        wait_for_budget(&device, client_mtu).await;
        if device.open_gate_for(generation) {
            egress_verified.store(true, Ordering::Relaxed);
            LOG.info("egress re-verified for the current epoch, peers admitted");
        }
    }
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
    match provision::load_conf(env) {
        Ok(conf) => match device.reload(&conf) {
            Ok(report) => LOG.info(&format!(
                "reloaded: {} added, {} removed, {} rebuilt, {} untouched",
                report.added.len(),
                report.removed.len(),
                report.rebuilt.len(),
                report.unchanged
            )),
            Err(err) => LOG.error(&format!("reload refused, nothing changed: {err}")),
        },
        Err(err) => LOG.error(&format!("reload could not read the configuration: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::device::GatewayOptions;
    use warren_burrow_core::{GatewayKey, PeerPlan};

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
