//! Daemon orchestration: build the client, pick candidates, run the
//! supervised failover datapath, publish health, forward ports, and exit
//! cleanly on signals.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use tokio::sync::watch;
use warren_headless::forward::{ForwardConfig, ForwardProto, ShellHooks};
use warren_headless::health::HealthView;
use warren_headless::log::Log;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{MapProto, ProxyConfig};
use warren_sdk::socks_egress::{FIRST_EGRESS_RECHECK, FIRST_EGRESS_VERIFY, verify_first_egress};
use warren_sdk::{
    ConnectionState, PortRelease, SupervisedForwardedPort, SupervisedProxyHandle, WarrenClient,
};

use crate::config::Config;

/// Every operator-facing line this daemon writes carries its own name.
const LOG: Log = Log("warren-proxy");

/// Runs the daemon until a signal or a terminal failure; returns the process
/// exit code (0 clean shutdown, 1 startup failure, 2 a terminal control-plane
/// refusal). There is no code for "every candidate exit failed": a transient
/// failure never stops the supervisor, it keeps rotating and retrying.
///
/// # Errors
///
/// Startup errors (API unreachable, no matching exit, bind failure) are
/// returned; after the datapath is up, failures translate into the exit code.
pub async fn run(config: Config) -> anyhow::Result<i32> {
    // First line of the container log: a support report that names a build is
    // the only way to tell a fixed daemon from an old one still running.
    LOG.info(&format!("version {}", env!("CARGO_PKG_VERSION")));
    let identity = WarrenIdentity::from_mnemonic(config.mnemonic.trim())
        .context("the recovery phrase must be 12 or 24 BIP39 words")?;
    LOG.info(&warren_headless::account_line(&identity.address()));

    let mut builder = WarrenClient::builder()
        .identity(identity)
        .server_pubkey_pin(
            config
                .server_pubkey_hex
                .as_deref()
                .unwrap_or(warren_sdk::product::SERVER_PUBKEY_HEX),
        );
    if let Some(base) = &config.api_base {
        builder = builder.api_base(base.clone());
    }
    let client = builder.build().context("client construction failed")?;

    let candidates =
        warren_headless::candidate_circuits(&client, &config.exit_filters, config.circuit, LOG)
            .await?;
    LOG.info(&format!(
        "{} candidate exit(s), circuit {:?}",
        candidates.len(),
        config.circuit
    ));

    let proxy_cfg = ProxyConfig {
        socks5: config.socks_listen,
        http: config.http_listen,
        dns_server: config.dns_server,
    };
    let handle = client
        .start_proxy_supervised_failover(&candidates, &proxy_cfg)
        .await
        .context("starting the supervised datapath failed")?;
    LOG.info(&format!("SOCKS5 listening on {}", handle.local_addr()));
    if let Some(http) = handle.http_addr() {
        LOG.info(&format!("HTTP CONNECT listening on {http}"));
    }

    let egress_verified = Arc::new(AtomicBool::new(false));
    let (port_tx, port_rx) = watch::channel(None::<u16>);

    if let Some(listen) = config.health_listen {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding the health endpoint on {listen}"))?;
        LOG.info(&format!("health endpoint on http://{listen}/healthz"));
        let view = HealthView::new(
            handle.watch_state(),
            Arc::clone(&egress_verified),
            port_rx.clone(),
        );
        tokio::spawn(warren_headless::health::serve(listener, view));
    }

    // Subscribed before the first probe rather than after it: the probe runs
    // for up to eighteen attempts, and an epoch that ends and restarts inside
    // that window is invisible to a receiver cloned once it is over, which
    // would leave the proof standing on a probe made against the epoch before.
    let tracker_rx = handle.watch_state();

    wait_until_connected(&handle, config.connect_timeout)
        .await
        .context("the tunnel never reached Connected")?;

    let probe_addr = probe_address(handle.local_addr());
    verify_first_egress(probe_addr, FIRST_EGRESS_VERIFY)
        .await
        .map_err(|e| anyhow::anyhow!("first egress verification failed: {e:?}"))?;
    egress_verified.store(true, Ordering::Relaxed);
    LOG.info("tunnel up, egress verified");

    tokio::spawn(warren_headless::health::track_egress_across_epochs(
        LOG,
        tracker_rx,
        Arc::clone(&egress_verified),
        move || async move {
            verify_first_egress(probe_addr, FIRST_EGRESS_RECHECK)
                .await
                .is_ok()
        },
    ));

    let forward: Option<SupervisedForwardedPort> = config
        .forward
        .as_ref()
        .map(|fwd| start_forward(&handle, fwd, port_tx));

    let stop =
        warren_headless::forward::wait_for_stop(handle.watch_state(), || handle.last_fatal()).await;
    // The live port comes from the watch channel the forward watcher
    // publishes, never from the status file: the file is optional, and reading
    // it there skipped the down hook for everyone who had not configured one.
    let granted = *port_rx.borrow();
    let code = warren_headless::forward::conclude(
        LOG,
        &ShellHooks(LOG),
        stop,
        config.forward.as_ref(),
        granted,
    )
    .await;
    // Release the lease at the exit rather than let it lapse: it runs for two
    // hours, so a restart on another internal port or protocol would leave the
    // public port stranded that long.
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
            // still not a proven delete, so report the port as possibly held.
            _ => LOG.info("the forwarded port release proved no delete, its lease may lapse"),
        }
    }
    handle.shutdown();
    Ok(code)
}

async fn wait_until_connected(
    handle: &SupervisedProxyHandle,
    timeout: std::time::Duration,
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

/// The SOCKS listener may be bound on an unspecified address (containers);
/// the local egress probe then dials loopback on the same port.
fn probe_address(bound: SocketAddr) -> SocketAddr {
    if bound.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port())
    } else {
        bound
    }
}

/// Starts the configured forward and the watcher that keeps the status file
/// and the up/down hooks in sync with the granted public port.
///
/// One transport, one mapping, one published port: the exit picks each proto's
/// public port independently, so a second leg would be reachable on a port the
/// daemon never announces (see [`ForwardProto`]).
fn start_forward(
    handle: &SupervisedProxyHandle,
    fwd: &ForwardConfig,
    port_tx: watch::Sender<Option<u16>>,
) -> SupervisedForwardedPort {
    let proto = match fwd.proto {
        ForwardProto::Tcp => MapProto::Tcp,
        ForwardProto::Udp => MapProto::Udp,
    };
    let forward = handle.forward_port(proto, fwd.internal_port, fwd.target);
    LOG.info(&format!(
        "port forward requested: internal {} -> {} ({:?})",
        fwd.internal_port, fwd.target, fwd.proto
    ));

    let mut external_rx = forward.watch_external_port();
    let fwd = fwd.clone();
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
    forward
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_address_maps_unspecified_to_loopback() {
        assert_eq!(
            probe_address("0.0.0.0:1080".parse().unwrap()),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            probe_address("127.0.0.1:1080".parse().unwrap()),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            probe_address("[::]:1080".parse().unwrap()),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap(),
            "v6 unspecified also probes over loopback v4"
        );
    }
}
