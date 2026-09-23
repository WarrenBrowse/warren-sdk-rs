//! Egress proof over a local SOCKS5 endpoint: the doc-62 contract, exported.
//!
//! Two userland shapes share this single home instead of re-deciding their
//! constants per client:
//!
//! - the PERIODIC liveness probe ([`run_socks5_egress_probe`]): an exit that
//!   is drained or half-swapped keeps ACKing QUIC keep-alives, so RX-silence
//!   never fires; a TCP CONNECT through the session's own SOCKS5 endpoint to
//!   a fixed anycast address proves real end-to-end egress. N consecutive
//!   failures while `Connected` publish `egress_dead = true`; one success
//!   clears it; any other state resets the count AND clears the verdict.
//! - the ONE-SHOT connect-time verifier ([`verify_first_egress`]): fail-closed
//!   launchers (wclaude) refuse to expose a listener until a probe has proven
//!   the tunnel egresses; short attempts catch the datapath warm-up moment
//!   within ~1 s. It first has the listener prove it holds the session's
//!   credentials, so a process squatting the address is refused before it is
//!   handed the password.
//!
//! The probe can never leak outside the tunnel: it enters the datapath the
//! same way every proxied byte does. Knob names are the engine's
//! (`warren_transport::egress_probe`), the shared cross-language anchor.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::watch;
use warren_net::socks5::Target;
use warren_net::{ListenerProofError, ProxyCredentials};
use warren_transport::ConnectionState;
pub use warren_transport::egress_probe::{
    EGRESS_PROBE_ENV, EGRESS_PROBE_FAILURES_ENV, EGRESS_PROBE_INTERVAL_ENV,
};

/// Fixed anycast probe target (Cloudflare `1.1.1.1:443`): globally reachable,
/// indistinguishable from ordinary traffic, and the connect originates from
/// the exit's IP like every proxied byte.
pub const PROBE_TARGET: [u8; 4] = [1, 1, 1, 1];
/// See [`PROBE_TARGET`].
pub const PROBE_PORT: u16 = 443;
/// Overall budget for one periodic probe (SOCKS handshake + tunneled connect).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(6);

/// Steady probe cadence (jittered +/-15% per tick).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(25);
const INTERVAL_RANGE_SECS: std::ops::RangeInclusive<u64> = 5..=600;
/// Consecutive failures before the egress-dead verdict.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;
const FAILURE_RANGE: std::ops::RangeInclusive<u32> = 1..=10;

/// Resolved periodic-probe settings (env knobs applied once per session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksEgressProbeConfig {
    /// `false` when `WARREN_EGRESS_PROBE=0`.
    pub enabled: bool,
    /// Steady cadence between probes.
    pub interval: Duration,
    /// Consecutive failures before the dead verdict.
    pub failure_threshold: u32,
}

impl SocksEgressProbeConfig {
    /// Reads the shared `WARREN_EGRESS_PROBE*` knobs.
    #[must_use]
    pub fn from_env() -> Self {
        Self::resolve(
            std::env::var(EGRESS_PROBE_ENV).ok().as_deref(),
            std::env::var(EGRESS_PROBE_INTERVAL_ENV).ok().as_deref(),
            std::env::var(EGRESS_PROBE_FAILURES_ENV).ok().as_deref(),
        )
    }

    /// Pure resolution: invalid or out-of-range values keep the default
    /// rather than clamping, so a typo never silently changes the cadence.
    #[must_use]
    pub fn resolve(enable: Option<&str>, interval: Option<&str>, failures: Option<&str>) -> Self {
        let enabled = enable.map(str::trim) != Some("0");
        let interval = match interval.map(|raw| raw.trim().parse::<u64>()) {
            Some(Ok(secs)) if INTERVAL_RANGE_SECS.contains(&secs) => Duration::from_secs(secs),
            _ => DEFAULT_INTERVAL,
        };
        let failure_threshold = match failures.map(|raw| raw.trim().parse::<u32>()) {
            Some(Ok(n)) if FAILURE_RANGE.contains(&n) => n,
            _ => DEFAULT_FAILURE_THRESHOLD,
        };
        Self {
            enabled,
            interval,
            failure_threshold,
        }
    }
}

/// IO surface consumed by [`run_verdict_scheduler`]; mocked in tests.
pub trait SocksProbeIo {
    /// Waits for the next tick. `false` = teardown, the loop exits.
    fn next_tick(&mut self) -> impl std::future::Future<Output = bool> + Send;
    /// `true` while the datapath state is `Connected`.
    fn connected(&mut self) -> bool;
    /// One end-to-end probe through the tunnel. `true` = egress alive.
    fn probe(&mut self) -> impl std::future::Future<Output = bool> + Send;
    /// Publishes the verdict (edge-triggered by the scheduler).
    fn publish(&mut self, egress_dead: bool);
}

/// Verdict scheduler: consecutive-failure counting, one-success clear,
/// non-connected states reset the count AND clear the verdict (those states
/// already tell the truth on their own, and a redial may land on a different
/// exit that must be judged fresh).
pub async fn run_verdict_scheduler<I: SocksProbeIo>(io: &mut I, failure_threshold: u32) {
    let mut consecutive_failures: u32 = 0;
    let mut dead = false;
    loop {
        if !io.next_tick().await {
            return;
        }
        if !io.connected() {
            consecutive_failures = 0;
            if dead {
                dead = false;
                io.publish(false);
            }
            continue;
        }
        if io.probe().await {
            consecutive_failures = 0;
            if dead {
                dead = false;
                io.publish(false);
            }
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);
            if !dead && consecutive_failures >= failure_threshold {
                dead = true;
                io.publish(true);
            }
        }
    }
}

/// Authenticated CONNECT to [`PROBE_TARGET`]:[`PROBE_PORT`]; `Ok(())` iff the
/// proxy replied success, i.e. a TCP handshake completed through the tunnel.
/// The error string carries only protocol detail, never identity material.
async fn socks5_connect(proxy: SocketAddr, credentials: &ProxyCredentials) -> Result<(), String> {
    let target = Target::Ip(SocketAddr::from((PROBE_TARGET, PROBE_PORT)));
    warren_net::socks5_connect(proxy, credentials, &target)
        .await
        .map(drop)
        .map_err(|e| e.to_string())
}

/// One bounded periodic probe through the session's own listener, presenting
/// its credentials. Local dial errors against our own listener are also
/// failures: the proxy front-end dying is not healthy egress either.
pub async fn probe_via_socks5(socks: SocketAddr, credentials: &ProxyCredentials) -> bool {
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, socks5_connect(socks, credentials)).await,
        Ok(Ok(()))
    )
}

/// Periodic probe loop attached to one session: gates on the state watch,
/// probes through the session's own SOCKS5 endpoint and publishes verdict
/// edges on `egress_tx`. The caller aborts the task at session teardown.
pub async fn run_socks5_egress_probe(
    socks: SocketAddr,
    credentials: ProxyCredentials,
    state_rx: watch::Receiver<ConnectionState>,
    egress_tx: watch::Sender<bool>,
) {
    let cfg = SocksEgressProbeConfig::from_env();
    if !cfg.enabled {
        return;
    }
    struct RealIo {
        interval: Duration,
        socks: SocketAddr,
        credentials: ProxyCredentials,
        state_rx: watch::Receiver<ConnectionState>,
        egress_tx: watch::Sender<bool>,
    }
    impl SocksProbeIo for RealIo {
        async fn next_tick(&mut self) -> bool {
            // +/-15% jitter so a fleet of clients never probes in lockstep.
            let fraction = warren_transport::drain_policy::stampede_fraction();
            tokio::time::sleep(warren_transport::egress_probe::jittered(
                self.interval,
                fraction,
            ))
            .await;
            true
        }
        fn connected(&mut self) -> bool {
            matches!(*self.state_rx.borrow(), ConnectionState::Connected)
        }
        async fn probe(&mut self) -> bool {
            probe_via_socks5(self.socks, &self.credentials).await
        }
        fn publish(&mut self, egress_dead: bool) {
            let _ = self.egress_tx.send(egress_dead);
        }
    }
    let mut io = RealIo {
        interval: cfg.interval,
        socks,
        credentials,
        state_rx,
        egress_tx,
    };
    run_verdict_scheduler(&mut io, cfg.failure_threshold).await;
}

/// One-shot connect-time verification schedule.
#[derive(Debug, Clone, Copy)]
pub struct FirstEgressVerify {
    /// Total probe attempts before failing closed.
    pub attempts: u32,
    /// Per-attempt budget.
    pub timeout: Duration,
    /// Pause between attempts.
    pub gap: Duration,
}

/// The tunnel egresses somewhere between ~2 s and ~6 s after connect (multihop
/// warmup). A short per-probe timeout plus a short gap detects that moment
/// within ~1 s of it happening, instead of the multi-second slack a long
/// timeout wastes; the attempt budget still covers a slow (~15 s) warmup.
pub const FIRST_EGRESS_VERIFY: FirstEgressVerify = FirstEgressVerify {
    attempts: 18,
    timeout: Duration::from_millis(800),
    gap: Duration::from_millis(200),
};

/// A quick variant for re-checking an already-proven listener: it only has to
/// reject a dead or wedged listener quickly.
pub const FIRST_EGRESS_RECHECK: FirstEgressVerify = FirstEgressVerify {
    attempts: 3,
    timeout: Duration::from_millis(800),
    gap: Duration::from_millis(200),
};

/// No probe attempt completed a tunneled TCP handshake: the tunnel does not
/// egress and a fail-closed caller must not expose the listener.
#[derive(Debug, thiserror::Error)]
#[error("egress not proven after {attempts} probe attempts: {last_error}")]
pub struct FirstEgressDead {
    /// Attempts consumed.
    pub attempts: u32,
    /// Protocol-level detail of the last failure (no identity material).
    pub last_error: String,
}

/// Why a connect-time verification refused to vouch for a listener. Either way
/// a fail-closed caller must not expose it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FirstEgressError {
    /// The listener is ours and the tunnel behind it does not egress.
    #[error(transparent)]
    Dead(#[from] FirstEgressDead),
    /// Something answers at the address without proving it holds the session's
    /// credentials: a process took the port over, and it was told nothing.
    #[error("the local listener did not prove it holds this session's credentials")]
    ListenerNotOurs,
}

/// Proves the tunnel actually egresses: once the listener has proven it holds
/// `credentials`, an authenticated SOCKS5 CONNECT to a public IP through it,
/// retried because the first packets race the datapath warm-up right after
/// connect.
///
/// # Errors
///
/// [`FirstEgressError::ListenerNotOurs`] as soon as the listener answers
/// without the proof (never retried: a squatter does not become the right
/// listener), [`FirstEgressError::Dead`] when every attempt failed or timed
/// out.
pub async fn verify_first_egress(
    socks: SocketAddr,
    credentials: &ProxyCredentials,
    options: FirstEgressVerify,
) -> Result<(), FirstEgressError> {
    let mut last_error = String::new();
    for attempt in 1..=options.attempts {
        let outcome =
            tokio::time::timeout(options.timeout, first_egress_attempt(socks, credentials)).await;
        match outcome {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(AttemptError::NotOurs)) => return Err(FirstEgressError::ListenerNotOurs),
            Ok(Err(AttemptError::Failed(e))) => last_error = e,
            Err(_) => last_error = "probe timeout".to_string(),
        }
        if attempt < options.attempts && !options.gap.is_zero() {
            tokio::time::sleep(options.gap).await;
        }
    }
    Err(FirstEgressError::Dead(FirstEgressDead {
        attempts: options.attempts,
        last_error,
    }))
}

enum AttemptError {
    NotOurs,
    Failed(String),
}

/// One verification attempt: the proof, then the egress. The proof comes first
/// on every attempt, so no attempt hands the password to a port that changed
/// hands since the previous one.
async fn first_egress_attempt(
    socks: SocketAddr,
    credentials: &ProxyCredentials,
) -> Result<(), AttemptError> {
    match warren_net::prove_socks5_listener(socks, credentials).await {
        Ok(()) => {}
        Err(ListenerProofError::NotOurs) => return Err(AttemptError::NotOurs),
        Err(e) => return Err(AttemptError::Failed(e.to_string())),
    }
    socks5_connect(socks, credentials)
        .await
        .map_err(AttemptError::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn config_defaults_and_knobs() {
        let cfg = SocksEgressProbeConfig::resolve(None, None, None);
        assert!(cfg.enabled);
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
        assert!(!SocksEgressProbeConfig::resolve(Some("0"), None, None).enabled);
        let cfg = SocksEgressProbeConfig::resolve(None, Some("40"), Some("2"));
        assert_eq!(cfg.interval, Duration::from_secs(40));
        assert_eq!(cfg.failure_threshold, 2);
        // Out-of-range values keep the defaults, never clamp.
        let cfg = SocksEgressProbeConfig::resolve(None, Some("1"), Some("0"));
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
    }

    /// Scripted mock: one entry per tick. `None` = not connected,
    /// `Some(ok)` = connected with that probe result.
    struct MockIo {
        script: VecDeque<Option<bool>>,
        published: Vec<bool>,
    }

    impl MockIo {
        fn scripted(script: impl IntoIterator<Item = Option<bool>>) -> Self {
            Self {
                script: script.into_iter().collect(),
                published: Vec::new(),
            }
        }
    }

    impl SocksProbeIo for MockIo {
        async fn next_tick(&mut self) -> bool {
            !self.script.is_empty()
        }
        fn connected(&mut self) -> bool {
            if self.script.front().expect("gated by next_tick").is_some() {
                true
            } else {
                self.script.pop_front();
                false
            }
        }
        async fn probe(&mut self) -> bool {
            self.script
                .pop_front()
                .flatten()
                .expect("probe only runs while connected")
        }
        fn publish(&mut self, egress_dead: bool) {
            self.published.push(egress_dead);
        }
    }

    #[tokio::test]
    async fn verdict_fires_only_at_threshold_and_clears_on_success() {
        let mut io = MockIo::scripted([Some(false), Some(false), Some(true)]);
        run_verdict_scheduler(&mut io, 3).await;
        assert!(
            io.published.is_empty(),
            "sub-threshold failures must never publish (rollout blip)"
        );

        let mut io = MockIo::scripted([Some(false), Some(false), Some(false), Some(true)]);
        run_verdict_scheduler(&mut io, 3).await;
        assert_eq!(
            io.published,
            vec![true, false],
            "threshold publishes dead once; one success clears it"
        );
    }

    #[tokio::test]
    async fn leaving_connected_resets_count_and_clears_the_verdict() {
        let mut io = MockIo::scripted([Some(false), Some(false), None, Some(false)]);
        run_verdict_scheduler(&mut io, 2).await;
        assert_eq!(
            io.published,
            vec![true, false],
            "a non-connected tick clears the stale verdict; the single \
             post-redial failure must not re-fire at threshold 2"
        );
    }

    #[tokio::test]
    async fn never_probes_while_not_connected() {
        // All ticks disconnected: probe() would panic (script entries are
        // None), so completing without a panic proves the gate.
        let mut io = MockIo::scripted([None, None, None]);
        run_verdict_scheduler(&mut io, 1).await;
        assert!(io.published.is_empty());
    }

    /// A connector standing in for the tunnel: it reaches the target, or it
    /// reports the tunnel gone. Counting its dials shows what a probe opened.
    #[derive(Clone)]
    struct FakeExit {
        reachable: bool,
        dials: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl warren_net::Connector for FakeExit {
        type Stream = tokio::io::DuplexStream;

        async fn connect(&self, _target: Target) -> Result<Self::Stream, warren_net::NetError> {
            self.dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.reachable {
                Ok(tokio::io::duplex(64).0)
            } else {
                Err(warren_net::NetError::EngineStopped)
            }
        }
    }

    /// The real SOCKS5 server, serving `credentials` over a [`FakeExit`].
    async fn session_listener(
        credentials: &ProxyCredentials,
        reachable: bool,
    ) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let dials = std::sync::Arc::default();
        let proxy = warren_net::Socks5Proxy::new(
            FakeExit {
                reachable,
                dials: std::sync::Arc::clone(&dials),
            },
            credentials.clone(),
        );
        tokio::spawn(async move { proxy.serve(listener).await });
        (addr, dials)
    }

    fn dead_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local addr")
    }

    #[tokio::test]
    async fn socks5_probe_succeeds_through_the_sessions_own_listener() {
        let creds = ProxyCredentials::generate();
        let (addr, _) = session_listener(&creds, true).await;
        assert!(
            probe_via_socks5(addr, &creds).await,
            "a connect that reached the target is live egress"
        );
    }

    #[tokio::test]
    async fn socks5_probe_fails_when_the_tunnel_cannot_reach_the_target() {
        let creds = ProxyCredentials::generate();
        let (addr, _) = session_listener(&creds, false).await;
        assert!(!probe_via_socks5(addr, &creds).await);
    }

    #[tokio::test]
    async fn socks5_probe_without_the_session_credentials_fails_and_dials_nothing() {
        let (addr, dials) = session_listener(&ProxyCredentials::generate(), true).await;
        assert!(!probe_via_socks5(addr, &ProxyCredentials::generate()).await);
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn socks5_probe_fails_when_the_listener_is_gone() {
        assert!(
            !probe_via_socks5(dead_addr(), &ProxyCredentials::generate()).await,
            "a dead proxy front-end is not healthy egress"
        );
    }

    const FAST: FirstEgressVerify = FirstEgressVerify {
        attempts: 2,
        timeout: Duration::from_millis(300),
        gap: Duration::from_millis(20),
    };

    #[tokio::test]
    async fn first_egress_passes_through_the_sessions_own_listener() {
        let creds = ProxyCredentials::generate();
        let (addr, dials) = session_listener(&creds, true).await;
        verify_first_egress(addr, &creds, FAST)
            .await
            .expect("the session's listener proves egress");
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn first_egress_fails_closed_when_the_tunnel_cannot_reach_the_target() {
        let creds = ProxyCredentials::generate();
        let (addr, _) = session_listener(&creds, false).await;
        let err = verify_first_egress(addr, &creds, FAST)
            .await
            .expect_err("an unreachable target must fail closed");
        let FirstEgressError::Dead(dead) = err else {
            panic!("a live listener with a dead tunnel is dead egress: {err:?}")
        };
        assert_eq!(dead.attempts, 2);
        assert!(dead.last_error.contains("rep=3"), "{}", dead.last_error);
    }

    #[tokio::test]
    async fn first_egress_refuses_a_listener_holding_other_credentials() {
        let (addr, dials) = session_listener(&ProxyCredentials::generate(), true).await;
        let err = verify_first_egress(addr, &ProxyCredentials::generate(), FAST)
            .await
            .expect_err("another session's listener is not ours");
        assert!(matches!(err, FirstEgressError::ListenerNotOurs), "{err:?}");
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn first_egress_refuses_a_squatter_without_handing_it_the_password() {
        // Accepts every method and answers any proof request with junk, the
        // way a process that took over a released port would.
        let creds = ProxyCredentials::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&seen);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut greeting = [0u8; 3];
                if stream.read_exact(&mut greeting).await.is_err() {
                    continue;
                }
                let _ = stream.write_all(&[0x05, greeting[2]]).await;
                let mut rest = [0u8; 512];
                if let Ok(n) = stream.read(&mut rest).await {
                    log.lock().unwrap().extend_from_slice(&rest[..n]);
                }
                let _ = stream.write_all(&[0u8; 32]).await;
            }
        });

        let err = verify_first_egress(addr, &creds, FAST)
            .await
            .expect_err("a squatter must be refused");

        assert!(matches!(err, FirstEgressError::ListenerNotOurs), "{err:?}");
        let seen = seen.lock().unwrap();
        assert!(
            !seen
                .windows(creds.password().len())
                .any(|w| w == creds.password().as_bytes()),
            "the squatter never receives the password"
        );
    }

    #[tokio::test]
    async fn first_egress_fails_closed_when_nothing_listens() {
        let err = verify_first_egress(dead_addr(), &ProxyCredentials::generate(), FAST)
            .await
            .expect_err("a dead listener must fail closed");
        assert!(matches!(err, FirstEgressError::Dead(_)), "{err:?}");
    }
}
