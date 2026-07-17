//! Egress proof over a local SOCKS5 endpoint: the doc-62 contract, exported.
//!
//! Two userland shapes share this single home instead of re-deciding their
//! constants per client (doc-94 B11):
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
//!   within ~1 s.
//!
//! The probe can never leak outside the tunnel: it enters the datapath the
//! same way every proxied byte does. Knob names are the engine's
//! (`warren_transport::egress_probe`), the shared cross-language anchor.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
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

/// SOCKS5 no-auth greeting + CONNECT to [`PROBE_TARGET`]:[`PROBE_PORT`];
/// `Ok(())` iff the proxy replied success (REP=0), i.e. a TCP handshake
/// completed through the tunnel. The error string carries only protocol
/// detail, never identity material.
async fn socks5_connect(proxy: SocketAddr) -> Result<(), String> {
    let mut s = tokio::net::TcpStream::connect(proxy)
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.map_err(|e| e.to_string())?;
    if method != [0x05, 0x00] {
        return Err("SOCKS5 no-auth refused".to_string());
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&PROBE_TARGET);
    req.extend_from_slice(&PROBE_PORT.to_be_bytes());
    s.write_all(&req).await.map_err(|e| e.to_string())?;
    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT; REP (byte 1) == 0 = success.
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT rejected (rep={})", reply[1]));
    }
    Ok(())
}

/// One bounded periodic probe. Local dial errors against our own listener are
/// also failures: the proxy front-end dying is not healthy egress either.
pub async fn probe_via_socks5(socks: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, socks5_connect(socks)).await,
        Ok(Ok(()))
    )
}

/// Periodic probe loop attached to one session: gates on the state watch,
/// probes through the session's own SOCKS5 endpoint and publishes verdict
/// edges on `egress_tx`. The caller aborts the task at session teardown.
pub async fn run_socks5_egress_probe(
    socks: SocketAddr,
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
            probe_via_socks5(self.socks).await
        }
        fn publish(&mut self, egress_dead: bool) {
            let _ = self.egress_tx.send(egress_dead);
        }
    }
    let mut io = RealIo {
        interval: cfg.interval,
        socks,
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

/// Proves the tunnel actually egresses: a SOCKS5 CONNECT to a public IP
/// through the local listener, retried because the first packets race the
/// datapath warm-up right after connect.
///
/// # Errors
///
/// [`FirstEgressDead`] when every attempt failed or timed out.
pub async fn verify_first_egress(
    socks: SocketAddr,
    options: FirstEgressVerify,
) -> Result<(), FirstEgressDead> {
    let mut last_error = String::new();
    for attempt in 1..=options.attempts {
        match tokio::time::timeout(options.timeout, socks5_connect(socks)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => last_error = e,
            Err(_) => last_error = "probe timeout".to_string(),
        }
        if attempt < options.attempts && !options.gap.is_zero() {
            tokio::time::sleep(options.gap).await;
        }
    }
    Err(FirstEgressDead {
        attempts: options.attempts,
        last_error,
    })
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

    /// Fake SOCKS5 server scripting sessions: reads the greeting + request,
    /// answers with `reply_code`.
    async fn fake_socks5(reply_code: u8) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake socks");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut greeting = [0u8; 3];
                    if stream.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&[0x05, 0x00]).await;
                    let mut req = [0u8; 10];
                    if stream.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let _ = stream
                        .write_all(&[0x05, reply_code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn socks5_probe_succeeds_on_a_zero_reply() {
        let addr = fake_socks5(0x00).await;
        assert!(
            probe_via_socks5(addr).await,
            "REP=0x00 means the engine connected through the exit"
        );
    }

    #[tokio::test]
    async fn socks5_probe_fails_on_an_error_reply() {
        // 0x04 = host unreachable: the engine could not egress.
        let addr = fake_socks5(0x04).await;
        assert!(!probe_via_socks5(addr).await);
    }

    #[tokio::test]
    async fn socks5_probe_fails_when_the_listener_is_gone() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        assert!(
            !probe_via_socks5(addr).await,
            "a dead proxy front-end is not healthy egress"
        );
    }

    const FAST: FirstEgressVerify = FirstEgressVerify {
        attempts: 2,
        timeout: Duration::from_millis(300),
        gap: Duration::from_millis(20),
    };

    #[tokio::test]
    async fn first_egress_passes_when_the_proxy_accepts_the_connect() {
        let addr = fake_socks5(0x00).await;
        verify_first_egress(addr, FAST)
            .await
            .expect("an accepting proxy proves egress");
    }

    #[tokio::test]
    async fn first_egress_fails_closed_when_the_proxy_rejects_the_connect() {
        let addr = fake_socks5(0x05).await;
        let err = verify_first_egress(addr, FAST)
            .await
            .expect_err("a rejecting proxy must fail closed");
        assert_eq!(err.attempts, 2);
        assert!(err.last_error.contains("rep=5"), "{}", err.last_error);
    }

    #[tokio::test]
    async fn first_egress_fails_closed_when_nothing_listens() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        verify_first_egress(addr, FAST)
            .await
            .expect_err("a dead listener must fail closed");
    }
}
