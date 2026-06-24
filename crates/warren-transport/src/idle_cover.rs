//! Idle cover traffic (ADR-0006 "B2-lite" in the warrenguard engine).
//!
//! A QUIC tunnel that relies on a fixed-interval keep-alive PING emits, while
//! idle, a periodic small packet that no browser produces: a metronome that
//! betrays the obfuscation on both the timing and the size axis. This module
//! replaces that beacon. While the tunnel is idle, [`IdleCoverDriver`] emits a
//! cover datagram at a JITTERED interval (10-20s) and a VARIED size, which
//! refreshes the NAT mapping and resets the idle timeout, so the keep-alive PING
//! can be disabled (see `warren_transport_config_with_idle_cover`). The cover
//! datagram reuses the existing DAITA discriminator (first byte `0xFF`), so the
//! exit drops it on receive with no new wire format.
//!
//! [`IdleCover`] is the pure, deterministic scheduler (a small splitmix64 PRNG;
//! the jitter only needs to break periodicity, and the payload is encrypted by
//! QUIC, so a CSPRNG would be overkill). [`IdleCoverDriver`] mirrors
//! [`crate::daita_driver::DaitaDriver`]: a caller-spawned task that emits cover
//! on the schedule, with a [`IdleCoverDriverHandle`] the datapath uses to report
//! real traffic (which pushes the deadline out, so cover is silent under load).
//! When the datapath does not report activity, the driver simply emits on every
//! jittered interval, which is still correct (it keeps the connection alive and
//! replaces the beacon), only without the under-load optimization.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Lower bound of the jittered idle interval before a cover datagram is emitted.
pub const IDLE_COVER_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// Upper bound of the jittered idle interval. Kept below the ~30s NAT/CGNAT UDP
/// mapping expiry (so cover refreshes the mapping) with margin; a dead exit is
/// still detected by the QUIC idle timeout once cover stops being acknowledged.
pub const IDLE_COVER_MAX_INTERVAL: Duration = Duration::from_secs(20);

/// Lower bound of the varied cover padding length, in bytes (the datagram is one
/// tag byte plus this). The upper bound is `max_inner_payload - 1`.
pub const IDLE_COVER_MIN_PADDING: usize = 63;

/// Hard cap on the cover padding length (full path-MTU floor minus the tag).
const IDLE_COVER_MAX_PADDING_CAP: usize = 1279;

// Compile-time guards: the interval ceiling must stay under the NAT expiry, or
// cover would stop refreshing the path.
const _: () = assert!(
    IDLE_COVER_MIN_INTERVAL.as_secs() < IDLE_COVER_MAX_INTERVAL.as_secs(),
    "idle cover min interval must be below the max"
);
const _: () = assert!(
    IDLE_COVER_MAX_INTERVAL.as_secs() < 30,
    "idle cover max interval must stay below the ~30s NAT mapping expiry"
);

/// A live tunnel session cover traffic can be driven over. Both
/// [`crate::client::ClientSession`] and [`crate::multihop::MultihopSession`]
/// implement it, so [`IdleCoverDriver`] is shared across the single-hop and
/// multihop paths.
pub trait CoverSink: Send + Sync + 'static {
    /// Sends one cover (dummy) datagram of `padding_len` padding bytes. Returns
    /// `false` if the tunnel is gone (the driver then stops). A `bool` keeps the
    /// trait free of each session's distinct error type.
    fn send_cover(&self, padding_len: usize) -> bool;
    /// The largest inner payload a cover datagram can carry on the current path.
    fn max_inner_payload(&self) -> usize;
    /// A stable, connection-local id used only to seed the jitter PRNG (never on
    /// the wire), so two concurrent tunnels do not share a cover schedule.
    fn cover_seed(&self) -> u64;
}

/// Jittered idle cover-traffic scheduler. See the module docs.
pub struct IdleCover {
    rng: u64,
    min_interval_us: u64,
    span_interval_us: u64,
    min_padding: usize,
    span_padding: usize,
    next: Instant,
}

impl IdleCover {
    /// Builds a scheduler seeded by `seed`, arming the first deadline relative to
    /// `now`. `max_inner_payload` is the connection's current datagram limit;
    /// cover padding is capped to `min(it - 1, 1279)` so a dummy never exceeds
    /// the path MTU.
    #[must_use]
    pub fn new(seed: u64, now: Instant, max_inner_payload: usize) -> Self {
        let max_padding = max_inner_payload
            .saturating_sub(1)
            .clamp(IDLE_COVER_MIN_PADDING, IDLE_COVER_MAX_PADDING_CAP);
        let min_us = IDLE_COVER_MIN_INTERVAL.as_micros() as u64;
        let max_us = IDLE_COVER_MAX_INTERVAL.as_micros() as u64;
        let mut cover = Self {
            rng: seed ^ 0x9E37_79B9_7F4A_7C15,
            min_interval_us: min_us,
            span_interval_us: max_us - min_us,
            min_padding: IDLE_COVER_MIN_PADDING,
            span_padding: max_padding - IDLE_COVER_MIN_PADDING,
            next: now,
        };
        cover.arm(now);
        cover
    }

    /// splitmix64: fast, well-distributed, non-cryptographic.
    fn next_u64(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn arm(&mut self, now: Instant) {
        let jitter = self.next_u64() % (self.span_interval_us + 1);
        self.next = now + Duration::from_micros(self.min_interval_us + jitter);
    }

    /// Reset the deadline because real traffic occurred at `now`. While there is
    /// real traffic the deadline keeps moving out, so no cover is emitted.
    pub fn note_activity(&mut self, now: Instant) {
        self.arm(now);
    }

    /// The instant the driver should sleep until before emitting cover.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.next
    }

    /// Produce the padding length for one cover datagram (idle elapsed) and
    /// re-arm the next deadline relative to `now`. Varied within
    /// `[IDLE_COVER_MIN_PADDING, max]`.
    #[must_use]
    pub fn fire(&mut self, now: Instant) -> usize {
        let padding = self.min_padding + (self.next_u64() as usize % (self.span_padding + 1));
        self.arm(now);
        padding
    }
}

/// Drives idle cover traffic for a [`CoverSink`] session. Construct with
/// [`new`](Self::new), spawn [`run`](Self::run), and report real traffic through
/// a [`handle`](Self::handle) so cover stays silent under load.
pub struct IdleCoverDriver<S: CoverSink> {
    session: Arc<S>,
    cover: Mutex<IdleCover>,
    wake: Notify,
    covers_sent: std::sync::atomic::AtomicU64,
}

impl<S: CoverSink> IdleCoverDriver<S> {
    /// Builds a driver for `session`, arming the first cover deadline now.
    #[must_use]
    pub fn new(session: Arc<S>) -> Arc<Self> {
        let cover = IdleCover::new(
            session.cover_seed(),
            Instant::now(),
            session.max_inner_payload(),
        );
        Arc::new(Self {
            session,
            cover: Mutex::new(cover),
            wake: Notify::new(),
            covers_sent: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// A cheap, cloneable handle the datapath uses to report real traffic.
    #[must_use]
    pub fn handle(self: &Arc<Self>) -> IdleCoverDriverHandle<S> {
        IdleCoverDriverHandle(Arc::clone(self))
    }

    /// Number of cover datagrams emitted so far (observability / tests).
    #[must_use]
    pub fn covers_sent(&self) -> u64 {
        self.covers_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Runs the cover loop until `stop` is notified or the tunnel closes (a cover
    /// send then errors). The loop never holds the lock across an `.await`, and
    /// the cover send is synchronous, so it cannot stall the runtime.
    pub async fn run(self: Arc<Self>, stop: Arc<Notify>) {
        loop {
            // Arm the wake waiter BEFORE reading the deadline so an activity
            // report that lands between the two cannot be missed for a cycle
            // (same race-free pattern as DaitaDriver).
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();

            let deadline = self.lock().deadline();
            let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
            tokio::pin!(sleep);
            tokio::select! {
                () = &mut sleep => {}
                () = &mut wake => continue,
                () = stop.notified() => return,
            }

            let padding_len = self.lock().fire(Instant::now());
            if !self.session.send_cover(padding_len) {
                // The tunnel is gone; stop (the session is finished).
                return;
            }
            self.covers_sent
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, IdleCover> {
        self.cover.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A cloneable handle the datapath uses to report real traffic, silencing cover
/// for the next interval. Optional: if the datapath never reports, the driver
/// still emits on every jittered interval (correct, just not load-optimized).
#[derive(Clone)]
pub struct IdleCoverDriverHandle<S: CoverSink>(Arc<IdleCoverDriver<S>>);

impl<S: CoverSink> IdleCoverDriverHandle<S> {
    /// Reports real application traffic (uplink or downlink) at this instant,
    /// pushing the next cover emission out by a fresh jittered interval.
    pub fn note_activity(&self) {
        self.0.lock().note_activity(Instant::now());
        self.0.wake.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_arms_first_deadline_within_bounds() {
        let now = Instant::now();
        let cover = IdleCover::new(1, now, 1280);
        let dl = cover.deadline();
        assert!(dl >= now + IDLE_COVER_MIN_INTERVAL && dl <= now + IDLE_COVER_MAX_INTERVAL);
    }

    #[test]
    fn note_activity_rearms_relative_to_now() {
        let t0 = Instant::now();
        let mut cover = IdleCover::new(7, t0, 1280);
        let later = t0 + Duration::from_secs(100);
        cover.note_activity(later);
        let dl = cover.deadline();
        assert!(
            dl >= later + IDLE_COVER_MIN_INTERVAL && dl <= later + IDLE_COVER_MAX_INTERVAL,
            "note_activity must push the deadline to now+[min,max], silencing cover under load"
        );
    }

    #[test]
    fn fire_padding_is_within_bounds() {
        let now = Instant::now();
        let mut cover = IdleCover::new(42, now, 1280);
        for _ in 0..200 {
            let pad = cover.fire(now);
            assert!(
                (IDLE_COVER_MIN_PADDING..=IDLE_COVER_MAX_PADDING_CAP).contains(&pad),
                "padding {pad} out of bounds"
            );
        }
    }

    #[test]
    fn fire_varies_both_padding_and_interval() {
        let mut now = Instant::now();
        let mut cover = IdleCover::new(0xC0FFEE, now, 1280);
        let mut pads = std::collections::BTreeSet::new();
        let mut intervals = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let before = cover.deadline();
            let gap = before.duration_since(now);
            assert!(gap >= IDLE_COVER_MIN_INTERVAL && gap <= IDLE_COVER_MAX_INTERVAL);
            intervals.insert(gap.as_micros());
            now = before;
            pads.insert(cover.fire(now));
        }
        assert!(pads.len() > 1, "cover must vary the size");
        assert!(intervals.len() > 1, "cover must vary the interval");
    }

    #[test]
    fn small_mtu_clamps_without_panicking() {
        let now = Instant::now();
        let mut cover = IdleCover::new(5, now, 10);
        assert_eq!(
            cover.fire(now),
            IDLE_COVER_MIN_PADDING,
            "below-min MTU clamps to the min padding, never panics on the modulo"
        );
    }

    /// A fake [`CoverSink`] for driver tests (no real connection).
    struct FakeSink;
    impl CoverSink for FakeSink {
        fn send_cover(&self, _padding_len: usize) -> bool {
            true
        }
        fn max_inner_payload(&self) -> usize {
            1280
        }
        fn cover_seed(&self) -> u64 {
            0xABCD
        }
    }

    #[tokio::test]
    async fn driver_construct_handle_and_stop_path() {
        let driver = IdleCoverDriver::new(Arc::new(FakeSink));
        assert_eq!(driver.covers_sent(), 0, "no cover emitted before run");

        // The handle reports activity (locks the scheduler + wakes the loop).
        let handle = driver.handle();
        handle.note_activity();

        // A pre-notified stop makes run return before the first 10s deadline,
        // so no cover is emitted: this exercises new/handle/covers_sent and the
        // stop branch of run without any timing flakiness.
        let stop = Arc::new(Notify::new());
        stop.notify_one();
        tokio::time::timeout(Duration::from_millis(200), driver.clone().run(stop))
            .await
            .expect("run must return promptly on stop");
        assert_eq!(
            driver.covers_sent(),
            0,
            "stop before the first jittered deadline emits no cover"
        );
    }
}
