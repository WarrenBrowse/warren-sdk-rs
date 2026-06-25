//! Reconnection primitives: full-jitter exponential backoff and a retrying
//! connector that drives an async connect operation until it succeeds.
//!
//! The backoff follows the AWS "Exponential Backoff and Jitter" pattern: the
//! first attempt fires immediately (delay zero), then each subsequent delay is
//! sampled uniformly in `[current / 2, current]` with `current` doubling up to
//! a hard ceiling. Full jitter avoids thundering-herd reconnects when many
//! clients race the same exit after an outage.
//!
//! The schedule is deliberately a plain iterator of [`Duration`]s so the same
//! shape maps cleanly to the sibling-language SDKs (the FFI layer wants narrow,
//! serializable seams). [`connect_with_retry`] is the async driver layered on
//! top; it is generic over the connect closure so it is testable without a
//! network.

use std::future::Future;
use std::iter::FusedIterator;
use std::time::Duration;

use rand::Rng;

/// Exponential backoff schedule (base delay + hard ceiling).
///
/// Purely descriptive: nothing happens until [`Backoff::take`] turns it into a
/// [`BackoffIter`]. If `base > max`, the iterator clamps the effective base to
/// `max` so the `delay <= max` invariant always holds.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use warren_transport::Backoff;
///
/// let delays: Vec<Duration> = Backoff::HANDSHAKE.take(3).collect();
/// assert_eq!(delays.len(), 3);
/// assert_eq!(delays[0], Duration::ZERO); // first attempt is immediate
/// assert!(delays.iter().all(|d| *d <= Backoff::HANDSHAKE.max));
/// ```
#[derive(Clone, Copy, Debug)]
#[must_use = "a Backoff schedule does nothing until you call `.take(n)`"]
pub struct Backoff {
    /// Initial non-zero delay (the first jitter upper bound).
    pub base: Duration,
    /// Hard ceiling: no individual delay ever exceeds this value.
    pub max: Duration,
}

impl Backoff {
    /// QUIC handshake / connect retry profile: base 500 ms, ceiling 15 s.
    pub const HANDSHAKE: Self = Self {
        base: Duration::from_millis(500),
        max: Duration::from_secs(15),
    };

    /// Long-running background loop profile: base 1 s, ceiling 60 s.
    pub const BACKGROUND: Self = Self {
        base: Duration::from_secs(1),
        max: Duration::from_secs(60),
    };

    /// Fast-call retry profile: base 200 ms, ceiling 5 s.
    pub const SHORT: Self = Self {
        base: Duration::from_millis(200),
        max: Duration::from_secs(5),
    };

    /// Builds a finite iterator yielding `attempts` successive delays. The
    /// first delay is always [`Duration::ZERO`] (retry immediately); each
    /// subsequent delay is drawn from `[current / 2, current]` with `current`
    /// doubling up to [`Backoff::max`].
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    pub fn take(self, attempts: usize) -> BackoffIter {
        BackoffIter {
            backoff: self,
            remaining: attempts,
            next: Duration::ZERO,
        }
    }

    /// Builds an unbounded [`JitterBackoff`] for a supervisor that retries
    /// indefinitely (the first delay is still [`Duration::ZERO`]).
    #[must_use]
    pub fn forever(self) -> JitterBackoff {
        JitterBackoff {
            backoff: self,
            next: Duration::ZERO,
        }
    }
}

/// Iterator of successive backoff delays from a [`Backoff`].
///
/// Created by [`Backoff::take`]. [`ExactSizeIterator`] exposes the remaining
/// attempt count; [`FusedIterator`] because it stays `None` once exhausted.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct BackoffIter {
    backoff: Backoff,
    remaining: usize,
    next: Duration,
}

/// Advances `next` per the full-jitter law and returns this attempt's delay: the
/// first call (when `next` is zero) fires immediately and seeds `next` at `base`;
/// each later call draws from `[current / 2, current]` and doubles up to `max`.
/// Shared by the finite [`BackoffIter`] and the unbounded [`JitterBackoff`].
fn jitter_step(backoff: &Backoff, next: &mut Duration) -> Duration {
    if next.is_zero() {
        *next = backoff.base.min(backoff.max);
        return Duration::ZERO;
    }
    let current = (*next).min(backoff.max);
    *next = current.saturating_mul(2).min(backoff.max);
    let half = current / 2;
    let half_nanos = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
    // Inclusive range so the delay can be exactly `current` (= half + half).
    let jitter_nanos = rand::thread_rng().gen_range(0..=half_nanos);
    half + Duration::from_nanos(jitter_nanos)
}

impl Iterator for BackoffIter {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(jitter_step(&self.backoff, &mut self.next))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

/// Unbounded full-jitter backoff for supervisors that retry indefinitely (where
/// the finite [`BackoffIter`] does not fit). Same jitter law: the first
/// [`next_delay`](Self::next_delay) is zero, then each is drawn from
/// `[current / 2, current]` doubling up to the ceiling. [`reset`](Self::reset)
/// returns to the immediate-retry state, e.g. after a session that stayed healthy.
#[derive(Clone, Copy, Debug)]
pub struct JitterBackoff {
    backoff: Backoff,
    next: Duration,
}

impl JitterBackoff {
    /// Returns the next delay and advances the schedule.
    #[must_use]
    pub fn next_delay(&mut self) -> Duration {
        jitter_step(&self.backoff, &mut self.next)
    }

    /// Resets to the immediate-retry state (the next delay is zero again).
    pub fn reset(&mut self) {
        self.next = Duration::ZERO;
    }
}

impl ExactSizeIterator for BackoffIter {
    fn len(&self) -> usize {
        self.remaining
    }
}

impl FusedIterator for BackoffIter {}

/// Outcome of [`connect_with_retry`] when no attempt succeeds.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RetryError<E: std::error::Error + 'static> {
    /// Every attempt failed; carries the count made and the last error.
    #[error("all {attempts} connect attempts failed")]
    Exhausted {
        /// Number of connect attempts actually made.
        attempts: usize,
        /// The error from the final attempt.
        #[source]
        last: E,
    },
    /// `attempts` was zero, so the connect closure was never called.
    #[error("no connect attempts were made")]
    NoAttempts,
}

/// Lifecycle state of a supervised connection, surfaced to observers (and, via
/// the FFI layer, to host apps). A plain C-like enum so it maps cleanly to every
/// sibling-language SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    /// The initial connect attempt is in flight.
    Connecting,
    /// A connection is established.
    Connected,
    /// A previous attempt failed; the next retry is in flight (after backoff).
    Reconnecting,
    /// ADR 36: the exit signalled a planned maintenance drain, and the
    /// supervisor is proactively migrating off it (a reconnect, but one the
    /// host can distinguish from a failure-driven `Reconnecting` to show a
    /// "switching server for maintenance" UI). Followed by `Connected`.
    Draining,
    /// Every attempt failed; the supervisor gave up.
    Failed,
}

/// Like [`connect_with_retry`], but reports each [`ConnectionState`] transition
/// to `on_state` as it happens: `Connecting` for the first attempt,
/// `Reconnecting` before each retry, then `Connected` on success or `Failed`
/// once attempts are exhausted.
///
/// The observer is a plain `FnMut` so tests can record the exact transition
/// sequence and the FFI layer can forward it to a uniffi callback interface. It
/// is invoked between awaits (never held across one).
///
/// # Errors
///
/// [`RetryError::Exhausted`] with the last error if every attempt fails;
/// [`RetryError::NoAttempts`] if `attempts` is zero.
pub async fn connect_with_state<F, Fut, T, E>(
    backoff: Backoff,
    attempts: usize,
    mut on_state: impl FnMut(ConnectionState),
    mut connect: F,
) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::error::Error + 'static,
{
    let mut last: Option<E> = None;
    let mut made = 0usize;
    for (i, delay) in backoff.take(attempts).enumerate() {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        on_state(if i == 0 {
            ConnectionState::Connecting
        } else {
            ConnectionState::Reconnecting
        });
        made += 1;
        match connect().await {
            Ok(value) => {
                on_state(ConnectionState::Connected);
                return Ok(value);
            }
            Err(e) => last = Some(e),
        }
    }
    on_state(ConnectionState::Failed);
    match last {
        Some(last) => Err(RetryError::Exhausted {
            attempts: made,
            last,
        }),
        None => Err(RetryError::NoAttempts),
    }
}

/// Drives `connect` with full-jitter backoff until it returns `Ok` or
/// `attempts` is exhausted. The first attempt is immediate; failing attempts
/// sleep for the next backoff delay before retrying.
///
/// Generic over the connect closure so the retry policy is unit-testable with
/// a fake connector and `tokio::time` paused; the real call sites pass a closure
/// that dials the exit.
///
/// # Errors
///
/// [`RetryError::Exhausted`] with the last error if every attempt fails;
/// [`RetryError::NoAttempts`] if `attempts` is zero.
pub async fn connect_with_retry<F, Fut, T, E>(
    backoff: Backoff,
    attempts: usize,
    mut connect: F,
) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::error::Error + 'static,
{
    let mut last: Option<E> = None;
    let mut made = 0usize;
    for delay in backoff.take(attempts) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        made += 1;
        match connect().await {
            Ok(value) => return Ok(value),
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(last) => Err(RetryError::Exhausted {
            attempts: made,
            last,
        }),
        None => Err(RetryError::NoAttempts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn first_delay_is_zero_then_jittered() {
        let delays: Vec<Duration> = Backoff::HANDSHAKE.take(4).collect();
        assert_eq!(delays.len(), 4);
        assert_eq!(delays[0], Duration::ZERO);
        for d in &delays[1..] {
            assert!(*d > Duration::ZERO, "post-first delays are non-zero");
        }
    }

    #[test]
    fn no_delay_ever_exceeds_the_ceiling() {
        // Take far past the doubling horizon so `current` saturates at `max`.
        for d in Backoff::SHORT.take(50) {
            assert!(d <= Backoff::SHORT.max, "delay {d:?} exceeded the ceiling");
        }
    }

    #[test]
    fn jitter_backoff_is_unbounded_zero_first_and_resets() {
        let mut b = Backoff::SHORT.forever();
        assert_eq!(b.next_delay(), Duration::ZERO, "first delay is immediate");
        // Drive far past the doubling horizon: stays bounded and non-zero, forever.
        for _ in 0..200 {
            let d = b.next_delay();
            assert!(d > Duration::ZERO, "post-first delays are non-zero");
            assert!(d <= Backoff::SHORT.max, "delay {d:?} exceeded the ceiling");
        }
        // Reset returns to the immediate-retry state (e.g. after a healthy session).
        b.reset();
        assert_eq!(
            b.next_delay(),
            Duration::ZERO,
            "reset re-arms immediate retry"
        );
    }

    #[test]
    fn second_delay_jitters_within_lower_half_of_base() {
        // The first non-zero delay uses current == base, so it must fall in
        // [base/2, base]. Sample many times to catch a broken range, and assert
        // the spread is non-degenerate so a collapse to a constant (e.g.
        // gen_range(0..=0)) is also caught, not just a wrong bound.
        let b = Backoff::SHORT;
        let (mut lo, mut hi) = (b.base, Duration::ZERO);
        for _ in 0..1000 {
            let d = b.take(2).nth(1).unwrap();
            assert!(d >= b.base / 2, "{d:?} below base/2");
            assert!(d <= b.base, "{d:?} above base");
            lo = lo.min(d);
            hi = hi.max(d);
        }
        assert!(lo < b.base * 5 / 8, "jitter never sampled near the low end");
        assert!(
            hi > b.base * 3 / 4,
            "jitter never sampled near the high end"
        );
    }

    #[test]
    fn take_yields_exactly_n_and_reports_remaining() {
        let mut it = Backoff::BACKGROUND.take(3);
        assert_eq!(it.len(), 3);
        it.next();
        assert_eq!(it.len(), 2);
        assert_eq!(it.count(), 2);
    }

    #[test]
    fn iterator_is_fused_after_exhaustion() {
        let mut it = Backoff::SHORT.take(1);
        assert!(it.next().is_some());
        assert!(it.next().is_none());
        assert!(it.next().is_none(), "a fused iterator stays None");
    }

    #[test]
    fn base_above_max_is_clamped_to_max() {
        let weird = Backoff {
            base: Duration::from_secs(100),
            max: Duration::from_secs(2),
        };
        for d in weird.take(10) {
            assert!(d <= weird.max, "clamp failed: {d:?}");
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("fake connect failure")]
    struct FakeErr;

    #[tokio::test(start_paused = true)]
    async fn succeeds_on_first_attempt_without_sleeping() {
        let calls = Cell::new(0);
        let out = connect_with_retry(Backoff::HANDSHAKE, 5, || {
            calls.set(calls.get() + 1);
            async { Ok::<_, FakeErr>(42) }
        })
        .await
        .expect("first attempt ok");
        assert_eq!(out, 42);
        assert_eq!(calls.get(), 1, "no retries when the first attempt succeeds");
    }

    #[tokio::test(start_paused = true)]
    async fn retries_until_success() {
        let calls = Cell::new(0);
        let out = connect_with_retry(Backoff::HANDSHAKE, 5, || {
            let n = calls.get() + 1;
            calls.set(n);
            async move { if n < 3 { Err(FakeErr) } else { Ok(n) } }
        })
        .await
        .expect("third attempt ok");
        assert_eq!(out, 3);
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn exhausts_and_returns_attempt_count_with_last_error() {
        let calls = Cell::new(0);
        let err = connect_with_retry(Backoff::HANDSHAKE, 4, || {
            calls.set(calls.get() + 1);
            async { Err::<u8, _>(FakeErr) }
        })
        .await
        .expect_err("all attempts fail");
        match err {
            RetryError::Exhausted { attempts, last: _ } => assert_eq!(attempts, 4),
            RetryError::NoAttempts => panic!("attempts were made"),
        }
        assert_eq!(calls.get(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn state_sequence_on_first_try_success() {
        let states = std::cell::RefCell::new(Vec::new());
        let out = connect_with_state(
            Backoff::HANDSHAKE,
            5,
            |s| states.borrow_mut().push(s),
            || async { Ok::<_, FakeErr>(7) },
        )
        .await
        .expect("ok");
        assert_eq!(out, 7);
        assert_eq!(
            *states.borrow(),
            vec![ConnectionState::Connecting, ConnectionState::Connected]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn state_sequence_reconnects_then_connects() {
        let states = std::cell::RefCell::new(Vec::new());
        let calls = Cell::new(0);
        connect_with_state(
            Backoff::HANDSHAKE,
            5,
            |s| states.borrow_mut().push(s),
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move { if n < 3 { Err(FakeErr) } else { Ok(n) } }
            },
        )
        .await
        .expect("third attempt ok");
        // First attempt is Connecting, the two retries are Reconnecting, success
        // is Connected. No Failed when a connection is ultimately established.
        assert_eq!(
            *states.borrow(),
            vec![
                ConnectionState::Connecting,
                ConnectionState::Reconnecting,
                ConnectionState::Reconnecting,
                ConnectionState::Connected,
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn state_sequence_ends_in_failed_when_exhausted() {
        let states = std::cell::RefCell::new(Vec::new());
        let err = connect_with_state(
            Backoff::HANDSHAKE,
            3,
            |s| states.borrow_mut().push(s),
            || async { Err::<u8, _>(FakeErr) },
        )
        .await
        .expect_err("all fail");
        assert!(matches!(err, RetryError::Exhausted { attempts: 3, .. }));
        // Exact sequence: attempt 0 Connecting, attempts 1-2 Reconnecting, then
        // the terminal Failed. Asserting the full vector (not just ends) catches
        // a stray or misordered transition.
        assert_eq!(
            *states.borrow(),
            vec![
                ConnectionState::Connecting,
                ConnectionState::Reconnecting,
                ConnectionState::Reconnecting,
                ConnectionState::Failed,
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_attempts_never_calls_connect() {
        let calls = Cell::new(0);
        let err = connect_with_retry(Backoff::HANDSHAKE, 0, || {
            calls.set(calls.get() + 1);
            async { Ok::<_, FakeErr>(1) }
        })
        .await
        .expect_err("zero attempts is an error");
        assert!(matches!(err, RetryError::NoAttempts));
        assert_eq!(calls.get(), 0, "connect must not be called");
    }
}
