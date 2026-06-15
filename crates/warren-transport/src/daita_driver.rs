//! Async DAITA pump for a multihop session.
//!
//! [`DaitaDriver`] drives a [`warren_daita::DaitaState`] over a live
//! [`MultihopSession`]: its [`run`](DaitaDriver::run) loop sleeps until the next
//! scheduled padding action, then emits a cover-traffic frame on the uplink and
//! feeds the `PaddingSent` event back into the maybenot framework. The datapath
//! reports real traffic through a [`DaitaDriverHandle`]
//! ([`note_uplink`](DaitaDriverHandle::note_uplink) /
//! [`note_downlink`](DaitaDriverHandle::note_downlink)), which also wakes the
//! loop so a freshly armed timer takes effect immediately.
//!
//! On the multihop path the client's defense is unilateral: it pads its own
//! uplink from a machine it picked (see [`warren_daita::DaitaPool`]); the exit
//! pads the downlink independently. A disabled state makes [`run`](DaitaDriver::run)
//! a no-op, so the driver is always safe to spawn.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Notify;
use warren_daita::{DaitaMetrics, DaitaState};

use crate::multihop::MultihopSession;

/// Drives uplink cover traffic for a [`MultihopSession`] from a DAITA state
/// machine. Construct with [`new`](Self::new), spawn [`run`](Self::run), and feed
/// traffic events through a [`handle`](Self::handle).
pub struct DaitaDriver {
    session: Arc<MultihopSession>,
    state: Mutex<DaitaState>,
    /// Wakes the run loop when an event arms a closer timer than the one it is
    /// currently sleeping on.
    wake: Notify,
}

impl DaitaDriver {
    /// Builds a driver for `session` driven by `state`. The returned `Arc` is
    /// shared between the [`run`](Self::run) task and any [`handle`](Self::handle)s.
    #[must_use]
    pub fn new(session: Arc<MultihopSession>, state: DaitaState) -> Arc<Self> {
        Arc::new(Self {
            session,
            state: Mutex::new(state),
            wake: Notify::new(),
        })
    }

    /// A cheap, cloneable handle the datapath uses to report traffic events.
    #[must_use]
    pub fn handle(self: &Arc<Self>) -> DaitaDriverHandle {
        DaitaDriverHandle(Arc::clone(self))
    }

    /// A snapshot of the DAITA counters (padding fired, blocking begins/ends).
    #[must_use]
    pub fn metrics(&self) -> DaitaMetrics {
        self.lock().metrics()
    }

    /// True if the underlying state drives any machine (false short-circuits
    /// [`run`](Self::run) to an immediate return).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.lock().is_enabled()
    }

    /// Runs the padding loop until `stop` is notified or the session's tunnel
    /// closes (a cover send then errors). A disabled state returns immediately.
    ///
    /// The loop never holds the state lock across an `.await`, and the cover send
    /// is synchronous, so it cannot stall the runtime.
    pub async fn run(self: Arc<Self>, stop: Arc<Notify>) {
        if !self.is_enabled() {
            return;
        }
        loop {
            let deadline = self.lock().sleep_deadline(Instant::now());
            let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
            tokio::pin!(sleep);
            tokio::select! {
                () = &mut sleep => {}
                // An event armed a (possibly closer) timer: re-arm on the new deadline.
                () = self.wake.notified() => continue,
                () = stop.notified() => return,
            }

            let now = Instant::now();
            let fired = self.lock().drain_expired(now);
            if fired.is_empty() {
                continue;
            }
            // Full-size dummies (minus the 1-byte dummy tag) so a constant-rate
            // machine like Tamaraw regularises the on-wire packet size too.
            let padding_len = self.session.max_inner_payload().saturating_sub(1);
            for machine in fired {
                if self.session.send_cover_traffic(padding_len).is_err() {
                    // The tunnel is gone; stop padding (the session is finished).
                    return;
                }
                self.lock().on_dummy_sent(machine, Instant::now());
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DaitaState> {
        // The state is plain bookkeeping; recover rather than poison-propagate so
        // a panicking caller never wedges the padding loop.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A cloneable handle the datapath uses to report real traffic to the driver.
/// Each call also wakes the run loop so a newly armed padding timer is honored
/// without waiting out the previous sleep.
#[derive(Clone)]
pub struct DaitaDriverHandle(Arc<DaitaDriver>);

impl DaitaDriverHandle {
    /// Reports one real application packet sent on the uplink (`NormalSent` then
    /// `TunnelSent`).
    pub fn note_uplink(&self) {
        self.0.lock().on_real_uplink_sent(Instant::now());
        self.0.wake.notify_one();
    }

    /// Reports one datagram received from the tunnel: `is_dummy` distinguishes a
    /// DAITA cover frame (`PaddingRecv`) from a real packet (`NormalRecv`).
    pub fn note_downlink(&self, is_dummy: bool) {
        self.0.lock().on_downlink_received(is_dummy, Instant::now());
        self.0.wake.notify_one();
    }

    /// A snapshot of the DAITA counters.
    #[must_use]
    pub fn metrics(&self) -> DaitaMetrics {
        self.0.metrics()
    }
}
