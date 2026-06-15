//! The synchronous DAITA driver: a [`maybenot`] framework wrapper plus the
//! per-machine timer bookkeeping. Does no I/O; an async pump (one level up)
//! owns the wall clock, the cover-traffic emission and the wake-ups.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};

use maybenot::{Framework, Machine, TriggerAction, TriggerEvent};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::config::{DaitaConfig, DaitaError};

/// Opaque identifier of a machine within a running framework (re-exported from
/// maybenot so callers can name the machine a drained padding action came from).
pub use maybenot::MachineId;

/// Idle sleep when no action timer is armed. The pump keeps one sleep arm so its
/// `select!` shape is uniform; the next traffic event (plus a `Notify`) re-arms
/// whatever is actually due, so this only bounds the idle wake-up cadence.
pub const DAITA_PLACEHOLDER_SLEEP: Duration = Duration::from_secs(3600);

/// Warren-side mirror of `maybenot::TriggerEvent`, kept separate so the public
/// surface does not leak upstream types and stays stable across version bumps.
///
/// Pairing convention: for every real packet sent, fire `NormalSent` then
/// `TunnelSent`; for every padding packet, `PaddingSent { machine }` then
/// `TunnelSent`. On receive, `TunnelRecv` then `PaddingRecv`/`NormalRecv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaitaEvent {
    /// One application packet was sent on the tunnel.
    NormalSent,
    /// One application packet was received on the tunnel.
    NormalRecv,
    /// One padding packet was sent, in response to a [`DaitaAction::SendPadding`].
    PaddingSent {
        /// The machine that requested the padding.
        machine: MachineId,
    },
    /// One padding packet was received on the tunnel.
    PaddingRecv,
    /// A packet of any kind was written to the network (after the kind event).
    TunnelSent,
    /// A packet of any kind was read from the network (before the kind event).
    TunnelRecv,
    /// Outgoing blocking started for `machine` (its `BlockOutgoing` timer fired).
    BlockingBegin {
        /// The machine whose blocking interval just started.
        machine: MachineId,
    },
    /// Outgoing blocking ended after its `duration` elapsed.
    BlockingEnd,
}

/// Which timer a [`DaitaAction::Cancel`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaitaTimer {
    /// The per-machine action timer (drives `SendPadding`/`BlockOutgoing`).
    Action,
    /// The per-machine internal (state-machine) timer.
    Internal,
    /// Both timers at once.
    Both,
}

/// Warren-side mirror of `maybenot::TriggerAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaitaAction {
    /// Arm an action timer; on expiry, emit one padding packet and fire
    /// `PaddingSent { machine }`.
    SendPadding {
        /// The machine requesting the padding.
        machine: MachineId,
        /// Delay until the padding must be emitted, relative to now.
        timeout: Duration,
        /// Padding may be sent during a bypassing block interval.
        bypass: bool,
        /// Padding may be replaced by an already-queued normal packet.
        replace: bool,
    },
    /// Arm an action timer; on expiry, block outgoing traffic for `duration`.
    BlockOutgoing {
        /// The machine requesting the blocking.
        machine: MachineId,
        /// Delay until blocking should start, relative to now.
        timeout: Duration,
        /// How long outgoing traffic stays blocked once started.
        duration: Duration,
        /// Bypass-marked padding is still allowed during the block.
        bypass: bool,
        /// Replace an existing block duration rather than extend it.
        replace: bool,
    },
    /// Cancel the specified timer(s) for the machine.
    Cancel {
        /// The machine whose timer(s) are cancelled.
        machine: MachineId,
        /// Which timer is targeted.
        timer: DaitaTimer,
    },
    /// Update the per-machine internal timer.
    UpdateTimer {
        /// The machine whose internal timer is updated.
        machine: MachineId,
        /// New duration for the internal timer.
        duration: Duration,
        /// Overwrite the existing internal timer rather than taking the max.
        replace: bool,
    },
}

/// The maybenot framework wrapper. `inner` is `None` for a disabled config so
/// every method is a no-op; the machines are owned by the framework (no leak).
struct DaitaFramework {
    inner: Option<Framework<Vec<Machine>, StdRng>>,
    machines_count: usize,
}

impl DaitaFramework {
    fn from_config(cfg: &DaitaConfig, start_time: Instant) -> Result<Self, DaitaError> {
        if !cfg.is_enabled() {
            return Ok(Self {
                inner: None,
                machines_count: 0,
            });
        }
        if !cfg.fractions_valid() {
            return Err(DaitaError::InvalidFraction);
        }
        let machines: Vec<Machine> = cfg
            .machine_specs
            .iter()
            .map(|s| Machine::from_str(s).map_err(|e| DaitaError::InvalidMachine(e.to_string())))
            .collect::<Result<_, _>>()?;
        let machines_count = machines.len();
        let inner = Framework::new(
            machines,
            cfg.max_padding_frac,
            cfg.max_blocking_frac,
            start_time,
            StdRng::from_os_rng(),
        )
        .map_err(|e| DaitaError::Framework(e.to_string()))?;
        Ok(Self {
            inner: Some(inner),
            machines_count,
        })
    }

    fn disabled() -> Self {
        Self {
            inner: None,
            machines_count: 0,
        }
    }

    fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    fn trigger(&mut self, events: &[DaitaEvent], now: Instant) -> Vec<DaitaAction> {
        let Some(fw) = self.inner.as_mut() else {
            return Vec::new();
        };
        let mb_events: Vec<TriggerEvent> = events.iter().map(event_to_maybenot).collect();
        fw.trigger_events(&mb_events, now)
            .map(action_from_maybenot)
            .collect()
    }
}

/// Per-machine timer slot. `action` drives the next `SendPadding`/`BlockOutgoing`
/// expiry; `block_end_at` schedules the matching `BlockingEnd`; `internal` is the
/// state-machine timer some machines re-trigger on.
#[derive(Debug, Default, Clone, Copy)]
struct MachineTimers {
    action: Option<Instant>,
    action_kind: Option<TimerKind>,
    block_end_at: Option<Instant>,
    internal: Option<Instant>,
}

/// Disambiguates the two action-timer kinds so [`DaitaState::drain_expired`]
/// fires the correct follow-up event into the framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerKind {
    Padding,
    Block { duration: Duration },
}

/// Per-session DAITA counters (observability only, never on the wire).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DaitaMetrics {
    /// Total `SendPadding` action timers that fired (one dummy emitted each).
    pub padding_fired: u64,
    /// Total `BlockOutgoing` action timers that fired.
    pub blocking_begins: u64,
    /// Total block intervals that ended.
    pub blocking_ends: u64,
}

/// Stateful driver around the framework, maintaining per-machine timers. Poll it
/// synchronously from an async pump: fire events on traffic, read
/// [`Self::sleep_deadline`] for the next wake, and [`Self::drain_expired`] on
/// wake to learn which machines want a dummy emitted.
pub struct DaitaState {
    framework: DaitaFramework,
    timers: HashMap<MachineId, MachineTimers>,
    metrics: DaitaMetrics,
}

impl std::fmt::Debug for DaitaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaitaState")
            .field("enabled", &self.framework.is_enabled())
            .field("machines", &self.framework.machines_count)
            .field("pending_action_timers", &self.count_pending_action_timers())
            .finish()
    }
}

impl DaitaState {
    /// Builds a driver from a wire-level [`DaitaConfig`]. The driver is disabled
    /// (`is_enabled() == false`) when the config carries no machines.
    ///
    /// # Errors
    ///
    /// [`DaitaError::InvalidFraction`] if the caps are out of range,
    /// [`DaitaError::InvalidMachine`] if a spec fails to parse,
    /// [`DaitaError::Framework`] if maybenot refuses the configuration.
    pub fn from_config(cfg: &DaitaConfig, start_time: Instant) -> Result<Self, DaitaError> {
        Ok(Self {
            framework: DaitaFramework::from_config(cfg, start_time)?,
            timers: HashMap::new(),
            metrics: DaitaMetrics::default(),
        })
    }

    /// A disabled driver (no machines, no timers) for an opted-out session.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            framework: DaitaFramework::disabled(),
            timers: HashMap::new(),
            metrics: DaitaMetrics::default(),
        }
    }

    /// A snapshot of the per-session counters.
    #[must_use]
    pub fn metrics(&self) -> DaitaMetrics {
        self.metrics
    }

    /// True if the framework drives any machine.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.framework.is_enabled()
    }

    /// Number of machines the framework drives.
    #[must_use]
    pub fn machines_count(&self) -> usize {
        self.framework.machines_count
    }

    /// Feeds `events` into the framework and updates the timer slots from the
    /// emitted actions. Returns the actions for caller inspection (the timer
    /// logic is already applied internally).
    pub fn fire_events(&mut self, events: &[DaitaEvent], now: Instant) -> Vec<DaitaAction> {
        let actions = self.framework.trigger(events, now);
        for action in &actions {
            self.apply_action(*action, now);
        }
        actions
    }

    /// Fires `NormalSent` then `TunnelSent` for one real uplink packet.
    pub fn on_real_uplink_sent(&mut self, now: Instant) {
        self.fire_events(&[DaitaEvent::NormalSent, DaitaEvent::TunnelSent], now);
    }

    /// Fires `PaddingSent { machine }` then `TunnelSent` after a dummy was put on
    /// the wire for `machine`. Call once per machine from [`Self::drain_expired`].
    pub fn on_dummy_sent(&mut self, machine: MachineId, now: Instant) {
        self.fire_events(
            &[DaitaEvent::PaddingSent { machine }, DaitaEvent::TunnelSent],
            now,
        );
    }

    /// Fires `TunnelRecv` then the kind event for one received datagram
    /// (`PaddingRecv` for a dummy the caller drops, else `NormalRecv`).
    pub fn on_downlink_received(&mut self, is_dummy: bool, now: Instant) {
        let kind = if is_dummy {
            DaitaEvent::PaddingRecv
        } else {
            DaitaEvent::NormalRecv
        };
        self.fire_events(&[DaitaEvent::TunnelRecv, kind], now);
    }

    /// The earliest pending action or block-end instant, or `None` if no timer is
    /// armed. The pump uses it with `sleep_until` to wake exactly when due.
    #[must_use]
    pub fn next_timer(&self) -> Option<Instant> {
        self.timers
            .values()
            .flat_map(|t| t.action.into_iter().chain(t.block_end_at))
            .min()
    }

    /// The deadline the pump should `sleep_until` before re-checking: the next
    /// armed timer, or [`DAITA_PLACEHOLDER_SLEEP`] from now when none is armed.
    #[must_use]
    pub fn sleep_deadline(&self, now: Instant) -> Instant {
        self.next_timer().unwrap_or(now + DAITA_PLACEHOLDER_SLEEP)
    }

    /// Drains action timers expired at or before `now`, returning one machine id
    /// per fired padding timer (the caller emits a dummy and calls
    /// [`Self::on_dummy_sent`] for each). `BlockingBegin`/`BlockingEnd` are fired
    /// back into the framework internally and are not surfaced.
    pub fn drain_expired(&mut self, now: Instant) -> Vec<MachineId> {
        let mut fired = Vec::new();
        let mut blocking_begins: Vec<MachineId> = Vec::new();
        let mut blocking_ends: Vec<MachineId> = Vec::new();
        for (id, t) in &mut self.timers {
            if let Some(at) = t.action
                && at <= now
            {
                t.action = None;
                let kind = t.action_kind.take();
                fired.push(*id);
                match kind {
                    Some(TimerKind::Block { duration }) => {
                        t.block_end_at = Some(now + duration);
                        blocking_begins.push(*id);
                        self.metrics.blocking_begins =
                            self.metrics.blocking_begins.saturating_add(1);
                    }
                    Some(TimerKind::Padding) | None => {
                        self.metrics.padding_fired = self.metrics.padding_fired.saturating_add(1);
                    }
                }
            }
            if let Some(end_at) = t.block_end_at
                && end_at <= now
            {
                t.block_end_at = None;
                blocking_ends.push(*id);
                self.metrics.blocking_ends = self.metrics.blocking_ends.saturating_add(1);
            }
        }
        for machine in blocking_begins {
            self.fire_events(&[DaitaEvent::BlockingBegin { machine }], now);
        }
        if !blocking_ends.is_empty() {
            self.fire_events(&[DaitaEvent::BlockingEnd], now);
        }
        fired
    }

    fn count_pending_action_timers(&self) -> usize {
        self.timers.values().filter(|t| t.action.is_some()).count()
    }

    fn apply_action(&mut self, action: DaitaAction, now: Instant) {
        match action {
            DaitaAction::SendPadding {
                machine, timeout, ..
            } => {
                let entry = self.timers.entry(machine).or_default();
                entry.action = Some(now + timeout);
                entry.action_kind = Some(TimerKind::Padding);
            }
            DaitaAction::BlockOutgoing {
                machine,
                timeout,
                duration,
                ..
            } => {
                let entry = self.timers.entry(machine).or_default();
                entry.action = Some(now + timeout);
                entry.action_kind = Some(TimerKind::Block { duration });
            }
            DaitaAction::Cancel { machine, timer } => {
                let entry = self.timers.entry(machine).or_default();
                match timer {
                    DaitaTimer::Action => {
                        entry.action = None;
                        entry.action_kind = None;
                    }
                    DaitaTimer::Internal => entry.internal = None,
                    DaitaTimer::Both => {
                        entry.action = None;
                        entry.action_kind = None;
                        entry.internal = None;
                    }
                }
            }
            DaitaAction::UpdateTimer {
                machine,
                duration,
                replace,
            } => {
                let at = now + duration;
                let entry = self.timers.entry(machine).or_default();
                entry.internal = match (entry.internal, replace) {
                    (None, _) | (Some(_), true) => Some(at),
                    (Some(prev), false) => Some(prev.max(at)),
                };
            }
        }
    }
}

fn event_to_maybenot(event: &DaitaEvent) -> TriggerEvent {
    match *event {
        DaitaEvent::NormalSent => TriggerEvent::NormalSent,
        DaitaEvent::NormalRecv => TriggerEvent::NormalRecv,
        DaitaEvent::PaddingSent { machine } => TriggerEvent::PaddingSent { machine },
        DaitaEvent::PaddingRecv => TriggerEvent::PaddingRecv,
        DaitaEvent::TunnelSent => TriggerEvent::TunnelSent,
        DaitaEvent::TunnelRecv => TriggerEvent::TunnelRecv,
        DaitaEvent::BlockingBegin { machine } => TriggerEvent::BlockingBegin { machine },
        DaitaEvent::BlockingEnd => TriggerEvent::BlockingEnd,
    }
}

fn action_from_maybenot(action: &TriggerAction) -> DaitaAction {
    match *action {
        TriggerAction::SendPadding {
            machine,
            timeout,
            bypass,
            replace,
        } => DaitaAction::SendPadding {
            machine,
            timeout,
            bypass,
            replace,
        },
        TriggerAction::BlockOutgoing {
            machine,
            timeout,
            duration,
            bypass,
            replace,
        } => DaitaAction::BlockOutgoing {
            machine,
            timeout,
            duration,
            bypass,
            replace,
        },
        TriggerAction::Cancel { machine, timer } => DaitaAction::Cancel {
            machine,
            timer: timer_from_maybenot(timer),
        },
        TriggerAction::UpdateTimer {
            machine,
            duration,
            replace,
        } => DaitaAction::UpdateTimer {
            machine,
            duration,
            replace,
        },
    }
}

fn timer_from_maybenot(timer: maybenot::Timer) -> DaitaTimer {
    match timer {
        maybenot::Timer::Action => DaitaTimer::Action,
        maybenot::Timer::Internal => DaitaTimer::Internal,
        maybenot::Timer::All => DaitaTimer::Both,
    }
}
