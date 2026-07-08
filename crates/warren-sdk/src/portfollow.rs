//! Port-follow policy for maintenance migrations (doc 59 SDK parity).
//!
//! When an exit drains for maintenance, a client with active NAT-PMP rules must
//! not silently lose its port. This module carries the app-facing policy
//! surface: how a supervised forward follows its external port across exit
//! changes ([`PortFollowPolicy`]), what happened to it on the last epoch
//! ([`PortFollowOutcome`]), the durable conflict [`AvoidSet`], the structured
//! [`MigrationEvent`] stream, and the candidate-selection decision engine
//! ([`plan_migration`]) used by the reserve-then-switch gate.

use std::time::{Duration, Instant};

/// How long a conflicted candidate exit stays out of rotation (aligned with the
/// warren-app avoid-set).
pub const DEFAULT_AVOID_TTL: Duration = Duration::from_secs(300);

/// Upper bound on one candidate pre-flight probe. Past it the candidate is
/// treated as CONFLICTED (fail-safe: an unreachable NAT-PMP gateway must not
/// look like a grant), mirroring the engine supervisor's pre-swap timeout.
pub const DEFAULT_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);

/// How a supervised forwarded port follows the client across reconnects and
/// maintenance migrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PortFollowPolicy {
    /// Re-suggest the last granted external port on every re-establish; when
    /// the new exit already holds that port, degrade ONCE to a server-assigned
    /// port (`suggested = 0`) instead of failing. A conflict never blocks a
    /// migration and never kills the forward.
    #[default]
    FollowBestEffort,
    /// The external port never degrades silently: on a conflict the mapping
    /// stays unset for that epoch (surfaced as
    /// [`PortFollowOutcome::ConflictStayed`]) and, once the reserve-then-switch
    /// gate is wired, the rule gates the migration itself.
    KeepPortOrStay,
    /// No follow: every epoch asks the exit for a fresh server-assigned port.
    Disabled,
}

/// Per-forward knobs for a supervised entry.
#[derive(Debug, Clone, Copy)]
pub struct PortFollowConfig {
    /// The follow policy (see [`PortFollowPolicy`]).
    pub policy: PortFollowPolicy,
    /// The user-pinned external port for [`PortFollowPolicy::KeepPortOrStay`].
    /// `None` pins the first port the exit grants.
    pub pinned_external_port: Option<u16>,
    /// Base delay of the in-epoch retry backoff after a transient (non-conflict)
    /// establish failure.
    pub retry_base: Duration,
    /// Ceiling of the jittered in-epoch retry backoff.
    pub retry_max: Duration,
}

impl Default for PortFollowConfig {
    fn default() -> Self {
        Self {
            policy: PortFollowPolicy::default(),
            pinned_external_port: None,
            retry_base: Duration::from_millis(250),
            retry_max: Duration::from_secs(20),
        }
    }
}

/// What happened to a supervised forward on its latest (re)establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortFollowOutcome {
    /// The previously-granted external port was re-granted: the public port
    /// followed the client onto this exit.
    Kept {
        /// The external port that was preserved.
        port: u16,
    },
    /// The exit granted a different external port (first grant, an explicit
    /// server pick, or a best-effort degrade after a conflict).
    Changed {
        /// The previous external port, `None` on the first grant.
        previous: Option<u16>,
        /// The newly granted external port.
        port: u16,
    },
    /// A pinned port was refused (held by another client) and the rule did not
    /// degrade: no mapping exists this epoch, the pin is kept for the next one.
    ConflictStayed {
        /// The pinned external port that stays requested.
        pinned: u16,
    },
    /// The mapping could not be established this epoch (transport failure or a
    /// non-conflict refusal); the supervisor keeps retrying.
    Failed,
}

/// A TTL set of candidate exits to keep out of rotation after a port conflict,
/// durable across rotation-cursor wraps (the cursor alone forgets a bad
/// candidate after one full turn).
#[derive(Debug)]
pub struct AvoidSet<K> {
    ttl: Duration,
    entries: Vec<(K, Instant)>,
}

impl<K: PartialEq> AvoidSet<K> {
    /// An empty set whose entries expire `ttl` after (re)insertion.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Vec::new(),
        }
    }

    /// Marks `key` avoided for the TTL (re-inserting refreshes the deadline).
    pub fn insert(&mut self, key: K) {
        self.insert_at(key, Instant::now());
    }

    /// True while `key` is inside its avoidance TTL.
    #[must_use]
    pub fn contains(&self, key: &K) -> bool {
        self.contains_at(key, Instant::now())
    }

    fn insert_at(&mut self, key: K, now: Instant) {
        self.entries
            .retain(|(k, at)| k != &key && now.saturating_duration_since(*at) < self.ttl);
        self.entries.push((key, now));
    }

    fn contains_at(&self, key: &K, now: Instant) -> bool {
        self.entries
            .iter()
            .any(|(k, at)| k == key && now.saturating_duration_since(*at) < self.ttl)
    }
}

impl<K: PartialEq> Default for AvoidSet<K> {
    fn default() -> Self {
        Self::new(DEFAULT_AVOID_TTL)
    }
}

/// The verdict of [`plan_migration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationDecision {
    /// Migrate to `candidates[index]`: it is not avoided and (when pinned rules
    /// exist) its pre-flight reserved every pinned port.
    MigrateTo(usize),
    /// Every candidate is exhausted (conflicted, timed out, or none exist): do
    /// NOT migrate; stay on the draining exit and keep the port.
    Stay,
}

/// Picks the migration target among `candidates`, in order.
///
/// Without pinned rules nothing gates a migration: the first non-avoided
/// candidate wins without probing (avoidance fails open to the first candidate
/// when all are avoided, because not migrating would be worse for an auto
/// rule). With pinned rules each non-avoided candidate is probed; `probe`
/// resolves `true` when every pinned rule was reserved on it. A refusal OR a
/// probe overrunning `probe_timeout` counts as a conflict (fail-safe) and
/// pushes the candidate into `avoid`; exhausting the ladder yields
/// [`MigrationDecision::Stay`] so the client keeps its port on the draining
/// exit.
pub async fn plan_migration<K, P, Fut>(
    candidates: &[K],
    has_pinned_rules: bool,
    avoid: &mut AvoidSet<K>,
    probe_timeout: Duration,
    mut probe: P,
) -> MigrationDecision
where
    K: PartialEq + Clone,
    P: FnMut(&K) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if candidates.is_empty() {
        return MigrationDecision::Stay;
    }
    if !has_pinned_rules {
        let idx = candidates
            .iter()
            .position(|c| !avoid.contains(c))
            .unwrap_or(0);
        return MigrationDecision::MigrateTo(idx);
    }
    for (idx, candidate) in candidates.iter().enumerate() {
        if avoid.contains(candidate) {
            continue;
        }
        let granted = tokio::time::timeout(probe_timeout, probe(candidate))
            .await
            .unwrap_or(false);
        if granted {
            return MigrationDecision::MigrateTo(idx);
        }
        avoid.insert(candidate.clone());
    }
    MigrationDecision::Stay
}

/// Rotation with durable avoidance: the first index at or after `start`
/// (wrapping) whose key is not avoided. When every candidate is avoided it
/// fails OPEN to `start % keys.len()` (staying offline would be worse than
/// dialing a recently-conflicted exit).
///
/// # Panics
///
/// Panics if `keys` is empty (the failover datapath rejects an empty candidate
/// list up front).
pub(crate) fn next_candidate<K: PartialEq>(start: usize, keys: &[K], avoid: &AvoidSet<K>) -> usize {
    let len = keys.len();
    (0..len)
        .map(|step| (start + step) % len)
        .find(|i| !avoid.contains(&keys[*i]))
        .unwrap_or(start % len)
}

/// A maintenance-migration lifecycle event, exposing the drain advisory's
/// fields plus the outcome, so a host app can render more than the bare
/// `Draining` connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationEvent {
    /// Unix seconds after which the draining exit hard-closes stragglers
    /// (`u64::MAX` = soft drain), from the drain advisory.
    pub deadline_unix_secs: u64,
    /// Opaque operator reason code from the drain advisory (0 = maintenance).
    pub reason_code: u8,
    /// Where the migration stands.
    pub outcome: MigrationOutcome,
}

/// Progress of one maintenance migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MigrationOutcome {
    /// The drain advisory arrived and the supervisor is moving off the exit.
    Migrating,
    /// The post-drain reconnect landed on the new exit (supervised forwards
    /// re-map immediately; watch each rule's [`PortFollowOutcome`]).
    Completed,
    /// Every migration candidate conflicted with a pinned port rule: the
    /// migration was cancelled, the client stays on the draining exit and keeps
    /// its port through the swap (the exit persists mappings across it).
    CancelledPortConflict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avoid_set_expires_entries_after_the_ttl() {
        let mut avoid = AvoidSet::new(Duration::from_secs(300));
        let t0 = Instant::now();
        avoid.insert_at("exit-a", t0);
        assert!(
            avoid.contains_at(&"exit-a", t0 + Duration::from_secs(299)),
            "still avoided within the TTL"
        );
        assert!(
            !avoid.contains_at(&"exit-a", t0 + Duration::from_secs(300)),
            "no longer avoided once the TTL elapses"
        );
        assert!(
            !avoid.contains_at(&"exit-b", t0),
            "an unknown key is never avoided"
        );
    }

    #[test]
    fn avoid_set_reinsert_refreshes_the_deadline() {
        let mut avoid = AvoidSet::new(Duration::from_secs(300));
        let t0 = Instant::now();
        avoid.insert_at("exit-a", t0);
        avoid.insert_at("exit-a", t0 + Duration::from_secs(200));
        assert!(
            avoid.contains_at(&"exit-a", t0 + Duration::from_secs(400)),
            "re-inserting must restart the avoidance window from the new instant"
        );
    }

    #[test]
    fn next_candidate_skips_avoided_exits_and_fails_open() {
        let keys = ["a", "b", "c"];
        let mut avoid = AvoidSet::default();
        assert_eq!(next_candidate(0, &keys, &avoid), 0, "nothing avoided");

        avoid.insert("a");
        assert_eq!(
            next_candidate(0, &keys, &avoid),
            1,
            "a conflicted exit is skipped even though the cursor points at it"
        );
        assert_eq!(
            next_candidate(2, &keys, &avoid),
            2,
            "the cursor position is honoured when it is not avoided"
        );

        avoid.insert("b");
        avoid.insert("c");
        assert_eq!(
            next_candidate(1, &keys, &avoid),
            1,
            "all avoided: fail open to the cursor instead of wedging"
        );
    }

    #[tokio::test]
    async fn plan_stays_when_there_are_no_candidates() {
        let mut avoid = AvoidSet::default();
        let decision = plan_migration(
            &[] as &[&str],
            true,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |_| async { true },
        )
        .await;
        assert_eq!(
            decision,
            MigrationDecision::Stay,
            "no candidate = no migration"
        );
    }

    #[tokio::test]
    async fn plan_without_pinned_rules_migrates_without_probing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let probes = AtomicUsize::new(0);
        let mut avoid = AvoidSet::default();
        let decision = plan_migration(
            &["a", "b"],
            false,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                async { false }
            },
        )
        .await;
        assert_eq!(
            decision,
            MigrationDecision::MigrateTo(0),
            "auto rules never gate a migration"
        );
        assert_eq!(
            probes.load(Ordering::SeqCst),
            0,
            "no pinned rule = nothing to reserve, no probe"
        );
    }

    #[tokio::test]
    async fn plan_without_pinned_rules_prefers_a_non_avoided_candidate() {
        let mut avoid = AvoidSet::default();
        avoid.insert("a");
        let decision = plan_migration(
            &["a", "b"],
            false,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |_| async { true },
        )
        .await;
        assert_eq!(
            decision,
            MigrationDecision::MigrateTo(1),
            "a recently conflicted candidate is skipped while an alternative exists"
        );

        avoid.insert("b");
        let decision = plan_migration(
            &["a", "b"],
            false,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |_| async { true },
        )
        .await;
        assert_eq!(
            decision,
            MigrationDecision::MigrateTo(0),
            "with every candidate avoided the avoid-set fails OPEN for auto rules"
        );
    }

    #[tokio::test]
    async fn plan_with_pinned_rules_takes_the_first_granting_candidate() {
        let mut avoid = AvoidSet::default();
        let decision = plan_migration(
            &["a", "b"],
            true,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |c| {
                let granted = *c == "a";
                async move { granted }
            },
        )
        .await;
        assert_eq!(decision, MigrationDecision::MigrateTo(0));
        assert!(!avoid.contains(&"a"), "a granting candidate is not avoided");
    }

    #[tokio::test]
    async fn plan_climbs_the_ladder_past_a_conflicted_candidate() {
        let mut avoid = AvoidSet::default();
        let decision = plan_migration(
            &["a", "b"],
            true,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |c| {
                let granted = *c == "b";
                async move { granted }
            },
        )
        .await;
        assert_eq!(
            decision,
            MigrationDecision::MigrateTo(1),
            "a conflict on the first candidate moves to the next"
        );
        assert!(
            avoid.contains(&"a"),
            "the conflicted candidate enters the avoid-set"
        );
    }

    #[tokio::test]
    async fn plan_stays_when_every_candidate_conflicts() {
        let mut avoid = AvoidSet::default();
        let decision = plan_migration(
            &["a", "b"],
            true,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |_| async { false },
        )
        .await;
        assert_eq!(
            decision,
            MigrationDecision::Stay,
            "all candidates conflicted: the pinned rule wins, no migration"
        );
        assert!(avoid.contains(&"a") && avoid.contains(&"b"));
    }

    #[tokio::test]
    async fn plan_treats_a_probe_timeout_as_a_conflict() {
        let mut avoid = AvoidSet::default();
        let decision = plan_migration(&["a"], true, &mut avoid, Duration::from_millis(50), |_| {
            std::future::pending::<bool>()
        })
        .await;
        assert_eq!(
            decision,
            MigrationDecision::Stay,
            "a hung pre-flight must fail SAFE (as a conflict), never as a grant"
        );
        assert!(
            avoid.contains(&"a"),
            "the timed-out candidate is avoided like a conflicted one"
        );
    }

    #[tokio::test]
    async fn plan_skips_an_avoided_candidate_without_probing_it() {
        use std::sync::Mutex;
        let probed = Mutex::new(Vec::new());
        let mut avoid = AvoidSet::default();
        avoid.insert("a");
        let decision = plan_migration(
            &["a", "b"],
            true,
            &mut avoid,
            DEFAULT_PREFLIGHT_TIMEOUT,
            |c| {
                probed.lock().unwrap().push(*c);
                async { true }
            },
        )
        .await;
        assert_eq!(decision, MigrationDecision::MigrateTo(1));
        assert_eq!(
            *probed.lock().unwrap(),
            vec!["b"],
            "an avoided candidate is not probed again inside its TTL"
        );
    }
}
