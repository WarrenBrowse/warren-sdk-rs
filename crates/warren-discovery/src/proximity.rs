//! Client-side RTT proximity scoring (doc 52 §6.2 client).
//!
//! The measurement STORE is single-homed in `warren-discovery-core`
//! ([`RttCache`], re-exported here): the same store, staleness rule and
//! endpoint keying feed the shared path-aware multihop selection and this
//! module's single-hop scoring, so the client-measured RTT has exactly one
//! source. This module keeps only the SDK's exit-proximity scoring:
//! [`crate::selector::ExitSelector::select_weighted_by_proximity`] turns a
//! fresh measured RTT into an effective score `weight * f(rtt)` and
//! weighted-picks over that.
//!
//! Design invariants:
//! - **Zero data == today.** An exit with no fresh RTT sample is scored at
//!   a fixed neutral baseline, and weighted selection is scale-invariant,
//!   so a fleet with no measurements yields exactly the weight-only
//!   distribution. Proximity only ever *re-weights* what has been probed.
//! - **Never excludes.** A positive-weight exit keeps a score of at least
//!   1 however bad its RTT, so a far exit stays reachable (failover, and
//!   the organic health probe the server floor mirrors).
//! - **Pure and time-injected.** No clock is read here; the caller passes
//!   `now_unix_secs`, so the cache and scoring are deterministically
//!   testable (the SDK portability + TDD rules).

pub use warren_discovery_core::{DEFAULT_RTT_TTL_SECS, EndpointId, RttCache};

/// Reference RTT (ms) shaping the proximity curve `f(rtt) = K / (K + rtt)`.
/// At `rtt == K` the factor is 0.5. 50 ms is a sensible mid-latency knee;
/// tune here if selection should be more or less RTT-sensitive.
const RTT_REFERENCE_MS: f64 = 50.0;

/// RTT (ms) an *unprobed* exit is scored as, so measured exits are ranked
/// relative to a neutral middle rather than being penalised for having
/// been measured at all. A close probed exit beats this baseline; a far
/// probed exit falls below it; an all-unprobed fleet collapses to the
/// weight-only distribution (every candidate shares this factor).
const NEUTRAL_RTT_MS: u32 = 60;

/// Proximity factor in `(0, 1]` for an RTT in ms: `K / (K + rtt)`,
/// monotonically decreasing, 1.0 at 0 ms.
fn proximity_factor(rtt_ms: u32) -> f64 {
    RTT_REFERENCE_MS / (RTT_REFERENCE_MS + f64::from(rtt_ms))
}

/// Effective score for weighted selection: `weight * f(rtt)`, floored at 1
/// for any positive weight so RTT never fully excludes a reachable exit.
/// A zero weight stays zero (the selector already excludes it upstream).
/// `rtt_ms` is the measured RTT, or [`NEUTRAL_RTT_MS`] for an unprobed exit.
#[must_use]
pub(crate) fn proximity_score(weight: u64, rtt_ms: u32) -> u64 {
    if weight == 0 {
        return 0;
    }
    // weight * factor with factor in (0,1]; f64 mantissa loses low bits on
    // near-u64::MAX weights, immaterial for a proportional weighting.
    let scaled = (weight as f64 * proximity_factor(rtt_ms)).round();
    // Clamp into u64 then floor at 1 so a positive-weight exit is never
    // dropped to 0 by a bad RTT.
    let as_u64 = if scaled >= u64::MAX as f64 {
        u64::MAX
    } else if scaled < 1.0 {
        1
    } else {
        scaled as u64
    };
    as_u64.max(1)
}

/// The RTT (ms) to score `endpoint_id` at: its fresh cached sample, or the
/// neutral baseline when unprobed/stale.
#[must_use]
pub(crate) fn effective_rtt_ms(
    cache: &RttCache,
    endpoint_id: EndpointId,
    now_unix_secs: u64,
    ttl_secs: u64,
) -> u32 {
    cache
        .fresh_rtt_ms(endpoint_id, now_unix_secs, ttl_secs)
        .unwrap_or(NEUTRAL_RTT_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eid(b: u8) -> EndpointId {
        [b; 32]
    }

    #[test]
    fn proximity_factor_is_monotonically_decreasing() {
        assert!(proximity_factor(0) > proximity_factor(25));
        assert!(proximity_factor(25) > proximity_factor(50));
        assert!(proximity_factor(50) > proximity_factor(200));
        // Known anchor: at rtt == reference the factor is 0.5.
        assert!((proximity_factor(50) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn score_prefers_lower_rtt_at_equal_weight() {
        // Same weight, closer exit must score strictly higher.
        let near = proximity_score(100, 10);
        let far = proximity_score(100, 200);
        assert!(near > far, "near={near} must beat far={far}");
    }

    #[test]
    fn score_never_drops_a_positive_weight_to_zero() {
        // Even an absurd RTT keeps a reachable exit selectable.
        assert!(proximity_score(1, u32::MAX) >= 1);
        // A zero weight stays zero (excluded upstream).
        assert_eq!(proximity_score(0, 10), 0);
    }

    #[test]
    fn unprobed_exits_share_the_neutral_baseline() {
        // Two unprobed exits of equal weight get identical scores, so the
        // distribution is unchanged from weight-only.
        let cache = RttCache::new();
        let a = proximity_score(
            100,
            effective_rtt_ms(&cache, eid(1), 0, DEFAULT_RTT_TTL_SECS),
        );
        let b = proximity_score(
            100,
            effective_rtt_ms(&cache, eid(2), 0, DEFAULT_RTT_TTL_SECS),
        );
        assert_eq!(a, b);
        assert_eq!(
            effective_rtt_ms(&cache, eid(1), 0, DEFAULT_RTT_TTL_SECS),
            NEUTRAL_RTT_MS
        );
    }

    #[test]
    fn a_probed_near_exit_beats_the_unprobed_baseline_and_a_probed_far_one_loses() {
        // Exercises the SHARED store through this crate's re-export: the
        // scoring must read exactly what the single-homed cache serves.
        let mut cache = RttCache::new();
        cache.record(eid(1), 10, 1_000); // near
        cache.record(eid(2), 200, 1_000); // far
        let near = proximity_score(
            100,
            effective_rtt_ms(&cache, eid(1), 1_000, DEFAULT_RTT_TTL_SECS),
        );
        let unprobed = proximity_score(
            100,
            effective_rtt_ms(&cache, eid(3), 1_000, DEFAULT_RTT_TTL_SECS),
        );
        let far = proximity_score(
            100,
            effective_rtt_ms(&cache, eid(2), 1_000, DEFAULT_RTT_TTL_SECS),
        );
        assert!(near > unprobed, "near {near} > neutral {unprobed}");
        assert!(unprobed > far, "neutral {unprobed} > far {far}");
    }
}
