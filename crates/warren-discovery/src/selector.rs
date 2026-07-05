//! Weighted exit selector over a resolved relay list.

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::proximity::{DEFAULT_RTT_TTL_SECS, RttCache, effective_rtt_ms, proximity_score};
use crate::query::ExitQuery;
use crate::relay::{Relay, RelayList};

/// Error returned when no relay satisfies a query.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectorError {
    /// No active relay with `weight > 0` satisfies the query constraints.
    #[error("no relay matches the query")]
    NoRelayMatch,
}

/// Selects an exit from a [`RelayList`] subject to an [`ExitQuery`].
#[derive(Debug, Clone)]
pub struct ExitSelector {
    relays: RelayList,
}

impl ExitSelector {
    /// Builds a selector from a resolved relay list.
    #[must_use]
    pub fn new(relays: RelayList) -> Self {
        Self { relays }
    }

    /// All relays in the underlying list (e.g. to cross-check another source,
    /// such as the multihop directory, against the pinned relay list).
    #[must_use]
    pub fn relays(&self) -> &[Relay] {
        self.relays.relays()
    }

    /// Deterministically selects the first matching relay (ignores weight).
    ///
    /// # Errors
    ///
    /// [`SelectorError::NoRelayMatch`] if nothing matches.
    pub fn select(&self, query: &ExitQuery) -> Result<&Relay, SelectorError> {
        self.relays
            .relays()
            .iter()
            .find(|relay| query.matches(relay))
            .ok_or(SelectorError::NoRelayMatch)
    }

    /// Selects a weighted-random matching relay using the thread RNG.
    ///
    /// This is the recommended default: it honors `weight` and excludes
    /// zero-weight relays, unlike [`Self::select`] (which returns the first
    /// match regardless of weight). Use [`Self::select_for_attempt`] when you
    /// need a deterministic, per-retry choice.
    ///
    /// # Errors
    ///
    /// [`SelectorError::NoRelayMatch`] if no active, positive-weight relay
    /// matches.
    pub fn select_weighted(&self, query: &ExitQuery) -> Result<&Relay, SelectorError> {
        self.select_with_rng(query, &mut rand::thread_rng())
    }

    /// Selects a relay weighted by `weight`, excluding `weight == 0`.
    ///
    /// # Errors
    ///
    /// [`SelectorError::NoRelayMatch`] if no active, positive-weight relay
    /// matches.
    pub fn select_with_rng<R: Rng + ?Sized>(
        &self,
        query: &ExitQuery,
        rng: &mut R,
    ) -> Result<&Relay, SelectorError> {
        let candidates: Vec<&Relay> = self
            .relays
            .relays()
            .iter()
            .filter(|relay| relay.weight() > 0 && query.matches(relay))
            .collect();
        if candidates.is_empty() {
            return Err(SelectorError::NoRelayMatch);
        }
        Ok(weighted_pick(&candidates, rng))
    }

    /// Selects a weighted-random matching relay, biased toward exits with a
    /// lower measured RTT (doc 52 §6.2 client / P4). The effective score is
    /// `weight * f(rtt)` per [`crate::proximity`]: at equal weight a nearer
    /// exit is preferred, an unprobed exit is scored at a neutral baseline,
    /// and a fleet with no measurements yields exactly the weight-only
    /// distribution of [`Self::select_weighted`]. `now_unix_secs` drives the
    /// cache's TTL; the caller passes the clock so selection stays testable.
    ///
    /// # Errors
    ///
    /// [`SelectorError::NoRelayMatch`] if no active, positive-weight relay
    /// matches.
    pub fn select_weighted_by_proximity(
        &self,
        query: &ExitQuery,
        rtt_cache: &RttCache,
        now_unix_secs: u64,
    ) -> Result<&Relay, SelectorError> {
        self.select_by_proximity_with_rng(query, rtt_cache, now_unix_secs, &mut rand::thread_rng())
    }

    /// [`Self::select_weighted_by_proximity`] with an injected RNG (tests).
    ///
    /// # Errors
    ///
    /// [`SelectorError::NoRelayMatch`] if no active, positive-weight relay
    /// matches.
    pub fn select_by_proximity_with_rng<R: Rng + ?Sized>(
        &self,
        query: &ExitQuery,
        rtt_cache: &RttCache,
        now_unix_secs: u64,
        rng: &mut R,
    ) -> Result<&Relay, SelectorError> {
        let scored: Vec<(&Relay, u64)> = self
            .relays
            .relays()
            .iter()
            .filter(|relay| relay.weight() > 0 && query.matches(relay))
            .map(|relay| {
                let rtt = effective_rtt_ms(
                    rtt_cache,
                    relay.exit_id(),
                    now_unix_secs,
                    DEFAULT_RTT_TTL_SECS,
                );
                (relay, proximity_score(relay.weight(), rtt))
            })
            .collect();
        if scored.is_empty() {
            return Err(SelectorError::NoRelayMatch);
        }
        Ok(weighted_pick_scored(&scored, rng))
    }

    /// Selects a relay for a given retry attempt. The attempt seeds the RNG so
    /// the same attempt is idempotent and successive attempts explore the space.
    ///
    /// # Errors
    ///
    /// See [`Self::select_with_rng`].
    pub fn select_for_attempt(
        &self,
        query: &ExitQuery,
        retry_attempt: u32,
    ) -> Result<&Relay, SelectorError> {
        let mut rng = StdRng::seed_from_u64(u64::from(retry_attempt));
        self.select_with_rng(query, &mut rng)
    }
}

/// Weighted random pick over a non-empty candidate slice.
fn weighted_pick<'a, R: Rng + ?Sized>(candidates: &[&'a Relay], rng: &mut R) -> &'a Relay {
    // Saturating sum: the weights come from a signed-but-server-controlled list,
    // so a hostile (yet validly signed) list with enormous weights must not
    // overflow the total (a debug panic, or a release wrap that corrupts the
    // roll). Saturating at u64::MAX keeps the pick well-defined.
    let total: u64 = candidates
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.weight()));
    if total == 0 {
        // All weights zero: there is nothing to weight by, so pick the first
        // deterministically rather than panicking in `gen_range(0..0)`.
        return candidates[0];
    }
    let mut roll = rng.gen_range(0..total);
    for relay in candidates {
        let w = relay.weight();
        if roll < w {
            return relay;
        }
        roll -= w;
    }
    // Statically unreachable: roll < total = sum(weights).
    candidates[candidates.len() - 1]
}

/// Weighted random pick over `(relay, score)` pairs. Same saturating-sum +
/// roll as [`weighted_pick`], but over precomputed scores (proximity).
fn weighted_pick_scored<'a, R: Rng + ?Sized>(
    candidates: &[(&'a Relay, u64)],
    rng: &mut R,
) -> &'a Relay {
    let total: u64 = candidates
        .iter()
        .fold(0u64, |acc, (_, score)| acc.saturating_add(*score));
    if total == 0 {
        return candidates[0].0;
    }
    let mut roll = rng.gen_range(0..total);
    for (relay, score) in candidates {
        if roll < *score {
            return relay;
        }
        roll -= *score;
    }
    candidates[candidates.len() - 1].0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit_id::ExitId;
    use crate::query::LocationConstraint;
    use crate::relay::Location;

    #[test]
    fn weighted_pick_saturates_instead_of_overflowing_on_huge_weights() {
        // Two near-u64::MAX weights sum past u64; the pick must not panic
        // (debug overflow) and must still return a candidate.
        let a = relay("FR", "Paris", u64::MAX, true);
        let b = relay("DE", "Berlin", u64::MAX, true);
        let cands = [&a, &b];
        let mut rng = StdRng::seed_from_u64(1);
        let picked = weighted_pick(&cands, &mut rng);
        assert!(std::ptr::eq(picked, &a) || std::ptr::eq(picked, &b));
    }

    #[test]
    fn weighted_pick_handles_all_zero_weights_without_panicking() {
        // A degenerate all-zero-weight slice must not hit gen_range(0..0).
        let a = relay("FR", "Paris", 0, true);
        let b = relay("DE", "Berlin", 0, true);
        let cands = [&a, &b];
        let mut rng = StdRng::seed_from_u64(1);
        assert!(std::ptr::eq(weighted_pick(&cands, &mut rng), &a));
    }

    fn relay(country: &str, city: &str, weight: u64, active: bool) -> Relay {
        Relay::new(
            [0u8; 32],
            ExitId::from_bytes([0xaa; 16]),
            vec!["127.0.0.1:7000".parse().unwrap()],
            Location::new(country, city),
            weight,
            active,
        )
    }

    #[test]
    fn select_returns_first_matching() {
        let list = RelayList::new(vec![relay("RO", "Bucharest", 100, true)]);
        let sel = ExitSelector::new(list);
        let got = sel.select(&ExitQuery::country("ro")).expect("match");
        assert_eq!(got.location().country_code(), "RO");
    }

    #[test]
    fn select_rejects_inactive() {
        let list = RelayList::new(vec![relay("RO", "Bucharest", 100, false)]);
        let sel = ExitSelector::new(list);
        assert_eq!(
            sel.select(&ExitQuery::country("RO")).unwrap_err(),
            SelectorError::NoRelayMatch
        );
    }

    #[test]
    fn weighted_pick_excludes_zero_weight() {
        let list = RelayList::new(vec![relay("RO", "A", 0, true)]);
        let sel = ExitSelector::new(list);
        let mut rng = StdRng::seed_from_u64(1);
        assert_eq!(
            sel.select_with_rng(&ExitQuery::any(), &mut rng)
                .unwrap_err(),
            SelectorError::NoRelayMatch
        );
    }

    #[test]
    fn select_weighted_excludes_zero_weight_and_matches_query() {
        let list = RelayList::new(vec![
            relay("RO", "Zero", 0, true),
            relay("DE", "Other", 100, true),
            relay("RO", "Good", 100, true),
        ]);
        let sel = ExitSelector::new(list);
        let got = sel
            .select_weighted(&ExitQuery::country("RO"))
            .expect("match");
        assert_eq!(got.location().city(), "Good");
    }

    #[test]
    fn weighted_pick_honors_weights() {
        // One relay with weight 1, one with weight 1_000_000. Over many draws
        // the heavy one dominates; the light one is still reachable.
        let list = RelayList::new(vec![
            relay("RO", "Light", 1, true),
            relay("RO", "Heavy", 1_000_000, true),
        ]);
        let sel = ExitSelector::new(list);
        let mut rng = StdRng::seed_from_u64(42);
        let mut heavy = 0;
        for _ in 0..1000 {
            let r = sel.select_with_rng(&ExitQuery::any(), &mut rng).unwrap();
            if r.location().city() == "Heavy" {
                heavy += 1;
            }
        }
        assert!(heavy > 950, "heavy relay should dominate, got {heavy}/1000");
    }

    #[test]
    fn select_for_attempt_is_deterministic() {
        let list = RelayList::new(vec![
            relay("RO", "A", 100, true),
            relay("RO", "B", 100, true),
        ]);
        let sel = ExitSelector::new(list);
        let q = ExitQuery::any();
        let a = sel
            .select_for_attempt(&q, 7)
            .unwrap()
            .location()
            .city()
            .to_owned();
        let b = sel
            .select_for_attempt(&q, 7)
            .unwrap()
            .location()
            .city()
            .to_owned();
        assert_eq!(a, b, "same attempt must be idempotent");
    }

    fn relay_id(country: &str, city: &str, weight: u64, id: u8) -> Relay {
        Relay::new(
            [0u8; 32],
            ExitId::from_bytes([id; 16]),
            vec!["127.0.0.1:7000".parse().unwrap()],
            Location::new(country, city),
            weight,
            true,
        )
    }

    #[test]
    fn proximity_prefers_the_nearer_exit_at_equal_weight() {
        // Two equal-weight exits; only their measured RTT differs. Over many
        // draws the low-RTT one must dominate (DoD P4: prefer a close exit).
        let near = relay_id("FR", "Near", 100, 1);
        let far = relay_id("FR", "Far", 100, 2);
        let sel = ExitSelector::new(RelayList::new(vec![near, far]));

        let mut cache = RttCache::new();
        cache.record(ExitId::from_bytes([1; 16]), 8, 1_000); // near: 8 ms
        cache.record(ExitId::from_bytes([2; 16]), 220, 1_000); // far: 220 ms

        let mut rng = StdRng::seed_from_u64(7);
        let mut near_hits = 0;
        for _ in 0..1000 {
            let r = sel
                .select_by_proximity_with_rng(&ExitQuery::any(), &cache, 1_000, &mut rng)
                .unwrap();
            if r.location().city() == "Near" {
                near_hits += 1;
            }
        }
        assert!(
            near_hits > 700,
            "near exit should dominate at equal weight, got {near_hits}/1000"
        );
    }

    #[test]
    fn proximity_with_empty_cache_matches_weight_only_distribution() {
        // No RTT data anywhere: proximity selection must reduce to the
        // weight-only distribution (heavy dominates, light still reachable),
        // i.e. zero behavioural change before any probing has happened.
        let light = relay_id("RO", "Light", 1, 1);
        let heavy = relay_id("RO", "Heavy", 1_000_000, 2);
        let sel = ExitSelector::new(RelayList::new(vec![light, heavy]));
        let cache = RttCache::new();

        let mut rng = StdRng::seed_from_u64(42);
        let mut heavy_hits = 0;
        for _ in 0..1000 {
            let r = sel
                .select_by_proximity_with_rng(&ExitQuery::any(), &cache, 0, &mut rng)
                .unwrap();
            if r.location().city() == "Heavy" {
                heavy_hits += 1;
            }
        }
        assert!(
            heavy_hits > 950,
            "with no RTT data the weight must still govern, got {heavy_hits}/1000"
        );
    }

    #[test]
    fn proximity_excludes_zero_weight_and_respects_query() {
        let sel = ExitSelector::new(RelayList::new(vec![
            relay_id("RO", "Zero", 0, 1),
            relay_id("DE", "Other", 100, 2),
            relay_id("RO", "Good", 100, 3),
        ]));
        let cache = RttCache::new();
        let mut rng = StdRng::seed_from_u64(1);
        let got = sel
            .select_by_proximity_with_rng(&ExitQuery::country("RO"), &cache, 0, &mut rng)
            .expect("match");
        assert_eq!(got.location().city(), "Good");
    }

    #[test]
    fn city_constraint_is_case_insensitive() {
        let list = RelayList::new(vec![relay("DE", "Kassel", 100, true)]);
        let sel = ExitSelector::new(list);
        let q = ExitQuery::any().with_location(LocationConstraint::City {
            country_code: "de".to_owned(),
            city: "kassel".to_owned(),
        });
        assert!(sel.select(&q).is_ok());
    }
}
