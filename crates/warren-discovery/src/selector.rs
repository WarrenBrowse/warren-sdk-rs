//! Weighted exit selector over a resolved relay list.

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

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
    let total: u64 = candidates.iter().map(|r| r.weight()).sum();
    debug_assert!(total > 0, "weighted_pick requires positive total weight");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit_id::ExitId;
    use crate::query::LocationConstraint;
    use crate::relay::Location;

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
