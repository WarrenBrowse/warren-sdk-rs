//! The curated pool of DAITA v2 machines.
//!
//! On the multihop path the client picks its own machine from this pool to pad
//! the uplink (the exit pads the downlink from its own pool). The five families
//! mirror warren-core's curated set byte-for-byte (same `StaticMachine`
//! parameters and the same per-entry fractional caps), so a Warren exit and this
//! client present the same distribution of defenses to an observer.

use maybenot_machines::{StaticMachine, get_machine};
use rand::seq::IndexedRandom;
use rand::{Rng, RngCore};

use crate::config::DaitaConfig;

/// One named recipe in the pool. The name is observability-only, never on wire.
#[derive(Debug, Clone)]
struct PoolEntry {
    name: &'static str,
    static_machine: StaticMachine,
    max_padding_frac: f64,
    max_blocking_frac: f64,
}

/// Warren's curated DAITA v2 machine pool (five families).
#[derive(Debug, Clone)]
pub struct DaitaPool {
    entries: Vec<PoolEntry>,
}

impl DaitaPool {
    /// The default Warren pool: five curated machine families, each a distinct
    /// defense regime. Parameters match warren-core (the wire-compat contract).
    #[must_use]
    pub fn default_pool() -> Self {
        Self {
            entries: vec![
                PoolEntry {
                    name: "netflow",
                    static_machine: StaticMachine::SimpleNetFlow,
                    max_padding_frac: 0.05,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "tamaraw",
                    // `p` is seconds per padding packet: 0.005 = 5 ms (~200 pkt/s).
                    // `stop_window` is microseconds: 1 s of silence stops it.
                    static_machine: StaticMachine::Tamaraw {
                        p: 0.005,
                        stop_window: 1_000_000.0,
                    },
                    max_padding_frac: 0.15,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "front",
                    static_machine: StaticMachine::Front {
                        padding_budget_max: 1500,
                        window_min: 1.0,
                        window_max: 14.0,
                        num_states: 200,
                    },
                    max_padding_frac: 0.10,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "interspace_server",
                    static_machine: StaticMachine::InterspaceServer,
                    max_padding_frac: 0.10,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "scrambler_server",
                    static_machine: StaticMachine::ScramblerServer {
                        interval: 4_000.0,
                        min_count: 4.0,
                        min_trail: 4.0,
                        max_trail: 16.0,
                    },
                    max_padding_frac: 0.20,
                    max_blocking_frac: 0.05,
                },
            ],
        }
    }

    /// Number of entries in the pool (always `>= 1` for [`Self::default_pool`]).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the pool has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry names in declaration order (observability / test coverage).
    #[must_use]
    pub fn entry_names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|e| e.name).collect()
    }

    /// Picks one entry uniformly at random as a wire [`DaitaConfig`], with the
    /// chosen family name. `None` only if the pool is empty.
    pub fn pick_with_name<R: Rng + RngCore>(
        &self,
        rng: &mut R,
    ) -> Option<(&'static str, DaitaConfig)> {
        let entry = self.entries.choose(rng)?;
        Some((entry.name, entry.to_config(rng)))
    }

    /// Picks one entry uniformly at random as a wire [`DaitaConfig`].
    pub fn pick<R: Rng + RngCore>(&self, rng: &mut R) -> Option<DaitaConfig> {
        self.pick_with_name(rng).map(|(_, cfg)| cfg)
    }

    /// Builds a [`DaitaConfig`] for the entry whose `name` matches, or `None`.
    /// Useful for driving one specific machine deterministically.
    pub fn pick_named<R: Rng + RngCore>(&self, name: &str, rng: &mut R) -> Option<DaitaConfig> {
        let entry = self.entries.iter().find(|e| e.name == name)?;
        Some(entry.to_config(rng))
    }
}

impl PoolEntry {
    fn to_config<R: Rng + RngCore>(&self, rng: &mut R) -> DaitaConfig {
        let machines = get_machine(&[self.static_machine], rng);
        DaitaConfig::from_specs(
            machines.iter().map(maybenot::Machine::serialize).collect(),
            self.max_padding_frac,
            self.max_blocking_frac,
        )
    }
}
