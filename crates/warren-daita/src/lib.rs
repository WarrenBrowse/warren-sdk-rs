//! Warren DAITA client surface (Defense Against AI-guided Traffic Analysis).
//!
//! DAITA obscures the packet-timing and packet-size fingerprint of encrypted
//! traffic by scheduling cover ("dummy") packets and outgoing-blocking from a
//! set of probabilistic state machines (the [`maybenot`] framework).
//!
//! This is now a thin re-export of the engine's `warrenguard-daita`, so a single
//! maybenot-driven implementation is shared with warren-core: the wire
//! [`DaitaConfig`], the curated [`DaitaPool`] of machines, and the synchronous
//! [`DaitaState`] driver. The behavioural-equivalence tests below stay as a
//! guard over the re-exported implementation (both sides drive the same
//! `maybenot::Framework`, so the curated cadence must match).

pub use warrenguard_daita::{
    DAITA_PLACEHOLDER_SLEEP, DaitaAction, DaitaConfig, DaitaConfigExt, DaitaError, DaitaEvent,
    DaitaMetrics, DaitaPool, DaitaState, DaitaTimer, MachineId,
};

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    fn rng() -> StdRng {
        // Fixed seed: machine selection / serialization is deterministic so the
        // tests do not flake, while the framework still seeds its own OS RNG.
        StdRng::seed_from_u64(0x5741_5252_454e_2121)
    }

    #[test]
    fn default_pool_carries_the_five_curated_families() {
        let pool = DaitaPool::default_pool();
        assert_eq!(pool.len(), 5);
        assert!(!pool.is_empty());
        let names = pool.entry_names();
        for expected in [
            "netflow",
            "tamaraw",
            "front",
            "interspace_server",
            "scrambler_server",
        ] {
            assert!(names.contains(&expected), "pool must include {expected}");
        }
    }

    #[test]
    fn every_pool_entry_yields_a_parseable_enabled_config() {
        let pool = DaitaPool::default_pool();
        let mut rng = rng();
        for name in pool.entry_names() {
            let cfg = pool.pick_named(name, &mut rng).expect("named pick");
            assert!(cfg.is_enabled(), "{name} must carry >= 1 machine");
            assert!(cfg.fractions_valid(), "{name} caps in range");
            // The config must build a live framework (specs parse via maybenot).
            DaitaState::from_config(&cfg, Instant::now())
                .unwrap_or_else(|e| panic!("{name} must build a DaitaState: {e:?}"));
        }
    }

    #[test]
    fn config_round_trips_through_serde() {
        // The serde shape (Vec<String>, f64, f64) must preserve every field. The
        // exact postcard byte layout is pinned where DaitaConfig is embedded in a
        // wire control message; here we assert the serde contract holds.
        let cfg = DaitaConfig::from_specs(vec!["02eNpjYEAHjOgCAAA0AAI=".to_owned()], 0.05, 0.1);
        let back: DaitaConfig =
            serde_json::from_slice(&serde_json::to_vec(&cfg).expect("ser")).expect("de");
        assert_eq!(back, cfg);
        assert!(back.is_enabled());
    }

    #[test]
    fn disabled_config_drives_no_machine_and_emits_nothing() {
        let mut state = DaitaState::from_config(&DaitaConfig::disabled(), Instant::now())
            .expect("disabled builds");
        assert!(!state.is_enabled());
        assert_eq!(state.machines_count(), 0);
        let now = Instant::now();
        state.on_real_uplink_sent(now);
        assert!(state.next_timer().is_none(), "disabled arms no timer");
        assert!(state.drain_expired(now).is_empty());
    }

    #[test]
    fn tamaraw_fires_padding_at_the_expected_cadence() {
        // Tamaraw is a constant-rate defense: `p = 0.005` is 5 ms/packet
        // (~200 pkt/s). Kick it once, then run a tight drain loop firing only the
        // `PaddingSent + TunnelSent` feedback after each emitted dummy (a normal
        // packet's TunnelSent would `replace`-reset the timer). A permissive cap
        // (0.5) lets the raw cadence through, like warren-core's cadence test, so
        // 1 s of simulated time yields ~200 actions. Bounds are generous below
        // (scheduler-jitter-proof) and capped above (a unit-mismatch regression,
        // e.g. p read as microseconds, would blow past 400).
        let mut rng = rng();
        let machines = maybenot_machines::get_machine(
            &[maybenot_machines::StaticMachine::Tamaraw {
                p: 0.005,
                stop_window: 1_000_000.0,
            }],
            &mut rng,
        );
        let specs: Vec<String> = machines.iter().map(maybenot::Machine::serialize).collect();
        let cfg = DaitaConfig::from_specs(specs, 0.5, 0.0);
        assert!(cfg.is_enabled());

        let start = Instant::now();
        let mut state = DaitaState::from_config(&cfg, start).expect("tamaraw state");
        state.fire_events(&[DaitaEvent::NormalSent], start);

        let step = Duration::from_micros(500);
        let mut now = start;
        let mut fired_total = 0usize;
        while now < start + Duration::from_secs(1) {
            now += step;
            let fired = state.drain_expired(now);
            for machine in &fired {
                state.on_dummy_sent(*machine, now);
            }
            fired_total += fired.len();
        }

        assert!(
            (50..=400).contains(&fired_total),
            "tamaraw 200 pkt/s cadence over 1 s should be ~200 actions, got {fired_total}"
        );
        // Every drained action is either a padding emission or a blocking-begin
        // (Tamaraw opens with one BlockOutgoing before its constant-rate padding).
        let m = state.metrics();
        assert_eq!((m.padding_fired + m.blocking_begins) as usize, fired_total);
        assert!(m.padding_fired >= 50, "the bulk are padding emissions");
    }

    #[test]
    fn sleep_deadline_falls_back_to_the_placeholder_when_idle() {
        let state = DaitaState::disabled();
        let now = Instant::now();
        let deadline = state.sleep_deadline(now);
        // No timer armed: park for the placeholder window (within a slack).
        let elapsed = deadline.saturating_duration_since(now);
        assert!(
            elapsed >= DAITA_PLACEHOLDER_SLEEP - Duration::from_secs(1),
            "idle sleep parks for the placeholder"
        );
    }

    #[test]
    fn invalid_fraction_is_rejected() {
        let cfg = DaitaConfig::from_specs(vec!["02eNpjYEAHjOgCAAA0AAI=".to_owned()], 2.0, 0.0);
        assert!(!cfg.fractions_valid());
        let err = DaitaState::from_config(&cfg, Instant::now()).unwrap_err();
        assert!(matches!(err, DaitaError::InvalidFraction));
    }

    #[test]
    fn invalid_machine_spec_is_rejected() {
        let cfg = DaitaConfig::from_specs(vec!["not-a-valid-machine".to_owned()], 0.05, 0.0);
        let err = DaitaState::from_config(&cfg, Instant::now()).unwrap_err();
        assert!(matches!(err, DaitaError::InvalidMachine(_)));
    }
}
