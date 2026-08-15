//! Session index generation.
//!
//! WireGuard names a session by a 32-bit index the receiver chose, and
//! boringtun derives every session index of a peer from one per-peer value
//! (`index << 8 | slot`), so the low byte is not ours to use: the generator
//! walks a 24-bit space. A sequential counter would leak how many peers a
//! gateway carries and when each was added, so the walk is a maximal-length
//! linear-feedback register instead: every value once, in an order an observer
//! cannot continue, and a refusal rather than a silent reuse at the end.

use rand::RngCore as _;

/// Largest index the generator can hand out.
pub const MAX_INDEX: u32 = 0x00ff_ffff;

// A 24-bit polynomial with a maximal period, taken from boringtun's own device
// (`src/device/mod.rs:866`) so two Warren gateways and a boringtun device
// number peers out of the same space.
const LFSR_POLY: u32 = 0x00d8_0000;

/// The gateway's peer index sequence.
#[derive(Debug, Clone)]
pub struct IndexGen {
    initial: u32,
    lfsr: u32,
    mask: u32,
    exhausted: bool,
}

impl IndexGen {
    /// Seeds a sequence from the operating system CSPRNG.
    #[must_use]
    pub fn new() -> Self {
        Self::from_seed(random_index(), random_index())
    }

    /// Seeds a sequence explicitly.
    ///
    /// The seed is forced non-zero because a zeroed register never leaves
    /// zero; both values are truncated to the 24 bits the index space has.
    #[must_use]
    pub fn from_seed(seed: u32, mask: u32) -> Self {
        let seed = match seed & MAX_INDEX {
            0 => 1,
            other => other,
        };
        Self {
            initial: seed,
            lfsr: seed,
            mask: mask & MAX_INDEX,
            exhausted: false,
        }
    }

    /// The next index, or `None` once the period is spent.
    ///
    /// Returning `None` rather than wrapping is deliberate: reusing an index
    /// while the previous peer still holds sessions under it would demux a
    /// stranger's data packet onto the wrong peer.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<u32> {
        loop {
            if self.exhausted {
                return None;
            }
            let value = self.lfsr - 1;
            self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1)) & LFSR_POLY);
            if self.lfsr == self.initial {
                self.exhausted = true;
            }
            let index = value ^ self.mask;
            if index != 0 {
                return Some(index);
            }
        }
    }
}

impl Default for IndexGen {
    fn default() -> Self {
        Self::new()
    }
}

fn random_index() -> u32 {
    loop {
        let candidate = rand::rngs::OsRng.next_u32() & MAX_INDEX;
        if candidate != 0 {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn hands_out_distinct_non_zero_indexes_that_fit_the_wire_field() {
        let mut generator = IndexGen::from_seed(0x00ab_cdef, 0x0012_3456);
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let index = generator.next().expect("far from the end of the period");
            assert!(index != 0 && index <= 0x00ff_ffff, "{index:#x}");
            assert!(seen.insert(index), "index {index:#x} handed out twice");
        }
    }

    #[test]
    fn never_repeats_within_its_period_and_then_refuses_rather_than_wrapping() {
        let mut generator = IndexGen::from_seed(1, 0);
        let mut count = 0u32;
        while generator.next().is_some() {
            count += 1;
        }
        // A maximal-length 24-bit register walks every non-zero state once,
        // and the one state that would render index zero is skipped.
        assert_eq!(count, (1 << 24) - 2);
        assert_eq!(generator.next(), None);
    }

    #[test]
    fn draws_a_different_sequence_per_gateway() {
        let mut first = IndexGen::new();
        let mut second = IndexGen::new();
        let a: Vec<u32> = (0..8).filter_map(|_| first.next()).collect();
        let b: Vec<u32> = (0..8).filter_map(|_| second.next()).collect();
        assert_ne!(a, b);
    }
}
