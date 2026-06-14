//! RFC 6479-style sliding window anti-replay tracker (reverse direction).
//!
//! The client maintains one window per `(exit_id, epoch)` over the seq field of
//! exit -> client frames. For each authenticated frame's `seq`,
//! [`ReplayWindow::check_and_record`] decides accept or reject:
//!
//! - `seq` strictly above the high-water mark: accept, advance the window.
//! - `seq` within the window and not yet seen: accept, mark seen.
//! - `seq` within the window and already seen: reject (replay).
//! - `seq` more than [`REPLAY_WINDOW_SIZE`] below the high-water mark: reject
//!   (too old).
//!
//! Mirrors the WireGuard `replay.c` algorithm: a `[u64; 16]` bitmap of 1024
//! bits where bit `i` (relative to the high-water mark) is `1` iff a frame with
//! `seq = high - i` was already recorded. Byte-for-byte the same acceptance
//! predicate as warren-core `warren-multihop::replay`.
//!
//! Use the two-phase verify-then-record pattern: [`ReplayWindow::check`] probes
//! before the AEAD open, [`ReplayWindow::check_and_record`] commits only once
//! the frame authenticated. Recording an unauthenticated `seq` would let a
//! hostile relay forge a far-future `seq` and slam the window past the
//! legitimate in-flight numbers.

use crate::SessionError;

/// Sliding-window size in bits (doc 19 § 5.4 specifies 1024).
pub const REPLAY_WINDOW_SIZE: u64 = 1024;

/// Internal alias kept short for the bit-manipulation code below.
const WINDOW_SIZE: u64 = REPLAY_WINDOW_SIZE;

/// Number of `u64` words backing the bitmap (1024 / 64 = 16).
const BITMAP_WORDS: usize = 16;

/// RFC 6479-style sliding window for the receiver-side anti-replay check. One
/// instance per `(exit_id, epoch)`.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest `seq` accepted so far. `None` means no seq seen yet, so the next
    /// call is unconditionally accepted.
    highest: Option<u64>,
    /// Bitmap of seen offsets: `bitmap` bit 0 (LSB) is `seq == highest`, bit 1
    /// is `seq == highest - 1`, through bit `WINDOW_SIZE - 1`.
    bitmap: [u64; BITMAP_WORDS],
}

impl ReplayWindow {
    /// Construct an empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: [0u64; BITMAP_WORDS],
        }
    }

    /// The current high-water mark, or `None` if no seq has been recorded.
    #[must_use]
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Check that `seq` is neither a replay nor too old, and record it as seen.
    ///
    /// # Errors
    ///
    /// [`SessionError::Replay`] if `seq` has already been seen or falls below
    /// the active window.
    #[inline]
    pub fn check_and_record(&mut self, seq: u64, epoch: u32) -> Result<(), SessionError> {
        let highest = match self.highest {
            None => {
                self.set_bit(0);
                self.highest = Some(seq);
                return Ok(());
            }
            Some(h) => h,
        };

        if seq > highest {
            let shift = seq - highest;
            self.shift_left(shift);
            self.set_bit(0);
            self.highest = Some(seq);
            Ok(())
        } else {
            let offset = highest - seq;
            if offset >= WINDOW_SIZE {
                return Err(SessionError::Replay { seq, epoch });
            }
            let offset = offset as usize;
            if self.get_bit(offset) {
                Err(SessionError::Replay { seq, epoch })
            } else {
                self.set_bit(offset);
                Ok(())
            }
        }
    }

    /// Check whether `seq` would be accepted, WITHOUT recording it. First phase
    /// of the verify-then-record pattern.
    ///
    /// # Errors
    ///
    /// [`SessionError::Replay`] under the same predicate as
    /// [`Self::check_and_record`], minus the commit.
    #[inline]
    pub fn check(&self, seq: u64, epoch: u32) -> Result<(), SessionError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if seq > highest {
            return Ok(());
        }
        let offset = highest - seq;
        if offset >= WINDOW_SIZE {
            return Err(SessionError::Replay { seq, epoch });
        }
        if self.get_bit(offset as usize) {
            return Err(SessionError::Replay { seq, epoch });
        }
        Ok(())
    }

    fn set_bit(&mut self, offset: usize) {
        let word = offset / 64;
        let bit = offset % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn get_bit(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        (self.bitmap[word] >> bit) & 1 == 1
    }

    fn shift_left(&mut self, shift: u64) {
        if shift >= WINDOW_SIZE {
            // Everything in the old window is now too old: wipe.
            self.bitmap = [0u64; BITMAP_WORDS];
            return;
        }

        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;

        let mut new_bitmap = [0u64; BITMAP_WORDS];
        for (i, dest) in new_bitmap.iter_mut().enumerate() {
            *dest = match i.checked_sub(word_shift) {
                Some(s) => self.bitmap[s],
                None => 0,
            };
        }
        if bit_shift != 0 {
            let mut carry = 0u64;
            for word in &mut new_bitmap {
                let shifted = (*word << bit_shift) | carry;
                carry = *word >> (64 - bit_shift);
                *word = shifted;
            }
        }
        self.bitmap = new_bitmap;
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_replay(window: &mut ReplayWindow, seq: u64) {
        match window.check_and_record(seq, 0) {
            Err(SessionError::Replay { .. }) => {}
            Ok(()) => panic!("expected Replay rejection for seq {seq}"),
            Err(other) => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn accepts_in_order_sequence_from_zero() {
        let mut w = ReplayWindow::new();
        for seq in 0..50 {
            w.check_and_record(seq, 0)
                .unwrap_or_else(|e| panic!("in-order accept failed at {seq}: {e:?}"));
        }
        assert_eq!(w.highest(), Some(49));
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        w.check_and_record(500, 0).unwrap();
        w.check_and_record(250, 0).unwrap();
        w.check_and_record(499, 0).unwrap();
        w.check_and_record(1, 0).unwrap();
    }

    #[test]
    fn rejects_replay_within_window() {
        let mut w = ReplayWindow::new();
        w.check_and_record(10, 0).unwrap();
        assert_replay(&mut w, 10);
        w.check_and_record(20, 0).unwrap();
        assert_replay(&mut w, 20);
        assert_replay(&mut w, 10);
    }

    #[test]
    fn rejects_too_old_below_window() {
        let mut w = ReplayWindow::new();
        w.check_and_record(2_000, 0).unwrap();
        // Window covers seq in (976 .. 2000]; 976 lands at offset exactly
        // WINDOW_SIZE, outside the window per the `offset < WINDOW_SIZE` bound.
        assert_replay(&mut w, 976);
        assert_replay(&mut w, 0);
        w.check_and_record(977, 0).unwrap();
    }

    #[test]
    fn accepts_newest_advancing_window() {
        let mut w = ReplayWindow::new();
        w.check_and_record(0, 0).unwrap();
        w.check_and_record(1024, 0).unwrap();
        assert_replay(&mut w, 0);
        w.check_and_record(1, 0).unwrap();
    }

    #[test]
    fn shift_by_more_than_window_clears_state() {
        let mut w = ReplayWindow::new();
        w.check_and_record(100, 0).unwrap();
        w.check_and_record(200, 0).unwrap();
        w.check_and_record(100_000, 0).unwrap();
        assert_replay(&mut w, 100);
        w.check_and_record(99_999, 0).unwrap();
    }

    #[test]
    fn check_only_probe_does_not_commit_the_seq() {
        let mut w = ReplayWindow::new();
        w.check_and_record(10, 0).unwrap();
        w.check(11, 0)
            .expect("first probe of an unseen seq accepts");
        w.check(11, 0)
            .expect("second probe of the same unseen seq must still accept");
        w.check_and_record(11, 0).expect("record after probe");
        assert!(
            matches!(w.check(11, 0), Err(SessionError::Replay { .. })),
            "after check_and_record, the probe must flag the replay"
        );
    }

    #[test]
    fn check_only_probe_matches_check_and_record_predicate() {
        let mut w = ReplayWindow::new();
        w.check_and_record(2_000, 0).unwrap();
        assert!(matches!(
            w.check(2_000, 0),
            Err(SessionError::Replay { .. })
        ));
        assert!(matches!(w.check(976, 0), Err(SessionError::Replay { .. })));
        w.check(977, 0)
            .expect("oldest in-window unseen seq accepted");
        w.check(3_000, 0).expect("future seq accepted");
    }

    #[test]
    fn small_in_window_accepts_then_rejects_replay() {
        let mut w = ReplayWindow::new();
        for seq in (0u64..1024).step_by(7) {
            w.check_and_record(seq, 0)
                .unwrap_or_else(|e| panic!("first pass {seq}: {e:?}"));
        }
        for seq in (0u64..1024).step_by(7) {
            assert_replay(&mut w, seq);
        }
    }
}
