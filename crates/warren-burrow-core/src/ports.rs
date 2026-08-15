//! The external port space, owned in one place.
//!
//! Every external port the gateway ever uses comes from here: a dynamic flow,
//! a preserved source port, a pinned forward. Splitting that ownership is how a
//! NAT ends up handing a running flow the port a static forward already
//! answers on, so the allocator is the single authority and a reservation is
//! taken out of the free list rather than merely remembered.
//!
//! The pick is a uniform draw from a CSPRNG. The port is not a secret, but a
//! predictable one lets an off-path attacker guess the four-tuple of a flow it
//! cannot see.

use std::ops::RangeInclusive;

use rand::{Rng, RngCore};

use crate::error::CoreError;

/// First port of the dynamic pool (the IANA ephemeral range, less the control
/// range this gateway keeps for itself).
pub const DYNAMIC_POOL_START: u16 = 32768;
/// Last port of the dynamic pool.
pub const DYNAMIC_POOL_END: u16 = 60999;
/// First port kept for the gateway's own control-plane flows (NAT-PMP, the
/// egress probe), which never come from the pool.
pub const CONTROL_RANGE_START: u16 = 61000;
/// Last port kept for the gateway's own control-plane flows.
pub const CONTROL_RANGE_END: u16 = 61999;

/// Marks a port that is not in the free list.
const TAKEN: u32 = u32::MAX;

/// A free list over one contiguous range of external ports or identifiers.
///
/// One instance per (protocol, address family): TCP and UDP each own their own
/// port space, and the ICMP echo identifiers are a third space of the same
/// shape.
#[derive(Debug, Clone)]
pub struct PortAllocator {
    base: u16,
    free: Vec<u16>,
    /// Per port: its index in `free`, or [`TAKEN`].
    slot: Vec<u32>,
    reserved: Vec<bool>,
}

impl PortAllocator {
    /// A free list over `range`.
    #[must_use]
    pub fn new(range: RangeInclusive<u16>) -> Self {
        let base = *range.start();
        let free: Vec<u16> = range.clone().collect();
        let len = free.len();
        Self {
            base,
            free,
            slot: (0..len)
                .map(|i| u32::try_from(i).unwrap_or(TAKEN))
                .collect(),
            reserved: vec![false; len],
        }
    }

    /// The dynamic pool every translated flow draws from.
    #[must_use]
    pub fn dynamic_pool() -> Self {
        Self::new(DYNAMIC_POOL_START..=DYNAMIC_POOL_END)
    }

    /// The ICMP echo identifier space, which is the whole non-zero 16-bit
    /// range: an identifier is not a port and nothing else competes for it.
    #[must_use]
    pub fn identifiers() -> Self {
        Self::new(1..=u16::MAX)
    }

    /// How many ports this space holds, which is also the hard cap on live
    /// mappings for that protocol and family.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slot.len()
    }

    /// How many ports are free right now.
    #[must_use]
    pub fn available(&self) -> usize {
        self.free.len()
    }

    /// True when `port` belongs to this space.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.index(port).is_some()
    }

    /// True when `port` is pinned to a static forward.
    #[must_use]
    pub fn is_reserved(&self, port: u16) -> bool {
        self.index(port)
            .and_then(|i| self.reserved.get(i))
            .copied()
            .unwrap_or(false)
    }

    fn index(&self, port: u16) -> Option<usize> {
        let offset = usize::from(port.checked_sub(self.base)?);
        (offset < self.slot.len()).then_some(offset)
    }

    /// Takes `port` out of the free list, whatever its position.
    fn take(&mut self, index: usize) -> Option<u16> {
        let at = usize::try_from(*self.slot.get(index)?).ok()?;
        let port = *self.free.get(at)?;
        self.free.swap_remove(at);
        if let Some(moved) = self.free.get(at).copied() {
            let moved_index = self.index(moved)?;
            if let Some(entry) = self.slot.get_mut(moved_index) {
                *entry = u32::try_from(at).unwrap_or(TAKEN);
            }
        }
        if let Some(entry) = self.slot.get_mut(index) {
            *entry = TAKEN;
        }
        Some(port)
    }

    /// Allocates an external port, keeping the peer's own source port when it
    /// lies inside this space and is free, otherwise drawing one uniformly.
    ///
    /// Returns `None` when the space is exhausted, which the caller counts and
    /// turns into a drop.
    pub fn alloc(&mut self, preferred: Option<u16>, rng: &mut dyn RngCore) -> Option<u16> {
        if let Some(port) = preferred
            && let Some(index) = self.index(port)
            && *self.slot.get(index)? != TAKEN
        {
            return self.take(index);
        }
        if self.free.is_empty() {
            return None;
        }
        let at = rng.gen_range(0..self.free.len());
        let port = *self.free.get(at)?;
        let index = self.index(port)?;
        self.take(index)
    }

    /// Pins `port` so no flow can ever be given it.
    ///
    /// # Errors
    ///
    /// [`CoreError::PortOutsidePool`] when the port is not in this space,
    /// [`CoreError::PortInUse`] when a flow already holds it (the caller has to
    /// decide whether to break that flow), [`CoreError::PortAlreadyReserved`]
    /// when it is pinned already.
    pub fn reserve(&mut self, port: u16) -> Result<(), CoreError> {
        let index = self.index(port).ok_or(CoreError::PortOutsidePool)?;
        if self.reserved.get(index).copied().unwrap_or(false) {
            return Err(CoreError::PortAlreadyReserved);
        }
        if self.slot.get(index).copied().unwrap_or(TAKEN) == TAKEN {
            return Err(CoreError::PortInUse);
        }
        self.take(index).ok_or(CoreError::PortInUse)?;
        if let Some(entry) = self.reserved.get_mut(index) {
            *entry = true;
        }
        Ok(())
    }

    /// Lifts a pin and returns the port to the free list. `false` when it was
    /// not pinned.
    pub fn unreserve(&mut self, port: u16) -> bool {
        let Some(index) = self.index(port) else {
            return false;
        };
        if !self.reserved.get(index).copied().unwrap_or(false) {
            return false;
        }
        if let Some(entry) = self.reserved.get_mut(index) {
            *entry = false;
        }
        self.push_free(index, port);
        true
    }

    /// Returns a port a flow held. A pinned port stays pinned, and a port that
    /// is already free is ignored, so a double release cannot duplicate it.
    pub fn release(&mut self, port: u16) {
        let Some(index) = self.index(port) else {
            return;
        };
        if self.reserved.get(index).copied().unwrap_or(false) {
            return;
        }
        if self.slot.get(index).copied().unwrap_or(TAKEN) != TAKEN {
            return;
        }
        self.push_free(index, port);
    }

    fn push_free(&mut self, index: usize, port: u16) {
        let at = self.free.len();
        self.free.push(port);
        if let Some(entry) = self.slot.get_mut(index) {
            *entry = u32::try_from(at).unwrap_or(TAKEN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    #[test]
    fn the_pool_is_the_whole_capacity_and_stops_before_the_control_range() {
        let pool = PortAllocator::dynamic_pool();
        assert_eq!(pool.capacity(), 28_232);
        assert_eq!(pool.available(), 28_232);
        assert!(pool.contains(DYNAMIC_POOL_START));
        assert!(pool.contains(DYNAMIC_POOL_END));
        assert!(!pool.contains(DYNAMIC_POOL_END + 1));
        assert!(!pool.contains(CONTROL_RANGE_START));
        assert!(!pool.contains(1024));
        assert_eq!(DYNAMIC_POOL_END + 1, CONTROL_RANGE_START);
    }

    #[test]
    fn preserves_a_source_port_that_lies_inside_the_pool() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(1);
        assert_eq!(pool.alloc(Some(40_000), &mut r), Some(40_000));
        assert_eq!(pool.available(), 28_231);
    }

    #[test]
    fn never_preserves_a_source_port_outside_the_pool() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(2);
        for outside in [80u16, 1024, CONTROL_RANGE_START, 61_500, 65_535, 0] {
            let got = pool.alloc(Some(outside), &mut r).expect("a pool port");
            assert_ne!(got, outside);
            assert!(pool.contains(got));
        }
    }

    #[test]
    fn falls_back_to_another_port_when_the_preferred_one_is_taken() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(3);
        assert_eq!(pool.alloc(Some(40_000), &mut r), Some(40_000));
        let second = pool.alloc(Some(40_000), &mut r).expect("a pool port");
        assert_ne!(second, 40_000);
    }

    #[test]
    fn never_hands_out_a_reserved_port() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(4);
        pool.reserve(51_820)
            .expect("a free pool port is reservable");
        assert!(pool.is_reserved(51_820));
        assert_eq!(pool.available(), 28_231);
        // Walk the entire pool: the pinned port is never handed out, and the
        // pool is exhausted one port early.
        let mut seen = 0usize;
        while let Some(port) = pool.alloc(None, &mut r) {
            assert_ne!(port, 51_820, "the pinned port was handed to a flow");
            seen += 1;
        }
        assert_eq!(seen, 28_231);
        assert_eq!(pool.alloc(Some(51_820), &mut r), None);
    }

    #[test]
    fn refuses_a_reservation_the_pool_cannot_honour() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(5);
        assert_eq!(pool.reserve(80), Err(CoreError::PortOutsidePool));
        assert_eq!(
            pool.reserve(CONTROL_RANGE_START),
            Err(CoreError::PortOutsidePool)
        );
        let taken = pool.alloc(None, &mut r).expect("a pool port");
        assert_eq!(pool.reserve(taken), Err(CoreError::PortInUse));
        pool.reserve(51_820).expect("free");
        assert_eq!(pool.reserve(51_820), Err(CoreError::PortAlreadyReserved));
    }

    #[test]
    fn a_released_port_is_allocatable_again_and_a_reserved_one_stays_reserved() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(6);
        let port = pool.alloc(None, &mut r).expect("a pool port");
        pool.release(port);
        assert_eq!(pool.available(), 28_232);
        assert_eq!(pool.alloc(Some(port), &mut r), Some(port));

        pool.reserve(51_820).expect("free");
        pool.release(51_820);
        assert!(
            pool.is_reserved(51_820),
            "releasing a flow must not unpin a reservation"
        );
        assert!(pool.unreserve(51_820));
        assert_eq!(pool.alloc(Some(51_820), &mut r), Some(51_820));
    }

    #[test]
    fn releasing_a_port_twice_does_not_duplicate_it() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(7);
        let port = pool.alloc(None, &mut r).expect("a pool port");
        pool.release(port);
        pool.release(port);
        pool.release(12_345); // never allocated, outside the pool
        assert_eq!(pool.available(), 28_232);
    }

    #[test]
    fn spreads_allocations_instead_of_walking_the_pool_in_order() {
        let mut pool = PortAllocator::dynamic_pool();
        let mut r = rng(8);
        let first: Vec<u16> = (0..64)
            .map(|_| pool.alloc(None, &mut r).expect("a pool port"))
            .collect();
        let sequential: Vec<u16> = (0..64).map(|i| DYNAMIC_POOL_START + i).collect();
        assert_ne!(first, sequential, "an off-path guesser must not walk it");
        assert!(
            first.windows(2).any(|w| w[1] < w[0]),
            "a uniform draw is not monotonic"
        );

        let mut other = PortAllocator::dynamic_pool();
        let mut r2 = rng(9);
        let second: Vec<u16> = (0..64)
            .map(|_| other.alloc(None, &mut r2).expect("a pool port"))
            .collect();
        assert_ne!(
            first, second,
            "two gateways must not draw the same sequence"
        );
    }

    #[test]
    fn the_identifier_space_covers_every_non_zero_value() {
        let ids = PortAllocator::identifiers();
        assert_eq!(ids.capacity(), 65_535);
        assert!(ids.contains(1));
        assert!(ids.contains(u16::MAX));
        assert!(!ids.contains(0), "zero is not an echo identifier");
    }
}
