//! Per-source handshake rate limiting.
//!
//! boringtun's own limiter is global: it counts every handshake the gateway
//! sees and starts demanding cookies past a threshold. That defends the
//! gateway's CPU, and it lets one source spend the whole budget. This bucket
//! sits in front of it and makes the spend per source address, so a single
//! misconfigured client retrying every 5 ms cannot push every other device
//! into the cookie path.
//!
//! Memory is bounded by construction: an attacker forging source addresses
//! would otherwise turn the map itself into the denial of service. Two
//! generations are kept and the older one is dropped whole, which costs one
//! allocation per `cap` new sources and never a scan.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Handshakes per second one source address may spend.
pub const HANDSHAKE_RATE_PER_IP: u32 = 5;
/// How many a source may spend at once after an idle period.
pub const HANDSHAKE_BURST_PER_IP: u32 = 10;
/// How many source addresses are tracked per generation.
pub const HANDSHAKE_SOURCES_TRACKED: usize = 4096;

/// ICMP errors and echo replies the gateway generates per second, every peer
/// together. A router bounds its own error generation (RFC 1812 section
/// 4.3.2.8) because an error costs it more than the packet that caused it; here
/// an answer costs a build plus a full AEAD seal, and a withdrawn IPv6 makes an
/// answer the response to every packet of a dual-stack peer.
pub const ANSWER_RATE_PER_SECOND: u32 = 1000;
/// How many answers may be generated at once after a quiet period.
pub const ANSWER_BURST: u32 = 1000;

// Tokens are counted in thousandths so a refill can be computed from elapsed
// milliseconds with integer arithmetic only.
const SCALE: u64 = 1000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u64,
    last: Instant,
}

/// One token bucket, for a budget that belongs to the gateway rather than to a
/// source address.
#[derive(Debug)]
pub struct TokenBucket {
    rate: u64,
    burst: u64,
    tokens: u64,
    last: Option<Instant>,
}

impl TokenBucket {
    /// A full bucket that refills at `rate` a second and holds `burst`.
    #[must_use]
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: u64::from(rate),
            burst: u64::from(burst) * SCALE,
            tokens: u64::from(burst) * SCALE,
            last: None,
        }
    }

    /// Spends one token, or refuses.
    pub fn admit(&mut self, now: Instant) -> bool {
        let last = *self.last.get_or_insert(now);
        let millis =
            u64::try_from(now.saturating_duration_since(last).as_millis()).unwrap_or(u64::MAX);
        let refill = millis.saturating_mul(self.rate);
        if refill > 0 {
            self.tokens = self.tokens.saturating_add(refill).min(self.burst);
            self.last = Some(now);
        }
        if self.tokens < SCALE {
            return false;
        }
        self.tokens -= SCALE;
        true
    }
}

/// One token bucket per source address, with a bounded number of buckets.
#[derive(Debug)]
pub struct HandshakeBuckets {
    rate: u64,
    burst: u64,
    cap: usize,
    current: HashMap<IpAddr, Bucket>,
    previous: HashMap<IpAddr, Bucket>,
}

impl HandshakeBuckets {
    /// The gateway's defaults: five handshakes a second per source, ten at
    /// once, 4096 sources tracked.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(
            HANDSHAKE_RATE_PER_IP,
            HANDSHAKE_BURST_PER_IP,
            HANDSHAKE_SOURCES_TRACKED,
        )
    }

    /// Builds a limiter with explicit limits.
    #[must_use]
    pub fn with_limits(rate: u32, burst: u32, cap: usize) -> Self {
        Self {
            rate: u64::from(rate),
            burst: u64::from(burst) * SCALE,
            cap: cap.max(1),
            current: HashMap::new(),
            previous: HashMap::new(),
        }
    }

    /// Spends one token for `source`, or refuses.
    pub fn admit(&mut self, source: IpAddr, now: Instant) -> bool {
        let burst = self.burst;
        let rate = self.rate;
        let mut bucket = match self.current.remove(&source) {
            Some(bucket) => bucket,
            None => self.previous.remove(&source).unwrap_or(Bucket {
                tokens: burst,
                last: now,
            }),
        };

        let elapsed = now.saturating_duration_since(bucket.last);
        let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let refill = millis.saturating_mul(rate);
        if refill > 0 {
            // The mark only moves once the elapsed time bought something. A
            // source arriving faster than once a millisecond otherwise has its
            // sub-millisecond remainder thrown away on every call, and never
            // refills past the burst it started with.
            bucket.tokens = bucket.tokens.saturating_add(refill).min(burst);
            bucket.last = now;
        }

        let admitted = bucket.tokens >= SCALE;
        if admitted {
            bucket.tokens -= SCALE;
        }

        if self.current.len() >= self.cap {
            // The older generation is dropped whole rather than scanned: a
            // source that is still active is re-admitted with a full bucket at
            // worst once per generation, which costs one handshake.
            self.previous = std::mem::take(&mut self.current);
        }
        self.current.insert(source, bucket);
        admitted
    }

    /// Forgets every bucket.
    pub fn clear(&mut self) {
        self.current.clear();
        self.previous.clear();
    }

    /// How many source addresses are held right now.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.current.len() + self.previous.len()
    }
}

impl Default for HandshakeBuckets {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn refuses_the_eleventh_initiation_from_one_source_in_the_same_instant() {
        let mut buckets = HandshakeBuckets::new();
        let now = Instant::now();
        for attempt in 1..=HANDSHAKE_BURST_PER_IP {
            assert!(buckets.admit(ip(1), now), "attempt {attempt}");
        }
        assert!(!buckets.admit(ip(1), now));
    }

    #[test]
    fn refills_at_the_configured_rate() {
        let mut buckets = HandshakeBuckets::new();
        let now = Instant::now();
        for _ in 0..HANDSHAKE_BURST_PER_IP {
            assert!(buckets.admit(ip(1), now));
        }
        assert!(!buckets.admit(ip(1), now));
        // Five tokens a second is one token every 200 ms.
        assert!(buckets.admit(ip(1), now + Duration::from_millis(200)));
        assert!(!buckets.admit(ip(1), now + Duration::from_millis(200)));
        // The bucket never fills past its burst, however long it idles.
        for _ in 0..HANDSHAKE_BURST_PER_IP {
            assert!(buckets.admit(ip(1), now + Duration::from_secs(3600)));
        }
        assert!(!buckets.admit(ip(1), now + Duration::from_secs(3600)));
    }

    #[test]
    fn refills_for_a_source_that_arrives_faster_than_once_a_millisecond() {
        // A source retrying every 200 microseconds sees a whole-millisecond
        // refill of zero on nearly every call. Advancing the bucket's mark
        // anyway threw that remainder away and pinned the source at its
        // initial burst forever, an effective rate of zero.
        let mut buckets = HandshakeBuckets::new();
        let start = Instant::now();
        let mut admitted = 0u32;
        for step in 0..=5_000u64 {
            if buckets.admit(ip(1), start + Duration::from_micros(step * 200)) {
                admitted += 1;
            }
        }
        let budget = HANDSHAKE_BURST_PER_IP + HANDSHAKE_RATE_PER_IP;
        // One token of tail: the last refill of the second lands after the
        // last arrival of the second.
        assert!(
            admitted >= budget - 1 && admitted <= budget,
            "one second of arrivals admitted {admitted}"
        );
    }

    #[test]
    fn a_gateway_wide_bucket_spends_its_burst_then_refills() {
        let mut bucket = TokenBucket::new(4, 8);
        let now = Instant::now();
        for attempt in 1..=8 {
            assert!(bucket.admit(now), "attempt {attempt}");
        }
        assert!(!bucket.admit(now));
        // Four a second is one every 250 ms.
        assert!(bucket.admit(now + Duration::from_millis(250)));
        assert!(!bucket.admit(now + Duration::from_millis(250)));
    }

    #[test]
    fn spends_one_source_budget_without_touching_another() {
        let mut buckets = HandshakeBuckets::new();
        let now = Instant::now();
        for _ in 0..HANDSHAKE_BURST_PER_IP {
            assert!(buckets.admit(ip(1), now));
        }
        assert!(!buckets.admit(ip(1), now));
        assert!(buckets.admit(ip(2), now));
    }

    #[test]
    fn bounds_its_memory_when_every_datagram_comes_from_a_new_source() {
        let mut buckets = HandshakeBuckets::with_limits(5, 10, 8);
        let now = Instant::now();
        for source in 0..=u8::MAX {
            assert!(buckets.admit(ip(source), now));
        }
        assert!(buckets.tracked() <= 16, "{}", buckets.tracked());
    }
}
