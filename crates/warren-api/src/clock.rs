//! The server's clock, as the API's answers tell it, for stamping signed
//! requests.
//!
//! A server refuses a signature whose timestamp is further than
//! [`SIGNATURE_WINDOW_SECS`] from its own clock. A device whose clock drifted
//! past that is refused on every signed call, and nothing it can see says why:
//! a Windows client 91 s fast lost its port forwarding, its session tokens and
//! its account screen for days (forum topic 219). The refusal itself carries
//! a `Date` header, read over the same TLS session as the answer, so the
//! client learns the server's clock from it, signs again at that clock, and
//! stamps every later request with it (`WarrenApiClient` reads only a
//! refusal's `Date`: any other answer can be a cached copy with a stale one).
//!
//! The logic is the one the desktop app validated for the forum broker first:
//! correct only a device that would otherwise be refused, and never let an
//! answer move the stamp far into the future (see
//! [`MAX_FORWARD_CORRECTION_SECS`]).
//!
//! **No-log policy**: only the offset (a duration) is ever worth logging,
//! never the request or the key.

use std::sync::atomic::{AtomicI64, Ordering};

use warren_contract::auth::SIGNATURE_WINDOW_SECS;

/// How far the stamp may be moved FORWARD, in seconds, at an answer's word.
///
/// The two directions are not the same risk. A stamp moved into the past is
/// spent: a signature carrying an instant that has gone by is replayable only
/// at an instant that has gone by. A stamp moved into the future is not: an
/// answer claiming a `Date` months ahead would mint signatures a hostile
/// server could hold and present when they become current, for a wallet whose
/// owner was not acting then. So a backward correction is bounded only by the
/// representable range, and a forward one by a quarter of an hour, past which
/// the device clock is the more credible of the two.
pub const MAX_FORWARD_CORRECTION_SECS: i64 = 15 * 60;

/// The server's clock minus the device's, in seconds, read off the `Date`
/// header of an answer received at `device_now` (Unix seconds): positive when
/// the device is behind. `None` when the header does not parse.
#[must_use]
pub fn clock_offset_secs(date_header: &str, device_now: u64) -> Option<i64> {
    let server = httpdate::parse_http_date(date_header.trim()).ok()?;
    let server_secs = server.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(server_secs)
        .ok()?
        .checked_sub(i64::try_from(device_now).ok()?)
}

/// The part of a measured offset a stamp is actually moved by.
///
/// Zero in the two cases where the answer must not decide the instant a
/// wallet signs at: a device already comfortably inside the server's window
/// (within half of it, so the round trip and the `Date` header's one-second
/// resolution cannot push it out), and a `Date` further ahead than
/// [`MAX_FORWARD_CORRECTION_SECS`].
#[must_use]
pub fn applicable_offset(offset_secs: i64) -> i64 {
    let window = i64::try_from(SIGNATURE_WINDOW_SECS).unwrap_or(i64::MAX);
    if offset_secs.unsigned_abs().saturating_mul(2) <= window.unsigned_abs()
        || offset_secs > MAX_FORWARD_CORRECTION_SECS
    {
        0
    } else {
        offset_secs
    }
}

/// The timestamp to sign at: `device_now` shifted by the applicable part of
/// `offset_secs`. A shift that would leave the representable range keeps the
/// device stamp, so a broken clock degrades to signing on the device clock
/// rather than at an absurd instant.
#[must_use]
pub fn corrected_timestamp(device_now: u64, offset_secs: i64) -> u64 {
    let applied = applicable_offset(offset_secs);
    i64::try_from(device_now)
        .ok()
        .and_then(|now| now.checked_add(applied))
        .and_then(|corrected| u64::try_from(corrected).ok())
        .unwrap_or(device_now)
}

/// The offset learned from the server's answers, shared by every request a
/// client signs (and by any other signer of the same wallet that talks to
/// the same servers, such as the forum broker).
///
/// Starts at zero: until an answer has been read, requests are stamped with
/// the device clock, as before the correction existed.
#[derive(Debug, Default)]
pub struct ServerClock {
    offset_secs: AtomicI64,
}

impl ServerClock {
    /// A clock that has read no answer yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the offset an answer's `Date` header shows, received at
    /// `device_now`, and returns it. An unparseable header records nothing
    /// and returns `None`: the last good reading stands.
    pub fn observe_date(&self, date_header: &str, device_now: u64) -> Option<i64> {
        let offset = clock_offset_secs(date_header, device_now)?;
        self.offset_secs.store(offset, Ordering::Relaxed);
        Some(offset)
    }

    /// The last measured offset (server minus device, seconds), whether or
    /// not it is large enough to be applied. Zero before any reading.
    #[must_use]
    pub fn offset_secs(&self) -> i64 {
        self.offset_secs.load(Ordering::Relaxed)
    }

    /// The part of [`Self::offset_secs`] a stamp is moved by now.
    #[must_use]
    pub fn applied_offset_secs(&self) -> i64 {
        applicable_offset(self.offset_secs())
    }

    /// The timestamp to sign a request at when the device clock reads
    /// `device_now`.
    #[must_use]
    pub fn stamp(&self, device_now: u64) -> u64 {
        corrected_timestamp(device_now, self.offset_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2023-11-14 22:13:20 UTC.
    const SERVER_NOW: u64 = 1_700_000_000;
    const SERVER_DATE: &str = "Tue, 14 Nov 2023 22:13:20 GMT";

    #[test]
    fn a_device_behind_the_server_signs_at_the_servers_clock() {
        let device_now = SERVER_NOW - 91;
        let offset = clock_offset_secs(SERVER_DATE, device_now).expect("parses");
        assert_eq!(offset, 91);
        assert_eq!(corrected_timestamp(device_now, offset), SERVER_NOW);
    }

    #[test]
    fn a_device_ahead_of_the_server_is_pulled_back() {
        // Forum topic 219: a Windows clock 91 s fast, refused on every call.
        let device_now = SERVER_NOW + 91;
        let offset = clock_offset_secs(SERVER_DATE, device_now).expect("parses");
        assert_eq!(offset, -91);
        assert_eq!(corrected_timestamp(device_now, offset), SERVER_NOW);
    }

    #[test]
    fn a_date_that_does_not_parse_measures_nothing() {
        assert_eq!(clock_offset_secs("not a date", SERVER_NOW), None);
    }

    /// The server accepts a stamp within its window, so a device already well
    /// inside it is left exactly as it is: the correction exists for a stamp
    /// that would otherwise be refused, and must never make a right clock
    /// worse by a round trip's worth of jitter.
    #[test]
    fn a_device_inside_half_the_window_is_left_alone() {
        assert_eq!(applicable_offset(30), 0);
        assert_eq!(applicable_offset(-30), 0);
        assert_eq!(applicable_offset(1), 0);
        assert_eq!(applicable_offset(31), 31);
        assert_eq!(applicable_offset(-31), -31);
    }

    /// The answer decides the instant a wallet signs at, so how far forward
    /// it may push that instant is bounded.
    #[test]
    fn an_answer_from_far_in_the_future_does_not_move_the_stamp() {
        assert_eq!(
            applicable_offset(MAX_FORWARD_CORRECTION_SECS),
            MAX_FORWARD_CORRECTION_SECS
        );
        assert_eq!(applicable_offset(MAX_FORWARD_CORRECTION_SECS + 1), 0);
        let a_year = 365 * 24 * 60 * 60;
        assert_eq!(corrected_timestamp(SERVER_NOW, a_year), SERVER_NOW);
    }

    /// The other direction is spent the moment it is signed, so a device
    /// stuck years ahead is still pulled back to the server.
    #[test]
    fn a_device_running_ahead_is_pulled_back_however_far() {
        let a_year: i64 = 365 * 24 * 60 * 60;
        let device_now = SERVER_NOW + a_year.unsigned_abs();
        assert_eq!(corrected_timestamp(device_now, -a_year), SERVER_NOW);
    }

    #[test]
    fn a_correction_that_would_leave_the_range_keeps_the_device_stamp() {
        assert_eq!(corrected_timestamp(10, -3_600), 10);
        assert_eq!(corrected_timestamp(u64::MAX, 60), u64::MAX);
    }

    #[test]
    fn the_server_clock_stamps_with_what_the_last_answer_said() {
        let clock = ServerClock::new();
        assert_eq!(
            clock.stamp(SERVER_NOW + 91),
            SERVER_NOW + 91,
            "nothing read yet"
        );

        assert_eq!(clock.observe_date(SERVER_DATE, SERVER_NOW + 91), Some(-91));
        assert_eq!(clock.offset_secs(), -91);
        assert_eq!(clock.applied_offset_secs(), -91);
        assert_eq!(clock.stamp(SERVER_NOW + 91), SERVER_NOW);

        // A later answer from a clock that was fixed brings the stamp home.
        assert_eq!(clock.observe_date(SERVER_DATE, SERVER_NOW), Some(0));
        assert_eq!(clock.stamp(SERVER_NOW), SERVER_NOW);
    }

    #[test]
    fn an_unreadable_date_keeps_the_last_good_reading() {
        let clock = ServerClock::new();
        clock.observe_date(SERVER_DATE, SERVER_NOW + 91);
        assert_eq!(clock.observe_date("garbage", SERVER_NOW + 91), None);
        assert_eq!(clock.offset_secs(), -91);
    }

    #[test]
    fn a_small_measured_offset_is_recorded_but_not_applied() {
        let clock = ServerClock::new();
        clock.observe_date(SERVER_DATE, SERVER_NOW + 2);
        assert_eq!(clock.offset_secs(), -2);
        assert_eq!(clock.applied_offset_secs(), 0);
        assert_eq!(clock.stamp(SERVER_NOW + 2), SERVER_NOW + 2);
    }
}
