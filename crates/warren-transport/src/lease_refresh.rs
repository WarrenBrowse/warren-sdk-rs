//! Epoch lease refresh, client side (warren-core doc 107 section 5.5).
//!
//! A session admitted on a token holds its fleet-wide lease only within the
//! token's epoch. After every setup on a token, the session announces to the
//! exit that it refreshes (`LeaseRefresh` with no token, retried until
//! acknowledged). When the exit reports the lease stale (`due`, sent at its
//! first renewal after the epoch boundary and repeated while the lease stays
//! stale), the session waits a random delay, so the fleet's sessions do not
//! all spend at the same second, then presents the tokens its source hands
//! out one at a time until the exit moves the lease onto one. The token the
//! lease moved onto stays held for as long as the session lives, so no other
//! session of this process leads with it.
//!
//! An exit that predates the refresh never acknowledges the announcement and
//! never asks: the task then ends, and so does the exit's reason to end the
//! session. The logic and its timings are the engine's
//! (`warrenguard_transport::lease_refresh`), ported onto this SDK's session.
//! Logs carry counts and states, never a token or a serial.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::mpsc;
use warren_wire::{MAX_SESSION_TOKENS, SessionToken};
use warrenguard_multihop::{LeaseRefreshStatus, WarrenControlMessage, encode_control};
use warrenguard_transport::multihop::MultiHopClient;

use crate::session_tokens::{SessionTokenSource, TokenHold};

/// When lease refresh requests are sent and re-sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseRefreshSchedule {
    /// Waits between two sends of one request; after the last one with no
    /// answer the request is given up (for the announcement: the exit
    /// predates the refresh).
    pub waits: [Duration; 5],
    /// Upper bound of the random wait between a `due` and the first token,
    /// so every session of the fleet does not spend in the same second.
    pub jitter_max: Duration,
    /// Pause after a refused token before the next: the exit spends at most
    /// one token per 2 s per session and drops anything sooner.
    pub refused_pause: Duration,
    /// Wait before presenting a token again after `unavailable`.
    pub unavailable_retry: Duration,
    /// How many times one refresh presents a token again after
    /// `unavailable`.
    pub unavailable_tries: u32,
}

impl LeaseRefreshSchedule {
    /// The production schedule, the engine's. The exit gives a stale lease
    /// minutes of grace, several of its 30 s renewal rounds, and asks at each
    /// round: the jitter plus one walk of a stack of five tokens fits in one
    /// round with room for a retry.
    pub const PRODUCTION: Self = Self {
        waits: [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
        ],
        jitter_max: Duration::from_secs(20),
        refused_pause: Duration::from_millis(2_100),
        unavailable_retry: Duration::from_secs(16),
        unavailable_tries: 3,
    };
}

impl Default for LeaseRefreshSchedule {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// A live session's lease refresh: where its downlink hands the exit's acks,
/// and the task, aborted with the session.
pub(crate) struct LeaseRefresh {
    tap: mpsc::UnboundedSender<LeaseRefreshStatus>,
    task: tokio::task::JoinHandle<()>,
}

impl LeaseRefresh {
    /// Starts refreshing the lease of the session `client` carries, drawing
    /// tokens from `tokens`.
    pub(crate) fn start(
        client: Weak<MultiHopClient>,
        tokens: Arc<dyn SessionTokenSource>,
        schedule: LeaseRefreshSchedule,
    ) -> Self {
        let (tap, acks) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_lease_refresh(client, tokens, acks, schedule));
        Self { tap, task }
    }

    /// Hands the task one `LeaseRefreshAck` read off the downlink.
    pub(crate) fn ack(&self, status: u8) {
        let _ = self.tap.send(LeaseRefreshStatus::from_code(status));
    }
}

impl Drop for LeaseRefresh {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What one request came to.
enum Answer {
    /// The exit answered this status.
    Status(LeaseRefreshStatus),
    /// Nothing came back after every retry.
    Silent,
    /// The session is gone.
    Closed,
}

/// Refresh one session's lease for as long as the session lives.
async fn run_lease_refresh(
    client: Weak<MultiHopClient>,
    tokens: Arc<dyn SessionTokenSource>,
    mut acks: mpsc::UnboundedReceiver<LeaseRefreshStatus>,
    schedule: LeaseRefreshSchedule,
) {
    let Ok(announce) = encode_control(&WarrenControlMessage::LeaseRefresh {
        session_token: None,
    }) else {
        return;
    };
    let mut due = match request(&client, &announce, false, &mut acks, &schedule).await {
        Answer::Status(LeaseRefreshStatus::Registered) => false,
        // The announcement's ack was lost and the exit already asks.
        Answer::Status(LeaseRefreshStatus::Due) => true,
        Answer::Silent => {
            tracing::debug!("exit does not refresh session leases");
            return;
        }
        Answer::Status(_) | Answer::Closed => return,
    };
    // The token the lease last moved onto, held until the session ends.
    let mut lease_hold: Option<TokenHold> = None;
    loop {
        if !due && !wait_for_due(&mut acks).await {
            return;
        }
        due = false;
        let jitter = schedule.jitter_max.mul_f64(unit_random());
        if pause(jitter, &mut acks).await {
            return;
        }
        match refresh_once(&client, tokens.as_ref(), &mut acks, &schedule).await {
            Some(Some(hold)) => {
                lease_hold.replace(hold);
                tracing::info!("session lease refreshed onto a token of the current epoch");
            }
            // Nothing refreshed: the exit asks again at its next renewal.
            Some(None) => {}
            None => return,
        }
    }
}

/// Present the source's tokens one at a time until the exit refreshes the
/// lease onto one. `Some(Some(hold))` on success, `Some(None)` when no token
/// was taken, `None` once the session is gone or cannot refresh.
async fn refresh_once(
    client: &Weak<MultiHopClient>,
    tokens: &dyn SessionTokenSource,
    acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>,
    schedule: &LeaseRefreshSchedule,
) -> Option<Option<TokenHold>> {
    let mut stack: VecDeque<SessionToken> = tokens
        .stack()
        .into_iter()
        .take(MAX_SESSION_TOKENS)
        .collect();
    let offered = stack.len();
    let mut unavailable = 0;
    while let Some(token) = stack.pop_front() {
        // Claimed before it is presented: a token another live session of
        // this process holds is never offered to the exit.
        let Some(hold) = tokens.claim(&token) else {
            continue;
        };
        let Ok(request_bytes) = encode_control(&WarrenControlMessage::LeaseRefresh {
            session_token: Some(Box::new(token)),
        }) else {
            return None;
        };
        loop {
            match request(client, &request_bytes, true, acks, schedule).await {
                Answer::Status(LeaseRefreshStatus::Refreshed) => return Some(Some(hold)),
                Answer::Status(LeaseRefreshStatus::Refused) => {
                    drop(hold);
                    if pause(schedule.refused_pause, acks).await {
                        return None;
                    }
                    break;
                }
                Answer::Status(LeaseRefreshStatus::Unavailable)
                    if unavailable < schedule.unavailable_tries =>
                {
                    // The same token again: the exit re-admits the serial it
                    // already spent for this session, so nothing is spent
                    // twice.
                    unavailable += 1;
                    if pause(schedule.unavailable_retry, acks).await {
                        return None;
                    }
                }
                Answer::Status(LeaseRefreshStatus::NotEligible | LeaseRefreshStatus::Expired)
                | Answer::Closed => return None,
                Answer::Status(_) | Answer::Silent => return Some(None),
            }
        }
    }
    // No-log: counts only.
    tracing::warn!(
        offered,
        "no token of the current epoch refreshed the session lease"
    );
    Some(None)
}

/// Send `bytes`, re-sending byte for byte on the schedule, and return the
/// first answer to it. Queued acks are dropped first: they carry no
/// correlation, and one from an earlier request must not be read as this
/// one's. A `due` or `registered` is never the answer to a token.
async fn request(
    client: &Weak<MultiHopClient>,
    bytes: &[u8],
    presents_token: bool,
    acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>,
    schedule: &LeaseRefreshSchedule,
) -> Answer {
    while acks.try_recv().is_ok() {}
    for wait in schedule.waits {
        let sent = client
            .upgrade()
            .is_some_and(|client| client.send_packet(bytes).is_ok());
        if !sent {
            return Answer::Closed;
        }
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, acks.recv()).await {
                Ok(None) => return Answer::Closed,
                Ok(Some(LeaseRefreshStatus::Due | LeaseRefreshStatus::Registered))
                    if presents_token => {}
                Ok(Some(status)) => return Answer::Status(status),
                Err(_) => break,
            }
        }
    }
    Answer::Silent
}

/// Wait for the exit to ask for a token. `false` once the session is gone.
async fn wait_for_due(acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>) -> bool {
    loop {
        match acks.recv().await {
            None => return false,
            Some(LeaseRefreshStatus::Due) => return true,
            Some(LeaseRefreshStatus::Expired) => {
                tracing::info!("exit ended the session: its lease was not refreshed in time");
            }
            Some(_) => {}
        }
    }
}

/// Sleep `wait`, consuming whatever arrives meanwhile. `true` when the
/// session ended during it.
async fn pause(wait: Duration, acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>) -> bool {
    tokio::time::timeout(wait, async { while acks.recv().await.is_some() {} })
        .await
        .is_ok()
}

/// A uniform draw in `[0, 1)`.
fn unit_random() -> f64 {
    use rand_core::RngCore;
    let bits = rand_core::UnwrapErr(rand_core::OsRng).next_u64() >> 11;
    // 53 random bits over 2^53: exact in an f64.
    bits as f64 / (1u64 << 53) as f64
}
