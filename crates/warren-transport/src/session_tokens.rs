//! How a tunnel is admitted at the exit: on an anonymous v7 session token
//! (warren-core doc 64), or on the wallet-signed v6 request.
//!
//! Every client of a wallet holds the same tokens, and an exit leases a serial
//! to one live session in the whole fleet, refusing the others with the same
//! sealed `Rejected` it answers an invalid token with. A refusal spends
//! nothing, so a dial walks its stack: it leads with one token, and on a
//! refusal redials leading with the next. The walk is bounded by the stack.
//!
//! The lease is keyed by serial and exit, and an exit renews a serial leased
//! on itself: a session leading with a token another one holds on the SAME
//! exit is admitted, not refused. The placement hint every dial sends keeps
//! the two on distinct inner addresses.

use std::sync::Arc;

use warren_multihop::SetupError;
use warren_wire::SessionToken;
use warrenguard_multihop::RejectionReason;

use crate::multihop::MultihopError;

/// Why a tokens-only session was never set up, the engine's own cause type.
pub use warrenguard_transport::multihop::NoSessionTokenCause;
/// How sessions are admitted, the engine's own policy type.
pub use warrenguard_transport::supervisor::SessionAdmission;

/// Where a tunnel draws the anonymous tokens it presents.
pub trait SessionTokenSource: Send + Sync {
    /// The tokens ONE new session may lead with, in the order to try them.
    /// Never mints, never consumes.
    fn stack(&self) -> Vec<SessionToken>;

    /// Holds `token` for a session about to present it, so no other session
    /// of this process leads with it while the hold lives. `None` when a live
    /// session already holds it.
    fn claim(&self, token: &SessionToken) -> Option<TokenHold>;
}

/// A live session's hold on the token it presents. Cloned by the bonded legs
/// that join the session; the last drop releases the token.
#[derive(Clone)]
pub struct TokenHold {
    _hold: Arc<dyn Send + Sync>,
}

impl TokenHold {
    /// Wraps whatever keeps the token held (a lease, a registry guard) until
    /// the last clone drops.
    #[must_use]
    pub fn new<H: Send + Sync + 'static>(hold: H) -> Self {
        Self {
            _hold: Arc::new(hold),
        }
    }
}

impl std::fmt::Debug for TokenHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenHold(..)")
    }
}

/// What the exit admitted a session on: an anonymous token, held for as long
/// as the session lives, or the wallet-signed request.
#[derive(Clone, Debug)]
pub struct Admission(pub(crate) Admitted);

#[derive(Clone, Debug)]
pub(crate) enum Admitted {
    /// The exit spent this token and never saw the wallet. The hold keeps the
    /// token out of every other session of this process.
    Token {
        token: Box<SessionToken>,
        hold: TokenHold,
    },
    /// The exit knows which account this is.
    Wallet,
}

impl Admission {
    pub(crate) fn on_token(token: SessionToken, hold: TokenHold) -> Self {
        Self(Admitted::Token {
            token: Box::new(token),
            hold,
        })
    }

    pub(crate) fn on_wallet() -> Self {
        Self(Admitted::Wallet)
    }

    /// Whether the exit admitted the session without learning the wallet.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        matches!(self.0, Admitted::Token { .. })
    }

    /// The token the exit spent, when it admitted the session on one. A
    /// bearer credential: never log it.
    #[must_use]
    pub fn token(&self) -> Option<&SessionToken> {
        match &self.0 {
            Admitted::Token { token, .. } => Some(token),
            Admitted::Wallet => None,
        }
    }
}

/// Whether a setup failure can be the exit refusing the presented token. The
/// exit answers an invalid token and a serial leased elsewhere with the same
/// sealed `Rejected`, or with the bare opaque close when that detail is lost.
pub(crate) fn is_token_refusal(error: &MultihopError) -> bool {
    match error {
        MultihopError::Setup(SetupError::Rejected) => true,
        MultihopError::SetupClosed(close) => {
            warrenguard_transport::multihop::rejection_from_conn_error(close)
                == Some(RejectionReason::PolicyRefused)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed_with(code: u32) -> MultihopError {
        MultihopError::SetupClosed(quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(code),
                reason: bytes::Bytes::new(),
            },
        ))
    }

    #[test]
    fn only_a_refusal_a_token_can_cause_moves_the_walk_on() {
        assert!(is_token_refusal(&MultihopError::Setup(
            SetupError::Rejected
        )));
        assert!(is_token_refusal(&closed_with(
            warrenguard_multihop::WARREN_MH_REJECTED
        )));
        // Pool exhaustion, a ban, a drain or a lost path say nothing about the
        // token: another token cannot change them.
        assert!(!is_token_refusal(&MultihopError::Setup(
            SetupError::IpExhausted
        )));
        assert!(!is_token_refusal(&MultihopError::Setup(
            SetupError::Banned(0)
        )));
        assert!(!is_token_refusal(&closed_with(
            warrenguard_multihop::WARREN_MH_DRAINING
        )));
        assert!(!is_token_refusal(&MultihopError::SetupClosed(
            quinn::ConnectionError::TimedOut
        )));
    }
}
