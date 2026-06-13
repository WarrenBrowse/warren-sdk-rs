//! Leak prevention seam.
//!
//! The guarantee differs by datapath, and the SDK is honest about it via
//! [`KillSwitchLevel`]:
//! - TUN mode installs an OS firewall default-drop (nftables / pf / WFP) =
//!   [`KillSwitchLevel::OsEnforced`].
//! - Proxy mode cannot enforce an OS-wide killswitch without privilege; it
//!   offers best-effort, per-app fail-closed behavior (the proxy listener is
//!   only up while the tunnel is, and DNS is forced through the tunnel) =
//!   [`KillSwitchLevel::BestEffortProxy`].

use crate::error::NetError;

/// The strength of leak protection a killswitch provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchLevel {
    /// System-wide, fail-closed, enforced by the OS firewall. Requires privilege.
    OsEnforced,
    /// Per-app, best-effort: configured apps lose connectivity when the tunnel
    /// drops, but unconfigured apps and proxy-bypassing components can still
    /// leak. No privilege required.
    BestEffortProxy,
}

/// A leak-prevention backend.
pub trait KillSwitch: Send + Sync {
    /// Engages protection, allowing only tunnel traffic plus the exit endpoint.
    fn engage(&self) -> impl std::future::Future<Output = Result<(), NetError>> + Send;
    /// Disengages protection, restoring normal connectivity.
    fn disengage(&self) -> impl std::future::Future<Output = Result<(), NetError>> + Send;
    /// The level of protection this backend can guarantee.
    fn guarantees(&self) -> KillSwitchLevel;
}

/// The killswitch used in proxy mode: best-effort, no privilege.
///
/// It carries no OS state; the per-app fail-closed behavior is implemented by
/// the proxy listener lifecycle (bound only while the tunnel is up) and the
/// remote-DNS policy. `engage`/`disengage` are no-ops at the firewall level.
#[derive(Debug, Default)]
pub struct ProxyOnlyKillSwitch;

impl KillSwitch for ProxyOnlyKillSwitch {
    async fn engage(&self) -> Result<(), NetError> {
        Ok(())
    }

    async fn disengage(&self) -> Result<(), NetError> {
        Ok(())
    }

    fn guarantees(&self) -> KillSwitchLevel {
        KillSwitchLevel::BestEffortProxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_killswitch_is_best_effort_and_engages() {
        let ks = ProxyOnlyKillSwitch;
        assert_eq!(ks.guarantees(), KillSwitchLevel::BestEffortProxy);
        ks.engage().await.expect("engage");
        ks.disengage().await.expect("disengage");
    }
}
