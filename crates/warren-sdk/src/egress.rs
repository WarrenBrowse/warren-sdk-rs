//! `am.i.warren` egress oracle: client side of the independent leak self-check.
//!
//! "Connected does not equal protected" (the iOS 9 / iOS 13.3.1 lesson): the
//! client's own belief that the tunnel is up is never authoritative, only
//! EGRESS observed from OUTSIDE is. This module owns the verdict contract the
//! oracle returns and the reconciliation that turns "I think I am connected" +
//! "what the server actually saw" into a [`LeakStatus`]. A client that reports
//! connected but whose egress is not in Warren is surfaced as a LEAK, not as
//! connected. A blocked or unreachable oracle is [`LeakStatus::Unknown`], never
//! "safe".
//!
//! No-log discipline: these types carry the exit's public IP (ground truth of
//! egress, meant to be shown to the user) but never a client identifier. The
//! oracle itself must retain nothing (see the plan's no-log design); this module
//! neither logs nor persists anything.
//!
//! The actual HTTP fetch of the oracle is done by the host through the tunnel
//! (so a passing result proves the app's own traffic traverses the tunnel); this
//! module is transport-agnostic: feed it the oracle's JSON body, or build a
//! [`EgressVerdict`] directly, then reconcile.

use serde::Deserialize;

/// The oracle's observation of a single egress, as reflected back to the client.
///
/// This is the wire contract shared with the server-side `am.i.warren` handler:
/// keep the field names and shape in sync with it. Every leak field is optional
/// so an older oracle that does not compute one degrades to "not asserted"
/// rather than a parse error.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct EgressVerdict {
    /// Whether the source IP the server observed is one of Warren's exit egress
    /// IPs. This is the ground-truth "am I in Warren", decided server-side from
    /// the exit's own advertised identity, never from geo-IP of the user.
    pub in_warren: bool,
    /// The public IP the server saw (reflected back). The truth of egress.
    #[serde(default)]
    pub exit_ip: Option<String>,
    /// The exit's country (ISO 3166-1 alpha-2), from the exit identity when the
    /// source is a Warren exit.
    #[serde(default)]
    pub exit_country: Option<String>,
    /// DNS-leak observation: `Some(true)` if the client's resolver was NOT a
    /// Warren exit resolver, `Some(false)` if it was, `None` if not measured.
    #[serde(default)]
    pub dns_leaked: Option<bool>,
    /// IPv6-leak observation: `Some(true)` if v6 egress was off-tunnel while only
    /// v4 is tunneled, `None` if not measured.
    #[serde(default)]
    pub ipv6_leaked: Option<bool>,
}

impl EgressVerdict {
    /// Parses the oracle JSON body. A malformed body yields [`OracleError`].
    ///
    /// # Errors
    ///
    /// [`OracleError::Malformed`] if the body is not the expected JSON shape.
    pub fn from_oracle_json(body: &str) -> Result<Self, OracleError> {
        serde_json::from_str(body).map_err(|_| OracleError::Malformed)
    }
}

/// A parse failure of an oracle response. Carries no server text (it is
/// untrusted and may be noisy); only the typed kind crosses out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OracleError {
    /// The oracle body was not the expected JSON shape.
    #[error("malformed oracle response")]
    Malformed,
}

/// Why egress is judged to be leaking. A single probe can surface several.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeakReason {
    /// The client believes it is connected but the observed egress is not a
    /// Warren exit (the "connected does not equal protected" case).
    EgressNotInWarren,
    /// DNS resolution egressed to a non-Warren resolver.
    DnsLeak,
    /// IPv6 egressed off-tunnel while only v4 is tunneled.
    Ipv6Leak,
    /// A WebRTC ICE probe (computed by the host, in-browser/webview) exposed a
    /// real local/public IP outside the tunnel.
    WebrtcLeak,
}

/// The reconciled verdict of an egress self-check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeakStatus {
    /// Egress is verifiably in Warren with no measured leak.
    Protected,
    /// One or more leaks were detected. Surfaced as a leak even if the client
    /// itself reports "connected".
    Leaking(Vec<LeakReason>),
    /// The oracle could not be reached (blocked, offline, malformed). Treated as
    /// UNKNOWN, never as safe: a blocked oracle must not read as protected.
    Unknown,
}

/// Reconciles the client's own belief with the oracle's observation.
///
/// `client_believes_connected` is what the app's tunnel state machine reports.
/// `verdict` is `None` when the oracle could not be reached (blocked/offline):
/// that is deliberately [`LeakStatus::Unknown`], never `Protected`.
/// `webrtc_leaked` folds in a host-computed WebRTC ICE result (`None` if not
/// measured), because that probe runs client-side, not at the server.
#[must_use]
pub fn reconcile(
    client_believes_connected: bool,
    verdict: Option<&EgressVerdict>,
    webrtc_leaked: Option<bool>,
) -> LeakStatus {
    let Some(v) = verdict else {
        // A blocked/unreachable oracle is never a safe verdict.
        return LeakStatus::Unknown;
    };

    let mut reasons = Vec::new();
    // The core "connected != protected" check: only meaningful when the client
    // thinks it is protected. If the app knows it is disconnected, an off-Warren
    // egress is expected, not a leak.
    if client_believes_connected && !v.in_warren {
        reasons.push(LeakReason::EgressNotInWarren);
    }
    if v.dns_leaked == Some(true) {
        reasons.push(LeakReason::DnsLeak);
    }
    if v.ipv6_leaked == Some(true) {
        reasons.push(LeakReason::Ipv6Leak);
    }
    if webrtc_leaked == Some(true) {
        reasons.push(LeakReason::WebrtcLeak);
    }

    if reasons.is_empty() {
        // No leak measured. "Protected" requires positively observing Warren
        // egress; if the client believes connected but the oracle says it is not
        // in Warren, that already produced a reason above, so reaching here with
        // in_warren == false means the client also believes it is disconnected.
        if v.in_warren || !client_believes_connected {
            LeakStatus::Protected
        } else {
            LeakStatus::Unknown
        }
    } else {
        LeakStatus::Leaking(reasons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_warren() -> EgressVerdict {
        EgressVerdict {
            in_warren: true,
            exit_ip: Some("203.0.113.7".to_owned()),
            exit_country: Some("NL".to_owned()),
            dns_leaked: Some(false),
            ipv6_leaked: Some(false),
        }
    }

    #[test]
    fn in_warren_with_no_leak_is_protected() {
        assert_eq!(
            reconcile(true, Some(&in_warren()), Some(false)),
            LeakStatus::Protected
        );
    }

    #[test]
    fn connected_but_egress_not_in_warren_is_a_leak_not_connected() {
        let mut v = in_warren();
        v.in_warren = false;
        // The iOS-9 lesson institutionalized: the app thinks it is connected but
        // egress proves otherwise, so the verdict is a leak, never Protected.
        assert_eq!(
            reconcile(true, Some(&v), None),
            LeakStatus::Leaking(vec![LeakReason::EgressNotInWarren])
        );
    }

    #[test]
    fn a_blocked_oracle_is_unknown_never_safe() {
        assert_eq!(reconcile(true, None, None), LeakStatus::Unknown);
    }

    #[test]
    fn dns_leak_is_detected_even_when_in_warren() {
        let mut v = in_warren();
        v.dns_leaked = Some(true);
        assert_eq!(
            reconcile(true, Some(&v), Some(false)),
            LeakStatus::Leaking(vec![LeakReason::DnsLeak])
        );
    }

    #[test]
    fn ipv6_leak_is_detected() {
        let mut v = in_warren();
        v.ipv6_leaked = Some(true);
        assert_eq!(
            reconcile(true, Some(&v), None),
            LeakStatus::Leaking(vec![LeakReason::Ipv6Leak])
        );
    }

    #[test]
    fn webrtc_leak_is_folded_in_from_the_host() {
        assert_eq!(
            reconcile(true, Some(&in_warren()), Some(true)),
            LeakStatus::Leaking(vec![LeakReason::WebrtcLeak])
        );
    }

    #[test]
    fn several_leaks_are_all_reported() {
        let mut v = in_warren();
        v.in_warren = false;
        v.dns_leaked = Some(true);
        v.ipv6_leaked = Some(true);
        let status = reconcile(true, Some(&v), Some(true));
        assert_eq!(
            status,
            LeakStatus::Leaking(vec![
                LeakReason::EgressNotInWarren,
                LeakReason::DnsLeak,
                LeakReason::Ipv6Leak,
                LeakReason::WebrtcLeak,
            ])
        );
    }

    #[test]
    fn disconnected_client_off_warren_is_not_a_leak() {
        let mut v = in_warren();
        v.in_warren = false;
        // The app knows it is disconnected, so an off-Warren egress is expected.
        assert_eq!(
            reconcile(false, Some(&v), Some(false)),
            LeakStatus::Protected
        );
    }

    #[test]
    fn parses_a_minimal_oracle_body_defaulting_unmeasured_fields() {
        let v = EgressVerdict::from_oracle_json(r#"{"in_warren":true}"#).expect("parse");
        assert!(v.in_warren);
        assert_eq!(v.dns_leaked, None);
        assert_eq!(v.ipv6_leaked, None);
        assert_eq!(v.exit_ip, None);
    }

    #[test]
    fn parses_a_full_oracle_body() {
        let body = r#"{"in_warren":true,"exit_ip":"203.0.113.7","exit_country":"NL","dns_leaked":false,"ipv6_leaked":false}"#;
        let v = EgressVerdict::from_oracle_json(body).expect("parse");
        assert_eq!(v, in_warren());
    }

    #[test]
    fn rejects_a_malformed_oracle_body() {
        assert_eq!(
            EgressVerdict::from_oracle_json("not json"),
            Err(OracleError::Malformed)
        );
    }
}
