//! Request and response DTOs for the Warren account API, wire-compatible with
//! warren-core (`warren-api-types`). Newtypes there are plain `String` here to
//! stay simple and FFI-friendly; the server validates shapes.

use std::fmt;

use serde::{Deserialize, Serialize};

/// `POST /v1/register` request (unsigned).
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterAccountRequest {
    /// Ed25519 public key to bind, as a Warren SS58 address (`wb…`).
    pub pubkey_ss58: String,
    /// Plain-text voucher secret (dashed or raw form).
    pub voucher_secret: String,
    /// Optional referral code (`wref-<16hex>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referral_code: Option<String>,
}

// The voucher secret is a bearer credential (80 bits of entropy, the sole proof
// to redeem a subscription): never render it in logs or panics. Mirrors
// warren-core's redacting Debug for this DTO.
impl fmt::Debug for RegisterAccountRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterAccountRequest")
            .field("pubkey_ss58", &self.pubkey_ss58)
            .field("voucher_secret", &"<redacted>")
            // Presence is safe to log; the value is withheld.
            .field(
                "referral_code",
                &self.referral_code.as_deref().map(|_| "<present>"),
            )
            .finish()
    }
}

/// `POST /v1/register` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAccountResponse {
    /// Unix epoch seconds at which the subscription expires.
    pub expires_at: u64,
}

/// `GET /v1/subscription` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionResponse {
    /// Unix epoch seconds at which the subscription expires.
    pub expires_at: u64,
}

/// `GET /v1/check` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResponse {
    /// Client's public IP as seen by the server.
    pub ip: String,
    /// `true` when `ip` matches a currently registered Warren exit.
    pub is_exit: bool,
    /// Country of the matching exit (ISO 3166-1 alpha-2), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_country: Option<String>,
    /// City of the matching exit, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_city: Option<String>,
}

/// `POST /v1/session/open` request (signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOpenRequest {
    /// Client wallet SS58 pubkey whose device count is capped.
    pub pubkey_ss58: String,
    /// Self-asserted device id (16 bytes as 32 lowercase hex chars).
    pub device_id_hex: String,
    /// Exit currently serving this device (diagnostics).
    pub exit_id: String,
    /// Optional cap override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_devices: Option<usize>,
}

/// `POST /v1/session/open` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOpenResponse {
    /// `true` if the device was admitted (fresh lease or renewal).
    pub admitted: bool,
    /// Cap in force.
    pub max: usize,
    /// Distinct live devices currently leased for this account.
    pub current: usize,
}

/// `POST /v1/session/close` request (signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCloseRequest {
    /// Client wallet SS58 pubkey whose lease is released.
    pub pubkey_ss58: String,
    /// Device id whose lease is released (16 bytes, 32 lowercase hex).
    pub device_id_hex: String,
}

/// `POST /v1/payments/apple/init` response (signed request, empty body).
///
/// The `app_account_token` is passed verbatim to StoreKit as the purchase's
/// `appAccountToken` so Apple's signed transaction can be mapped back to this
/// Warren pubkey server-side, without Apple ever seeing the pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitApplePaymentResponse {
    /// UUID v4 string (lowercase, hyphenated) to pass to StoreKit.
    pub app_account_token: String,
}

/// `POST /v1/payments/apple/check` request (signed). Carries the StoreKit 2
/// signed transaction JWS for server-side validation and subscription credit.
#[derive(Clone, Serialize, Deserialize)]
pub struct CheckApplePaymentRequest {
    /// JWS string from `Transaction.jwsRepresentation` (StoreKit 2).
    pub jws_transaction: String,
}

// The JWS is a bearer credit token: never render it in logs or panics.
impl fmt::Debug for CheckApplePaymentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckApplePaymentRequest")
            .field("jws_transaction", &"<redacted>")
            .finish()
    }
}

/// Shared response for the mobile payment check endpoints. Same shape as the
/// register response but kept distinct for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobilePaymentResponse {
    /// Unix epoch seconds at which the subscription now expires.
    pub expires_at: u64,
}

/// Allowed `reason_code` values on the failover-incident wire. A discriminated
/// enum (not a free-form string) so the public endpoint cannot be used to
/// smuggle arbitrary telemetry strings. Serializes as SCREAMING_SNAKE_CASE
/// (`TIMEOUT`, `HANDSHAKE_FAIL`, `AUTH_FAIL`) to match warren-core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentReason {
    /// QUIC handshake never completed (DNS / TCP / TLS error pre-auth).
    Timeout,
    /// QUIC connection established but the post-handshake exchange (HPKE setup
    /// or Warren `Setup` frame) failed.
    HandshakeFail,
    /// Server rejected the client identity (stale enrollment / revoked cert).
    AuthFail,
}

/// `POST /v1/incidents/exit-down` request (signed). Best-effort failover
/// telemetry: the server keeps only an aggregate count keyed by
/// `exit_pubkey_hex`, never the signer identity, IP, or `ts_unix`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentExitDownRequest {
    /// Hex-encoded Ed25519 public key of the unreachable exit (64 lowercase
    /// hex chars; the server enforces the shape and returns 400 otherwise).
    pub exit_pubkey_hex: String,
    /// Why the report fired. Unknown variants are rejected 422 server-side.
    pub reason_code: IncidentReason,
    /// Client-supplied Unix seconds of the failed handshake. The server
    /// replaces it with its own clock when recording (kept on the wire for
    /// forward compatibility); do not rely on it being stored.
    pub ts_unix: u64,
}

/// `POST /v1/incidents/pubkey-mismatch` request (signed). Reports that a known
/// `exit_id` served a pubkey diverging from the locally pinned baseline so the
/// operator can correlate substitution attempts. Log-only server-side, no DB
/// row, signer identity not recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentPubkeyMismatchRequest {
    /// 32-char hex stable exit identifier whose pin entry was flagged.
    pub exit_id_hex: String,
    /// Pubkey hex previously pinned for this `exit_id`.
    pub old_pubkey_hex: String,
    /// Pubkey hex observed on the failed connect.
    pub new_pubkey_hex: String,
    /// Forensic snapshot at pin time (ISO 3166 alpha-2, lowercase). Optional
    /// via empty string.
    #[serde(default)]
    pub country_code: String,
    /// Forensic snapshot at pin time (free-form city label). Optional.
    #[serde(default)]
    pub city: String,
    /// Client-supplied unix seconds of the observation. The server replaces it
    /// with its own clock when logging.
    pub ts_unix: u64,
}

/// `POST /v1/support` request (signed). A redacted log bundle plus a free-form
/// user message. The signer pubkey (auth header) identifies the user, so no
/// account id is echoed in the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportReportRequest {
    /// Free-form user message (max 4096 chars enforced server-side; empty ok).
    pub user_message: String,
    /// Redacted, newline-joined log lines (max 256 KB enforced server-side).
    pub redacted_logs: String,
    /// Optional client app version string (e.g. `1.2.3`).
    #[serde(default)]
    pub app_version: String,
    /// Optional client platform tag (e.g. `macos-arm64`).
    #[serde(default)]
    pub platform: String,
}

/// `POST /v1/support` response. An opaque reference id the user can quote in a
/// follow-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportReportResponse {
    /// 32-char hex reference id (UUID v4 minus dashes).
    pub reference_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_request_debug_redacts_the_voucher_secret() {
        let req = RegisterAccountRequest {
            pubkey_ss58: "wbPUBKEY".to_owned(),
            voucher_secret: "ABCD-EFGH-JKMN-PQRS".to_owned(),
            referral_code: Some("wref-0123456789abcdef".to_owned()),
        };
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("ABCD-EFGH-JKMN-PQRS"),
            "the bearer voucher secret must never appear in Debug output"
        );
        assert!(
            !rendered.contains("wref-0123456789abcdef"),
            "the referral code value must be withheld"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("<present>"));
        // The pubkey is public and kept for debugging correlation.
        assert!(rendered.contains("wbPUBKEY"));
    }

    #[test]
    fn register_request_debug_marks_absent_referral_as_none() {
        let req = RegisterAccountRequest {
            pubkey_ss58: "wbPUBKEY".to_owned(),
            voucher_secret: "secret".to_owned(),
            referral_code: None,
        };
        let rendered = format!("{req:?}");
        assert!(rendered.contains("None"));
        assert!(!rendered.contains("<present>"));
    }

    #[test]
    fn check_apple_payment_debug_redacts_the_jws() {
        let req = CheckApplePaymentRequest {
            jws_transaction: "super.secret.jws".to_owned(),
        };
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("super.secret.jws"),
            "the bearer JWS must never appear in Debug output"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn incident_reason_uses_screaming_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&IncidentReason::Timeout).unwrap(),
            "\"TIMEOUT\""
        );
        assert_eq!(
            serde_json::to_string(&IncidentReason::HandshakeFail).unwrap(),
            "\"HANDSHAKE_FAIL\""
        );
        assert_eq!(
            serde_json::to_string(&IncidentReason::AuthFail).unwrap(),
            "\"AUTH_FAIL\""
        );
        // Parse direction for every variant: a rename drift on the inbound
        // path would otherwise pass unnoticed for the untested variants.
        for (json, want) in [
            ("\"TIMEOUT\"", IncidentReason::Timeout),
            ("\"HANDSHAKE_FAIL\"", IncidentReason::HandshakeFail),
            ("\"AUTH_FAIL\"", IncidentReason::AuthFail),
        ] {
            let parsed: IncidentReason = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, want);
        }
    }

    #[test]
    fn pubkey_mismatch_optionals_default_to_empty_when_absent() {
        // A minimal body without the optional forensic fields must still parse,
        // matching the server's `#[serde(default)]` contract.
        let json = r#"{
            "exit_id_hex":"00112233445566778899aabbccddeeff",
            "old_pubkey_hex":"11",
            "new_pubkey_hex":"22",
            "ts_unix":7
        }"#;
        let req: IncidentPubkeyMismatchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.country_code, "");
        assert_eq!(req.city, "");
        assert_eq!(req.ts_unix, 7);
    }

    #[test]
    fn support_report_optionals_default_when_absent() {
        let json = r#"{"user_message":"hi","redacted_logs":""}"#;
        let req: SupportReportRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.app_version, "");
        assert_eq!(req.platform, "");
    }
}
