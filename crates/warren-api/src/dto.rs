//! Request and response DTOs for the Warren account API, wire-compatible with
//! warren-core (`warren-api-types`). Newtypes there are plain `String` here to
//! stay simple and FFI-friendly; the server validates shapes.

use serde::{Deserialize, Serialize};

/// `POST /v1/register` request (unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAccountRequest {
    /// Ed25519 public key to bind, as a Warren SS58 address (`wb…`).
    pub pubkey_ss58: String,
    /// Plain-text voucher secret (dashed or raw form).
    pub voucher_secret: String,
    /// Optional referral code (`wref-<16hex>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referral_code: Option<String>,
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
