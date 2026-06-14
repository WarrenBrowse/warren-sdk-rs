//! FFI surface for the Warren SDK, exported via `uniffi`.
//!
//! Every function uses plain, owned, generic-free types and a serializable
//! [`FfiError`], the shape `uniffi` generates Swift/Kotlin/Python/Ruby bindings
//! from (and that `flutter_rust_bridge` can consume for Dart). The bindings are
//! produced by the `uniffi-bindgen` binary in `src/bin/` against the built
//! `cdylib`; see the crate README for the generate commands.
//!
//! Two surfaces are exported: the pure, deterministic identity functions (shared
//! by every sibling-language SDK and validated against `vectors/`), and a
//! [`WarrenFfiClient`] object with async account/directory methods (redeem,
//! subscription, tunnel check, exit listing) plus `start_proxy`, which retries
//! with backoff, reports each [`FfiConnectionState`] to an optional
//! [`ConnectionObserver`], and returns a [`WarrenFfiProxy`] lifecycle handle.

// FFI exports take owned arguments by value on purpose: uniffi marshals owned
// values across the language boundary, so a borrowed signature would not match
// the generated bindings.
#![allow(clippy::needless_pass_by_value)]
// FFI BOUNDARY EXCEPTION: this is the one crate where `unsafe_code` is not
// `forbid` (the workspace forbids it everywhere else). uniffi generates the
// C-ABI scaffolding, which is unavoidably `unsafe`; we hand-write zero unsafe.
// The manifest keeps the lint at `deny`, and this single documented `allow`
// admits only the generated boundary code.
#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use warren_sdk::api::{ClientError, RegisterAccountRequest, SupportReportRequest};
use warren_sdk::identity::{WarrenIdentity, ss58};
use warren_sdk::net::ProxyConfig;
use warren_sdk::transport::{Backoff, ConnectionState, RetryError, connect_with_state};
use warren_sdk::{DefaultClient, ProxyHandle, SdkError, WarrenClient};

uniffi::setup_scaffolding!();

/// A serializable error for the FFI boundary.
#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum FfiError {
    /// The mnemonic is not a valid BIP39 phrase.
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    /// A hex argument was malformed or the wrong length.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// The SS58 address was malformed.
    #[error("invalid address")]
    InvalidAddress,
    /// The server returned a non-2xx status. The body is intentionally dropped
    /// (it is server-controlled and may be noisy); only the code crosses the FFI.
    #[error("server returned status {status}")]
    ServerStatus {
        /// HTTP status code.
        status: u16,
    },
    /// A transport, build, or other client-side failure. The message is derived
    /// from a no-log-safe `Display` (no pubkey/address/IP/secret).
    #[error("client error: {message}")]
    Client {
        /// Human-readable, redaction-safe summary.
        message: String,
    },
}

/// Connection lifecycle state reported to a [`ConnectionObserver`]. Mirrors
/// [`warren_sdk::transport::ConnectionState`] across the FFI boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FfiConnectionState {
    /// The initial connect attempt is in flight.
    Connecting,
    /// A connection is established.
    Connected,
    /// A previous attempt failed; a retry is in flight.
    Reconnecting,
    /// Every attempt failed; the supervisor gave up.
    Failed,
}

/// Receives connection-state transitions during [`WarrenFfiClient::start_proxy`].
/// Implemented on the foreign side (uniffi callback interface) to drive UI.
#[uniffi::export(callback_interface)]
pub trait ConnectionObserver: Send + Sync {
    /// Called for each state transition, in order.
    fn on_state(&self, state: FfiConnectionState);
}

/// A Warren identity in FFI-friendly form.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiIdentity {
    /// The 12-word BIP39 mnemonic (secret).
    pub mnemonic: String,
    /// The canonical SS58 `wb…` address.
    pub address: String,
    /// The 32-byte Ed25519 public key as 64 hex chars.
    pub public_key_hex: String,
}

// Manual Debug: the mnemonic is seed material and must never reach a log, so it
// is redacted while the public address and pubkey stay visible for debugging.
impl std::fmt::Debug for FfiIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiIdentity")
            .field("mnemonic", &"<redacted>")
            .field("address", &self.address)
            .field("public_key_hex", &self.public_key_hex)
            .finish()
    }
}

/// A verified multihop exit, as exposed to the FFI boundary. All fields are
/// public directory data (no secrets): safe to render in a server picker.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiExit {
    /// 16-byte exit id (cleartext routing key), as 32 hex chars.
    pub exit_id_hex: String,
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// City label.
    pub city: String,
    /// QUIC endpoint to dial (`ip:port`).
    pub endpoint: String,
    /// The exit's Ed25519 identity (TLS RPK pin), as 64 hex chars.
    pub exit_ed25519_pubkey_hex: String,
}

/// The four `X-Warren-*` header values for a signed request.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSignedHeaders {
    /// `X-Warren-PubKey` (SS58 address).
    pub pubkey_ss58: String,
    /// `X-Warren-Sig` (128 hex chars).
    pub signature_hex: String,
    /// `X-Warren-Timestamp` (unix seconds).
    pub timestamp: u64,
    /// `X-Warren-Nonce` (32 hex chars).
    pub nonce_hex: String,
}

/// Generates a fresh identity.
#[uniffi::export]
#[must_use]
pub fn generate_identity() -> FfiIdentity {
    let (identity, mnemonic) = WarrenIdentity::generate();
    to_ffi(&identity, mnemonic)
}

/// Rebuilds an identity from a BIP39 mnemonic.
///
/// # Errors
///
/// [`FfiError::InvalidMnemonic`] if the phrase is not valid BIP39.
#[uniffi::export]
pub fn identity_from_mnemonic(mnemonic: String) -> Result<FfiIdentity, FfiError> {
    let identity =
        WarrenIdentity::from_mnemonic(&mnemonic).map_err(|_| FfiError::InvalidMnemonic)?;
    Ok(to_ffi(&identity, mnemonic))
}

/// Returns the SS58 `wb…` address for a mnemonic.
///
/// # Errors
///
/// [`FfiError::InvalidMnemonic`] if the phrase is not valid BIP39.
#[uniffi::export]
pub fn address_from_mnemonic(mnemonic: String) -> Result<String, FfiError> {
    Ok(WarrenIdentity::from_mnemonic(&mnemonic)
        .map_err(|_| FfiError::InvalidMnemonic)?
        .address())
}

/// Encodes a 32-byte pubkey (64 hex chars) as a Warren SS58 address.
///
/// # Errors
///
/// [`FfiError::InvalidHex`] if the input is not 32 bytes of hex.
#[uniffi::export]
pub fn ss58_encode(public_key_hex: String) -> Result<String, FfiError> {
    let pk = hex32(&public_key_hex)?;
    Ok(ss58::encode(&pk))
}

/// Decodes a Warren SS58 address into the 32-byte pubkey (64 hex chars).
///
/// # Errors
///
/// [`FfiError::InvalidAddress`] if the address is malformed.
#[uniffi::export]
pub fn ss58_decode(address: String) -> Result<String, FfiError> {
    ss58::decode(&address)
        .map(hex::encode)
        .map_err(|_| FfiError::InvalidAddress)
}

/// Signs a Warren API request, returning the four header values.
///
/// `nonce_hex` must be 32 hex chars (16 bytes). The caller supplies `timestamp`
/// and `nonce_hex` so the binding layer owns the clock and RNG.
///
/// # Errors
///
/// [`FfiError::InvalidMnemonic`] or [`FfiError::InvalidHex`].
#[uniffi::export]
pub fn sign_request(
    mnemonic: String,
    method: String,
    path: String,
    body_utf8: String,
    timestamp: u64,
    nonce_hex: String,
) -> Result<FfiSignedHeaders, FfiError> {
    let identity =
        WarrenIdentity::from_mnemonic(&mnemonic).map_err(|_| FfiError::InvalidMnemonic)?;
    let nonce = hex16(&nonce_hex)?;
    let sig = identity.sign_request(&method, &path, body_utf8.as_bytes(), timestamp, nonce);
    Ok(FfiSignedHeaders {
        pubkey_ss58: sig.pubkey_ss58,
        signature_hex: sig.signature_hex,
        timestamp: sig.timestamp,
        nonce_hex: sig.nonce_hex,
    })
}

/// A live Warren SDK client exposed across the FFI boundary.
///
/// Wraps the default reqwest-backed [`DefaultClient`]. Async methods run on the
/// tokio runtime the host app drives (uniffi `async_runtime = "tokio"`). Held by
/// the foreign side as an opaque handle; drop it to release the client.
#[derive(uniffi::Object)]
pub struct WarrenFfiClient {
    inner: DefaultClient,
}

#[uniffi::export(async_runtime = "tokio")]
impl WarrenFfiClient {
    /// Builds a client from a BIP39 mnemonic, the API base URL (no trailing
    /// slash), and the server's 64-hex Ed25519 pin.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidMnemonic`] if the phrase is not valid BIP39. (The pin
    /// is validated lazily on the first signed fetch, not here.)
    #[uniffi::constructor]
    pub fn new(
        mnemonic: String,
        api_base: String,
        server_pubkey_pin: String,
    ) -> Result<Arc<Self>, FfiError> {
        let identity =
            WarrenIdentity::from_mnemonic(&mnemonic).map_err(|_| FfiError::InvalidMnemonic)?;
        let inner = WarrenClient::builder()
            .identity(identity)
            .api_base(api_base)
            .server_pubkey_pin(server_pubkey_pin)
            .build()
            // Unreachable in practice (identity and pin are both set above), but
            // surfaced rather than unwrapped to keep the boundary panic-free.
            .map_err(|e| FfiError::Client {
                message: e.to_string(),
            })?;
        Ok(Arc::new(Self { inner }))
    }

    /// The wallet SS58 `wb…` address of this client.
    #[must_use]
    pub fn address(&self) -> String {
        self.inner.api().address()
    }

    /// Fetches the subscription expiry (unix epoch seconds) for this account.
    ///
    /// # Errors
    ///
    /// [`FfiError::ServerStatus`] on a non-2xx reply (e.g. no subscription),
    /// [`FfiError::Client`] on a transport or other client-side failure.
    pub async fn subscription_expiry(&self) -> Result<u64, FfiError> {
        let sub = self
            .inner
            .api()
            .subscription()
            .await
            .map_err(map_client_error)?;
        Ok(sub.expires_at)
    }

    /// Redeems a voucher secret to create or extend the subscription bound to
    /// this client's wallet pubkey (unsigned `POST /v1/register`; the voucher is
    /// the proof of purchase). Returns the new expiry (unix epoch seconds).
    ///
    /// # Errors
    ///
    /// [`FfiError::ServerStatus`] on a non-2xx reply (e.g. an invalid or spent
    /// voucher), [`FfiError::Client`] on a transport or other client-side
    /// failure.
    pub async fn redeem_voucher(&self, voucher_secret: String) -> Result<u64, FfiError> {
        let req = RegisterAccountRequest {
            pubkey_ss58: self.inner.api().address(),
            voucher_secret,
            referral_code: None,
        };
        let resp = self
            .inner
            .api()
            .register(&req)
            .await
            .map_err(map_client_error)?;
        Ok(resp.expires_at)
    }

    /// Deletes the subscription bound to this client's wallet (signed
    /// `DELETE /v1/account`).
    ///
    /// # Errors
    ///
    /// [`FfiError::ServerStatus`] on a non-2xx reply, [`FfiError::Client`] on a
    /// transport or other client-side failure.
    pub async fn delete_account(&self) -> Result<(), FfiError> {
        self.inner
            .api()
            .delete_account()
            .await
            .map_err(map_client_error)
    }

    /// Submits a redacted log bundle and a free-form message to the operator
    /// (signed `POST /v1/support`). Returns the support reference id.
    ///
    /// # Errors
    ///
    /// [`FfiError::ServerStatus`] on a non-2xx reply (e.g. payload too large),
    /// [`FfiError::Client`] on a transport or other client-side failure.
    pub async fn submit_support(
        &self,
        user_message: String,
        redacted_logs: String,
        app_version: String,
        platform: String,
    ) -> Result<String, FfiError> {
        let req = SupportReportRequest {
            user_message,
            redacted_logs,
            app_version,
            platform,
        };
        let resp = self
            .inner
            .api()
            .submit_support_report(&req)
            .await
            .map_err(map_client_error)?;
        Ok(resp.reference_id)
    }

    /// Whether this client's current egress IP is a Warren exit, i.e. the tunnel
    /// is active (signed `GET /v1/check`).
    ///
    /// # Errors
    ///
    /// [`FfiError::ServerStatus`] on a non-2xx reply, [`FfiError::Client`] on a
    /// transport or other client-side failure.
    pub async fn is_tunnel_active(&self) -> Result<bool, FfiError> {
        let check = self.inner.api().check().await.map_err(map_client_error)?;
        Ok(check.is_exit)
    }

    /// Fetches and verifies the signed multihop directory, returning the trusted
    /// exits (public data, safe to display in a server picker).
    ///
    /// # Errors
    ///
    /// [`FfiError::Client`] if no directory is published, it fails verification,
    /// is expired, rolled back, or the fetch fails; [`FfiError::ServerStatus`]
    /// on a non-2xx API reply.
    pub async fn fetch_multihop_exits(&self) -> Result<Vec<FfiExit>, FfiError> {
        let exits = self
            .inner
            .fetch_multihop_directory()
            .await
            .map_err(map_sdk_error)?;
        Ok(exits
            .into_iter()
            .map(|e| FfiExit {
                exit_id_hex: hex::encode(e.exit_id),
                country: e.country,
                city: e.city,
                endpoint: e.endpoint.to_string(),
                exit_ed25519_pubkey_hex: hex::encode(e.exit_ed25519_pubkey),
            })
            .collect())
    }

    /// Starts the non-root SOCKS5 proxy over a multihop tunnel to the exit with
    /// the given `exit_id_hex` (from [`fetch_multihop_exits`](Self::fetch_multihop_exits)),
    /// binding the listener at `socks5_listen` (e.g. `127.0.0.1:0` for an
    /// ephemeral port). The returned handle's
    /// [`socks5_address`](WarrenFfiProxy::socks5_address) is the bound listener;
    /// drop it or call [`shutdown`](WarrenFfiProxy::shutdown) to tear it down.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidHex`] for a malformed `exit_id_hex`; [`FfiError::Client`]
    /// for a bad listen address, an exit id absent from the verified directory,
    /// or a connect/datapath failure; [`FfiError::ServerStatus`] on a non-2xx
    /// API reply.
    pub async fn start_proxy(
        &self,
        exit_id_hex: String,
        socks5_listen: String,
        observer: Option<Box<dyn ConnectionObserver>>,
    ) -> Result<Arc<WarrenFfiProxy>, FfiError> {
        // Validate both arguments before any network so caller mistakes fail
        // fast and cheaply (and before any state is reported).
        let want = hex16(&exit_id_hex)?;
        let socks5: SocketAddr = socks5_listen.parse().map_err(|_| FfiError::Client {
            message: "invalid socks5 listen address".to_owned(),
        })?;
        let cfg = ProxyConfig {
            socks5,
            http: None,
            dns_server: None,
        };

        // Forward each supervisor transition to the foreign observer (if any),
        // ignoring states this binding does not yet model (non_exhaustive).
        let notify = |state: ConnectionState| {
            let mapped = match state {
                ConnectionState::Connecting => Some(FfiConnectionState::Connecting),
                ConnectionState::Connected => Some(FfiConnectionState::Connected),
                ConnectionState::Reconnecting => Some(FfiConnectionState::Reconnecting),
                ConnectionState::Failed => Some(FfiConnectionState::Failed),
                _ => None,
            };
            if let (Some(obs), Some(m)) = (observer.as_ref(), mapped) {
                obs.on_state(m);
            }
        };

        // One attempt = re-verify the directory, pick the exit, dial. Transient
        // failures retry with full-jitter backoff; each transition is reported.
        let attempt = || async {
            let exit = self
                .inner
                .fetch_multihop_directory()
                .await?
                .into_iter()
                .find(|e| e.exit_id == want)
                .ok_or(SdkError::NoMultihopExit)?;
            self.inner.start_proxy_multihop(&exit, &cfg).await
        };

        let handle = connect_with_state(Backoff::HANDSHAKE, 3, notify, attempt)
            .await
            .map_err(|e| match e {
                RetryError::Exhausted { last, .. } => map_sdk_error(last),
                // NoAttempts and any future variant: a connect was not achieved.
                _ => FfiError::Client {
                    message: "connection was not established".to_owned(),
                },
            })?;
        let socks5_address = handle.local_addr().to_string();
        let http_address = handle.http_addr().map(|a| a.to_string());
        Ok(Arc::new(WarrenFfiProxy {
            socks5_address,
            http_address,
            handle: Mutex::new(Some(handle)),
        }))
    }
}

/// A running non-root SOCKS5 proxy over a multihop tunnel.
///
/// Point a SOCKS5-aware app at [`socks5_address`](Self::socks5_address). Dropping
/// this handle (or calling [`shutdown`](Self::shutdown)) tears down the listeners
/// and the tunnel.
#[derive(uniffi::Object)]
pub struct WarrenFfiProxy {
    socks5_address: String,
    http_address: Option<String>,
    // Taken out and consumed by `shutdown`; otherwise dropped with the object,
    // whose `ProxyHandle::drop` aborts the listener tasks.
    handle: Mutex<Option<ProxyHandle>>,
}

#[uniffi::export]
impl WarrenFfiProxy {
    /// The bound SOCKS5 listener address (`ip:port`), with the real port when the
    /// caller requested `:0`.
    #[must_use]
    pub fn socks5_address(&self) -> String {
        self.socks5_address.clone()
    }

    /// The bound HTTP CONNECT listener address, if one was configured.
    #[must_use]
    pub fn http_address(&self) -> Option<String> {
        self.http_address.clone()
    }

    /// Tears down the proxy and its tunnel. Idempotent: a second call is a no-op.
    pub fn shutdown(&self) {
        // A poisoned lock means a prior holder panicked; the handle is still
        // safe to take and drop, so recover rather than propagate.
        if let Ok(mut guard) = self.handle.lock()
            && let Some(handle) = guard.take()
        {
            handle.shutdown();
        }
    }
}

/// Maps a [`ClientError`] to the FFI error, keeping the no-log discipline: the
/// server-status body is dropped and only redaction-safe `Display` text crosses.
fn map_client_error(e: ClientError) -> FfiError {
    match e {
        ClientError::ServerStatus { status, .. } => FfiError::ServerStatus { status },
        other => FfiError::Client {
            message: other.to_string(),
        },
    }
}

/// Maps an [`SdkError`] to the FFI error. The nested API case reuses
/// [`map_client_error`] (so a server status stays structured); every other
/// variant has a no-log-safe `Display` (transparent verification errors or fixed
/// strings, no pubkey/address/IP).
fn map_sdk_error(e: SdkError) -> FfiError {
    match e {
        SdkError::Api(inner) => map_client_error(inner),
        other => FfiError::Client {
            message: other.to_string(),
        },
    }
}

fn to_ffi(identity: &WarrenIdentity, mnemonic: String) -> FfiIdentity {
    FfiIdentity {
        mnemonic,
        address: identity.address(),
        public_key_hex: hex::encode(identity.public_key()),
    }
}

fn hex32(s: &str) -> Result<[u8; 32], FfiError> {
    hex::decode(s)
        .map_err(|e| FfiError::InvalidHex(e.to_string()))?
        .try_into()
        .map_err(|_| FfiError::InvalidHex("expected 32 bytes".to_owned()))
}

fn hex16(s: &str) -> Result<[u8; 16], FfiError> {
    hex::decode(s)
        .map_err(|e| FfiError::InvalidHex(e.to_string()))?
        .try_into()
        .map_err(|_| FfiError::InvalidHex("expected 16 bytes".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_ENTROPY_24W: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn address_from_mnemonic_matches_frozen_vector() {
        let addr = address_from_mnemonic(ZERO_ENTROPY_24W.to_owned()).expect("valid");
        assert_eq!(addr, "wbDSf2fncAfyDQkNbkyqjuhi8kpg3z8kCHqL2TYDSM2F1nVED");
    }

    #[test]
    fn identity_roundtrips_through_ffi() {
        let id = generate_identity();
        let restored = identity_from_mnemonic(id.mnemonic.clone()).expect("valid");
        assert_eq!(id, restored);
        assert!(id.address.starts_with("wb"));
    }

    #[test]
    fn ss58_encode_decode_roundtrip() {
        let id = generate_identity();
        let decoded = ss58_decode(id.address.clone()).expect("decode");
        assert_eq!(decoded, id.public_key_hex);
        let encoded = ss58_encode(id.public_key_hex.clone()).expect("encode");
        assert_eq!(encoded, id.address);
    }

    #[test]
    fn sign_request_emits_four_header_values() {
        let id = generate_identity();
        let headers = sign_request(
            id.mnemonic,
            "GET".to_owned(),
            "/v1/subscription".to_owned(),
            String::new(),
            1_700_000_000,
            "00112233445566778899aabbccddeeff".to_owned(),
        )
        .expect("sign");
        assert_eq!(headers.pubkey_ss58, id.address);
        assert_eq!(headers.signature_hex.len(), 128);
        assert_eq!(headers.nonce_hex.len(), 32);
    }

    #[test]
    fn ffi_identity_debug_redacts_the_mnemonic() {
        let id = generate_identity();
        let rendered = format!("{id:?}");
        assert!(
            !rendered.contains(&id.mnemonic),
            "the seed mnemonic must never appear in Debug output"
        );
        assert!(rendered.contains("<redacted>"));
        // The public address stays visible for debugging.
        assert!(rendered.contains(&id.address));
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        assert!(matches!(
            address_from_mnemonic("not a mnemonic".to_owned()),
            Err(FfiError::InvalidMnemonic)
        ));
    }

    #[test]
    fn client_new_rejects_bad_mnemonic() {
        let r = WarrenFfiClient::new(
            "not a mnemonic".to_owned(),
            "https://api.example.test".to_owned(),
            "ab".repeat(32),
        );
        assert!(matches!(r, Err(FfiError::InvalidMnemonic)));
    }

    #[test]
    fn client_new_accepts_valid_inputs_and_exposes_address() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic.clone(),
            "https://api.example.test".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        assert_eq!(client.address(), id.address);
    }

    #[tokio::test]
    async fn subscription_expiry_surfaces_a_client_error_on_unroutable_host() {
        // Port 1 on loopback refuses fast, so this exercises the full async FFI
        // bridge and ClientError -> FfiError mapping without a live server.
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client.subscription_expiry().await;
        assert!(
            matches!(
                r,
                Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
            ),
            "an unroutable host must surface as a client/server error, not panic"
        );
    }

    #[tokio::test]
    async fn delete_account_surfaces_a_client_error_on_unroutable_host() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client.delete_account().await;
        assert!(matches!(
            r,
            Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
        ));
    }

    #[tokio::test]
    async fn submit_support_surfaces_a_client_error_on_unroutable_host() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client
            .submit_support(
                "stuck".to_owned(),
                String::new(),
                "1.0".to_owned(),
                "macos-arm64".to_owned(),
            )
            .await;
        assert!(matches!(
            r,
            Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
        ));
    }

    #[tokio::test]
    async fn redeem_voucher_surfaces_a_client_error_on_unroutable_host() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client.redeem_voucher("voucher-secret".to_owned()).await;
        assert!(matches!(
            r,
            Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
        ));
    }

    #[tokio::test]
    async fn is_tunnel_active_surfaces_a_client_error_on_unroutable_host() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client.is_tunnel_active().await;
        assert!(matches!(
            r,
            Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
        ));
    }

    #[tokio::test]
    async fn fetch_multihop_exits_surfaces_a_client_error_on_unroutable_host() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client.fetch_multihop_exits().await;
        assert!(matches!(
            r,
            Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
        ));
    }

    #[tokio::test]
    async fn start_proxy_rejects_bad_exit_id_hex_before_any_network() {
        let id = generate_identity();
        // api_base is bogus but never contacted: hex parsing fails first.
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://api.example.test".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client
            .start_proxy("not-hex".to_owned(), "127.0.0.1:0".to_owned(), None)
            .await;
        assert!(matches!(r, Err(FfiError::InvalidHex(_))));
    }

    #[tokio::test]
    async fn start_proxy_rejects_bad_listen_address_before_any_network() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://api.example.test".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client
            .start_proxy(
                "ab".repeat(16),
                "definitely not an address".to_owned(),
                None,
            )
            .await;
        assert!(matches!(r, Err(FfiError::Client { .. })));
    }

    #[tokio::test]
    async fn start_proxy_surfaces_a_client_error_on_unroutable_host() {
        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client
            .start_proxy("ab".repeat(16), "127.0.0.1:0".to_owned(), None)
            .await;
        assert!(matches!(
            r,
            Err(FfiError::Client { .. }) | Err(FfiError::ServerStatus { .. })
        ));
    }

    #[tokio::test]
    async fn start_proxy_reports_states_to_the_observer_and_ends_in_failed() {
        // A callback interface is a plain trait, so it is fully testable in Rust.
        struct Recorder {
            log: Arc<Mutex<Vec<FfiConnectionState>>>,
        }
        impl ConnectionObserver for Recorder {
            fn on_state(&self, state: FfiConnectionState) {
                self.log.lock().unwrap().push(state);
            }
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let observer = Recorder {
            log: Arc::clone(&log),
        };

        let id = generate_identity();
        let client = WarrenFfiClient::new(
            id.mnemonic,
            "https://127.0.0.1:1".to_owned(),
            "ab".repeat(32),
        )
        .expect("valid build");
        let r = client
            .start_proxy(
                "ab".repeat(16),
                "127.0.0.1:0".to_owned(),
                Some(Box::new(observer)),
            )
            .await;
        assert!(r.is_err(), "an unroutable host must fail");
        let states = log.lock().unwrap();
        assert_eq!(
            states.first(),
            Some(&FfiConnectionState::Connecting),
            "the first reported state is Connecting"
        );
        assert_eq!(
            states.last(),
            Some(&FfiConnectionState::Failed),
            "exhausted retries end in Failed"
        );
        assert!(
            states.contains(&FfiConnectionState::Reconnecting),
            "retries report Reconnecting"
        );
    }

    #[test]
    fn bad_nonce_hex_is_rejected() {
        let id = generate_identity();
        assert!(matches!(
            sign_request(
                id.mnemonic,
                "GET".to_owned(),
                "/x".to_owned(),
                String::new(),
                1,
                "tooshort".to_owned(),
            ),
            Err(FfiError::InvalidHex(_))
        ));
    }
}
