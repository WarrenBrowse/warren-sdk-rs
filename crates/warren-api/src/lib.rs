//! Signed Warren account API client.
//!
//! [`WarrenApiClient`] builds and signs requests to the Warren API (`/v1/*`),
//! attaching the four `X-Warren-*` headers from
//! [`warren_identity::WarrenIdentity`]. The path (including any query) is part
//! of the signed canonical message, matching warren-core byte-for-byte.
//!
//! The client is generic over an [`HttpTransport`] so the request logic is
//! testable without a network. A batteries-included reqwest transport ships
//! behind the `reqwest-transport` feature.

pub mod client;
pub mod dto;
pub mod tokens;
pub mod transport;

#[cfg(feature = "reqwest-transport")]
pub mod reqwest_transport;

#[cfg(feature = "marked-transport")]
pub mod marked_transport;

pub use client::{ClientError, WarrenApiClient};
pub use dto::{
    CheckApplePaymentRequest, CheckResponse, IncidentExitDownRequest,
    IncidentPubkeyMismatchRequest, IncidentReason, InitApplePaymentResponse, MobilePaymentResponse,
    PubkeyHex, PubkeySs58, RegisterAccountRequest, RegisterAccountResponse, SessionCloseRequest,
    SessionOpenRequest, SessionOpenResponse, SessionRejectReason, SubscriptionResponse,
    TokenEpochRequest, TokenEpochResponse, TokenIssueRequest, TokenIssueResponse,
    TokenIssuerDirectory, TokenIssuerKey,
};
pub use tokens::{
    CredentialClass, MintedEpoch, PersistedTokens, PortEntitlementManager, TokenClientError,
    TokenManager, TokenStore, current_epoch, mint_tokens, mint_tokens_for,
};
pub use transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};

#[cfg(feature = "reqwest-transport")]
pub use reqwest_transport::ReqwestTransport;

#[cfg(feature = "marked-transport")]
pub use marked_transport::MarkedTransport;
