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
pub mod transport;

#[cfg(feature = "reqwest-transport")]
pub mod reqwest_transport;

pub use client::{ClientError, WarrenApiClient};
pub use dto::{
    CheckApplePaymentRequest, CheckResponse, IncidentExitDownRequest,
    IncidentPubkeyMismatchRequest, IncidentReason, InitApplePaymentResponse, MobilePaymentResponse,
    PubkeyHex, PubkeySs58, RegisterAccountRequest, RegisterAccountResponse, SessionCloseRequest,
    SessionOpenRequest, SessionOpenResponse, SubscriptionResponse, SupportReportRequest,
    SupportReportResponse,
};
pub use transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};

#[cfg(feature = "reqwest-transport")]
pub use reqwest_transport::ReqwestTransport;
