//! Transport abstraction: the seam between the signed request builder and an
//! actual HTTP stack. Keeping it a trait lets the request logic be unit-tested
//! without a network and lets the FFI/sibling SDKs plug their platform stack.

/// HTTP method used by the Warren API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `DELETE`.
    Delete,
}

impl Method {
    /// The uppercase wire name, used in the canonical signing message.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Delete => "DELETE",
        }
    }
}

/// A fully-built HTTP request ready to send.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request method.
    pub method: Method,
    /// Absolute URL (api base joined with the path, including any query).
    pub url: String,
    /// Header name/value pairs (already includes the `X-Warren-*` auth headers
    /// for signed requests).
    pub headers: Vec<(String, String)>,
    /// Request body (empty for bodyless requests).
    pub body: Vec<u8>,
    /// Whether to send the TLS SNI extension. The anti-censorship fallback
    /// retries the primary host with this set to `false` so a transport that
    /// supports it can defeat SNI-based blocking. Transports that cannot toggle
    /// SNI may ignore it.
    pub use_sni: bool,
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Error raised by a transport while executing a request (connect failure,
/// timeout, TLS error). Distinct from an HTTP error status, which is a
/// successful round trip with a non-2xx code.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The connection could not be established (DNS, TCP or TLS handshake). This
    /// is the retryable case that drives the anti-censorship host fallback.
    #[error("transport connect error: {0}")]
    Connect(String),
    /// The request failed after connecting (mid-response, timeout, decode). Not
    /// retried on another host.
    #[error("transport error: {0}")]
    Io(String),
}

impl TransportError {
    /// Whether this failure is a connect-establishment error, the only case the
    /// host fallback retries on another host or without SNI.
    #[must_use]
    pub fn is_connect(&self) -> bool {
        matches!(self, TransportError::Connect(_))
    }
}

/// An async HTTP transport. Implemented by the bundled reqwest backend (feature
/// `reqwest-transport`) and by test mocks.
pub trait HttpTransport: Send + Sync {
    /// Executes `request` and returns the response.
    ///
    /// # Errors
    ///
    /// [`TransportError::Connect`] if the connection could not be established
    /// (the retryable case for host fallback), or [`TransportError::Io`] if the
    /// round trip failed after connecting. A non-2xx HTTP status is a successful
    /// round trip, not an error here.
    fn execute(
        &self,
        request: HttpRequest,
    ) -> impl std::future::Future<Output = Result<HttpResponse, TransportError>> + Send;
}
