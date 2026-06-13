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
    /// The request could not be completed at the network layer.
    #[error("transport error: {0}")]
    Io(String),
}

/// An async HTTP transport. Implemented by the bundled reqwest backend (feature
/// `reqwest-transport`) and by test mocks.
pub trait HttpTransport: Send + Sync {
    /// Executes `request` and returns the response, or a [`TransportError`] if
    /// the round trip failed at the network layer.
    fn execute(
        &self,
        request: HttpRequest,
    ) -> impl std::future::Future<Output = Result<HttpResponse, TransportError>> + Send;
}
