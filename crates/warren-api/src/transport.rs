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
///
/// Built with [`HttpResponse::new`] outside this crate, so a field added
/// later does not break every transport.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// The `Date` header of the answer, verbatim, when it carried one. The
    /// client reads the server's clock off it (`crate::clock`), so a
    /// transport that drops it leaves a device with a drifted clock refused
    /// on every signed call.
    pub date: Option<String>,
}

impl HttpResponse {
    /// A response with no `Date` header.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            date: None,
        }
    }

    /// The same response carrying the answer's `Date` header.
    #[must_use]
    pub fn with_date(mut self, date: impl Into<String>) -> Self {
        self.date = Some(date.into());
        self
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_as_str_is_the_uppercase_wire_name() {
        // A wrong mapping here silently breaks every request signature.
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Post.as_str(), "POST");
        assert_eq!(Method::Delete.as_str(), "DELETE");
    }

    #[test]
    fn a_response_carries_the_date_it_was_given_and_none_otherwise() {
        let plain = HttpResponse::new(204, b"x".to_vec());
        assert_eq!(
            (plain.status, plain.body.as_slice()),
            (204, b"x".as_slice())
        );
        assert_eq!(plain.date, None);
        let dated = plain.with_date("Tue, 14 Nov 2023 22:13:20 GMT");
        assert_eq!(dated.date.as_deref(), Some("Tue, 14 Nov 2023 22:13:20 GMT"));
    }

    #[test]
    fn is_connect_distinguishes_the_retryable_case() {
        assert!(TransportError::Connect("x".to_owned()).is_connect());
        assert!(!TransportError::Io("x".to_owned()).is_connect());
    }
}
