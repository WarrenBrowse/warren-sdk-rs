//! Bundled reqwest-backed [`HttpTransport`] (feature `reqwest-transport`).
//!
//! A batteries-included transport for native Rust apps. The connect and total
//! timeouts mirror warren-core (5s connect, 15s total).

use std::time::Duration;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};

/// A reqwest-backed transport.
///
/// Holds two clients: one that sends the TLS SNI extension and one that omits it
/// (`tls_sni(false)`). The fallback sequence in [`WarrenApiClient`] uses the
/// SNI-less client for its final attempt to defeat SNI-based blocking. The
/// no-SNI client still verifies the server certificate against the requested
/// host name (standard verification), so it is no weaker than the default path.
///
/// [`WarrenApiClient`]: crate::WarrenApiClient
pub struct ReqwestTransport {
    client: reqwest::Client,
    client_no_sni: reqwest::Client,
}

impl ReqwestTransport {
    /// Builds a transport with the default Warren timeouts.
    ///
    /// # Panics
    ///
    /// Panics if the underlying TLS stack fails to initialize, which indicates
    /// a broken build environment rather than a runtime condition.
    #[must_use]
    pub fn new() -> Self {
        let build = |sni: bool| {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .tls_sni(sni)
                .build()
                .expect("reqwest client builds with a working TLS backend")
        };
        Self {
            client: build(true),
            client_no_sni: build(false),
        }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

fn to_reqwest_method(method: Method) -> reqwest::Method {
    match method {
        Method::Get => reqwest::Method::GET,
        Method::Post => reqwest::Method::POST,
        Method::Delete => reqwest::Method::DELETE,
    }
}

/// Classifies a reqwest error: connect-establishment failures drive the host
/// fallback; everything else is a non-retryable transport error.
///
/// The reqwest `Display` carries the URL/host/IP, so it is deliberately NOT
/// propagated: the error is mapped to a generic, address-free reason (no-log
/// discipline).
fn to_transport_error(e: &reqwest::Error) -> TransportError {
    if e.is_connect() {
        TransportError::Connect("connection failed".to_owned())
    } else if e.is_timeout() {
        TransportError::Io("request timed out".to_owned())
    } else {
        TransportError::Io("request failed".to_owned())
    }
}

impl HttpTransport for ReqwestTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let client = if request.use_sni {
            &self.client
        } else {
            &self.client_no_sni
        };
        let mut builder = client.request(to_reqwest_method(request.method), &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body);
        }
        let resp = builder.send().await.map_err(|e| to_transport_error(&e))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| to_transport_error(&e))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}
