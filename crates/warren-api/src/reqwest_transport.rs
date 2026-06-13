//! Bundled reqwest-backed [`HttpTransport`] (feature `reqwest-transport`).
//!
//! A batteries-included transport for native Rust apps. The connect and total
//! timeouts mirror warren-core (5s connect, 15s total).

use std::time::Duration;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};

/// A reqwest-backed transport.
pub struct ReqwestTransport {
    client: reqwest::Client,
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
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client builds with a working TLS backend");
        Self { client }
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

impl HttpTransport for ReqwestTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut builder = self
            .client
            .request(to_reqwest_method(request.method), &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}
