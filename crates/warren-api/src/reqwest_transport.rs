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
    /// Builds a transport with the default Warren timeouts, returning an error
    /// instead of panicking if the underlying TLS/HTTP stack fails to initialize.
    ///
    /// Prefer this over [`new`](Self::new) on the FFI path: a panic would unwind
    /// across the boundary, while this surfaces a recoverable error.
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] if the HTTP client cannot be built (a broken TLS
    /// backend; never happens with a working ring/rustls build). The reqwest
    /// cause is not propagated (no-log discipline).
    pub fn try_new() -> Result<Self, TransportError> {
        let build = |sni: bool| -> Result<reqwest::Client, TransportError> {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .tls_sni(sni)
                .build()
                .map_err(|_| TransportError::Io("tls/http client initialization failed".to_owned()))
        };
        Ok(Self {
            client: build(true)?,
            client_no_sni: build(false)?,
        })
    }

    /// Builds a transport with the default Warren timeouts.
    ///
    /// # Panics
    ///
    /// Panics if the underlying TLS stack fails to initialize, which indicates
    /// a broken build environment rather than a runtime condition. Use
    /// [`try_new`](Self::try_new) to handle that case without unwinding.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("reqwest client builds with a working TLS backend")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_builds_a_transport_in_a_working_environment() {
        // The fallible constructor must succeed with a normal ring/rustls build;
        // `new()` is just this with an expect, so this also covers the happy path
        // of the panic-free FFI construction route.
        assert!(ReqwestTransport::try_new().is_ok());
    }

    #[test]
    fn methods_map_to_their_reqwest_equivalents() {
        assert_eq!(to_reqwest_method(Method::Get), reqwest::Method::GET);
        assert_eq!(to_reqwest_method(Method::Post), reqwest::Method::POST);
        assert_eq!(to_reqwest_method(Method::Delete), reqwest::Method::DELETE);
    }

    #[tokio::test]
    async fn execute_classifies_a_refused_connection_as_a_connect_error() {
        // Port 1 on loopback refuses immediately, so this drives the real send
        // path and the `is_connect` classification that triggers host fallback.
        // The error must NOT leak the address (no-log discipline).
        let transport = ReqwestTransport::new();
        let request = HttpRequest {
            method: Method::Get,
            url: "http://127.0.0.1:1/".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
            use_sni: true,
        };
        let err = transport.execute(request).await.unwrap_err();
        match err {
            TransportError::Connect(msg) => {
                assert!(!msg.contains("127.0.0.1"), "must not leak the address");
            }
            other => panic!("expected a Connect error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_uses_the_no_sni_client_when_sni_is_disabled() {
        // The SNI-less fallback client must also be wired into execute; a refused
        // connection through it still classifies as a connect error.
        let transport = ReqwestTransport::new();
        let request = HttpRequest {
            method: Method::Post,
            url: "http://127.0.0.1:1/".to_owned(),
            headers: vec![("x-test".to_owned(), "1".to_owned())],
            body: b"body".to_vec(),
            use_sni: false,
        };
        let err = transport.execute(request).await.unwrap_err();
        assert!(matches!(err, TransportError::Connect(_)), "got {err:?}");
    }
}
