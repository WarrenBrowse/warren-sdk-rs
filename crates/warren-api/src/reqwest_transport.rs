//! Bundled reqwest-backed [`HttpTransport`] (feature `reqwest-transport`).
//!
//! A batteries-included transport for native Rust apps. The connect and total
//! timeouts mirror warren-core (5s connect, 15s total).

use std::time::Duration;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};

/// A reqwest-backed transport.
///
/// Holds two clients: one that sends the TLS SNI extension and one that omits it. The fallback sequence in [`WarrenApiClient`] uses the
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
        Self::with_roots(&rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
    }

    fn with_roots(roots: &rustls::RootCertStore) -> Result<Self, TransportError> {
        let build = |sni: bool| -> Result<reqwest::Client, TransportError> {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .use_preconfigured_tls(client_config(roots.clone(), sni)?)
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

/// The rustls config of both clients. reqwest's own keeps session tickets and
/// resumes with them, which lets a server link a client's connections across
/// time and across the addresses it came from; the marked transport and the
/// engine already refuse resumption. A preconfigured config replaces every TLS
/// option of the builder, so SNI is set here, and the ALPN list is the one
/// reqwest offers with its HTTP/2 feature on.
fn client_config(
    roots: rustls::RootCertStore,
    sni: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| TransportError::Io("tls client config initialization failed".to_owned()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_sni = sni;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
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
        let date = resp
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = resp
            .bytes()
            .await
            .map_err(|e| to_transport_error(&e))?
            .to_vec();
        let response = HttpResponse::new(status, body);
        Ok(match date {
            Some(date) => response.with_date(date),
            None => response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use rustls::{HandshakeKind, ServerConfig};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CA: &[u8] = include_bytes!("testdata/tls-test-ca.cert.pem");
    const CERT: &[u8] = include_bytes!("testdata/tls-localhost.cert.pem");
    const KEY: &[u8] = include_bytes!("testdata/tls-localhost.key.pem");

    /// What the server saw of one TLS handshake.
    struct Seen {
        sni: Option<String>,
        kind: Option<HandshakeKind>,
    }

    /// A TLS server that issues session tickets and would resume on them, so a
    /// client that resumes shows up as a resumed handshake.
    async fn server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<Seen>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(CERT).unwrap()],
                PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            )
            .unwrap();
        config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let (_, connection) = tls.get_ref();
                let _ = tx.send(Seen {
                    sni: connection.server_name().map(str::to_owned),
                    kind: connection.handshake_kind(),
                });
                let mut request = [0u8; 1024];
                let _ = tls.read(&mut request).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nDate: Tue, 14 Nov 2023 22:13:20 GMT\r\n\
                          Content-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = tls.shutdown().await;
            }
        });
        (port, rx)
    }

    async fn two_requests(use_sni: bool) -> Vec<Seen> {
        let (port, mut seen) = server().await;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(CA).unwrap())
            .unwrap();
        let transport = ReqwestTransport::with_roots(&roots).unwrap();

        let mut handshakes = Vec::new();
        for _ in 0..2 {
            let request = HttpRequest {
                method: Method::Get,
                url: format!("https://localhost:{port}/"),
                headers: Vec::new(),
                body: Vec::new(),
                use_sni,
            };
            let response = transport.execute(request).await.unwrap();
            assert_eq!(response.status, 200);
            handshakes.push(seen.recv().await.unwrap());
        }
        handshakes
    }

    /// The client reads the server's clock off this header; a transport that
    /// dropped it would leave a drifted device refused on every signed call.
    #[tokio::test]
    async fn the_answers_date_header_reaches_the_client() {
        let (port, _seen) = server().await;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(CA).unwrap())
            .unwrap();
        let transport = ReqwestTransport::with_roots(&roots).unwrap();

        let response = transport
            .execute(HttpRequest {
                method: Method::Get,
                url: format!("https://localhost:{port}/"),
                headers: Vec::new(),
                body: Vec::new(),
                use_sni: true,
            })
            .await
            .unwrap();

        assert_eq!(
            response.date.as_deref(),
            Some("Tue, 14 Nov 2023 22:13:20 GMT")
        );
    }

    #[tokio::test]
    async fn a_second_connection_does_not_resume_the_first_session() {
        let handshakes = two_requests(true).await;

        assert_eq!(handshakes[1].kind, Some(HandshakeKind::Full));
    }

    #[tokio::test]
    async fn the_no_sni_client_sends_no_sni() {
        let handshakes = two_requests(false).await;

        assert!(handshakes.iter().all(|seen| seen.sni.is_none()));
    }

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
