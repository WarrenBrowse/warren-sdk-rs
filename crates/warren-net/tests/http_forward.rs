//! Plain-HTTP forwarding on the authenticated HTTP listener: an absolute-form
//! request reaches its origin through the connector, rewritten to origin form,
//! and nothing that authenticates the client to the proxy leaves the machine.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use warren_net::socks5::Target;
use warren_net::{Connector, DirectConnector, HttpConnectProxy, NetError, ProxyCredentials};

/// Dials directly and counts every dial.
#[derive(Clone, Default)]
struct CountingConnector(Arc<AtomicUsize>);

impl CountingConnector {
    fn dials(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Connector for CountingConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: Target) -> Result<TcpStream, NetError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        DirectConnector.connect(target).await
    }
}

/// An origin server that records every byte it receives, on every connection.
struct Origin {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    connections: Arc<AtomicUsize>,
}

impl Origin {
    fn received(&self) -> String {
        String::from_utf8_lossy(&self.received.lock().unwrap()).into_owned()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// Answers `response` once `complete` says the request has fully arrived, then
/// closes its sending side and keeps recording whatever else arrives until the
/// proxy hangs up, so bytes forwarded past the request are caught too.
async fn spawn_origin(complete: fn(&[u8]) -> bool, response: &'static [u8]) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let (log, count) = (Arc::clone(&received), Arc::clone(&connections));
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut answered = false;
                let mut buf = [0u8; 4096];
                loop {
                    let read = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf));
                    let n = match read.await {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => return,
                    };
                    log.lock().unwrap().extend_from_slice(&buf[..n]);
                    seen.extend_from_slice(&buf[..n]);
                    if !answered && complete(&seen) {
                        answered = true;
                        let _ = sock.write_all(response).await;
                        let _ = sock.shutdown().await;
                    }
                }
            });
        }
    });
    Origin {
        addr,
        received,
        connections,
    }
}

fn head_complete(seen: &[u8]) -> bool {
    seen.windows(4).any(|w| w == b"\r\n\r\n")
}

const OK_HELLO: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";

fn creds() -> ProxyCredentials {
    ProxyCredentials::new("warren", "forward-test-secret").unwrap()
}

async fn spawn_proxy(credentials: ProxyCredentials) -> (SocketAddr, CountingConnector) {
    let dials = CountingConnector::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = HttpConnectProxy::new(dials.clone(), credentials);
    tokio::spawn(async move { proxy.serve(listener).await });
    (addr, dials)
}

fn auth_line(credentials: &ProxyCredentials) -> String {
    format!(
        "Proxy-Authorization: {}\r\n",
        &*credentials.basic_authorization()
    )
}

/// Sends `request` in one write and returns everything the proxy answers
/// before it closes (bounded, so a proxy that never closes fails the test).
async fn exchange(proxy: SocketAddr, request: &[u8]) -> String {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request).await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut got)).await;
    String::from_utf8_lossy(&got).into_owned()
}

fn header_names(head: &str) -> Vec<String> {
    head.split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.trim().to_ascii_lowercase())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authenticated_absolute_form_request_reaches_its_origin_in_origin_form() {
    let origin = spawn_origin(head_complete, OK_HELLO).await;
    let credentials = creds();
    let (proxy, dials) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{port}/path/page?q=1 HTTP/1.1\r\nHost: stale.example\r\n{}Accept: text/html\r\n\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.ends_with("\r\n\r\nhello"), "{answer}");
    let received = origin.received();
    assert!(
        received.starts_with("GET /path/page?q=1 HTTP/1.1\r\n"),
        "origin form on the wire: {received}"
    );
    assert!(
        received.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\n")),
        "Host names the target, whatever the client sent: {received}"
    );
    assert!(!received.contains("stale.example"), "{received}");
    assert!(received.contains("\r\nAccept: text/html\r\n"), "{received}");
    assert_eq!(dials.dials(), 1, "carried through the connector");
}

#[tokio::test(flavor = "multi_thread")]
async fn hop_by_hop_fields_are_dropped_both_ways() {
    let origin = spawn_origin(
        head_complete,
        b"HTTP/1.1 200 OK\r\nConnection: keep-alive, X-Origin-Hop\r\nKeep-Alive: timeout=5\r\nX-Origin-Hop: 1\r\nUpgrade: h2c\r\nX-End: 1\r\nContent-Length: 2\r\n\r\nok",
    )
    .await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Proxy-Connection: keep-alive\r\nConnection: keep-alive, X-Client-Hop\r\nKeep-Alive: 300\r\nX-Client-Hop: 1\r\nTE: trailers\r\nUpgrade: websocket\r\nX-Kept: 1\r\n\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    let sent = header_names(&origin.received());
    assert_eq!(
        sent,
        ["host", "x-kept", "connection"],
        "only end-to-end fields travel, plus our own Connection: close"
    );
    assert!(origin.received().contains("\r\nConnection: close\r\n"));
    let answered = header_names(&answer);
    assert_eq!(
        answered,
        ["x-end", "content-length", "connection"],
        "{answer}"
    );
    assert!(answer.contains("\r\nConnection: close\r\n"), "{answer}");
    assert!(answer.ends_with("\r\n\r\nok"), "{answer}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_credentials_never_reach_the_origin() {
    let origin = spawn_origin(head_complete, OK_HELLO).await;
    let credentials = creds();
    let (proxy, dials) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();
    let one = format!(
        "GET http://127.0.0.1:{port}/one HTTP/1.1\r\n{}\r\n",
        auth_line(&credentials)
    );
    let two = format!(
        "GET http://127.0.0.1:{port}/two HTTP/1.1\r\n{}\r\n",
        auth_line(&credentials)
    );

    // A client pipelining a second request behind the first, in one write.
    let answer = exchange(proxy, format!("{one}{two}").as_bytes()).await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    let received = origin.received();
    assert!(
        !received.contains(credentials.password()),
        "the password left the machine: {received}"
    );
    assert!(
        !received.contains(&*credentials.basic_authorization()),
        "the Basic value left the machine: {received}"
    );
    assert!(
        !received
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "{received}"
    );
    assert!(
        !received.contains("/two"),
        "nothing past the authenticated request is forwarded: {received}"
    );
    assert_eq!(dials.dials(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_absolute_form_request_is_refused_and_forwards_nothing() {
    let origin = spawn_origin(head_complete, OK_HELLO).await;
    let (proxy, dials) = spawn_proxy(creds()).await;
    let wrong = ProxyCredentials::generate();
    let port = origin.addr.port();

    let missing = exchange(
        proxy,
        format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    let refused = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{}\r\n",
            auth_line(&wrong)
        )
        .as_bytes(),
    )
    .await;

    assert!(missing.starts_with("HTTP/1.1 407 "), "{missing}");
    assert!(missing.contains("Proxy-Authenticate: Basic"), "{missing}");
    assert_eq!(refused, missing, "the same refusal as CONNECT gets");
    assert_eq!(dials.dials(), 0, "nothing dialed");
    assert_eq!(origin.connections(), 0, "the origin saw nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_a_lenient_origin_could_read_differently_is_refused() {
    let credentials = creds();
    let (proxy, dials) = spawn_proxy(credentials.clone()).await;
    let smuggled = format!(
        "GET http://127.0.0.1:9/ HTTP/1.1\r\n{}X-Note: a\nProxy-Authorization: {}\r\n\r\n",
        auth_line(&credentials),
        &*credentials.basic_authorization()
    );
    let folded = format!(
        "GET http://127.0.0.1:9/ HTTP/1.1\r\n{}X-Note: a\r\n  folded\r\n\r\n",
        auth_line(&credentials)
    );

    for request in [smuggled, folded] {
        let answer = exchange(proxy, request.as_bytes()).await;
        assert!(answer.starts_with("HTTP/1.1 400 "), "{answer}");
    }
    assert_eq!(dials.dials(), 0, "a refused head dials nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_body_is_relayed_by_its_length_and_nothing_after_it() {
    let origin = spawn_origin(|seen| seen.ends_with(b"hello"), OK_HELLO).await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "POST http://127.0.0.1:{port}/submit HTTP/1.1\r\n{}Content-Length: 5\r\n\r\nhelloGET http://127.0.0.1:{port}/extra HTTP/1.1\r\n\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    let received = origin.received();
    assert!(
        received.starts_with("POST /submit HTTP/1.1\r\n"),
        "{received}"
    );
    assert!(received.contains("\r\nContent-Length: 5\r\n"), "{received}");
    assert!(received.ends_with("\r\n\r\nhello"), "{received}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunked_request_body_is_relayed_to_its_last_chunk() {
    let origin = spawn_origin(|seen| seen.ends_with(b"0\r\n\r\n"), OK_HELLO).await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "POST http://127.0.0.1:{port}/up HTTP/1.1\r\n{}Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\ntrailing-garbage",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    let received = origin.received();
    assert!(
        received.ends_with("\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"),
        "the chunks travel as sent, the trailer fields and what follows do not: {received}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_origin_cannot_pose_as_the_proxy_asking_for_credentials() {
    let origin = spawn_origin(
        head_complete,
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(
        answer.starts_with("HTTP/1.1 502 "),
        "a 407 on this connection must only ever come from this proxy: {answer}"
    );
    assert!(
        !answer.to_ascii_lowercase().contains("proxy-authenticate"),
        "{answer}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_interim_response_is_relayed_and_the_final_one_still_rewritten() {
    let origin = spawn_origin(
        head_complete,
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nKeep-Alive: timeout=5\r\nContent-Length: 2\r\n\r\nok",
    )
    .await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(
        answer.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"),
        "{answer}"
    );
    assert!(!answer.contains("Keep-Alive"), "{answer}");
    assert!(answer.ends_with("Connection: close\r\n\r\nok"), "{answer}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_origin_is_answered_by_this_proxy_with_its_cause() {
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);

    let answer = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
    assert!(answer.contains("Warren-Tunnel: "), "{answer}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_origin_that_closes_without_answering_gets_a_bad_gateway() {
    let origin = spawn_origin(head_complete, b"").await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
}
