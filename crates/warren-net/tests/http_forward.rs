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
    ended: Arc<AtomicUsize>,
}

impl Origin {
    fn received(&self) -> String {
        String::from_utf8_lossy(&self.received.lock().unwrap()).into_owned()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Waits until the proxy has opened a connection and hung up on every one
    /// it opened, so a check that something never arrived is not a check made
    /// too early.
    async fn settled(&self) {
        let all_ended = async {
            while self.connections() == 0 || self.ended.load(Ordering::SeqCst) < self.connections()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), all_ended)
            .await
            .expect("the proxy never hung up on the origin");
    }
}

/// What the origin does with its connection once it has answered.
#[derive(Clone, Copy)]
enum AfterAnswer {
    Close,
    /// Ignores the request's `Connection: close` and waits for the proxy.
    StayOpen,
}

/// Answers `response` once `complete` says the request has fully arrived,
/// keeps recording whatever else arrives until the proxy hangs up, so bytes
/// forwarded past the request are caught too.
async fn spawn_origin_then(
    complete: fn(&[u8]) -> bool,
    response: &'static [u8],
    after: AfterAnswer,
) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicUsize::new(0));
    let (log, count, done) = (
        Arc::clone(&received),
        Arc::clone(&connections),
        Arc::clone(&ended),
    );
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let (log, done) = (Arc::clone(&log), Arc::clone(&done));
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut answered = false;
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    log.lock().unwrap().extend_from_slice(&buf[..n]);
                    seen.extend_from_slice(&buf[..n]);
                    if !answered && complete(&seen) {
                        answered = true;
                        let _ = sock.write_all(response).await;
                        if matches!(after, AfterAnswer::Close) {
                            let _ = sock.shutdown().await;
                        }
                    }
                }
                done.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Origin {
        addr,
        received,
        connections,
        ended,
    }
}

async fn spawn_origin(complete: fn(&[u8]) -> bool, response: &'static [u8]) -> Origin {
    spawn_origin_then(complete, response, AfterAnswer::Close).await
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

/// Everything the proxy answers until it closes. A reset instead of a close
/// is tolerated (Windows resets a connection closed with input unread), a
/// proxy that never ends the exchange is not.
async fn answer_of(client: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut got)).await;
    assert!(ended.is_ok(), "the proxy never ended the exchange");
    String::from_utf8_lossy(&got).into_owned()
}

/// Sends `request` in one write and returns the whole answer.
async fn exchange(proxy: SocketAddr, request: &[u8]) -> String {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request).await.unwrap();
    answer_of(&mut client).await
}

fn get(port: u16, credentials: &ProxyCredentials) -> String {
    format!(
        "GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n",
        auth_line(credentials)
    )
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
        ["connection", "x-end", "content-length"],
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
    origin.settled().await;

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
    origin.settled().await;

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
    origin.settled().await;

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
        answer.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nConnection: close\r\n"),
        "{answer}"
    );
    assert!(!answer.contains("Keep-Alive"), "{answer}");
    assert!(answer.ends_with("\r\n\r\nok"), "{answer}");
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

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_half_closes_after_its_request_still_gets_the_answer() {
    let origin = spawn_origin(head_complete, OK_HELLO).await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(get(origin.addr.port(), &credentials).as_bytes())
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let answer = answer_of(&mut client).await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.ends_with("\r\n\r\nhello"), "{answer}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_cut_short_ends_the_exchange_and_is_answered_as_malformed() {
    let origin = spawn_origin(|seen| seen.ends_with(b"0123456789"), OK_HELLO).await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Content-Length: 10\r\n\r\n01234",
                auth_line(&credentials)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let answer = answer_of(&mut client).await;
    origin.settled().await;

    assert!(answer.starts_with("HTTP/1.1 400 "), "{answer}");
    assert!(origin.received().ends_with("\r\n\r\n01234"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_chunked_body_ends_the_exchange_before_anything_past_it() {
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let long_trailer = format!("X-Long: {}\r\n", "t".repeat(5000));
    for (body, forwarded) in [
        ("zz\r\nMARK", ""),
        ("5\r\nhelloXXMARK\r\n0\r\n\r\n", "5\r\nhello"),
        (
            &*format!("5\r\nhello\r\n0\r\n{long_trailer}MARK\r\n\r\n"),
            "5\r\nhello\r\n0\r\n",
        ),
    ] {
        let origin = spawn_origin(|seen| seen.ends_with(b"\r\n0\r\n\r\n"), OK_HELLO).await;
        let port = origin.addr.port();

        let answer = exchange(
            proxy,
            format!(
                "POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Transfer-Encoding: chunked\r\n\r\n{body}",
                auth_line(&credentials)
            )
            .as_bytes(),
        )
        .await;
        origin.settled().await;

        assert!(answer.starts_with("HTTP/1.1 400 "), "{body:?}: {answer}");
        let received = origin.received();
        assert!(
            received.ends_with(&format!("\r\n\r\n{forwarded}")),
            "{body:?}: {received}"
        );
        assert!(!received.contains("MARK"), "{body:?}: {received}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_response_head_over_the_limit_gets_a_bad_gateway() {
    static HUGE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let huge = HUGE.get_or_init(|| {
        let mut head = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        head.extend(std::iter::repeat_n(b'a', 70 * 1024));
        head.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        head
    });
    let origin = spawn_origin(head_complete, huge).await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;

    let answer = exchange(proxy, get(origin.addr.port(), &credentials).as_bytes()).await;

    assert!(
        answer.starts_with("HTTP/1.1 502 "),
        "{}",
        &answer[..answer.len().min(200)]
    );
    assert!(!answer.contains("X-Big"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_response_line_a_browser_could_split_in_two_is_refused() {
    let origin = spawn_origin(
        head_complete,
        b"HTTP/1.1 200 OK\r\nX-A: 1\rConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok",
    )
    .await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;

    let answer = exchange(proxy, get(origin.addr.port(), &credentials).as_bytes()).await;

    assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
    assert!(!answer.contains("keep-alive"), "{answer}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_exchange_ends_with_the_body_even_when_the_origin_stays_open() {
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    for (response, body) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..],
            "hello",
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            "5\r\nhello\r\n0\r\n\r\n",
        ),
        (b"HTTP/1.1 204 No Content\r\n\r\n", ""),
    ] {
        let response: &'static [u8] = Box::leak(response.to_vec().into_boxed_slice());
        let origin = spawn_origin_then(head_complete, response, AfterAnswer::StayOpen).await;

        let answer = exchange(proxy, get(origin.addr.port(), &credentials).as_bytes()).await;

        assert!(answer.ends_with(&format!("\r\n\r\n{body}")), "{answer}");
        origin.settled().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_request_is_answered_without_a_body_whatever_its_length() {
    let origin = spawn_origin_then(
        head_complete,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        AfterAnswer::StayOpen,
    )
    .await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let answer = exchange(
        proxy,
        format!(
            "HEAD http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n",
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.ends_with("\r\n\r\n"), "{answer}");
    origin.settled().await;
}

/// Connects to a scripted origin over an in-memory pipe: it reads the request
/// head, answers `413` and hangs up at once, so the proxy's next write of the
/// body fails while the answer still waits to be read.
#[derive(Clone, Copy)]
struct HangUpAfterAnswer;

impl Connector for HangUpAfterAnswer {
    type Stream = tokio::io::DuplexStream;

    async fn connect(&self, _target: Target) -> Result<Self::Stream, NetError> {
        let (proxy_side, mut origin_side) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0u8; 256];
            while !head_complete(&seen) {
                match origin_side.read(&mut buf).await {
                    Ok(n) if n > 0 => seen.extend_from_slice(&buf[..n]),
                    _ => return,
                }
            }
            let _ = origin_side
                .write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        Ok(proxy_side)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_origin_that_stops_taking_the_body_still_has_its_answer_relayed() {
    let credentials = creds();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let server = HttpConnectProxy::new(HangUpAfterAnswer, credentials.clone());
    tokio::spawn(async move { server.serve(listener).await });

    // Which of the failed write and the waiting answer the proxy sees first is
    // a race; enough rounds make an answer lost to the write a certain failure.
    for _ in 0..20 {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let request = format!(
            "POST http://example.com/ HTTP/1.1\r\n{}Content-Length: 100000\r\n\r\n{}",
            auth_line(&credentials),
            "x".repeat(64 * 1024)
        );
        let _ = client.write_all(request.as_bytes()).await;
        let answer = answer_of(&mut client).await;

        assert!(answer.starts_with("HTTP/1.1 413 "), "{answer}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_keeps_draining_a_client_still_uploading_after_its_answer() {
    let origin = spawn_origin(
        head_complete,
        b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let port = origin.addr.port();

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Content-Length: 10000000\r\n\r\n",
                auth_line(&credentials)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (mut read, mut write) = client.split();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut answer))
        .await
        .expect("the answer ends")
        .expect("the answer arrives");

    // A connection dropped with input unread answers the next bytes with a
    // reset, and Windows and Linux then discard an answer the client had not
    // read yet. The proxy reads on for a while instead, so these writes land.
    let chunk = vec![b'x'; 8 * 1024];
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        write
            .write_all(&chunk)
            .await
            .expect("the proxy is still reading what the client sends");
    }
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 413 "));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_larger_than_the_first_buffer_reaches_the_origin_whole() {
    let origin = spawn_origin(head_complete, OK_HELLO).await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;
    let cookie = "c".repeat(20 * 1024);

    let answer = exchange(
        proxy,
        format!(
            "GET http://127.0.0.1:{}/ HTTP/1.1\r\n{}Cookie: {cookie}\r\n\r\n",
            origin.addr.port(),
            auth_line(&credentials)
        )
        .as_bytes(),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(
        origin
            .received()
            .contains(&format!("\r\nCookie: {cookie}\r\n"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_sent_a_byte_at_a_time_is_read_to_its_end() {
    let origin = spawn_origin(head_complete, OK_HELLO).await;
    let credentials = creds();
    let (proxy, _) = spawn_proxy(credentials.clone()).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.set_nodelay(true).unwrap();
    for byte in get(origin.addr.port(), &credentials).bytes() {
        client.write_all(&[byte]).await.unwrap();
        tokio::time::sleep(Duration::from_micros(200)).await;
    }
    let answer = answer_of(&mut client).await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
}
