//! Access control on the local proxy listeners: nothing is forwarded for a
//! client that does not present the session's credentials, and a client can
//! tell its own listener from a process squatting the port.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use warren_net::socks5::Target;
use warren_net::{
    Connector, DirectConnector, HttpConnectProxy, ListenerProofError, NetError, ProxyCredentials,
    Socks5ClientError, Socks5Proxy, prove_http_listener, prove_socks5_listener, socks5_connect,
};

/// Dials directly and counts every dial, so a test can prove a refused client
/// made the proxy open nothing upstream.
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

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn spawn_socks(creds: &ProxyCredentials) -> (SocketAddr, CountingConnector) {
    let dials = CountingConnector::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Socks5Proxy::new(dials.clone(), creds.clone());
    tokio::spawn(async move { proxy.serve(listener).await });
    (addr, dials)
}

async fn spawn_http(creds: &ProxyCredentials) -> (SocketAddr, CountingConnector) {
    let dials = CountingConnector::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = HttpConnectProxy::new(dials.clone(), creds.clone());
    tokio::spawn(async move { proxy.serve(listener).await });
    (addr, dials)
}

fn connect_request(target: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = target else {
        panic!("v4 target")
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    req
}

/// Everything the server sends until it closes (bounded, so a server that
/// keeps the connection open fails the test instead of hanging it).
async fn read_until_close(client: &mut TcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut got)).await;
    got
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_without_credentials_is_refused_and_dials_nothing() {
    let echo = spawn_echo().await;
    let (addr, dials) = spawn_socks(&ProxyCredentials::generate()).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    // Push a CONNECT through anyway, as a client ignoring the refusal would.
    let _ = client.write_all(&connect_request(echo)).await;
    let _ = read_until_close(&mut client).await;

    assert_eq!(
        method,
        [0x05, 0xff],
        "no acceptable method without credentials"
    );
    assert_eq!(dials.dials(), 0, "nothing dialed upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_with_a_wrong_password_is_refused_and_dials_nothing() {
    let echo = spawn_echo().await;
    let (addr, dials) = spawn_socks(&ProxyCredentials::generate()).await;
    let wrong = ProxyCredentials::generate();

    let err = socks5_connect(addr, &wrong, &Target::Ip(echo))
        .await
        .unwrap_err();

    assert!(
        matches!(err, Socks5ClientError::AuthRefused),
        "wrong password refused: {err:?}"
    );
    assert_eq!(dials.dials(), 0, "nothing dialed upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_refuses_a_request_sent_after_a_failed_authentication() {
    let echo = spawn_echo().await;
    let (addr, dials) = spawn_socks(&ProxyCredentials::generate()).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);
    client
        .write_all(&[0x01, 6, b'w', b'a', b'r', b'r', b'e', b'n', 1, b'x'])
        .await
        .unwrap();
    let _ = client.write_all(&connect_request(echo)).await;
    let answer = read_until_close(&mut client).await;

    assert_eq!(answer, vec![0x01, 0x01], "a failure status, then the close");
    assert_eq!(dials.dials(), 0, "nothing dialed upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_with_the_session_credentials_relays() {
    let echo = spawn_echo().await;
    let creds = ProxyCredentials::generate();
    let (addr, dials) = spawn_socks(&creds).await;

    let mut stream = socks5_connect(addr, &creds, &Target::Ip(echo))
        .await
        .expect("authenticated connect");
    stream.write_all(b"warren").await.unwrap();
    let mut got = [0u8; 6];
    stream.read_exact(&mut got).await.unwrap();

    assert_eq!(&got, b"warren");
    assert_eq!(dials.dials(), 1);
}

async fn http_exchange(addr: SocketAddr, request: &str) -> String {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    String::from_utf8_lossy(&read_until_close(&mut client).await).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn http_connect_without_credentials_is_refused_and_dials_nothing() {
    let echo = spawn_echo().await;
    let (addr, dials) = spawn_http(&ProxyCredentials::generate()).await;

    let text = http_exchange(
        addr,
        &format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n"),
    )
    .await;

    assert!(text.starts_with("HTTP/1.1 407 "), "{text}");
    assert!(
        text.contains("Proxy-Authenticate: Basic"),
        "a client that waits for the challenge can still answer it: {text}"
    );
    assert_eq!(dials.dials(), 0, "nothing dialed upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn http_connect_with_a_wrong_password_gets_the_same_refusal_and_dials_nothing() {
    let echo = spawn_echo().await;
    let (addr, dials) = spawn_http(&ProxyCredentials::generate()).await;
    let wrong = ProxyCredentials::generate();

    let missing = http_exchange(
        addr,
        &format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n"),
    )
    .await;
    let refused = http_exchange(
        addr,
        &format!(
            "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\nProxy-Authorization: {}\r\n\r\n",
            &*wrong.basic_authorization()
        ),
    )
    .await;

    assert!(refused.starts_with("HTTP/1.1 407 "), "{refused}");
    assert_eq!(
        refused, missing,
        "a wrong secret and no secret get the same answer"
    );
    assert_eq!(dials.dials(), 0, "nothing dialed upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn http_refuses_any_unauthenticated_method_before_saying_what_it_serves() {
    let (addr, dials) = spawn_http(&ProxyCredentials::generate()).await;

    let text = http_exchange(
        addr,
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;

    assert!(text.starts_with("HTTP/1.1 407 "), "{text}");
    assert_eq!(dials.dials(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn http_connect_with_the_session_credentials_relays() {
    let echo = spawn_echo().await;
    let creds = ProxyCredentials::generate();
    let (addr, dials) = spawn_http(&creds).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\nproxy-authorization: {}\r\n\r\n",
        &*creds.basic_authorization()
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    client.write_all(b"warren").await.unwrap();
    let mut got = [0u8; 6];
    client.read_exact(&mut got).await.unwrap();

    assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    assert_eq!(&got, b"warren");
    assert_eq!(dials.dials(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn both_listeners_prove_they_hold_the_session_credentials() {
    let creds = ProxyCredentials::generate();
    let (socks, socks_dials) = spawn_socks(&creds).await;
    let (http, http_dials) = spawn_http(&creds).await;

    prove_socks5_listener(socks, &creds)
        .await
        .expect("the SOCKS5 listener proves it");
    prove_http_listener(http, &creds)
        .await
        .expect("the HTTP listener proves it");

    assert_eq!(
        socks_dials.dials() + http_dials.dials(),
        0,
        "a proof forwards nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listener_holding_other_credentials_fails_the_proof() {
    let (socks, _) = spawn_socks(&ProxyCredentials::generate()).await;
    let (http, _) = spawn_http(&ProxyCredentials::generate()).await;
    let mine = ProxyCredentials::generate();

    assert!(matches!(
        prove_socks5_listener(socks, &mine).await,
        Err(ListenerProofError::NotOurs)
    ));
    assert!(matches!(
        prove_http_listener(http, &mine).await,
        Err(ListenerProofError::NotOurs)
    ));
}

/// A squatter that took over a released port: it selects whatever method a
/// client offers, answers a proof request with a forged proof, and records
/// every byte a client sends it.
async fn spawn_squatter(http: bool) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let mut answered_method = false;
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    log.lock().unwrap().extend_from_slice(&buf[..n]);
                    let answer = if http {
                        format!(
                            "HTTP/1.1 200 OK\r\nWarren-Proof: {}\r\n\r\n",
                            "00".repeat(32)
                        )
                        .into_bytes()
                    } else if !answered_method {
                        answered_method = true;
                        vec![0x05, buf[2]]
                    } else {
                        vec![0u8; 32]
                    };
                    if sock.write_all(&answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_squatting_listener_fails_the_proof_and_never_sees_the_password() {
    let creds = ProxyCredentials::generate();
    let (socks, socks_seen) = spawn_squatter(false).await;
    let (http, http_seen) = spawn_squatter(true).await;

    let socks_verdict =
        tokio::time::timeout(Duration::from_secs(2), prove_socks5_listener(socks, &creds)).await;
    let http_verdict =
        tokio::time::timeout(Duration::from_secs(2), prove_http_listener(http, &creds)).await;

    assert!(
        matches!(socks_verdict, Ok(Err(ListenerProofError::NotOurs))),
        "{socks_verdict:?}"
    );
    assert!(
        matches!(http_verdict, Ok(Err(ListenerProofError::NotOurs))),
        "{http_verdict:?}"
    );
    for seen in [socks_seen, http_seen] {
        let seen = seen.lock().unwrap();
        assert!(
            !seen
                .windows(creds.password().len())
                .any(|w| w == creds.password().as_bytes()),
            "the proof request must not carry the password"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proof_request_to_a_dead_port_is_an_io_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    assert!(matches!(
        prove_socks5_listener(addr, &ProxyCredentials::generate()).await,
        Err(ListenerProofError::Io(_))
    ));
}

/// A client that connects and never authenticates is dropped once the
/// handshake deadline passes, so silent connections cannot pile up.
async fn assert_silent_client_is_dropped(addr: SocketAddr) {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut got = Vec::new();
    let closed = tokio::time::timeout(
        warren_net::proxy::HANDSHAKE_TIMEOUT * 3,
        client.read_to_end(&mut got),
    )
    .await;
    assert!(
        matches!(closed, Ok(Ok(0))),
        "a silent client must be closed after the handshake deadline: {closed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn socks5_drops_a_client_that_never_authenticates() {
    let (addr, dials) = spawn_socks(&ProxyCredentials::generate()).await;
    assert_silent_client_is_dropped(addr).await;
    assert_eq!(dials.dials(), 0);
}

#[tokio::test(start_paused = true)]
async fn http_drops_a_client_that_never_sends_its_head() {
    let (addr, dials) = spawn_http(&ProxyCredentials::generate()).await;
    assert_silent_client_is_dropped(addr).await;
    assert_eq!(dials.dials(), 0);
}
