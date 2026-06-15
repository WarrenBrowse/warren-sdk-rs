use std::net::SocketAddr;
use std::sync::Arc;

use warren_api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_discovery::VerifiedExit;
use warren_identity::WarrenIdentity;
use warren_transport::ConnectionState;

use crate::client::{DefaultClient, WarrenClient};
use crate::error::SdkError;
use crate::proxy::TunnelState;
use crate::supervisor::EstablishedTunnel;
use crate::supervisor::supervise_proxy;

/// A packet sink whose read side closes on demand, modelling a tunnel that
/// dies when its `close` notifier fires (so the supervisor must reconnect).
struct ClosableSink {
    close: Arc<tokio::sync::Notify>,
}

impl warren_net::PacketSink for ClosableSink {
    async fn send_packet(&self, _packet: &[u8]) -> Result<(), warren_net::NetError> {
        Ok(())
    }

    async fn recv_packet(&self) -> Result<bytes::Bytes, warren_net::NetError> {
        self.close.notified().await;
        Err(warren_net::NetError::EngineStopped)
    }

    fn max_payload(&self) -> usize {
        1280
    }
}

/// A bare TCP connect to `addr` succeeds within ~2s (the supervisor's accept
/// loop is live there). Retried because the serve loop starts asynchronously.
async fn proxy_accepts(addr: SocketAddr) -> bool {
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_reconnects_on_drop_keeping_a_stable_listener() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stable_addr = socks_listener.local_addr().unwrap();

    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    // Each (re)connect publishes its kill notifier so the test can drop that
    // session; the mpsc (unlike a watch) never coalesces, so every cycle shows.
    let (kill_tx, mut kill_rx) = tokio::sync::mpsc::unbounded_channel();
    let cycles = Arc::new(AtomicUsize::new(0));

    let task = {
        let cycles = Arc::clone(&cycles);
        tokio::spawn(async move {
            supervise_proxy(socks_listener, None, None, state_tx, move || {
                let kill_tx = kill_tx.clone();
                let cycles = Arc::clone(&cycles);
                async move {
                    let close = Arc::new(tokio::sync::Notify::new());
                    let _ = kill_tx.send(Arc::clone(&close));
                    cycles.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, SdkError>(EstablishedTunnel {
                        sink: ClosableSink { close },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            })
            .await;
        })
    };

    // Cycle 1 establishes and accepts on the stable address.
    let kill1 = tokio::time::timeout(std::time::Duration::from_secs(5), kill_rx.recv())
        .await
        .expect("first connect happened")
        .expect("kill handle");
    assert!(proxy_accepts(stable_addr).await, "listener live in cycle 1");

    // Simulate a tunnel drop: the supervisor must re-establish on its own.
    kill1.notify_one();
    let kill2 = tokio::time::timeout(std::time::Duration::from_secs(5), kill_rx.recv())
        .await
        .expect("supervisor reconnected after the drop")
        .expect("kill handle");

    // The SAME bound address still accepts after the automatic reconnect.
    assert!(
        proxy_accepts(stable_addr).await,
        "listener stays stable across the reconnect"
    );
    assert_eq!(cycles.load(Ordering::SeqCst), 2, "exactly one reconnect");

    kill2.notify_one();
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_serves_both_socks_and_http_listeners() {
    // Exercises the dual-listener serve epoch (the `select!` two-branch path):
    // both stable addresses accept once the tunnel is up.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let http_addr = http_listener.local_addr().unwrap();

    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let keep_open = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn(async move {
        supervise_proxy(
            socks_listener,
            Some(http_listener),
            None,
            state_tx,
            move || {
                let keep_open = Arc::clone(&keep_open);
                async move {
                    Ok::<_, SdkError>(EstablishedTunnel {
                        sink: ClosableSink { close: keep_open },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            },
        )
        .await;
    });

    assert!(proxy_accepts(socks_addr).await, "SOCKS5 listener is live");
    assert!(proxy_accepts(http_addr).await, "HTTP listener is live");
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_failover_rotates_past_a_broken_exit() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Two candidate "exits": index 0 always fails to connect (a broken exit
    // like prod SG), index 1 connects. This mirrors the rotating closure of
    // start_proxy_multihop_supervised_failover: the cursor advances only on
    // failure, so the supervisor must rotate past 0 and succeed on 1.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let cursor = Arc::new(AtomicUsize::new(0));
    let (ok_tx, mut ok_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let keep_open = Arc::new(tokio::sync::Notify::new());

    let task = tokio::spawn(async move {
        supervise_proxy(socks_listener, None, None, state_tx, move || {
            let cursor = Arc::clone(&cursor);
            let ok_tx = ok_tx.clone();
            let keep_open = Arc::clone(&keep_open);
            async move {
                let idx = cursor.load(Ordering::Relaxed) % 2;
                if idx == 0 {
                    cursor.fetch_add(1, Ordering::Relaxed); // rotate past the broken exit
                    return Err(SdkError::NoMultihopExit);
                }
                let _ = ok_tx.send(idx);
                Ok(EstablishedTunnel {
                    sink: ClosableSink { close: keep_open },
                    local_ip: "10.66.0.2".parse().unwrap(),
                    prefix: 24,
                    gateway: "10.66.0.1".parse().unwrap(),
                    ipv6: None,
                })
            }
        })
        .await;
    });

    let success_idx = tokio::time::timeout(std::time::Duration::from_secs(5), ok_rx.recv())
        .await
        .expect("failover reached a working exit in time")
        .expect("a connect succeeded");
    assert_eq!(
        success_idx, 1,
        "failover rotated past the broken exit 0 to the working exit 1"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_failover_sticks_with_a_working_exit_across_a_drop() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Same rotate-only-on-failure cursor as the failover closure, but exit 0
    // always works. After a healthy session drops, the supervisor must
    // reconnect on the SAME exit 0 (stable egress), not rotate away: the
    // cursor advances on connect failure, never on a mere drop.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let cursor = Arc::new(AtomicUsize::new(0));
    let (used_tx, mut used_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let (close_tx, mut close_rx) =
        tokio::sync::mpsc::unbounded_channel::<Arc<tokio::sync::Notify>>();

    let task = tokio::spawn(async move {
        supervise_proxy(socks_listener, None, None, state_tx, move || {
            let cursor = Arc::clone(&cursor);
            let used_tx = used_tx.clone();
            let close_tx = close_tx.clone();
            async move {
                let idx = cursor.load(Ordering::Relaxed) % 2;
                if idx != 0 {
                    cursor.fetch_add(1, Ordering::Relaxed);
                    return Err(SdkError::NoMultihopExit);
                }
                // Exit 0 works: hand the test a fresh close handle for this
                // session so it can drop it, and report the idx used.
                let close = Arc::new(tokio::sync::Notify::new());
                let _ = close_tx.send(Arc::clone(&close));
                let _ = used_tx.send(idx);
                Ok(EstablishedTunnel {
                    sink: ClosableSink { close },
                    local_ip: "10.66.0.2".parse().unwrap(),
                    prefix: 24,
                    gateway: "10.66.0.1".parse().unwrap(),
                    ipv6: None,
                })
            }
        })
        .await;
    });

    // Cycle 1: connected on exit 0.
    let used1 = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
        .await
        .expect("first connect happened")
        .expect("idx");
    let close1 = close_rx.recv().await.expect("close handle 1");
    assert_eq!(used1, 0);

    // Drop the healthy session; the supervisor reconnects.
    close1.notify_one();
    let used2 = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
        .await
        .expect("reconnected after the drop")
        .expect("idx");
    assert_eq!(
        used2, 0,
        "a healthy drop reconnects on the SAME exit (stable egress), no rotation"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_retries_past_failed_attempts_then_connects() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stable_addr = socks_listener.local_addr().unwrap();

    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let attempts = Arc::new(AtomicUsize::new(0));

    let task = {
        let attempts = Arc::clone(&attempts);
        // Keeps the eventual success session's read side open (never closes).
        let keep_open = Arc::new(tokio::sync::Notify::new());
        tokio::spawn(async move {
            supervise_proxy(socks_listener, None, None, state_tx, move || {
                let attempts = Arc::clone(&attempts);
                let keep_open = Arc::clone(&keep_open);
                async move {
                    // Fail the first two attempts, then establish: exercises the
                    // backoff/retry branch and the recovery to Connected.
                    if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                        return Err(SdkError::NoMultihopExit);
                    }
                    Ok(EstablishedTunnel {
                        sink: ClosableSink { close: keep_open },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            })
            .await;
        })
    };

    // The supervisor must retry past the two failures (with backoff) and make
    // the third, successful attempt rather than giving up after the first.
    let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while attempts.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "supervisor retried past the failures to a successful connect"
    );
    // A successful (third) attempt means the serve loop is now live on the
    // stable address; a bare TCP connect to it succeeds.
    assert!(proxy_accepts(stable_addr).await, "stable listener is live");
    task.abort();
}

/// Builds a `VerifiedExit` pointing at an in-process fake multihop exit.
fn fake_verified_exit(
    addr: SocketAddr,
    keys: &warren_test_support::MultihopExitKeys,
) -> VerifiedExit {
    VerifiedExit {
        exit_id: keys.exit_id,
        exit_ed25519_pubkey: keys.ed25519_pubkey,
        exit_x25519_multihop_pubkey: keys.x25519_pubkey,
        endpoint: addr,
        country: "ZZ".to_owned(),
        city: "Test".to_owned(),
        weight: 100,
        dns_disabled: false,
    }
}

fn test_client() -> DefaultClient {
    let (id, _m) = WarrenIdentity::generate();
    WarrenClient::builder()
        .identity(id)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build()
        .expect("build")
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_multihop_against_a_fake_exit_assigns_ip() {
    // Validates the facade's multihop connect + IpAssign extraction in process
    // (otherwise only exercised by the live examples) against a fake exit that
    // completes the sealed handshake and assigns 10.66.0.2/24.
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);

    let sink = test_client()
        .connect_multihop(&exit)
        .await
        .expect("multihop connect succeeds against the fake exit");
    assert_eq!(
        sink.session().assigned_ipv4(),
        std::net::Ipv4Addr::new(10, 66, 0, 2)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn supervised_proxy_reaches_connected_against_a_fake_exit() {
    // Full supervised facade wiring in process: bind listener, background
    // establish over the fake exit, report Connected on the state watch.
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);

    let cfg = warren_net::ProxyConfig {
        socks5: "127.0.0.1:0".parse().unwrap(),
        http: None,
        dns_server: None,
    };
    let handle = test_client()
        .start_proxy_multihop_supervised(&exit, &cfg)
        .await
        .expect("supervised proxy binds");

    let mut rx = handle.watch_state();
    let connected = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if *rx.borrow_and_update() == ConnectionState::Connected {
                return true;
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        connected,
        "the supervised proxy reaches Connected against the fake exit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn start_proxy_multihop_against_a_fake_exit_is_connected() {
    // The non-supervised datapath sets up over the fake exit and reports a
    // live tunnel (the proxy listener is bound and the state is Connected).
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);
    let cfg = warren_net::ProxyConfig {
        socks5: "127.0.0.1:0".parse().unwrap(),
        http: None,
        dns_server: None,
    };
    let handle = test_client()
        .start_proxy_multihop(&exit, &cfg)
        .await
        .expect("proxy datapath starts over the fake exit");
    assert_eq!(handle.state(), TunnelState::Connected);
}

#[tokio::test]
async fn start_proxy_multihop_refuses_a_dns_disabled_exit_without_a_resolver() {
    // The guard must fire before any connect attempt, so an unroutable address
    // never matters: a dns_disabled exit with no override resolver is rejected.
    let exit = VerifiedExit {
        exit_id: [0u8; 16],
        exit_ed25519_pubkey: [0u8; 32],
        exit_x25519_multihop_pubkey: [0u8; 32],
        endpoint: "203.0.113.1:443".parse().unwrap(),
        country: "ZZ".to_owned(),
        city: "Test".to_owned(),
        weight: 1,
        dns_disabled: true,
    };
    let cfg = warren_net::ProxyConfig {
        socks5: "127.0.0.1:0".parse().unwrap(),
        http: None,
        dns_server: None,
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        test_client().start_proxy_multihop(&exit, &cfg),
    )
    .await
    .expect("the guard returns immediately, well before any connect timeout");
    match result {
        Err(SdkError::ExitDnsDisabled) => {}
        Err(other) => panic!("expected ExitDnsDisabled, got {other:?}"),
        Ok(_) => panic!("a dns_disabled exit without a resolver must be refused"),
    }
}

/// A transport that is never actually called by these builder tests.
struct NullTransport;

impl HttpTransport for NullTransport {
    async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Io("unused".into()))
    }
}

#[test]
fn builder_constructs_with_identity() {
    let (id, _m) = WarrenIdentity::generate();
    let addr = id.address();
    let client = WarrenClient::builder()
        .identity(id)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build()
        .expect("build");
    assert_eq!(client.api().address(), addr);
}

#[test]
fn build_requires_identity() {
    let result = WarrenClient::builder()
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build_with_transport(NullTransport);
    assert!(matches!(
        result,
        Err(crate::error::BuildError::MissingIdentity)
    ));
}

#[test]
fn build_refuses_unpinned_unless_explicit() {
    let (id, _m) = WarrenIdentity::generate();
    let result = WarrenClient::builder()
        .identity(id)
        .api_base("https://api.example.test")
        .build_with_transport(NullTransport);
    assert!(matches!(
        result,
        Err(crate::error::BuildError::UnpinnedServerKey)
    ));
}
