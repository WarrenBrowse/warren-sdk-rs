use std::net::SocketAddr;
use std::sync::Arc;

use warren_api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_discovery::VerifiedExit;
use warren_identity::WarrenIdentity;
use warren_transport::ConnectionState;

use crate::client::{DaitaMode, DefaultClient, WarrenClient, daita_mode};
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

/// A sink that models a tunnel whose exit signals a maintenance DRAIN (ADR 36):
/// `drain_watch` surfaces a (possibly pre-seeded) advisory so the supervisor's
/// make-before-break race can fire its drain arm; `close` still drives the
/// ordinary dead-path. Used to prove the failover datapath rotates its cursor
/// on a drain (not only on a connect failure).
struct DrainingSink {
    close: Arc<tokio::sync::Notify>,
    drain_rx: tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>>,
}

impl warren_net::PacketSink for DrainingSink {
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

    fn drain_watch(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>>> {
        Some(self.drain_rx.clone())
    }
}

/// A drain watch receiver: `draining` => pre-seeded with an advisory that fires
/// immediately; otherwise a receiver whose sender is dropped, so the watch holds
/// `None` forever and the drain arm never fires (the session just serves).
/// The seeded deadline is already past so the engine drain policy yields a
/// zero anti-stampede spread (no test-time sleep).
fn make_drain_rx(
    draining: bool,
) -> tokio::sync::watch::Receiver<Option<warren_transport::DrainAdvisory>> {
    let seed = draining.then_some(warren_transport::DrainAdvisory {
        deadline_unix_secs: 1,
        reason_code: 0,
    });
    tokio::sync::watch::channel(seed).1
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
            supervise_proxy(
                socks_listener,
                None,
                None,
                crate::supervisor::SupervisorOutputs {
                    egress_probe: false,
                    state_tx,
                    forwarder_tx: tokio::sync::watch::channel(None).0,
                    migration_tx: tokio::sync::watch::channel(None).0,
                    fatal_tx: tokio::sync::watch::channel(None).0,
                },
                crate::supervisor::EpochGuards {
                    pre_migrate: None,
                    network_watch: None,
                },
                move || {
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
                },
                || {},
            )
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
async fn network_path_change_redials_immediately_without_rotating() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // A handover (the preferred local source moves to a live new path) must
    // end the serving epoch and redial at once, instead of riding the dead
    // session into idle-timeout/dead-path detection minutes later. It must
    // NOT rotate the failover cursor: the exit is healthy, the network moved.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let (kill_tx, mut kill_rx) = tokio::sync::mpsc::unbounded_channel();
    let rotations = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(std::sync::Mutex::new(Some(
        "192.0.2.10".parse::<std::net::IpAddr>().unwrap(),
    )));

    let task = {
        let rotations = Arc::clone(&rotations);
        let probe_source = Arc::clone(&source);
        tokio::spawn(async move {
            supervise_proxy(
                socks_listener,
                None,
                None,
                crate::supervisor::SupervisorOutputs {
                    egress_probe: false,
                    state_tx,
                    forwarder_tx: tokio::sync::watch::channel(None).0,
                    migration_tx: tokio::sync::watch::channel(None).0,
                    fatal_tx: tokio::sync::watch::channel(None).0,
                },
                crate::supervisor::EpochGuards {
                    pre_migrate: None,
                    network_watch: Some(crate::supervisor::NetworkWatch {
                        probe: Box::new(move || *probe_source.lock().unwrap()),
                        interval: std::time::Duration::from_millis(20),
                    }),
                },
                move || {
                    let kill_tx = kill_tx.clone();
                    async move {
                        let close = Arc::new(tokio::sync::Notify::new());
                        let _ = kill_tx.send(Arc::clone(&close));
                        Ok::<_, SdkError>(EstablishedTunnel {
                            sink: ClosableSink { close },
                            local_ip: "10.66.0.2".parse().unwrap(),
                            prefix: 24,
                            gateway: "10.66.0.1".parse().unwrap(),
                            ipv6: None,
                        })
                    }
                },
                move || {
                    rotations.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
        })
    };

    // Epoch 1 is up (the tunnel is healthy and never closed by the sink).
    let kill1 = tokio::time::timeout(std::time::Duration::from_secs(5), kill_rx.recv())
        .await
        .expect("first connect happened")
        .expect("kill handle");
    // Let the epoch's watcher take its baseline (several poll intervals): the
    // watcher baselines on the network the epoch dialed from, so a flip before
    // its first poll would just look like the starting point.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Simulated handover: the preferred source moves (Wi-Fi -> Ethernet).
    *source.lock().unwrap() = Some("198.51.100.20".parse().unwrap());

    let kill2 = tokio::time::timeout(std::time::Duration::from_secs(5), kill_rx.recv())
        .await
        .expect("the supervisor redialed on the network move without waiting for session death")
        .expect("kill handle");
    assert_eq!(
        rotations.load(Ordering::SeqCst),
        0,
        "a network move keeps the same exit: the failover cursor must not rotate"
    );

    kill1.notify_one();
    kill2.notify_one();
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_stops_and_surfaces_the_fatal_cause_on_a_policy_rejection() {
    // A policy rejection (unauthorized account) is fatal, not transient: the
    // engine verdict recurs on every redial, so the supervisor must STOP after
    // one attempt and surface the specific cause + a distinct terminal Failed
    // state rather than loop "Reconnecting" forever.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use warren_transport::{FatalCause, MultihopError, SetupError};

    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let (fatal_tx, fatal_rx) = tokio::sync::watch::channel(None);
    let attempts = Arc::new(AtomicUsize::new(0));

    let task = {
        let attempts = Arc::clone(&attempts);
        tokio::spawn(async move {
            supervise_proxy(
                socks_listener,
                None,
                None,
                crate::supervisor::SupervisorOutputs {
                    egress_probe: false,
                    state_tx,
                    forwarder_tx: tokio::sync::watch::channel(None).0,
                    migration_tx: tokio::sync::watch::channel(None).0,
                    fatal_tx,
                },
                crate::supervisor::EpochGuards {
                    pre_migrate: None,
                    network_watch: None,
                },
                move || {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Err::<EstablishedTunnel<ClosableSink>, SdkError>(SdkError::Multihop(
                            MultihopError::Setup(SetupError::Rejected),
                        ))
                    }
                },
                || {},
            )
            .await;
        })
    };

    // A fatal verdict must make the supervisor task RETURN, never loop.
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("a fatal verdict stops the supervisor instead of looping")
        .expect("the supervisor task joined cleanly");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a fatal rejection stops after ONE attempt (no silent Reconnecting loop)"
    );
    assert_eq!(
        *state_rx.borrow(),
        ConnectionState::Failed,
        "the terminal state is Failed, distinct from a transient Reconnecting"
    );
    assert_eq!(
        *fatal_rx.borrow(),
        Some(FatalCause::NotAuthorized),
        "the specific fatal cause is surfaced to the facade"
    );
}

#[test]
fn daita_defaults_to_the_negotiated_model_with_local_pick_as_explicit_override() {
    // Plain `.daita()` advertises support and lets the exit pick
    // (the production-proven model); only a NAMED machine keeps the
    // client-side unilateral pick.
    assert_eq!(daita_mode(false, None), DaitaMode::Off);
    assert_eq!(daita_mode(true, None), DaitaMode::Negotiated);
    assert_eq!(
        daita_mode(true, Some("tamaraw")),
        DaitaMode::LocalPick("tamaraw".into())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_reselects_on_an_exhaustion_refusal_without_going_fatal() {
    // A drain / pool-exhaustion refusal is NOT fatal and must NOT redial the same
    // exit: the supervisor advances the failover cursor (on_drain) so the next
    // attempt reselects a different exit. A same-target retry would never call
    // on_drain, so a non-zero count is the reselect proof.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use warren_transport::{MultihopError, SetupError};

    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let (fatal_tx, fatal_rx) = tokio::sync::watch::channel(None);
    let reselects = Arc::new(AtomicUsize::new(0));

    let task = {
        let reselects = Arc::clone(&reselects);
        tokio::spawn(async move {
            supervise_proxy(
                socks_listener,
                None,
                None,
                crate::supervisor::SupervisorOutputs {
                    egress_probe: false,
                    state_tx,
                    forwarder_tx: tokio::sync::watch::channel(None).0,
                    migration_tx: tokio::sync::watch::channel(None).0,
                    fatal_tx,
                },
                crate::supervisor::EpochGuards {
                    pre_migrate: None,
                    network_watch: None,
                },
                || async {
                    Err::<EstablishedTunnel<ClosableSink>, SdkError>(SdkError::Multihop(
                        MultihopError::Setup(SetupError::IpExhausted),
                    ))
                },
                move || {
                    reselects.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
        })
    };

    // Wait for at least one reselect cycle (the engine redial schedule's
    // first draws stay well under this budget).
    for _ in 0..80 {
        if reselects.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        reselects.load(Ordering::SeqCst) >= 1,
        "an exhaustion refusal must advance the failover cursor (reselect), which a \
         same-target retry would never do"
    );
    assert_eq!(
        *fatal_rx.borrow(),
        None,
        "a reselect verdict is NOT fatal: no fatal cause is latched"
    );
    assert_ne!(
        *state_rx.borrow(),
        ConnectionState::Failed,
        "a reselect verdict never reaches the terminal Failed state"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_publishes_a_forwarder_while_connected_and_clears_it_on_death() {
    use crate::supervisor::supervise_proxy;

    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let (forwarder_tx, mut forwarder_rx) = tokio::sync::watch::channel(None);
    let (kill_tx, mut kill_rx) = tokio::sync::mpsc::unbounded_channel();

    let task = tokio::spawn(async move {
        supervise_proxy(
            socks_listener,
            None,
            None,
            crate::supervisor::SupervisorOutputs {
                egress_probe: false,
                state_tx,
                forwarder_tx,
                migration_tx: tokio::sync::watch::channel(None).0,
                fatal_tx: tokio::sync::watch::channel(None).0,
            },
            crate::supervisor::EpochGuards {
                pre_migrate: None,
                network_watch: None,
            },
            move || {
                let kill_tx = kill_tx.clone();
                async move {
                    let close = Arc::new(tokio::sync::Notify::new());
                    let _ = kill_tx.send(Arc::clone(&close));
                    Ok::<_, SdkError>(EstablishedTunnel {
                        sink: ClosableSink { close },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            },
            || {},
        )
        .await;
    });

    // A forwarder is published once the first tunnel is up.
    let kill1 = tokio::time::timeout(std::time::Duration::from_secs(5), kill_rx.recv())
        .await
        .expect("first connect")
        .expect("kill handle");
    forwarder_rx.changed().await.unwrap();
    assert!(
        forwarder_rx.borrow_and_update().is_some(),
        "forwarder present while connected"
    );

    // On tunnel death it is cleared before the reconnect backoff.
    kill1.notify_one();
    forwarder_rx.changed().await.unwrap();
    assert!(
        forwarder_rx.borrow_and_update().is_none(),
        "forwarder cleared when the tunnel dies"
    );

    task.abort();
}

#[tokio::test]
async fn supervise_forward_remaps_across_epochs_and_clears_on_drop() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::supervisor::{ExternalPort, supervise_forward};

    #[derive(Clone)]
    struct FakeForwarder(u16);

    struct FakePort {
        external: u16,
        dropped: Arc<AtomicBool>,
    }
    impl ExternalPort for FakePort {
        fn external_port(&self) -> u16 {
            self.external
        }
    }
    impl Drop for FakePort {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    let (fwd_tx, fwd_rx) = tokio::sync::watch::channel::<Option<FakeForwarder>>(None);
    let (ext_tx, mut ext_rx) = tokio::sync::watch::channel::<Option<u16>>(None);
    let establishes = Arc::new(AtomicUsize::new(0));
    let first_dropped = Arc::new(AtomicBool::new(false));

    let task = {
        let establishes = Arc::clone(&establishes);
        let first_dropped = Arc::clone(&first_dropped);
        tokio::spawn(async move {
            supervise_forward(
                fwd_rx,
                ext_tx,
                tokio::sync::watch::channel(None).0,
                crate::portfollow::PortFollowConfig::default(),
                move |f: FakeForwarder, _suggested: u16| {
                    let establishes = Arc::clone(&establishes);
                    let dropped = Arc::clone(&first_dropped);
                    async move {
                        establishes.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, SdkError>(FakePort {
                            external: f.0,
                            dropped,
                        })
                    }
                },
            )
            .await;
        })
    };

    // Epoch 1: the forwarder grants external port 5000.
    fwd_tx.send(Some(FakeForwarder(5000))).unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(*ext_rx.borrow(), Some(5000));

    // Tunnel dies: the mapping is torn down and the external port cleared.
    fwd_tx.send(None).unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(*ext_rx.borrow(), None);
    assert!(
        first_dropped.load(Ordering::SeqCst),
        "the previous mapping is dropped on disconnect"
    );

    // Epoch 2: a fresh forwarder re-establishes, possibly on a new port.
    fwd_tx.send(Some(FakeForwarder(6001))).unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(*ext_rx.borrow(), Some(6001));
    assert_eq!(
        establishes.load(Ordering::SeqCst),
        2,
        "re-established once per connected epoch"
    );

    task.abort();
}

#[tokio::test]
async fn supervise_forward_resuggests_the_last_granted_external_port() {
    // The public port must "follow" the client: the first establish suggests 0
    // (auto), and every subsequent establish re-suggests the port the exit last
    // granted, so a reconnect/exit-change keeps the same external port instead of
    // a fresh random one.
    use std::sync::Mutex;

    use crate::supervisor::{ExternalPort, supervise_forward};

    #[derive(Clone)]
    struct FakeForwarder(u16);

    struct FakePort(u16);
    impl ExternalPort for FakePort {
        fn external_port(&self) -> u16 {
            self.0
        }
    }

    let (fwd_tx, fwd_rx) = tokio::sync::watch::channel::<Option<FakeForwarder>>(None);
    let (ext_tx, mut ext_rx) = tokio::sync::watch::channel::<Option<u16>>(None);
    let suggested_seen = Arc::new(Mutex::new(Vec::<u16>::new()));

    let task = {
        let suggested_seen = Arc::clone(&suggested_seen);
        tokio::spawn(async move {
            supervise_forward(
                fwd_rx,
                ext_tx,
                tokio::sync::watch::channel(None).0,
                crate::portfollow::PortFollowConfig::default(),
                move |f: FakeForwarder, suggested: u16| {
                    let suggested_seen = Arc::clone(&suggested_seen);
                    async move {
                        suggested_seen.lock().unwrap().push(suggested);
                        Ok::<_, SdkError>(FakePort(f.0))
                    }
                },
            )
            .await;
        })
    };

    // Epoch 1: the exit grants external port 5000.
    fwd_tx.send(Some(FakeForwarder(5000))).unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(*ext_rx.borrow(), Some(5000));

    // Tunnel dies, then a fresh forwarder reconnects (a different exit that would
    // auto-pick 9999). The re-suggested port must be the last grant (5000), not
    // whatever the new exit would otherwise choose.
    fwd_tx.send(None).unwrap();
    ext_rx.changed().await.unwrap();
    fwd_tx.send(Some(FakeForwarder(9999))).unwrap();
    ext_rx.changed().await.unwrap();

    task.abort();

    assert_eq!(
        *suggested_seen.lock().unwrap(),
        vec![0, 5000],
        "first establish suggests 0 (auto); the next re-suggests the last-granted port"
    );
}

/// A port-conflict error exactly as the datapath surfaces it: the gateway's
/// strict honour-or-error refusal of an explicit suggestion.
fn conflict_error() -> SdkError {
    SdkError::PortForward(warren_net::PortForwardError::Gateway(
        warren_net::ResultCode::SuggestedPortUnavailable,
    ))
}

#[test]
fn sdk_error_classifies_only_the_strict_suggestion_refusal_as_conflict() {
    assert!(conflict_error().is_port_conflict());
    assert!(
        !SdkError::PortForward(warren_net::PortForwardError::Timeout).is_port_conflict(),
        "a transport timeout is not a port conflict"
    );
    assert!(
        !SdkError::NoMultihopExit.is_port_conflict(),
        "non-portforward errors are never conflicts"
    );
}

#[tokio::test]
async fn supervise_forward_auto_conflict_degrades_to_a_server_pick() {
    // A best-effort (auto) rule whose sticky re-suggestion hits a
    // conflict on the new exit must retry ONCE with `suggested = 0` (server
    // pick) instead of dying, surface the change, and forget the stale sticky.
    use std::sync::Mutex;

    use crate::portfollow::{PortFollowConfig, PortFollowOutcome};
    use crate::supervisor::{ExternalPort, supervise_forward};

    #[derive(Clone)]
    struct FakeForwarder {
        taken: u16,
        auto_pick: u16,
    }
    struct FakePort(u16);
    impl ExternalPort for FakePort {
        fn external_port(&self) -> u16 {
            self.0
        }
    }

    let (fwd_tx, fwd_rx) = tokio::sync::watch::channel::<Option<FakeForwarder>>(None);
    let (ext_tx, mut ext_rx) = tokio::sync::watch::channel::<Option<u16>>(None);
    let (out_tx, mut out_rx) = tokio::sync::watch::channel::<Option<PortFollowOutcome>>(None);
    let suggested_seen = Arc::new(Mutex::new(Vec::<u16>::new()));

    let task = {
        let suggested_seen = Arc::clone(&suggested_seen);
        tokio::spawn(async move {
            supervise_forward(
                fwd_rx,
                ext_tx,
                out_tx,
                PortFollowConfig::default(),
                move |f: FakeForwarder, suggested: u16| {
                    let suggested_seen = Arc::clone(&suggested_seen);
                    async move {
                        suggested_seen.lock().unwrap().push(suggested);
                        if suggested == f.taken {
                            return Err(conflict_error());
                        }
                        Ok(FakePort(if suggested == 0 {
                            f.auto_pick
                        } else {
                            suggested
                        }))
                    }
                },
            )
            .await;
        })
    };

    // Epoch 1: first establish (auto), the exit grants 5000.
    fwd_tx
        .send(Some(FakeForwarder {
            taken: 0xFFFF,
            auto_pick: 5000,
        }))
        .unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(*ext_rx.borrow(), Some(5000));

    // Epoch 2 (new exit): 5000 is taken there. The rule must degrade to a
    // server pick (7777), not fail.
    fwd_tx.send(None).unwrap();
    ext_rx.changed().await.unwrap();
    fwd_tx
        .send(Some(FakeForwarder {
            taken: 5000,
            auto_pick: 7777,
        }))
        .unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(
        *ext_rx.borrow(),
        Some(7777),
        "the auto rule degraded to the server-assigned port instead of dying"
    );
    out_rx.changed().await.ok();
    assert_eq!(
        *out_rx.borrow_and_update(),
        Some(PortFollowOutcome::Changed {
            previous: Some(5000),
            port: 7777
        }),
        "the degrade is surfaced as a Changed outcome carrying the old port"
    );
    assert_eq!(
        *suggested_seen.lock().unwrap(),
        vec![0, 5000, 0],
        "conflict on the sticky re-suggestion retried once with suggested=0"
    );
    task.abort();
}

#[tokio::test]
async fn supervise_forward_pinned_conflict_stays_without_degrading() {
    // A PINNED rule never silently degrades. A conflict leaves the
    // mapping unset for the epoch (ConflictStayed), and the SAME pinned port is
    // requested again on the next epoch; `suggested = 0` is never sent.
    use std::sync::Mutex;

    use crate::portfollow::{PortFollowConfig, PortFollowOutcome, PortFollowPolicy};
    use crate::supervisor::{ExternalPort, supervise_forward};

    #[derive(Clone)]
    struct FakeForwarder {
        taken: bool,
    }
    struct FakePort(u16);
    impl ExternalPort for FakePort {
        fn external_port(&self) -> u16 {
            self.0
        }
    }

    let (fwd_tx, fwd_rx) = tokio::sync::watch::channel::<Option<FakeForwarder>>(None);
    let (ext_tx, mut ext_rx) = tokio::sync::watch::channel::<Option<u16>>(None);
    let (out_tx, mut out_rx) = tokio::sync::watch::channel::<Option<PortFollowOutcome>>(None);
    let suggested_seen = Arc::new(Mutex::new(Vec::<u16>::new()));

    let config = PortFollowConfig {
        policy: PortFollowPolicy::KeepPortOrStay,
        pinned_external_port: Some(6000),
        ..PortFollowConfig::default()
    };
    let task = {
        let suggested_seen = Arc::clone(&suggested_seen);
        tokio::spawn(async move {
            supervise_forward(
                fwd_rx,
                ext_tx,
                out_tx,
                config,
                move |f: FakeForwarder, suggested: u16| {
                    let suggested_seen = Arc::clone(&suggested_seen);
                    async move {
                        suggested_seen.lock().unwrap().push(suggested);
                        if f.taken {
                            return Err(conflict_error());
                        }
                        Ok(FakePort(suggested))
                    }
                },
            )
            .await;
        })
    };

    // Epoch 1: the pinned port is granted.
    fwd_tx.send(Some(FakeForwarder { taken: false })).unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(*ext_rx.borrow(), Some(6000));

    // Epoch 2 (new exit): 6000 is taken. The rule must NOT degrade; it stays
    // unmapped and reports the conflict.
    fwd_tx.send(None).unwrap();
    ext_rx.changed().await.unwrap();
    fwd_tx.send(Some(FakeForwarder { taken: true })).unwrap();
    out_rx
        .wait_for(|o| matches!(o, Some(PortFollowOutcome::ConflictStayed { pinned: 6000 })))
        .await
        .expect("the pinned conflict is surfaced as ConflictStayed");
    assert_eq!(
        *ext_rx.borrow(),
        None,
        "no mapping exists for the conflicted epoch (never a silent other port)"
    );

    // Epoch 3: back on an exit where the pin is free; the SAME port returns.
    // The conflicted epoch published no external change to sync on, so yield
    // long enough for the task to observe the `None` before the new epoch
    // (production epochs are seconds apart; a coalesced watch cannot happen).
    fwd_tx.send(None).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    fwd_tx.send(Some(FakeForwarder { taken: false })).unwrap();
    ext_rx
        .wait_for(|p| *p == Some(6000))
        .await
        .expect("the pinned port is re-granted once free");
    out_rx
        .wait_for(|o| matches!(o, Some(PortFollowOutcome::Kept { port: 6000 })))
        .await
        .expect("re-granting the pinned port is a Kept outcome");

    task.abort();
    assert!(
        suggested_seen.lock().unwrap().iter().all(|&s| s == 6000),
        "a pinned rule only ever requests its pin, never suggested=0: {:?}",
        suggested_seen.lock().unwrap()
    );
}

#[tokio::test]
async fn supervise_forward_disabled_policy_never_resuggests() {
    // Disabled follow: every epoch asks for a fresh server-assigned port.
    use std::sync::Mutex;

    use crate::portfollow::{PortFollowConfig, PortFollowPolicy};
    use crate::supervisor::{ExternalPort, supervise_forward};

    #[derive(Clone)]
    struct FakeForwarder(u16);
    struct FakePort(u16);
    impl ExternalPort for FakePort {
        fn external_port(&self) -> u16 {
            self.0
        }
    }

    let (fwd_tx, fwd_rx) = tokio::sync::watch::channel::<Option<FakeForwarder>>(None);
    let (ext_tx, mut ext_rx) = tokio::sync::watch::channel::<Option<u16>>(None);
    let (out_tx, _out_rx) = tokio::sync::watch::channel(None);
    let suggested_seen = Arc::new(Mutex::new(Vec::<u16>::new()));

    let config = PortFollowConfig {
        policy: PortFollowPolicy::Disabled,
        ..PortFollowConfig::default()
    };
    let task = {
        let suggested_seen = Arc::clone(&suggested_seen);
        tokio::spawn(async move {
            supervise_forward(
                fwd_rx,
                ext_tx,
                out_tx,
                config,
                move |f: FakeForwarder, suggested: u16| {
                    let suggested_seen = Arc::clone(&suggested_seen);
                    async move {
                        suggested_seen.lock().unwrap().push(suggested);
                        Ok(FakePort(f.0))
                    }
                },
            )
            .await;
        })
    };

    fwd_tx.send(Some(FakeForwarder(5000))).unwrap();
    ext_rx.changed().await.unwrap();
    fwd_tx.send(None).unwrap();
    ext_rx.changed().await.unwrap();
    fwd_tx.send(Some(FakeForwarder(9999))).unwrap();
    ext_rx.changed().await.unwrap();
    assert_eq!(*ext_rx.borrow(), Some(9999));

    task.abort();
    assert_eq!(
        *suggested_seen.lock().unwrap(),
        vec![0, 0],
        "Disabled never re-suggests a previous port"
    );
}

#[tokio::test]
async fn supervise_forward_retries_a_transient_failure_within_the_epoch() {
    // A transient (non-conflict) failure right after connect must not leave the
    // forward dead for the whole epoch: it retries with a jittered backoff and
    // recovers without waiting for the next reconnect.
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::portfollow::{PortFollowConfig, PortFollowOutcome};
    use crate::supervisor::{ExternalPort, supervise_forward};

    #[derive(Clone)]
    struct FakeForwarder;
    struct FakePort(u16);
    impl ExternalPort for FakePort {
        fn external_port(&self) -> u16 {
            self.0
        }
    }

    let (fwd_tx, fwd_rx) = tokio::sync::watch::channel::<Option<FakeForwarder>>(None);
    let (ext_tx, mut ext_rx) = tokio::sync::watch::channel::<Option<u16>>(None);
    let (out_tx, out_rx) = tokio::sync::watch::channel(None);
    let attempts = Arc::new(AtomicUsize::new(0));

    let config = PortFollowConfig {
        retry_base: std::time::Duration::from_millis(1),
        retry_max: std::time::Duration::from_millis(5),
        ..PortFollowConfig::default()
    };
    let task = {
        let attempts = Arc::clone(&attempts);
        tokio::spawn(async move {
            supervise_forward(
                fwd_rx,
                ext_tx,
                out_tx,
                config,
                move |_f: FakeForwarder, _suggested: u16| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                            return Err(SdkError::PortForward(
                                warren_net::PortForwardError::Timeout,
                            ));
                        }
                        Ok(FakePort(5000))
                    }
                },
            )
            .await;
        })
    };

    fwd_tx.send(Some(FakeForwarder)).unwrap();
    let granted = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ext_rx.wait_for(|p| p.is_some()),
    )
    .await;
    assert!(
        granted.is_ok(),
        "the forward recovered within the epoch (no reconnect happened)"
    );
    assert!(
        attempts.load(Ordering::SeqCst) >= 3,
        "it retried past the transient failures"
    );
    assert_eq!(
        *out_rx.borrow(),
        Some(PortFollowOutcome::Changed {
            previous: None,
            port: 5000
        }),
        "the eventual grant is surfaced"
    );
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
            crate::supervisor::SupervisorOutputs {
                egress_probe: false,
                state_tx,
                forwarder_tx: tokio::sync::watch::channel(None).0,
                migration_tx: tokio::sync::watch::channel(None).0,
                fatal_tx: tokio::sync::watch::channel(None).0,
            },
            crate::supervisor::EpochGuards {
                pre_migrate: None,
                network_watch: None,
            },
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
            || {},
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
        supervise_proxy(
            socks_listener,
            None,
            None,
            crate::supervisor::SupervisorOutputs {
                egress_probe: false,
                state_tx,
                forwarder_tx: tokio::sync::watch::channel(None).0,
                migration_tx: tokio::sync::watch::channel(None).0,
                fatal_tx: tokio::sync::watch::channel(None).0,
            },
            crate::supervisor::EpochGuards {
                pre_migrate: None,
                network_watch: None,
            },
            move || {
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
            },
            || {},
        )
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
async fn supervisor_failover_rotates_on_drain() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Two candidate exits, BOTH connect fine. Exit 0 signals a maintenance
    // DRAIN; exit 1 does not. The failover `on_drain` must advance the cursor so
    // the proactive reconnect rotates 0 -> 1 directly, instead of waiting for the
    // draining exit's hard-close to produce the `Err` that the broken-exit path
    // relies on.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let cursor = Arc::new(AtomicUsize::new(0));
    let drain_cursor = Arc::clone(&cursor);
    let (used_tx, mut used_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let keep_open = Arc::new(tokio::sync::Notify::new());

    let task = tokio::spawn(async move {
        supervise_proxy(
            socks_listener,
            None,
            None,
            crate::supervisor::SupervisorOutputs {
                egress_probe: false,
                state_tx,
                forwarder_tx: tokio::sync::watch::channel(None).0,
                migration_tx: tokio::sync::watch::channel(None).0,
                fatal_tx: tokio::sync::watch::channel(None).0,
            },
            crate::supervisor::EpochGuards {
                pre_migrate: None,
                network_watch: None,
            },
            move || {
                let cursor = Arc::clone(&cursor);
                let used_tx = used_tx.clone();
                let keep_open = Arc::clone(&keep_open);
                async move {
                    let idx = cursor.load(Ordering::Relaxed) % 2;
                    let _ = used_tx.send(idx);
                    Ok::<_, SdkError>(EstablishedTunnel {
                        // Exit 0 drains immediately; exit 1 never drains.
                        sink: DrainingSink {
                            close: Arc::clone(&keep_open),
                            drain_rx: make_drain_rx(idx == 0),
                        },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            },
            // The failover datapath's on_drain: rotate past the draining exit.
            move || {
                drain_cursor.fetch_add(1, Ordering::Relaxed);
            },
        )
        .await;
    });

    let first = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
        .await
        .expect("first connect in time")
        .expect("first idx");
    assert_eq!(first, 0, "first dial is exit 0");
    let second = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
        .await
        .expect("the drain must trigger a reconnect in time")
        .expect("second idx");
    assert_eq!(
        second, 1,
        "the drain advisory must rotate the failover cursor 0 -> 1 (both exits connect; \
         only the drain, via on_drain, moves the cursor)"
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
        supervise_proxy(
            socks_listener,
            None,
            None,
            crate::supervisor::SupervisorOutputs {
                egress_probe: false,
                state_tx,
                forwarder_tx: tokio::sync::watch::channel(None).0,
                migration_tx: tokio::sync::watch::channel(None).0,
                fatal_tx: tokio::sync::watch::channel(None).0,
            },
            crate::supervisor::EpochGuards {
                pre_migrate: None,
                network_watch: None,
            },
            move || {
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
            },
            || {},
        )
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
            supervise_proxy(
                socks_listener,
                None,
                None,
                crate::supervisor::SupervisorOutputs {
                    egress_probe: false,
                    state_tx,
                    forwarder_tx: tokio::sync::watch::channel(None).0,
                    migration_tx: tokio::sync::watch::channel(None).0,
                    fatal_tx: tokio::sync::watch::channel(None).0,
                },
                crate::supervisor::EpochGuards {
                    pre_migrate: None,
                    network_watch: None,
                },
                move || {
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
                },
                || {},
            )
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

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_emits_structured_migration_events_on_drain() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::portfollow::{MigrationEvent, MigrationOutcome};

    // Exit 0 drains; the migration proceeds (no gate) onto exit 1. The host app
    // must see MORE than the bare `Draining` state: a structured event carrying
    // the advisory's fields, first `Migrating`, then `Completed` once the
    // reconnect lands.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let (migration_tx, mut migration_rx) =
        tokio::sync::watch::channel::<Option<MigrationEvent>>(None);
    let cursor = Arc::new(AtomicUsize::new(0));
    let drain_cursor = Arc::clone(&cursor);
    let keep_open = Arc::new(tokio::sync::Notify::new());

    let task = tokio::spawn(async move {
        supervise_proxy(
            socks_listener,
            None,
            None,
            crate::supervisor::SupervisorOutputs {
                egress_probe: false,
                state_tx,
                forwarder_tx: tokio::sync::watch::channel(None).0,
                migration_tx,
                fatal_tx: tokio::sync::watch::channel(None).0,
            },
            crate::supervisor::EpochGuards {
                pre_migrate: None,
                network_watch: None,
            },
            move || {
                let cursor = Arc::clone(&cursor);
                let keep_open = Arc::clone(&keep_open);
                async move {
                    let idx = cursor.load(Ordering::Relaxed) % 2;
                    Ok::<_, SdkError>(EstablishedTunnel {
                        sink: DrainingSink {
                            close: Arc::clone(&keep_open),
                            drain_rx: make_drain_rx(idx == 0),
                        },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            },
            move || {
                drain_cursor.fetch_add(1, Ordering::Relaxed);
            },
        )
        .await;
    });

    let migrating = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        migration_rx.wait_for(|e| e.is_some()),
    )
    .await
    .expect("a migration event is emitted on drain")
    .expect("watch alive")
    .expect("event");
    assert_eq!(
        migrating,
        MigrationEvent {
            deadline_unix_secs: 1,
            reason_code: 0,
            outcome: MigrationOutcome::Migrating,
        },
        "the event exposes the drain advisory's fields"
    );

    let completed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        migration_rx.wait_for(|e| {
            matches!(
                e,
                Some(MigrationEvent {
                    outcome: MigrationOutcome::Completed,
                    ..
                })
            )
        }),
    )
    .await;
    assert!(
        completed.is_ok(),
        "the post-drain reconnect emits a Completed migration event"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_gate_veto_cancels_the_migration_and_keeps_serving() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::portfollow::{MigrationEvent, MigrationOutcome};

    // The reserve-then-switch gate refuses every candidate (all pinned ports
    // conflicted): the migration must be CANCELLED, the cursor must NOT rotate,
    // no reconnect happens, and the current (draining) session keeps serving.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stable_addr = socks_listener.local_addr().unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let (migration_tx, mut migration_rx) =
        tokio::sync::watch::channel::<Option<MigrationEvent>>(None);
    let connects = Arc::new(AtomicUsize::new(0));
    let rotations = Arc::new(AtomicUsize::new(0));
    let rotations_in = Arc::clone(&rotations);
    let keep_open = Arc::new(tokio::sync::Notify::new());

    let task = {
        let connects = Arc::clone(&connects);
        tokio::spawn(async move {
            supervise_proxy(
                socks_listener,
                None,
                None,
                crate::supervisor::SupervisorOutputs {
                    egress_probe: false,
                    state_tx,
                    forwarder_tx: tokio::sync::watch::channel(None).0,
                    migration_tx,
                    fatal_tx: tokio::sync::watch::channel(None).0,
                },
                crate::supervisor::EpochGuards {
                    pre_migrate: Some(Box::new(|_advisory| Box::pin(async { false }))),
                    network_watch: None,
                },
                move || {
                    let connects = Arc::clone(&connects);
                    let keep_open = Arc::clone(&keep_open);
                    async move {
                        connects.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, SdkError>(EstablishedTunnel {
                            sink: DrainingSink {
                                close: Arc::clone(&keep_open),
                                drain_rx: make_drain_rx(true),
                            },
                            local_ip: "10.66.0.2".parse().unwrap(),
                            prefix: 24,
                            gateway: "10.66.0.1".parse().unwrap(),
                            ipv6: None,
                        })
                    }
                },
                move || {
                    rotations_in.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
        })
    };

    let event = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        migration_rx.wait_for(|e| e.is_some()),
    )
    .await
    .expect("the cancelled migration is surfaced in time")
    .expect("watch alive")
    .expect("event");
    assert_eq!(
        event.outcome,
        MigrationOutcome::CancelledPortConflict,
        "an all-candidates-conflicted verdict surfaces as a cancellation"
    );

    // The refusal must not have torn the session down or rotated the cursor.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        connects.load(Ordering::SeqCst),
        1,
        "no reconnect: the client stays on the draining exit"
    );
    assert_eq!(
        rotations.load(Ordering::SeqCst),
        0,
        "the failover cursor does not rotate on a cancelled migration"
    );
    assert!(
        proxy_accepts(stable_addr).await,
        "the current session keeps serving after the cancellation"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn supervisor_gate_approval_lets_the_migration_proceed() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // The gate grants (pre-flight reserved the pinned ports on the candidate):
    // the migration proceeds exactly like the no-gate path, rotating the cursor.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state_tx, _state_rx) = tokio::sync::watch::channel(ConnectionState::Connecting);
    let cursor = Arc::new(AtomicUsize::new(0));
    let drain_cursor = Arc::clone(&cursor);
    let (used_tx, mut used_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let keep_open = Arc::new(tokio::sync::Notify::new());

    let task = tokio::spawn(async move {
        supervise_proxy(
            socks_listener,
            None,
            None,
            crate::supervisor::SupervisorOutputs {
                egress_probe: false,
                state_tx,
                forwarder_tx: tokio::sync::watch::channel(None).0,
                migration_tx: tokio::sync::watch::channel(None).0,
                fatal_tx: tokio::sync::watch::channel(None).0,
            },
            crate::supervisor::EpochGuards {
                pre_migrate: Some(Box::new(|_advisory| Box::pin(async { true }))),
                network_watch: None,
            },
            move || {
                let cursor = Arc::clone(&cursor);
                let used_tx = used_tx.clone();
                let keep_open = Arc::clone(&keep_open);
                async move {
                    let idx = cursor.load(Ordering::Relaxed) % 2;
                    let _ = used_tx.send(idx);
                    Ok::<_, SdkError>(EstablishedTunnel {
                        sink: DrainingSink {
                            close: Arc::clone(&keep_open),
                            drain_rx: make_drain_rx(idx == 0),
                        },
                        local_ip: "10.66.0.2".parse().unwrap(),
                        prefix: 24,
                        gateway: "10.66.0.1".parse().unwrap(),
                        ipv6: None,
                    })
                }
            },
            move || {
                drain_cursor.fetch_add(1, Ordering::Relaxed);
            },
        )
        .await;
    });

    let first = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
        .await
        .expect("first connect in time")
        .expect("first idx");
    assert_eq!(first, 0);
    let second = tokio::time::timeout(std::time::Duration::from_secs(5), used_rx.recv())
        .await
        .expect("the approved migration reconnects in time")
        .expect("second idx");
    assert_eq!(second, 1, "the approved migration rotated to the candidate");
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
        asn: 0,
        city: "Test".to_owned(),
        weight: 100,
        dns_disabled: false,
        cover_domain: None,
        tcp_fallback: false,
        edge_cert_sha256: None,
        exit_mlkem768_pubkey: None,
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
async fn arming_the_carrier_on_a_non_cover_exit_is_inert_and_still_connects() {
    // roster v10: an exit that advertises `tcp_fallback` but carries NO cover
    // domain must keep the RPK multihop dial (the carrier needs a cover-domain
    // SNI). Arming must not divert onto the WebPKI/carrier path, which the RPK
    // fake exit would reject: this guards the `cover_domain`-gated arm in
    // `MultihopClientTunnel::connect`.
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let mut exit = fake_verified_exit(addr, &keys);
    exit.tcp_fallback = true;

    let sink = test_client()
        .connect_multihop(&exit)
        .await
        .expect("an armed carrier stays dormant on a non-cover exit and connects over UDP");
    assert_eq!(
        sink.session().assigned_ipv4(),
        std::net::Ipv4Addr::new(10, 66, 0, 2)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_multihop_with_daita_pads_the_uplink() {
    // Facade wiring: `.daita_machine(..)` makes connect_multihop spawn a DAITA
    // driver over the session and hand the sink a handle. The handshake still
    // assigns an IP, and driving real uplink traffic makes the Tamaraw machine
    // schedule cover frames the driver emits on the same tunnel.
    use warren_net::PacketSink;

    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);

    let (id, _m) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(id)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .daita_machine("tamaraw")
        .build()
        .expect("build");

    let sink = client
        .connect_multihop(&exit)
        .await
        .expect("daita multihop connect assigns an IP");
    assert_eq!(
        sink.session().assigned_ipv4(),
        std::net::Ipv4Addr::new(10, 66, 0, 2)
    );

    for _ in 0..40u8 {
        let mut pkt = vec![0x45u8];
        pkt.extend_from_slice(&[0u8; 64]);
        let _ = sink.send_packet(&pkt).await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        sink.session().metrics_snapshot().cover_packets_sent >= 1,
        "the DAITA driver must emit uplink cover traffic"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_multihop_with_an_unknown_daita_machine_is_rejected() {
    // A machine name outside the curated pool surfaces a typed, no-log error
    // (the name is a public protocol label), after the handshake succeeded.
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);

    let (id, _m) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(id)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .daita_machine("does-not-exist")
        .build()
        .expect("build");

    match client.connect_multihop(&exit).await {
        Err(SdkError::UnknownDaitaMachine { name }) => assert_eq!(name, "does-not-exist"),
        Err(other) => panic!("expected UnknownDaitaMachine, got {other:?}"),
        Ok(_) => panic!("unknown DAITA machine must fail"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn start_proxy_reports_a_listener_bind_failure() {
    // A SOCKS5 listen address that cannot bind (already in use) surfaces as the
    // documented SdkError::Proxy, before any tunnel work.
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);

    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let busy = occupied.local_addr().unwrap();
    let cfg = warren_net::ProxyConfig {
        socks5: busy,
        http: None,
        dns_server: None,
    };

    match test_client()
        .start_proxy_multihop_supervised(&exit, &cfg)
        .await
    {
        Err(SdkError::Proxy(_)) => {}
        Err(other) => panic!("expected SdkError::Proxy, got {other:?}"),
        Ok(_) => panic!("binding an occupied port must fail"),
    }
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
    // The multihop datapath exposes live session metrics (epoch 0 at setup).
    let m = handle.metrics().expect("multihop proxy exposes metrics");
    assert_eq!(m.epoch, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn start_proxy_multihop_bonded_with_one_member_connects() {
    // The bundle-of-one is a transparent wrapper (warren-core's n=1 case): the
    // bonded datapath sets up over the fake exit and reports a live tunnel. The
    // n>=2 striping/merge logic is covered by the BondedPacketSink unit test.
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);
    let cfg = warren_net::ProxyConfig {
        socks5: "127.0.0.1:0".parse().unwrap(),
        http: None,
        dns_server: None,
    };
    let handle = test_client()
        .start_proxy_multihop_bonded(&exit, 1, &cfg)
        .await
        .expect("bonded proxy datapath starts over the fake exit");
    assert_eq!(handle.state(), TunnelState::Connected);
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_multihop_bonded_treats_zero_members_as_one() {
    // Direct test of the bonding builder's `n.max(1)` guard: requesting zero
    // members must still produce a single-member bundle (one real tunnel), not an
    // empty sink. The fake exit serves exactly one connection, so n=1-effective is
    // what this can assert in-process.
    let exit_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (addr, keys) = warren_test_support::spawn_fake_multihop_exit(exit_key).await;
    let exit = fake_verified_exit(addr, &keys);
    let bonded = test_client()
        .connect_multihop_bonded(&exit, 0)
        .await
        .expect("bonded connect over the fake exit");
    assert_eq!(bonded.len(), 1, "n=0 is clamped to a single member");
    assert!(!bonded.is_empty());
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
        asn: 0,
        city: "Test".to_owned(),
        weight: 1,
        dns_disabled: true,
        cover_domain: None,
        tcp_fallback: false,
        edge_cert_sha256: None,
        exit_mlkem768_pubkey: None,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_port_is_refused_when_exit_lacks_port_forward_capability() {
    // doc 79: the port-forward offer is gated on the selected exit's advertised
    // NAT-PMP capability. When the exit does not run NAT-PMP, the SDK must
    // refuse the mapping up front with a clear typed error, without emitting a
    // request the exit would reject. This is the datapath-facing half of the
    // gate; ExitQuery::with_require_port_forward covers selection.
    let sink = ClosableSink {
        close: Arc::new(tokio::sync::Notify::new()),
    };
    let gw = std::net::Ipv4Addr::new(10, 66, 0, 1);
    let config =
        warren_net::NetstackConfig::new(std::net::Ipv4Addr::new(10, 66, 0, 2), 16, gw, 1280);
    let (connector, _alive) = warren_net::spawn_over_sink(Arc::new(sink), config);
    let forwarder = crate::proxy::ProxyForwarder {
        connector,
        gateway: gw,
        port_forward_supported: false,
    };
    let err = forwarder
        .forward_port(
            warren_net::MapProto::Tcp,
            8080,
            "127.0.0.1:9000".parse().unwrap(),
        )
        .await
        .expect_err("a non-capable exit must refuse the forward");
    assert!(
        matches!(err, SdkError::PortForwardUnsupported),
        "gate must fail closed with the typed capability error, got {err:?}"
    );
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
fn request_ipv6_is_off_by_default_and_opt_in() {
    let (id, _m) = WarrenIdentity::generate();
    let default = WarrenClient::builder()
        .identity(id)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build()
        .expect("build");
    assert!(!default.wants_ipv6, "IPv6 must be opt-in");

    let (id2, _m2) = WarrenIdentity::generate();
    let enabled = WarrenClient::builder()
        .identity(id2)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .request_ipv6()
        .build()
        .expect("build");
    assert!(enabled.wants_ipv6);
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

/// Builds a `VerifiedExit` with a chosen `dns_disabled` flag (other fields are
/// placeholders; only `dns_disabled` matters for the candidate filter).
fn exit_with_dns(dns_disabled: bool) -> VerifiedExit {
    VerifiedExit {
        exit_id: [0u8; 16],
        exit_ed25519_pubkey: [0u8; 32],
        exit_x25519_multihop_pubkey: [0u8; 32],
        endpoint: "127.0.0.1:443".parse().unwrap(),
        country: "ZZ".to_owned(),
        asn: 0,
        city: "Test".to_owned(),
        weight: 100,
        dns_disabled,
        cover_domain: None,
        tcp_fallback: false,
        edge_cert_sha256: None,
        exit_mlkem768_pubkey: None,
    }
}

#[test]
fn dns_capable_candidates_excludes_dns_disabled_without_an_override() {
    // A mixed list with no override must drop the dns_disabled exit so failover
    // never rotates onto one and silently breaks name resolution.
    let exits = [exit_with_dns(false), exit_with_dns(true)];
    let kept = crate::client::dns_capable_candidates(&exits, false);
    assert_eq!(kept.len(), 1);
    assert!(!kept[0].dns_disabled);
}

#[test]
fn dns_capable_candidates_keeps_all_when_an_override_is_set() {
    // With a dns_server override every exit can resolve, so none are dropped.
    let exits = [exit_with_dns(false), exit_with_dns(true)];
    let kept = crate::client::dns_capable_candidates(&exits, true);
    assert_eq!(kept.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn failover_refuses_an_all_dns_disabled_list_without_an_override() {
    // After filtering, no DNS-capable candidate remains, so the supervisor fails
    // closed rather than starting a datapath that cannot resolve names.
    let client = test_client();
    let exits = [exit_with_dns(true), exit_with_dns(true)];
    let cfg = warren_net::ProxyConfig {
        socks5: "127.0.0.1:0".parse().unwrap(),
        http: None,
        dns_server: None,
    };
    let result = client
        .start_proxy_multihop_supervised_failover(&exits, &cfg)
        .await;
    assert!(matches!(result, Err(SdkError::ExitDnsDisabled)));
}
