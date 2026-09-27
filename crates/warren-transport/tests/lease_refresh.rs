//! A session admitted on a token keeps its fleet-wide lease across epochs:
//! it announces that it refreshes, and when the exit reports the lease stale
//! it presents the source's tokens one per request until the exit moves the
//! lease onto one. Against the in-process fake exit, over the real sealed
//! datagram plane.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warren_test_support::{
    MultihopExitKeys, StaticTokens, TokenExit, fake_session_token as token,
    spawn_token_multihop_exit,
};
use warren_transport::{LeaseRefreshSchedule, MultihopClientTunnel, MultihopSession};
use warren_wire::WarrenControlMessage;

const REGISTERED: u8 = 0;
const REFRESHED: u8 = 1;
const REFUSED: u8 = 2;
const DUE: u8 = 5;

/// The production schedule, scaled down to test time.
const FAST: LeaseRefreshSchedule = LeaseRefreshSchedule {
    waits: [Duration::from_millis(40); 5],
    jitter_max: Duration::from_millis(20),
    refused_pause: Duration::from_millis(10),
    unavailable_retry: Duration::from_millis(40),
    unavailable_tries: 2,
};

async fn exit() -> (SocketAddr, MultihopExitKeys, TokenExit) {
    spawn_token_multihop_exit(SigningKey::from_bytes(&[9u8; 32])).await
}

/// Dials the exit with `tokens` on the fast schedule and keeps the downlink
/// read, as every datapath does, so the exit's acks reach the session.
async fn live_session(
    addr: SocketAddr,
    keys: &MultihopExitKeys,
    tokens: &StaticTokens,
) -> (Arc<MultihopSession>, tokio::task::JoinHandle<()>) {
    let session = MultihopClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]))
        .with_session_tokens(Arc::new(tokens.clone()))
        .with_lease_refresh_schedule(FAST)
        .connect(keys.ed25519_pubkey, keys.x25519_pubkey, keys.exit_id, addr)
        .await
        .expect("admitted");
    let session = Arc::new(session);
    let reader = Arc::clone(&session);
    let downlink = tokio::spawn(async move { while reader.recv_packet().await.is_ok() {} });
    (session, downlink)
}

async fn wait_for(what: &str, done: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn ask_for_a_token(exit: &TokenExit) {
    exit.send_control(WarrenControlMessage::LeaseRefreshAck { status: DUE }, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_session_announces_it_refreshes_its_lease_and_waits_to_be_asked() {
    let (addr, keys, exit) = exit().await;
    exit.answer_lease_requests([Some(REGISTERED)]);
    let tokens = StaticTokens::new(vec![token(0x11), token(0x12)]);

    let (session, downlink) = live_session(addr, &keys, &tokens).await;

    wait_for("the announcement", || exit.lease_requests().len() == 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        exit.lease_requests(),
        [None],
        "one announcement, acknowledged, and no token until the exit asks"
    );
    downlink.abort();
    drop(session);
}

#[tokio::test(flavor = "multi_thread")]
async fn when_asked_it_walks_the_sources_tokens_until_the_exit_refreshes_one() {
    let (addr, keys, exit) = exit().await;
    exit.answer_lease_requests([Some(REGISTERED), Some(REFUSED), Some(REFRESHED)]);
    let tokens = StaticTokens::new(vec![token(0x12), token(0x21), token(0x22)]);
    let (session, downlink) = live_session(addr, &keys, &tokens).await;
    wait_for("the announcement", || exit.lease_requests().len() == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    ask_for_a_token(&exit);

    wait_for("the refresh", || exit.lease_requests().len() == 3).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        exit.lease_requests(),
        [None, Some(token(0x21)), Some(token(0x22))],
        "the refused token is followed by the next, one per request, and nothing after the refresh"
    );
    assert_eq!(
        tokens.held(),
        [token(0x12), token(0x22)],
        "the refused token is released and the one the lease moved onto stays held"
    );
    downlink.abort();
    drop(session);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exit_that_never_answers_the_announcement_is_never_sent_a_token() {
    let (addr, keys, exit) = exit().await;
    let tokens = StaticTokens::new(vec![token(0x13), token(0x31)]);
    let (session, downlink) = live_session(addr, &keys, &tokens).await;

    wait_for("every retry", || exit.lease_requests().len() == 5).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ask_for_a_token(&exit);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        exit.lease_requests(),
        [None; 5],
        "an exit that predates the refresh is announced to five times, then left alone"
    );
    downlink.abort();
    drop(session);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_session_never_announces_a_lease_refresh() {
    let (addr, keys, exit) = exit().await;
    exit.answer_lease_requests([Some(REGISTERED)]);
    // A source with nothing to lead with: the dial falls back to the wallet.
    let tokens = StaticTokens::new(Vec::new());
    let (session, downlink) = live_session(addr, &keys, &tokens).await;
    assert!(!session.admission().is_anonymous());

    tokio::time::sleep(Duration::from_millis(300)).await;
    ask_for_a_token(&exit);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        exit.lease_requests().is_empty(),
        "a wallet session holds no lease"
    );
    downlink.abort();
    drop(session);
}
