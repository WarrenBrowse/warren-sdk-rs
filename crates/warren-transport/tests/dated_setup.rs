//! The dated setup: every setup carries the caller's clock, an exit that
//! predates it is sent the legacy request, and a clock refusal blames the
//! device only once two different exits made it. Against the in-process fake
//! exit, over the real HPKE setup exchange.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use warren_test_support::{
    MultihopExitKeys, SeenSetup, StaticTokens, TokenExit, fake_session_token as token,
    spawn_token_multihop_exit_with_id,
};
use warren_transport::{
    ClockSkewWatch, FatalCause, MultihopClientTunnel, MultihopError, MultihopSession, Retryability,
    SetupError,
};

const CLOCK_SKEW: u8 = 1;
const REPLAYED: u8 = 2;

async fn exit_tagged(tag: u8) -> (SocketAddr, MultihopExitKeys, TokenExit) {
    spawn_token_multihop_exit_with_id(SigningKey::from_bytes(&[9u8; 32]), [tag; 16]).await
}

/// A tunnel with its own clock refusal tally, so no other test's exits count.
fn tunnel() -> MultihopClientTunnel {
    MultihopClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]))
        .with_clock_skew_watch(ClockSkewWatch::new())
}

async fn dial(
    tunnel: &MultihopClientTunnel,
    addr: SocketAddr,
    keys: &MultihopExitKeys,
) -> Result<MultihopSession, MultihopError> {
    tunnel
        .connect(keys.ed25519_pubkey, keys.x25519_pubkey, keys.exit_id, addr)
        .await
}

fn refusal(result: Result<MultihopSession, MultihopError>) -> MultihopError {
    match result {
        Ok(_) => panic!("admitted, expected a refusal"),
        Err(error) => error,
    }
}

fn device_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_setup_carries_the_time_of_the_callers_clock() {
    let (addr, keys, exit) = exit_tagged(0x11).await;
    let tunnel = tunnel().with_setup_clock(Arc::new(|| 1_900_000_000));

    let session = dial(&tunnel, addr, &keys).await.expect("admitted");

    assert_eq!(exit.setup_times(), [Some(1_900_000_000)]);
    assert_eq!(exit.seen(), [SeenSetup::Wallet { names_pubkey: true }]);
    drop(session);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_clock_a_setup_carries_the_device_time() {
    let (addr, keys, exit) = exit_tagged(0x11).await;
    let before = device_now();

    let session = dial(&tunnel(), addr, &keys).await.expect("admitted");

    let [Some(sent)] = exit.setup_times()[..] else {
        panic!("one dated setup, got {:?}", exit.setup_times());
    };
    assert!((before..=device_now()).contains(&sent), "{sent}");
    drop(session);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_setup_is_dated_and_still_walks_on_a_refusal_that_says_why() {
    let (addr, keys, exit) = exit_tagged(0x11).await;
    exit.hold_elsewhere(token(1));
    let tokens = StaticTokens::new(vec![token(1), token(2)]);
    let tunnel = tunnel()
        .with_session_tokens(Arc::new(tokens))
        .with_setup_clock(Arc::new(|| 1_900_000_000));

    let session = dial(&tunnel, addr, &keys)
        .await
        .expect("admitted on token 2");

    assert_eq!(
        exit.setup_times(),
        [Some(1_900_000_000), Some(1_900_000_000)]
    );
    assert_eq!(session.admission().token().copied(), Some(token(2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exit_that_predates_the_dated_request_is_sent_the_legacy_one_from_then_on() {
    let (addr, keys, exit) = exit_tagged(0x11).await;
    exit.predate_dated_setup();
    let tunnel = tunnel().with_setup_clock(Arc::new(|| 1_900_000_000));

    let first = dial(&tunnel, addr, &keys).await.expect("admitted, legacy");
    drop(first);
    let second = dial(&tunnel, addr, &keys).await.expect("admitted again");

    assert_eq!(
        exit.setup_times(),
        [Some(1_900_000_000), None, None],
        "one dated attempt answered with the plain Rejected, then legacy only"
    );
    assert!(!second.admission().is_anonymous());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exit_upgraded_since_it_was_marked_old_is_asked_the_dated_request_once_more() {
    let (addr, keys, exit) = exit_tagged(0x11).await;
    exit.predate_dated_setup();
    let tunnel = tunnel().with_setup_clock(Arc::new(|| 1_900_000_000));
    drop(dial(&tunnel, addr, &keys).await.expect("admitted, legacy"));
    exit.require_bound_sessions();

    let session = dial(&tunnel, addr, &keys)
        .await
        .expect("admitted on the dated request");

    assert_eq!(
        exit.setup_times(),
        [Some(1_900_000_000), None, None, Some(1_900_000_000)],
        "the legacy request refused, the dated one asked again"
    );
    drop(session);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exit_that_really_predates_it_and_refuses_the_account_is_not_asked_in_a_loop() {
    // Marked old within this very dial, a plain refusal of the legacy request
    // is the account's: asking the dated request again would only repeat it.
    let (addr, keys, exit) = exit_tagged(0x11).await;
    exit.predate_dated_setup();
    exit.refuse_as_invalid(token(1));
    let tunnel = tunnel().with_session_tokens(Arc::new(StaticTokens::new(vec![token(1)])));

    let _ = dial(&tunnel, addr, &keys).await;

    assert_eq!(
        exit.setup_times()
            .iter()
            .filter(|time| time.is_some())
            .count(),
        1,
        "the dated request is asked once: {:?}",
        exit.setup_times()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_exit_refusing_the_clock_reselects() {
    let (addr, keys, exit) = exit_tagged(0xA1).await;
    exit.refuse_dated_setups(CLOCK_SKEW);

    let error = refusal(dial(&tunnel(), addr, &keys).await);

    assert!(
        matches!(error, MultihopError::Setup(SetupError::SetupRefused(1))),
        "{error:?}"
    );
    assert_eq!(error.retryability(), Retryability::RetryReselect);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_exit_refusing_the_clock_is_a_fatal_clock_skew() {
    let (addr_a, keys_a, exit_a) = exit_tagged(0xA1).await;
    let (addr_b, keys_b, exit_b) = exit_tagged(0xB2).await;
    exit_a.refuse_dated_setups(CLOCK_SKEW);
    exit_b.refuse_dated_setups(CLOCK_SKEW);
    let watch = ClockSkewWatch::new();
    let tunnel_a = tunnel().with_clock_skew_watch(watch.clone());
    let tunnel_b = tunnel().with_clock_skew_watch(watch);

    let again_a = {
        let first = refusal(dial(&tunnel_a, addr_a, &keys_a).await);
        assert_eq!(first.retryability(), Retryability::RetryReselect);
        refusal(dial(&tunnel_a, addr_a, &keys_a).await)
    };
    let at_b = refusal(dial(&tunnel_b, addr_b, &keys_b).await);

    assert_eq!(
        again_a.retryability(),
        Retryability::RetryReselect,
        "the same exit twice may still be that exit's clock"
    );
    assert!(matches!(at_b, MultihopError::ClockSkew), "{at_b:?}");
    assert_eq!(
        at_b.retryability(),
        Retryability::Fatal(FatalCause::ClockSkew)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admitted_setup_clears_the_earlier_clock_refusals() {
    let (addr_a, keys_a, exit_a) = exit_tagged(0xA1).await;
    let (addr_b, keys_b, exit_b) = exit_tagged(0xB2).await;
    let (addr_c, keys_c, _exit_c) = exit_tagged(0xC3).await;
    exit_a.refuse_dated_setups(CLOCK_SKEW);
    exit_b.refuse_dated_setups(CLOCK_SKEW);
    let tunnel = tunnel();

    let _ = refusal(dial(&tunnel, addr_a, &keys_a).await);
    drop(dial(&tunnel, addr_c, &keys_c).await.expect("admitted"));
    let at_b = refusal(dial(&tunnel, addr_b, &keys_b).await);

    assert_eq!(at_b.retryability(), Retryability::RetryReselect);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_setup_redials_and_never_counts_against_the_clock() {
    let (addr_a, keys_a, exit_a) = exit_tagged(0xA1).await;
    let (addr_b, keys_b, exit_b) = exit_tagged(0xB2).await;
    exit_a.refuse_dated_setups(REPLAYED);
    exit_b.refuse_dated_setups(CLOCK_SKEW);
    let tunnel = tunnel();

    let replayed = refusal(dial(&tunnel, addr_a, &keys_a).await);
    let skewed = refusal(dial(&tunnel, addr_b, &keys_b).await);

    assert!(!replayed.retryability().is_fatal(), "{replayed:?}");
    assert_eq!(
        skewed.retryability(),
        Retryability::RetryReselect,
        "a replay says nothing about the device clock"
    );
}
