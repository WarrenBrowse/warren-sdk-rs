//! A tunnel's admission at the exit: an anonymous v7 token when it has one,
//! walking past the tokens the exit refuses, and the wallet-signed request only
//! where the policy allows it. Against the in-process fake exit, over the real
//! HPKE setup exchange.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use warren_test_support::{
    MultihopExitKeys, SeenSetup, StaticTokens, TokenExit, fake_session_token as token,
    spawn_token_multihop_exit,
};
use warren_transport::{
    MultihopClientTunnel, MultihopError, MultihopSession, NoSessionTokenCause, SessionAdmission,
};

async fn exit() -> (SocketAddr, MultihopExitKeys, TokenExit) {
    spawn_token_multihop_exit(SigningKey::from_bytes(&[9u8; 32])).await
}

fn tunnel() -> MultihopClientTunnel {
    MultihopClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]))
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

fn tokens_led_by(fill: u8) -> SeenSetup {
    SeenSetup::Tokens(vec![token(fill)])
}

fn admitted_token(session: &MultihopSession) -> Option<warren_wire::SessionToken> {
    session.admission().token().copied()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_with_tokens_presents_one_and_never_the_wallet() {
    let (addr, keys, exit) = exit().await;
    let tokens = StaticTokens::new(vec![token(1), token(2)]);
    let tunnel = tunnel().with_session_tokens(Arc::new(tokens.clone()));

    let session = dial(&tunnel, addr, &keys)
        .await
        .expect("admitted on a token");

    assert_eq!(exit.seen(), [tokens_led_by(1)]);
    assert_eq!(admitted_token(&session), Some(token(1)));
    assert!(session.admission().is_anonymous());
    assert_eq!(tokens.held(), [token(1)], "the session holds its token");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_token_is_followed_by_the_next_one_on_a_fresh_dial() {
    let (addr, keys, exit) = exit().await;
    exit.hold_elsewhere(token(1));
    let tokens = StaticTokens::new(vec![token(1), token(2), token(3)]);
    let tunnel = tunnel().with_session_tokens(Arc::new(tokens.clone()));

    let session = dial(&tunnel, addr, &keys)
        .await
        .expect("admitted on the next token");

    assert_eq!(exit.seen(), [tokens_led_by(1), tokens_led_by(2)]);
    assert_eq!(admitted_token(&session), Some(token(2)));
    assert_eq!(tokens.held(), [token(2)], "the refused token is released");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_token_refused_falls_back_to_the_wallet_by_default() {
    // A wallet shared by more people than it has tokens keeps its service: the
    // wallet-signed request is what admitted every one of them before.
    let (addr, keys, exit) = exit().await;
    exit.hold_elsewhere(token(1));
    exit.hold_elsewhere(token(2));
    let tokens = StaticTokens::new(vec![token(1), token(2)]);
    let tunnel = tunnel().with_session_tokens(Arc::new(tokens.clone()));

    let session = dial(&tunnel, addr, &keys)
        .await
        .expect("admitted on the wallet");

    assert_eq!(
        exit.seen(),
        [
            tokens_led_by(1),
            tokens_led_by(2),
            SeenSetup::Wallet { names_pubkey: true }
        ]
    );
    assert!(!session.admission().is_anonymous());
    assert!(tokens.held().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_only_with_every_token_refused_fails_typed_and_never_names_the_wallet() {
    let (addr, keys, exit) = exit().await;
    exit.hold_elsewhere(token(1));
    exit.hold_elsewhere(token(2));
    let tunnel = tunnel()
        .with_session_tokens(Arc::new(StaticTokens::new(vec![token(1), token(2)])))
        .with_session_admission(SessionAdmission::TokensOnly);

    let result = dial(&tunnel, addr, &keys).await;

    assert!(
        matches!(
            result,
            Err(MultihopError::NoSessionToken(
                NoSessionTokenCause::AllRefused
            ))
        ),
        "got {:?}",
        result.map(|_| ())
    );
    assert_eq!(exit.seen(), [tokens_led_by(1), tokens_led_by(2)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_only_without_a_token_fails_before_any_dial() {
    let (addr, keys, exit) = exit().await;
    let tunnel = tunnel()
        .with_session_tokens(Arc::new(StaticTokens::new(Vec::new())))
        .with_session_admission(SessionAdmission::TokensOnly);

    let result = dial(&tunnel, addr, &keys).await;

    assert!(
        matches!(
            result,
            Err(MultihopError::NoSessionToken(NoSessionTokenCause::Empty))
        ),
        "got {:?}",
        result.map(|_| ())
    );
    assert!(exit.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_only_without_a_token_source_fails_before_any_dial() {
    let (addr, keys, exit) = exit().await;
    let tunnel = tunnel().with_session_admission(SessionAdmission::TokensOnly);

    let result = dial(&tunnel, addr, &keys).await;

    assert!(
        matches!(
            result,
            Err(MultihopError::NoSessionToken(NoSessionTokenCause::Empty))
        ),
        "got {:?}",
        result.map(|_| ())
    );
    assert!(exit.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_without_tokens_keeps_the_wallet_request() {
    let (addr, keys, exit) = exit().await;

    let session = dial(&tunnel(), addr, &keys)
        .await
        .expect("admitted on the wallet");

    assert_eq!(exit.seen(), [SeenSetup::Wallet { names_pubkey: true }]);
    assert!(!session.admission().is_anonymous());
    assert!(session.admission().token().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_session_of_the_process_leads_with_a_token_the_first_does_not_hold() {
    let (addr, keys, exit) = exit().await;
    let tokens = Arc::new(StaticTokens::new(vec![token(1), token(2)]));
    let tunnel = tunnel().with_session_tokens(tokens.clone());

    let first = dial(&tunnel, addr, &keys).await.expect("first session");
    let second = dial(&tunnel, addr, &keys).await.expect("second session");

    assert_eq!(exit.seen(), [tokens_led_by(1), tokens_led_by(2)]);
    assert_eq!(admitted_token(&first), Some(token(1)));
    assert_eq!(admitted_token(&second), Some(token(2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_joining_leg_presents_the_token_its_session_was_admitted_on() {
    // Bonded legs share one serial, hence one sticky tunnel address.
    let (addr, keys, exit) = exit().await;
    let tokens = StaticTokens::new(vec![token(1), token(2)]);
    let first = dial(
        &tunnel().with_session_tokens(Arc::new(tokens.clone())),
        addr,
        &keys,
    )
    .await
    .expect("first leg");

    let joined = dial(&tunnel().joining(&first), addr, &keys)
        .await
        .expect("joined leg");

    assert_eq!(exit.seen(), [tokens_led_by(1), tokens_led_by(1)]);
    assert_eq!(admitted_token(&joined), Some(token(1)));
    drop(first);
    assert_eq!(tokens.held(), [token(1)], "the joined leg keeps the hold");
    drop(joined);
    assert!(tokens.held().is_empty(), "released with the last leg");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_leg_joining_a_wallet_session_presents_the_wallet() {
    // The leg joins what its session got, even when it could claim a token of
    // its own: a token would land it on another serial and another address.
    let (addr, keys, exit) = exit().await;
    let first = dial(&tunnel(), addr, &keys).await.expect("first leg");
    let joining = tunnel()
        .with_session_tokens(Arc::new(StaticTokens::new(vec![token(1)])))
        .joining(&first);

    dial(&joining, addr, &keys).await.expect("joined leg");

    assert_eq!(
        exit.seen(),
        [
            SeenSetup::Wallet { names_pubkey: true },
            SeenSetup::Wallet { names_pubkey: true }
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_releases_its_token_when_it_ends() {
    let (addr, keys, _exit) = exit().await;
    let tokens = StaticTokens::new(vec![token(1)]);
    let session = dial(
        &tunnel().with_session_tokens(Arc::new(tokens.clone())),
        addr,
        &keys,
    )
    .await
    .expect("admitted");

    drop(session);

    assert!(tokens.held().is_empty());
}

#[test]
fn a_missing_token_is_retried_and_never_an_account_verdict() {
    for cause in [NoSessionTokenCause::Empty, NoSessionTokenCause::AllRefused] {
        assert_eq!(
            MultihopError::NoSessionToken(cause).retryability(),
            warren_transport::Retryability::RetrySameTarget,
            "{cause}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_live_snapshot_says_whether_the_exit_learned_the_wallet() {
    let (addr, keys, _exit) = exit().await;
    let anonymous = dial(
        &tunnel().with_session_tokens(Arc::new(StaticTokens::new(vec![token(1)]))),
        addr,
        &keys,
    )
    .await
    .expect("admitted on a token");
    let named = dial(&tunnel(), addr, &keys)
        .await
        .expect("admitted on the wallet");

    assert!(anonymous.metrics_snapshot().anonymous);
    assert!(
        anonymous.metrics().snapshot().anonymous,
        "a detached counters handle answers too"
    );
    assert!(!named.metrics_snapshot().anonymous);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_independent_dial_asks_for_an_address_no_other_session_holds() {
    // The exit keys a v7 session by its serial and renews a serial leased on
    // itself, so two devices leading with one token on one exit are both
    // admitted: the hint is what keeps them off one inner address.
    let (addr, keys, exit) = exit().await;

    dial(
        &tunnel().with_session_tokens(Arc::new(StaticTokens::new(vec![token(1)]))),
        addr,
        &keys,
    )
    .await
    .expect("admitted on a token");
    dial(&tunnel(), addr, &keys)
        .await
        .expect("admitted on the wallet");

    assert_eq!(exit.placements(), [Some([0, 0, 0, 0]), Some([0, 0, 0, 0])]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_joining_leg_asks_for_its_session_address() {
    let (addr, keys, exit) = exit().await;
    let first = dial(
        &tunnel().with_session_tokens(Arc::new(StaticTokens::new(vec![token(1)]))),
        addr,
        &keys,
    )
    .await
    .expect("first leg");

    dial(&tunnel().joining(&first), addr, &keys)
        .await
        .expect("joined leg");

    assert_eq!(
        exit.placements()[1],
        Some(first.assigned_ipv4().octets()),
        "the leg names the address its session holds"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_another_token_cannot_change_ends_the_walk_without_the_wallet() {
    let (addr, keys, exit) = exit().await;
    exit.hold_elsewhere(token(1));
    exit.exhaust_for(token(2));
    let tokens = StaticTokens::new(vec![token(1), token(2), token(3)]);
    let tunnel = tunnel().with_session_tokens(Arc::new(tokens.clone()));

    let result = dial(&tunnel, addr, &keys).await;

    assert!(
        matches!(
            result,
            Err(MultihopError::Setup(
                warren_transport::SetupError::IpExhausted
            ))
        ),
        "got {:?}",
        result.map(|_| ())
    );
    assert_eq!(exit.seen(), [tokens_led_by(1), tokens_led_by(2)]);
    assert!(tokens.held().is_empty(), "no token stays held");
}
