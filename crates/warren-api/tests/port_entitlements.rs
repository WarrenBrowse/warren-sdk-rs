//! The client's side of the port-entitlement credential (warren-core docs 99
//! and 105).
//!
//! An entitlement buys one forwarded port and is presented on every NAT-PMP
//! request the rule makes, so what matters here is not just minting: it is
//! that ONE rule keeps ONE credential for the whole epoch (re-presenting a
//! different one on each refresh would spend the subscriber's whole batch on
//! a single port), that it moves to the next epoch's batch when the current
//! one stops being spendable, and that what it presents is the entitlement
//! ENVELOPE (token plus the attribution tag minted beside it): every exit
//! refuses a bare token.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use rand010::SeedableRng;
use rand010::rngs::StdRng;
use warren_api::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_api::{
    AttributionTag, BanReasonCode, BlindingKey, ClientError, CredentialClass, EntitlementEnvelope,
    PortEntitlementManager, PubkeyHex, TokenClientError, TokenEpochResponse, TokenIssueRequest,
    TokenIssueResponse, TokenIssuerDirectory, TokenIssuerKey, WarrenApiClient, mint_tokens,
};
use warren_contract::pf_attribution::{
    CIPHERTEXT_LEN, ENVELOPE_LEN, NONCE_LEN, TAG_VERSION, signing_preimage,
};
use warren_identity::WarrenIdentity;
use warrenguard_token::{IssuerSecretKey, Token};

const EPOCH_SECS: u64 = 3600;
const QUOTA: u32 = 5;
const ISSUER_NAME: &str = "api.warrenbrowse.com";
const CONTEXT_LABEL: &str = "warren/session-token/v1";

/// How the fake issuer departs from a correct attribution answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TagFault {
    None,
    /// One tag fewer than blind signatures.
    DropOne,
    /// Every tag minted for the epoch after the one requested.
    WrongEpoch,
    /// Every tag signed by a key other than the published one.
    ForeignSigner,
    /// The directory publishes no attribution key at all.
    NoPublishedKey,
    /// The directory publishes 32 bytes that are not an Ed25519 point.
    InvalidPublishedKey,
}

/// A tag laid out by hand from the contract's layout and signed by `key`.
/// The ciphertext is filler: only warren-api can open a tag, and the client
/// never tries.
fn tag_for(key: &SigningKey, epoch: u64, filler: u8) -> AttributionTag {
    let nonce = [filler; NONCE_LEN];
    let ciphertext = [filler; CIPHERTEXT_LEN];
    let signature = key.sign(&signing_preimage(epoch, &nonce, &ciphertext));
    let mut raw = vec![TAG_VERSION];
    raw.extend_from_slice(&epoch.to_be_bytes());
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ciphertext);
    raw.extend_from_slice(&signature.to_bytes());
    AttributionTag::from_bytes(&raw).expect("hand-built tag parses")
}

/// Serves the ENTITLEMENT endpoints only. Answering `/v1/tokens/*` here would
/// hide the bug this suite exists to catch: a client pointed at the session
/// class mints against the wrong key and every exit refuses it.
///
/// It keeps warren-api's issuance ledger: the first batch sent for an epoch
/// takes it, the SAME batch sent again is signed again with freshly minted
/// tags, and any other batch is refused `already_issued`.
struct FakeIssuer {
    keys: HashMap<u64, IssuerSecretKey>,
    attribution_key: SigningKey,
    fault: TagFault,
    /// When set, every issue call is answered 403 with this body.
    banned_body: Option<&'static str>,
    issue_calls: AtomicUsize,
    last_paths: Mutex<Vec<String>>,
    /// The batch that took each epoch.
    ledger: Mutex<HashMap<u64, Vec<String>>>,
}

impl FakeIssuer {
    fn new(epochs: &[u64]) -> Self {
        Self::with_fault(epochs, TagFault::None)
    }

    fn with_fault(epochs: &[u64], fault: TagFault) -> Self {
        let mut rng = StdRng::seed_from_u64(11);
        Self {
            keys: epochs
                .iter()
                .map(|&e| (e, IssuerSecretKey::generate(&mut rng).unwrap()))
                .collect(),
            attribution_key: SigningKey::from_bytes(&[0x42; 32]),
            fault,
            banned_body: None,
            issue_calls: AtomicUsize::new(0),
            last_paths: Mutex::new(Vec::new()),
            ledger: Mutex::new(HashMap::new()),
        }
    }

    fn directory(&self) -> TokenIssuerDirectory {
        let mut keys: Vec<TokenIssuerKey> = self
            .keys
            .iter()
            .map(|(&epoch, sk)| {
                let pk = sk.public_key();
                TokenIssuerKey {
                    epoch,
                    token_key_id: pk.key_id().to_hex(),
                    spki_b64: BASE64URL_NOPAD.encode(&pk.to_spki()),
                    not_before: epoch * EPOCH_SECS,
                    not_after: (epoch + 1) * EPOCH_SECS,
                }
            })
            .collect();
        keys.sort_by_key(|k| k.epoch);
        let published = match self.fault {
            TagFault::NoPublishedKey => None,
            TagFault::InvalidPublishedKey => {
                // y = 2 has no x on edwards25519: well-formed hex, no point.
                let mut raw = [0u8; 32];
                raw[0] = 2;
                Some(PubkeyHex::try_from(hex::encode(raw).as_str()).unwrap())
            }
            _ => Some(
                PubkeyHex::try_from(
                    hex::encode(self.attribution_key.verifying_key().as_bytes()).as_str(),
                )
                .unwrap(),
            ),
        };
        TokenIssuerDirectory {
            issuer_name: ISSUER_NAME.to_owned(),
            token_type: 2,
            epoch_secs: EPOCH_SECS,
            context_label: CONTEXT_LABEL.to_owned(),
            quota_per_epoch: QUOTA,
            prefetch_epochs: 48,
            keys,
            attribution_verifying_key_hex: published,
            route_admission: None,
        }
    }

    /// `count` tags for `epoch`, their filler drawn from `call` so that a
    /// re-served batch carries other tags than the first service, as warren-api
    /// mints a fresh nonce per tag.
    fn tags(&self, epoch: u64, count: usize, call: usize) -> Vec<AttributionTag> {
        let foreign = SigningKey::from_bytes(&[0x43; 32]);
        let (signer, tag_epoch, count) = match self.fault {
            TagFault::DropOne => (&self.attribution_key, epoch, count - 1),
            TagFault::WrongEpoch => (&self.attribution_key, epoch + 1, count),
            TagFault::ForeignSigner => (&foreign, epoch, count),
            _ => (&self.attribution_key, epoch, count),
        };
        (0..count)
            .map(|i| {
                tag_for(
                    signer,
                    tag_epoch,
                    u8::try_from((call * 16 + i) % 256).unwrap(),
                )
            })
            .collect()
    }
}

impl HttpTransport for FakeIssuer {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        // A real transport suspends here, which is what lets two refreshes
        // of one manager overlap.
        tokio::task::yield_now().await;
        self.last_paths.lock().unwrap().push(request.url.clone());
        if request.url.ends_with("/v1/port-entitlements/keys") {
            return Ok(HttpResponse::new(
                200,
                serde_json::to_vec(&self.directory()).unwrap(),
            ));
        }
        assert!(
            request.url.ends_with("/v1/port-entitlements/issue"),
            "the client must never reach {} for an entitlement",
            request.url
        );
        let call = self.issue_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(body) = self.banned_body {
            return Ok(HttpResponse::new(403, body.as_bytes().to_vec()));
        }
        let req: TokenIssueRequest = serde_json::from_slice(&request.body).unwrap();
        let epochs = req
            .epochs
            .iter()
            .map(|e| {
                let taken_by_another_batch = self
                    .ledger
                    .lock()
                    .unwrap()
                    .entry(e.epoch)
                    .or_insert_with(|| e.blinded.clone())
                    != &e.blinded;
                if taken_by_another_batch {
                    return TokenEpochResponse {
                        epoch: e.epoch,
                        issued: false,
                        blind_signatures: Vec::new(),
                        token_key_id: None,
                        reject_reason: Some("already_issued".to_owned()),
                        attribution_tags: Vec::new(),
                    };
                }
                let sk = self.keys.get(&e.epoch).expect("key for requested epoch");
                TokenEpochResponse {
                    epoch: e.epoch,
                    issued: true,
                    blind_signatures: e
                        .blinded
                        .iter()
                        .map(|b| {
                            let bytes = BASE64URL_NOPAD.decode(b.as_bytes()).unwrap();
                            BASE64URL_NOPAD.encode(&sk.blind_sign(&bytes).unwrap())
                        })
                        .collect(),
                    token_key_id: Some(sk.public_key().key_id().to_hex()),
                    reject_reason: None,
                    attribution_tags: self.tags(e.epoch, e.blinded.len(), call),
                }
            })
            .collect();
        Ok(HttpResponse::new(
            200,
            serde_json::to_vec(&TokenIssueResponse { epochs }).unwrap(),
        ))
    }
}

/// The wallet every client here signs as.
const WALLET_SEED: [u8; 32] = [0x51; 32];

fn client(issuer: FakeIssuer) -> WarrenApiClient<FakeIssuer> {
    WarrenApiClient::new(
        "https://api.example.test",
        WarrenIdentity::from_seed(&WALLET_SEED),
        issuer,
    )
}

fn entitlement_key() -> BlindingKey {
    BlindingKey::port_entitlement(&WALLET_SEED)
}

fn manager_over(api: &Arc<WarrenApiClient<FakeIssuer>>) -> PortEntitlementManager<FakeIssuer> {
    PortEntitlementManager::new(Arc::clone(api), entitlement_key())
}

fn manager(epochs: &[u64]) -> PortEntitlementManager<FakeIssuer> {
    manager_over(&Arc::new(client(FakeIssuer::new(epochs))))
}

/// Mints epoch 100 against an issuer answering with `fault`.
async fn mint_with(fault: TagFault) -> (Result<usize, TokenClientError>, usize) {
    let api = client(FakeIssuer::with_fault(&[100], fault));
    let directory = api.transport().directory();
    let minted = mint_tokens(&api, &directory, &[100], &entitlement_key())
        .await
        .map(|batches| batches.iter().map(|b| b.tokens.len()).sum());
    (minted, api.transport().issue_calls.load(Ordering::SeqCst))
}

/// The exit refuses what `slot` presents at `now`.
fn refuse(m: &PortEntitlementManager<FakeIssuer>, slot: usize, now: u64) {
    let presented = m.credential_for_slot(slot, now).expect("an entitlement");
    m.mark_refused(slot, &presented, now);
}

/// The entitlement token slot `slot` presents at `now`, without its tag.
fn token_at(m: &PortEntitlementManager<FakeIssuer>, slot: usize, now: u64) -> Vec<u8> {
    let credential = m.credential_for_slot(slot, now).expect("an entitlement");
    EntitlementEnvelope::parse(&credential)
        .expect("an envelope")
        .token()
        .to_vec()
}

#[tokio::test]
async fn a_slot_presents_an_envelope_whose_token_and_tag_both_verify() {
    // The exit parses the envelope, checks the tag under the published key and
    // that its epoch is the token's, then spends the token. A bare token, or a
    // tag the exit cannot verify, refuses the Map request.
    let issuer = FakeIssuer::new(&[100]);
    let token_key = issuer.keys[&100].public_key();
    let attribution_key = issuer.attribution_key.verifying_key();
    let m = manager_over(&Arc::new(client(issuer)));
    m.refresh_auto(100 * EPOCH_SECS).await.unwrap();

    let credential = m.credential_for_slot(0, 100 * EPOCH_SECS).unwrap();

    assert_eq!(credential.len(), ENVELOPE_LEN);
    let envelope = EntitlementEnvelope::parse(&credential).expect("a well-formed envelope");
    let token = Token::parse(envelope.token()).expect("the envelope carries a token");
    token_key
        .verify_token(&token)
        .expect("the token is one the epoch key signed");
    envelope
        .tag()
        .verify(&attribution_key)
        .expect("the tag verifies under the published attribution key");
    assert_eq!(envelope.tag().epoch(), 100);
}

#[tokio::test]
async fn two_slots_present_two_different_tags() {
    // One tag per entitlement: each port carries its own, so the one an abuse
    // revocation returns names the mapping that was reported and no other.
    let m = manager(&[100]);
    m.refresh_auto(100 * EPOCH_SECS).await.unwrap();

    let a =
        EntitlementEnvelope::parse(&m.credential_for_slot(0, 100 * EPOCH_SECS).unwrap()).unwrap();
    let b =
        EntitlementEnvelope::parse(&m.credential_for_slot(1, 100 * EPOCH_SECS).unwrap()).unwrap();

    assert_ne!(a.tag(), b.tag());
}

#[tokio::test]
async fn a_batch_with_fewer_tags_than_signatures_is_refused() {
    let (minted, _) = mint_with(TagFault::DropOne).await;

    assert!(
        matches!(
            minted,
            Err(TokenClientError::AttributionTagCount {
                epoch: 100,
                signatures: 5,
                tags: 4,
            })
        ),
        "an entitlement without its tag is refused by every exit"
    );
}

#[tokio::test]
async fn a_tag_minted_for_another_epoch_is_refused() {
    let (minted, _) = mint_with(TagFault::WrongEpoch).await;

    assert!(matches!(
        minted,
        Err(TokenClientError::AttributionTagEpoch { epoch: 100 })
    ));
}

#[tokio::test]
async fn a_tag_that_does_not_verify_under_the_published_key_is_refused() {
    // Caught here rather than at the exit: a broken issuer shows up as a mint
    // error on the device instead of every Map request failing later.
    let (minted, _) = mint_with(TagFault::ForeignSigner).await;

    assert!(matches!(
        minted,
        Err(TokenClientError::AttributionTagInvalid { epoch: 100, .. })
    ));
}

#[tokio::test]
async fn a_directory_without_an_attribution_key_fails_before_the_epoch_is_issued() {
    // Issuance is once per account and epoch: a mint that could only end in
    // unverifiable tags must not spend it.
    let (minted, issue_calls) = mint_with(TagFault::NoPublishedKey).await;

    assert!(matches!(minted, Err(TokenClientError::BadAttributionKey)));
    assert_eq!(issue_calls, 0, "the epoch was issued for nothing");
}

#[tokio::test]
async fn an_attribution_key_that_is_not_an_ed25519_point_fails_before_the_epoch_is_issued() {
    let (minted, issue_calls) = mint_with(TagFault::InvalidPublishedKey).await;

    assert!(matches!(minted, Err(TokenClientError::BadAttributionKey)));
    assert_eq!(issue_calls, 0, "the epoch was issued for nothing");
}

#[tokio::test]
async fn a_refresh_surfaces_a_directory_without_an_attribution_key() {
    // Swallowed, this reads as a refresh that went fine and stocked nothing,
    // and every rule's request then goes out bare and is refused.
    let m = manager_over(&Arc::new(client(FakeIssuer::with_fault(
        &[100],
        TagFault::NoPublishedKey,
    ))));

    let err = m
        .refresh_auto(100 * EPOCH_SECS)
        .await
        .expect_err("the broken directory reaches the caller");

    assert!(
        matches!(err, TokenClientError::BadAttributionKey),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_refresh_surfaces_a_batch_whose_tags_fail_the_checks() {
    let m = manager_over(&Arc::new(client(FakeIssuer::with_fault(
        &[100],
        TagFault::DropOne,
    ))));

    let err = m
        .refresh_auto(100 * EPOCH_SECS)
        .await
        .expect_err("the broken batch reaches the caller");

    assert!(
        matches!(
            err,
            TokenClientError::AttributionTagCount { epoch: 100, .. }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_banned_wallet_gets_a_typed_refusal_from_entitlement_issuance() {
    let mut issuer = FakeIssuer::new(&[100]);
    issuer.banned_body = Some(r#"{"error":"banned","reason_code":"other"}"#);
    let m = manager_over(&Arc::new(client(issuer)));

    let err = m
        .refresh_auto(100 * EPOCH_SECS)
        .await
        .expect_err("a banned wallet mints no entitlement");

    assert!(
        matches!(
            err,
            TokenClientError::Api(ClientError::Banned {
                reason_code: BanReasonCode::Other,
                lapses_at_unix_secs: None,
            })
        ),
        "{err:?}"
    );
    assert_eq!(m.credential_for_slot(0, 100 * EPOCH_SECS), None);
}

#[test]
fn the_class_names_its_own_endpoints() {
    assert_eq!(
        CredentialClass::PortEntitlement.keys_path(),
        "/v1/port-entitlements/keys"
    );
    assert_eq!(CredentialClass::Session.keys_path(), "/v1/tokens/keys");
    assert_ne!(
        CredentialClass::PortEntitlement.issue_path(),
        CredentialClass::Session.issue_path(),
        "one issue path for both classes would mint session tokens for ports"
    );
}

#[tokio::test]
async fn a_rule_keeps_one_credential_for_the_whole_epoch() {
    // The exit spends a credential the first time it sees it and renews the
    // spend afterwards. Handing the rule a different credential on the next
    // refresh would spend a second entitlement for the same port.
    let m = manager(&[100, 101]);
    m.refresh_auto(100 * EPOCH_SECS).await.unwrap();

    let first = m.credential_for_slot(0, 100 * EPOCH_SECS).unwrap();
    let again = m.credential_for_slot(0, 100 * EPOCH_SECS + 1800).unwrap();

    assert_eq!(first, again, "the rule's credential moved mid-epoch");
}

#[tokio::test]
async fn two_rules_hold_two_different_credentials() {
    // One entitlement buys ONE port. Two rules sharing one credential would
    // read at the exit as a single port and the second would be refused.
    let m = manager(&[100]);
    m.refresh_auto(100 * EPOCH_SECS).await.unwrap();

    let a = m.credential_for_slot(0, 100 * EPOCH_SECS).unwrap();
    let b = m.credential_for_slot(1, 100 * EPOCH_SECS).unwrap();

    assert_ne!(a, b);
}

#[tokio::test]
async fn a_rule_moves_to_the_next_epoch_batch_when_its_epoch_ends() {
    // A credential verifies against its own epoch's issuer key and no other,
    // so a rule outliving the epoch must present the next one or its renewal
    // stops being spendable anywhere.
    let m = manager(&[100, 101]);
    m.refresh_auto(100 * EPOCH_SECS).await.unwrap();

    let in_100 = m.credential_for_slot(0, 100 * EPOCH_SECS).unwrap();
    let in_101 = m.credential_for_slot(0, 101 * EPOCH_SECS).unwrap();

    assert_ne!(in_100, in_101, "the rule kept an unspendable credential");
}

#[tokio::test]
async fn a_slot_past_the_batch_gets_nothing_rather_than_a_shared_credential() {
    // Beyond the per-epoch quota there is nothing left to hand out. Returning
    // a credential already assigned would silently make two rules one port at
    // the exit; returning nothing makes the sixth rule's request go out bare,
    // which the exit refuses, and that is the cap working.
    let m = manager(&[100]);
    m.refresh_auto(100 * EPOCH_SECS).await.unwrap();

    for slot in 0..QUOTA as usize {
        assert!(m.credential_for_slot(slot, 100 * EPOCH_SECS).is_some());
    }

    assert_eq!(
        m.credential_for_slot(QUOTA as usize, 100 * EPOCH_SECS),
        None
    );
}

#[tokio::test]
async fn nothing_is_handed_out_before_the_first_refresh() {
    let m = manager(&[100]);
    assert_eq!(m.credential_for_slot(0, 100 * EPOCH_SECS), None);
}

#[test]
fn the_browser_proxy_class_names_its_own_endpoints() {
    // A browser blinding against the session directory would mint credentials
    // the CONNECT ingress refuses, and would spend the account's session slot
    // for the epoch (warren-core doc 103).
    assert_eq!(
        CredentialClass::BrowserProxy.keys_path(),
        "/v1/browser-proxy/keys"
    );
    assert_eq!(
        CredentialClass::BrowserProxy.issue_path(),
        "/v1/browser-proxy/issue"
    );
    for other in [CredentialClass::Session, CredentialClass::PortEntitlement] {
        assert_ne!(CredentialClass::BrowserProxy.keys_path(), other.keys_path());
        assert_ne!(
            CredentialClass::BrowserProxy.issue_path(),
            other.issue_path()
        );
    }
}

// ---- the batch derived from the wallet (warren-core doc 99 section 4 bis) --

const NOW: u64 = 100 * EPOCH_SECS + 5;

#[tokio::test]
async fn a_restarted_manager_is_served_the_batch_its_wallet_already_holds() {
    // The issuer takes an account's epoch with the first batch it signs and
    // re-serves only that batch. A batch the restarted process could not
    // rebuild would be refused `already_issued`, and every forward refused
    // until the whole prefetch window (48 h) had run out.
    let api = Arc::new(client(FakeIssuer::new(&[100])));
    let before = manager_over(&api);
    before.refresh_auto(NOW).await.unwrap();
    let mut held: Vec<Vec<u8>> = (0..QUOTA as usize)
        .map(|s| token_at(&before, s, NOW))
        .collect();
    drop(before);

    let restarted = manager_over(&api);
    restarted.refresh_auto(NOW).await.unwrap();

    let mut served: Vec<Vec<u8>> = (0..QUOTA as usize)
        .map(|s| token_at(&restarted, s, NOW))
        .collect();
    held.sort_unstable();
    served.sort_unstable();
    assert_eq!(served, held, "the restart holds the account's entitlements");
}

#[tokio::test]
async fn a_batch_another_client_of_the_wallet_took_reads_as_issued_to_another_batch() {
    // A device of the wallet on a release that blinds otherwise takes every
    // epoch first: this manager is then refused `already_issued` and presents
    // nothing, which its caller must be able to tell from an empty refresh.
    let api = Arc::new(client(FakeIssuer::new(&[100])));
    let older_device =
        PortEntitlementManager::new(Arc::clone(&api), BlindingKey::port_entitlement(&[0x52; 32]));
    older_device.refresh_auto(NOW).await.unwrap();
    let this_device = manager_over(&api);

    this_device.refresh_auto(NOW).await.unwrap();

    assert!(this_device.issued_to_another_batch(NOW));
    assert!(!older_device.issued_to_another_batch(NOW));
}

#[tokio::test]
async fn a_slot_presents_the_same_entitlement_in_every_manager_of_the_wallet() {
    // A rule rebuilt by a restarted process re-presents what the exit already
    // spent for its port, whatever order the rules come back in, so the exit
    // renews that lease instead of spending a second entitlement.
    let api = Arc::new(client(FakeIssuer::new(&[100])));
    let first = manager_over(&api);
    let second = manager_over(&api);
    first.refresh_auto(NOW).await.unwrap();
    second.refresh_auto(NOW).await.unwrap();
    let in_first: Vec<Vec<u8>> = (0..QUOTA as usize)
        .map(|s| token_at(&first, s, NOW))
        .collect();

    let mut in_second: Vec<Vec<u8>> = (0..QUOTA as usize)
        .rev()
        .map(|s| token_at(&second, s, NOW))
        .collect();

    in_second.reverse();
    assert_eq!(in_second, in_first);
}

#[tokio::test]
#[should_panic(expected = "port-entitlement blinding key")]
async fn a_manager_refuses_a_key_of_another_class() {
    // A session key would mint the session class and present nothing, every
    // forward then refused with no error anywhere to explain it.
    let api = Arc::new(client(FakeIssuer::new(&[100])));

    let _ = PortEntitlementManager::new(api, BlindingKey::session(&WALLET_SEED));
}

#[tokio::test]
async fn a_slot_the_exit_refused_moves_to_an_entitlement_no_other_slot_holds() {
    // Another device of the wallet holds the same batch, so its first rule
    // presents what this one's first rule presents, and the exit leases a
    // serial to one port fleet-wide. The refused slot moves on rather than
    // presenting the held serial again at every retry.
    let m = manager(&[100]);
    m.refresh_auto(NOW).await.unwrap();
    let refused = token_at(&m, 0, NOW);
    let other = token_at(&m, 1, NOW);

    refuse(&m, 0, NOW);

    let moved = token_at(&m, 0, NOW);
    assert_ne!(moved, refused, "the slot presents the refused serial again");
    assert_ne!(moved, other, "two slots now present one serial");
    assert_eq!(token_at(&m, 0, NOW), moved, "the slot keeps its new one");
}

#[tokio::test]
async fn a_slot_that_moved_keeps_its_place_in_the_next_epoch() {
    // Back at the first place at every epoch, the slot would meet the other
    // device's serial again and be refused once an hour.
    let api = Arc::new(client(FakeIssuer::new(&[100, 101])));
    let m = manager_over(&api);
    m.refresh_auto(NOW).await.unwrap();
    refuse(&m, 0, NOW);
    let _ = token_at(&m, 0, NOW);
    let reference = manager_over(&api);
    reference.refresh_auto(NOW).await.unwrap();

    let next = NOW + EPOCH_SECS;
    assert_eq!(token_at(&m, 0, next), token_at(&reference, 1, next));
}

#[tokio::test]
async fn once_every_free_entitlement_was_refused_the_slot_starts_over() {
    // A refusal is often transient (the serial is held by this client's
    // previous tunnel address until the exit reaps it), so a slot that ran
    // out of untried entitlements tries them again rather than none.
    let m = manager(&[100]);
    m.refresh_auto(NOW).await.unwrap();
    let first = token_at(&m, 0, NOW);
    for _ in 0..QUOTA {
        refuse(&m, 0, NOW);
    }

    assert_eq!(token_at(&m, 0, NOW), first);
}

#[tokio::test]
async fn a_refusal_of_what_the_slot_no_longer_presents_moves_nothing() {
    // The refusal of a request sent before an epoch boundary arrives after it:
    // the slot's entitlement of the new epoch was never refused.
    let m = manager(&[100, 101]);
    m.refresh_auto(NOW).await.unwrap();
    let old = m.credential_for_slot(0, NOW).expect("epoch 100");
    let next = NOW + EPOCH_SECS;
    let current = token_at(&m, 0, next);

    m.mark_refused(0, &old, next);

    assert_eq!(token_at(&m, 0, next), current);
}

#[tokio::test]
async fn a_released_slot_leaves_its_place_to_a_refused_one() {
    // Five rules lived, four are gone, and another device takes the first
    // place. Held by the dead slots, the four free places would leave the
    // live rule nothing to move to but the refused one.
    let m = manager(&[100]);
    m.refresh_auto(NOW).await.unwrap();
    let places: Vec<Vec<u8>> = (0..QUOTA as usize).map(|s| token_at(&m, s, NOW)).collect();
    for slot in 1..QUOTA as usize {
        m.release(slot);
    }

    refuse(&m, 0, NOW);

    assert_eq!(token_at(&m, 0, NOW), places[1]);
}

#[tokio::test]
async fn two_overlapping_refreshes_stock_the_batch_once() {
    // Both are served the same batch, since the wallet derives it. Stocked
    // twice, the batch would hold every serial twice and two slots would
    // present one.
    let m = manager(&[100]);

    let (a, b) = tokio::join!(m.refresh_auto(NOW), m.refresh_auto(NOW));

    a.unwrap();
    b.unwrap();
    let presented: std::collections::HashSet<Vec<u8>> = (0..)
        .map_while(|slot| m.credential_for_slot(slot, NOW))
        .map(|credential| {
            EntitlementEnvelope::parse(&credential)
                .expect("an envelope")
                .token()
                .to_vec()
        })
        .collect();
    assert_eq!(presented.len(), QUOTA as usize);
    assert_eq!(m.credential_for_slot(QUOTA as usize, NOW), None);
}
