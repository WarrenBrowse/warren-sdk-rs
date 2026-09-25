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
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use rand010::SeedableRng;
use rand010::rngs::StdRng;
use warren_api::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_api::{
    AttributionTag, CredentialClass, EntitlementEnvelope, PortEntitlementManager, PubkeyHex,
    TokenClientError, TokenEpochResponse, TokenIssueRequest, TokenIssueResponse,
    TokenIssuerDirectory, TokenIssuerKey, TokenManager, WarrenApiClient, mint_tokens_for,
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
struct FakeIssuer {
    keys: HashMap<u64, IssuerSecretKey>,
    attribution_key: SigningKey,
    fault: TagFault,
    issue_calls: AtomicUsize,
    last_paths: Mutex<Vec<String>>,
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
            issue_calls: AtomicUsize::new(0),
            last_paths: Mutex::new(Vec::new()),
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
        }
    }

    fn tags(&self, epoch: u64, count: usize) -> Vec<AttributionTag> {
        let foreign = SigningKey::from_bytes(&[0x43; 32]);
        let (signer, tag_epoch, count) = match self.fault {
            TagFault::DropOne => (&self.attribution_key, epoch, count - 1),
            TagFault::WrongEpoch => (&self.attribution_key, epoch + 1, count),
            TagFault::ForeignSigner => (&foreign, epoch, count),
            _ => (&self.attribution_key, epoch, count),
        };
        (0..count)
            .map(|i| tag_for(signer, tag_epoch, u8::try_from(i).unwrap()))
            .collect()
    }
}

impl HttpTransport for FakeIssuer {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.last_paths.lock().unwrap().push(request.url.clone());
        if request.url.ends_with("/v1/port-entitlements/keys") {
            return Ok(HttpResponse {
                status: 200,
                body: serde_json::to_vec(&self.directory()).unwrap(),
            });
        }
        assert!(
            request.url.ends_with("/v1/port-entitlements/issue"),
            "the client must never reach {} for an entitlement",
            request.url
        );
        self.issue_calls.fetch_add(1, Ordering::SeqCst);
        let req: TokenIssueRequest = serde_json::from_slice(&request.body).unwrap();
        let epochs = req
            .epochs
            .iter()
            .map(|e| {
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
                    attribution_tags: self.tags(e.epoch, e.blinded.len()),
                }
            })
            .collect();
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&TokenIssueResponse { epochs }).unwrap(),
        })
    }
}

fn client(issuer: FakeIssuer) -> WarrenApiClient<FakeIssuer> {
    WarrenApiClient::new(
        "https://api.example.test",
        WarrenIdentity::from_seed(&[0x51; 32]),
        issuer,
    )
}

fn manager(epochs: &[u64]) -> PortEntitlementManager<FakeIssuer> {
    PortEntitlementManager::new(std::sync::Arc::new(client(FakeIssuer::new(epochs))))
}

/// Mints epoch 100 against an issuer answering with `fault`.
async fn mint_with(fault: TagFault) -> (Result<usize, TokenClientError>, usize) {
    let api = client(FakeIssuer::with_fault(&[100], fault));
    let directory = api.transport().directory();
    let mut rng = StdRng::seed_from_u64(7);
    let minted = mint_tokens_for(
        CredentialClass::PortEntitlement,
        &api,
        &directory,
        &[100],
        &mut rng,
    )
    .await
    .map(|batches| batches.iter().map(|b| b.tokens.len()).sum());
    (minted, api.transport().issue_calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn a_slot_presents_an_envelope_whose_token_and_tag_both_verify() {
    // The exit parses the envelope, checks the tag under the published key and
    // that its epoch is the token's, then spends the token. A bare token, or a
    // tag the exit cannot verify, refuses the Map request.
    let issuer = FakeIssuer::new(&[100]);
    let token_key = issuer.keys[&100].public_key();
    let attribution_key = issuer.attribution_key.verifying_key();
    let m = PortEntitlementManager::new(std::sync::Arc::new(client(issuer)));
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
async fn an_unusable_attribution_key_fails_before_the_epoch_is_issued() {
    // Issuance is once per account and epoch: a mint that could only end in
    // unverifiable tags must not spend it.
    for fault in [TagFault::NoPublishedKey, TagFault::InvalidPublishedKey] {
        let (minted, issue_calls) = mint_with(fault).await;

        assert!(matches!(minted, Err(TokenClientError::BadAttributionKey)));
        assert_eq!(issue_calls, 0, "the epoch was issued for nothing");
    }
}

#[tokio::test]
async fn a_port_entitlement_token_manager_never_vends_a_bare_token() {
    // Every exit refuses a bare entitlement, so the session-token surface of
    // a manager of this class hands out nothing.
    let manager = TokenManager::for_class(
        std::sync::Arc::new(client(FakeIssuer::new(&[100]))),
        CredentialClass::PortEntitlement,
    );
    manager.refresh_auto(100 * EPOCH_SECS).await.unwrap();
    assert_eq!(
        manager.available(100),
        QUOTA as usize,
        "the batch was minted"
    );

    assert!(manager.take_current_stack(100 * EPOCH_SECS).is_empty());
}

#[tokio::test]
async fn a_port_entitlement_batch_is_never_exported_for_persistence() {
    // The persisted bundle carries bare tokens only, so an entitlement written
    // to disk would come back without its tag and be refused everywhere.
    let manager = TokenManager::for_class(
        std::sync::Arc::new(client(FakeIssuer::new(&[100]))),
        CredentialClass::PortEntitlement,
    );
    manager.refresh_auto(100 * EPOCH_SECS).await.unwrap();

    assert!(manager.export_persistable().is_none());
}

#[tokio::test]
async fn a_persisted_bundle_restores_no_port_entitlement() {
    // A bundle holds bare tokens only (one written by a build that predates
    // the tag, or crafted): dropped rather than presented.
    let mut well_formed = [0u8; warrenguard_token::TOKEN_LEN];
    well_formed[..2].copy_from_slice(&0x0002u16.to_be_bytes());
    let body = format!(
        r#"{{"epoch_secs":3600,"epochs":{{"100":["{}"]}}}}"#,
        BASE64URL_NOPAD.encode(&well_formed)
    );
    let bundle = warren_api::PersistedTokens::from_json(&body).unwrap();
    let session = TokenManager::new(std::sync::Arc::new(client(FakeIssuer::new(&[100]))));
    assert_eq!(
        session.restore_persisted(&bundle),
        1,
        "the bundle is well formed: a session manager takes it"
    );
    let entitlements = TokenManager::for_class(
        std::sync::Arc::new(client(FakeIssuer::new(&[100]))),
        CredentialClass::PortEntitlement,
    );

    assert_eq!(entitlements.restore_persisted(&bundle), 0);
    assert_eq!(entitlements.available(100), 0);
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
