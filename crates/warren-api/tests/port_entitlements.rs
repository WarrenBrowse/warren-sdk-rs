//! The client's side of the port-entitlement credential (warren-core doc 99).
//!
//! An entitlement buys one forwarded port and is presented on every NAT-PMP
//! request the rule makes, so what matters here is not just minting: it is
//! that ONE rule keeps ONE credential for the whole epoch (re-presenting a
//! different one on each refresh would spend the subscriber's whole batch on
//! a single port), and that it moves to the next epoch's batch when the
//! current one stops being spendable.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use data_encoding::BASE64URL_NOPAD;
use rand010::SeedableRng;
use rand010::rngs::StdRng;
use warren_api::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_api::{
    CredentialClass, PortEntitlementManager, TokenEpochResponse, TokenIssueRequest,
    TokenIssueResponse, TokenIssuerDirectory, TokenIssuerKey, WarrenApiClient,
};
use warren_identity::WarrenIdentity;
use warrenguard_token::IssuerSecretKey;

const EPOCH_SECS: u64 = 3600;
const QUOTA: u32 = 5;
const ISSUER_NAME: &str = "api.warrenbrowse.com";
const CONTEXT_LABEL: &str = "warren/session-token/v1";

/// Serves the ENTITLEMENT endpoints only. Answering `/v1/tokens/*` here would
/// hide the bug this suite exists to catch: a client pointed at the session
/// class mints against the wrong key and every exit refuses it.
struct FakeIssuer {
    keys: HashMap<u64, IssuerSecretKey>,
    issue_calls: AtomicUsize,
    last_paths: Mutex<Vec<String>>,
}

impl FakeIssuer {
    fn new(epochs: &[u64]) -> Self {
        let mut rng = StdRng::seed_from_u64(11);
        Self {
            keys: epochs
                .iter()
                .map(|&e| (e, IssuerSecretKey::generate(&mut rng).unwrap()))
                .collect(),
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
        TokenIssuerDirectory {
            issuer_name: ISSUER_NAME.to_owned(),
            token_type: 2,
            epoch_secs: EPOCH_SECS,
            context_label: CONTEXT_LABEL.to_owned(),
            quota_per_epoch: QUOTA,
            prefetch_epochs: 48,
            keys,
        }
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
                }
            })
            .collect();
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&TokenIssueResponse { epochs }).unwrap(),
        })
    }
}

fn manager(epochs: &[u64]) -> PortEntitlementManager<FakeIssuer> {
    PortEntitlementManager::new(std::sync::Arc::new(WarrenApiClient::new(
        "https://api.example.test",
        WarrenIdentity::from_seed(&[0x51; 32]),
        FakeIssuer::new(epochs),
    )))
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
    // a credential already assigned would silently make two rules one port;
    // returning nothing leaves the exit on its configured quota, which is the
    // documented degrade path.
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
