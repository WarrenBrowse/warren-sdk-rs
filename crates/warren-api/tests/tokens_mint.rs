//! End-to-end minting tests for the anonymous session-token client
//! (Privacy Pass, doc 64): real blinding, real RSA blind signatures, real
//! finalization/verification, with only the HTTP layer faked (the transport
//! is the system boundary the shared TDD rules allow mocking).
//!
//! The fake issuer signs with `warrenguard_token::IssuerSecretKey`, i.e. the
//! same engine crypto warren-api uses server-side, so a passing test means
//! the client's bytes would satisfy a real issuer.

use std::collections::HashMap;
use std::sync::Mutex;

use data_encoding::BASE64URL_NOPAD;
use rand010::SeedableRng;
use rand010::rngs::StdRng;
use warren_api::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_api::{
    TokenClientError, TokenEpochResponse, TokenIssueRequest, TokenIssueResponse,
    TokenIssuerDirectory, TokenIssuerKey, TokenStore, WarrenApiClient, current_epoch, mint_tokens,
};
use warren_identity::WarrenIdentity;
use warrenguard_token::{IssuerSecretKey, TokenChallenge};

const EPOCH_SECS: u64 = 3600;
const QUOTA: u32 = 3;
const ISSUER_NAME: &str = "api.warrenbrowse.com";
const CONTEXT_LABEL: &str = "warren/session-token/v1";

/// A fake warren-api issuer behind the real `HttpTransport` seam: serves the
/// directory and blind-signs issue requests with per-epoch engine keys.
struct FakeIssuer {
    keys: HashMap<u64, IssuerSecretKey>,
    /// Epochs the fake refuses (simulating quota/subscription rejects).
    refuse: Vec<u64>,
    /// Last issue request seen, for asserting what left the client.
    last_issue: Mutex<Option<(HttpRequest, TokenIssueRequest)>>,
    /// Headers seen on the directory fetch.
    last_keys_headers: Mutex<Option<Vec<(String, String)>>>,
}

impl FakeIssuer {
    fn new(epochs: &[u64]) -> Self {
        let mut rng = StdRng::seed_from_u64(4242);
        let keys = epochs
            .iter()
            .map(|&e| (e, IssuerSecretKey::generate(&mut rng).unwrap()))
            .collect();
        Self {
            keys,
            refuse: Vec::new(),
            last_issue: Mutex::new(None),
            last_keys_headers: Mutex::new(None),
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
        let ok = |body: Vec<u8>| Ok(HttpResponse { status: 200, body });
        if request.url.ends_with("/v1/tokens/keys") {
            *self.last_keys_headers.lock().unwrap() = Some(request.headers.clone());
            return ok(serde_json::to_vec(&self.directory()).unwrap());
        }
        assert!(
            request.url.ends_with("/v1/tokens/issue"),
            "unexpected URL {}",
            request.url
        );
        let req: TokenIssueRequest = serde_json::from_slice(&request.body).unwrap();
        let mut epochs = Vec::new();
        for e in &req.epochs {
            if self.refuse.contains(&e.epoch) {
                epochs.push(TokenEpochResponse {
                    epoch: e.epoch,
                    issued: false,
                    blind_signatures: Vec::new(),
                    token_key_id: None,
                    reject_reason: Some("not_subscribed".to_owned()),
                });
                continue;
            }
            let sk = self.keys.get(&e.epoch).expect("key for requested epoch");
            let sigs = e
                .blinded
                .iter()
                .map(|b| {
                    let bytes = BASE64URL_NOPAD.decode(b.as_bytes()).unwrap();
                    BASE64URL_NOPAD.encode(&sk.blind_sign(&bytes).unwrap())
                })
                .collect();
            epochs.push(TokenEpochResponse {
                epoch: e.epoch,
                issued: true,
                blind_signatures: sigs,
                token_key_id: Some(sk.public_key().key_id().to_hex()),
                reject_reason: None,
            });
        }
        *self.last_issue.lock().unwrap() = Some((request.clone(), req));
        ok(serde_json::to_vec(&TokenIssueResponse { epochs }).unwrap())
    }
}

fn client(fake: FakeIssuer) -> WarrenApiClient<FakeIssuer> {
    WarrenApiClient::new(
        "https://api.example.test",
        WarrenIdentity::from_seed(&[0x33; 32]),
        fake,
    )
}

#[tokio::test]
async fn mints_verifying_tokens_for_the_requested_epochs() {
    let c = client(FakeIssuer::new(&[100, 101]));
    let directory = c.token_keys().await.unwrap();
    let mut rng = StdRng::seed_from_u64(7);

    let minted = mint_tokens(&c, &directory, &[100, 101], &mut rng)
        .await
        .unwrap();

    assert_eq!(minted.len(), 2);
    for m in &minted {
        assert_eq!(m.tokens.len(), QUOTA as usize, "full fixed-size batch");
        // Every token is bound to ITS epoch's challenge, derived exactly as
        // the engine freezes it.
        let ch = TokenChallenge::for_epoch(ISSUER_NAME, CONTEXT_LABEL, m.epoch).unwrap();
        for t in &m.tokens {
            assert_eq!(t.challenge_digest(), &ch.digest());
        }
    }
    // Serials are unique across the whole mint (fresh nonce per token).
    let mut serials: Vec<String> = minted
        .iter()
        .flat_map(|m| m.tokens.iter().map(|t| t.serial().to_hex()))
        .collect();
    serials.sort();
    serials.dedup();
    assert_eq!(serials.len(), 2 * QUOTA as usize);
}

#[tokio::test]
async fn keys_fetch_is_unsigned_and_issue_is_wallet_signed() {
    // The privacy split: fetching the public directory must not name the
    // wallet; the issue request must (that is where policy is enforced).
    let c = client(FakeIssuer::new(&[100]));
    let directory = c.token_keys().await.unwrap();
    let mut rng = StdRng::seed_from_u64(8);
    mint_tokens(&c, &directory, &[100], &mut rng).await.unwrap();

    let keys_headers = c
        .transport()
        .last_keys_headers
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert!(
        !keys_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-warren-pubkey")),
        "directory fetch must be unsigned"
    );
    let (issue_req, parsed) = c.transport().last_issue.lock().unwrap().take().unwrap();
    assert!(
        issue_req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-warren-pubkey")),
        "issue must be wallet-signed"
    );
    assert_eq!(parsed.epochs.len(), 1);
    assert_eq!(parsed.epochs[0].blinded.len(), QUOTA as usize);
}

#[tokio::test]
async fn a_refused_epoch_fails_the_mint_with_the_server_reason() {
    let mut fake = FakeIssuer::new(&[100, 101]);
    fake.refuse.push(101);
    let c = client(fake);
    let directory = c.token_keys().await.unwrap();
    let mut rng = StdRng::seed_from_u64(9);

    let err = mint_tokens(&c, &directory, &[100, 101], &mut rng)
        .await
        .unwrap_err();
    match err {
        TokenClientError::EpochRefused { epoch, reason } => {
            assert_eq!(epoch, 101);
            assert_eq!(reason.as_deref(), Some("not_subscribed"));
        }
        other => panic!("expected EpochRefused, got {other:?}"),
    }
}

#[tokio::test]
async fn a_missing_directory_key_fails_before_any_network_issue() {
    let c = client(FakeIssuer::new(&[100]));
    let directory = c.token_keys().await.unwrap();
    let mut rng = StdRng::seed_from_u64(10);

    let err = mint_tokens(&c, &directory, &[999], &mut rng)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        TokenClientError::MissingEpochKey { epoch: 999 }
    ));
    assert!(
        c.transport().last_issue.lock().unwrap().is_none(),
        "no issue request may leave the device without a valid epoch key"
    );
}

#[tokio::test]
async fn a_tampered_directory_key_id_fails_closed() {
    let c = client(FakeIssuer::new(&[100]));
    let mut directory = c.token_keys().await.unwrap();
    directory.keys[0].token_key_id = "00".repeat(32);
    let mut rng = StdRng::seed_from_u64(11);

    let err = mint_tokens(&c, &directory, &[100], &mut rng)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        TokenClientError::BadDirectoryKey { epoch: 100 }
    ));
}

#[tokio::test]
async fn store_pops_tokens_once_and_prunes_past_epochs() {
    let c = client(FakeIssuer::new(&[100, 101]));
    let directory = c.token_keys().await.unwrap();
    let mut rng = StdRng::seed_from_u64(12);
    let minted = mint_tokens(&c, &directory, &[100, 101], &mut rng)
        .await
        .unwrap();

    let mut store = TokenStore::new();
    for m in minted {
        store.insert(m);
    }
    assert_eq!(store.available(100), QUOTA as usize);

    // One token = one admission: takes are consuming and run dry.
    let mut seen = Vec::new();
    while let Some(t) = store.take(100) {
        seen.push(t.serial().to_hex());
    }
    assert_eq!(seen.len(), QUOTA as usize);
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), QUOTA as usize, "takes never repeat a token");
    assert_eq!(store.available(100), 0);

    // Rollover housekeeping: pruning drops only strictly-past epochs.
    store.prune_before(101);
    assert_eq!(store.available(101), QUOTA as usize);
    store.prune_before(102);
    assert_eq!(store.available(101), 0);
    assert!(store.epochs().is_empty());
}

#[test]
fn current_epoch_follows_the_directory_policy() {
    let fake = FakeIssuer::new(&[1]);
    let dir = fake.directory();
    assert_eq!(current_epoch(&dir, 0), Some(0));
    assert_eq!(current_epoch(&dir, EPOCH_SECS - 1), Some(0));
    assert_eq!(current_epoch(&dir, EPOCH_SECS), Some(1));
    let mut broken = dir;
    broken.epoch_secs = 0;
    assert_eq!(current_epoch(&broken, 10), None, "zero policy fails closed");
}
