//! A port-entitlement and session-token issuer behind the [`HttpTransport`]
//! seam, so the SDK's real `PortEntitlementManager` and `TokenManager` mint,
//! pair and vend credentials in a test without a network.
//!
//! It serves the two entitlement endpoints the way warren-api does (warren-core
//! docs 99 and 105): a per-epoch blind-signing key directory with the
//! attribution verifying key, and an issue call answering one blind signature
//! and one signed attribution tag per blinded message. The tag's ciphertext is
//! filler: only warren-api can open a tag, and no client ever tries.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand010::SeedableRng;
use rand010::rngs::StdRng;
use warren_api::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_api::{
    AttributionTag, PubkeyHex, TokenEpochResponse, TokenIssueRequest, TokenIssueResponse,
    TokenIssuerDirectory, TokenIssuerKey,
};
use warren_contract::pf_attribution::{CIPHERTEXT_LEN, NONCE_LEN, TAG_VERSION, signing_preimage};
use warrenguard_token::IssuerSecretKey;

/// The epoch length the fake issuer publishes, in seconds.
pub const EPOCH_SECS: u64 = 3600;

/// The 403 body warren-api answers for a wallet on the revocation list.
const BANNED_BODY: &str =
    r#"{"error":"banned","reason_code":"port_forwarding_abuse","lapses_at_unix_secs":1790000000}"#;

/// Serves `/v1/port-entitlements/{keys,issue}` and `/v1/tokens/{keys,issue}`
/// for a fixed set of epochs. The session class gets the same directory and
/// the same answers; a session client ignores the attribution tags.
pub struct FakeEntitlementIssuer {
    keys: HashMap<u64, IssuerSecretKey>,
    attribution_key: SigningKey,
    quota: u32,
    banned: AtomicBool,
    directory_fetches: AtomicUsize,
}

impl FakeEntitlementIssuer {
    /// An issuer publishing `epochs`, each minting `quota` entitlements.
    ///
    /// # Panics
    ///
    /// When the engine refuses to generate an issuer key (a broken build).
    #[must_use]
    pub fn new(epochs: &[u64], quota: u32) -> Self {
        let mut rng = StdRng::seed_from_u64(11);
        Self {
            keys: epochs
                .iter()
                .map(|&e| {
                    (
                        e,
                        IssuerSecretKey::generate(&mut rng).expect("issuer key generates"),
                    )
                })
                .collect(),
            attribution_key: SigningKey::from_bytes(&[0x42; 32]),
            quota,
            banned: AtomicBool::new(false),
            directory_fetches: AtomicUsize::new(0),
        }
    }

    /// Answers every later issue call as warren-api answers a banned wallet.
    pub fn ban(&self) {
        self.banned.store(true, Ordering::SeqCst);
    }

    /// How many times the key directory was fetched: once per refresh.
    #[must_use]
    pub fn directory_fetches(&self) -> usize {
        self.directory_fetches.load(Ordering::SeqCst)
    }

    /// The key an exit verifies every attribution tag against.
    #[must_use]
    pub fn attribution_key(&self) -> VerifyingKey {
        self.attribution_key.verifying_key()
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
            issuer_name: "api.warrenbrowse.com".to_owned(),
            token_type: 2,
            epoch_secs: EPOCH_SECS,
            context_label: "warren/session-token/v1".to_owned(),
            quota_per_epoch: self.quota,
            prefetch_epochs: 48,
            keys,
            attribution_verifying_key_hex: Some(
                PubkeyHex::try_from(
                    hex::encode(self.attribution_key.verifying_key().as_bytes()).as_str(),
                )
                .expect("32-byte hex"),
            ),
        }
    }

    fn tag(&self, epoch: u64, filler: u8) -> AttributionTag {
        let nonce = [filler; NONCE_LEN];
        let ciphertext = [filler; CIPHERTEXT_LEN];
        let signature = self
            .attribution_key
            .sign(&signing_preimage(epoch, &nonce, &ciphertext));
        let mut raw = vec![TAG_VERSION];
        raw.extend_from_slice(&epoch.to_be_bytes());
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ciphertext);
        raw.extend_from_slice(&signature.to_bytes());
        AttributionTag::from_bytes(&raw).expect("hand-built tag parses")
    }

    fn issue(&self, body: &[u8]) -> HttpResponse {
        let req: TokenIssueRequest = serde_json::from_slice(body).expect("an issue request");
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
                            let bytes = BASE64URL_NOPAD
                                .decode(b.as_bytes())
                                .expect("base64url blinded message");
                            BASE64URL_NOPAD.encode(&sk.blind_sign(&bytes).expect("blind signature"))
                        })
                        .collect(),
                    token_key_id: Some(sk.public_key().key_id().to_hex()),
                    reject_reason: None,
                    attribution_tags: (0..e.blinded.len())
                        .map(|i| self.tag(e.epoch, u8::try_from(i).expect("small batch")))
                        .collect(),
                }
            })
            .collect();
        HttpResponse {
            status: 200,
            body: serde_json::to_vec(&TokenIssueResponse { epochs }).expect("serializes"),
        }
    }
}

impl HttpTransport for FakeEntitlementIssuer {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        if request.url.ends_with("/v1/port-entitlements/keys")
            || request.url.ends_with("/v1/tokens/keys")
        {
            self.directory_fetches.fetch_add(1, Ordering::SeqCst);
            return Ok(HttpResponse {
                status: 200,
                body: serde_json::to_vec(&self.directory()).expect("serializes"),
            });
        }
        assert!(
            request.url.ends_with("/v1/port-entitlements/issue")
                || request.url.ends_with("/v1/tokens/issue"),
            "a credential client must never reach {}",
            request.url
        );
        if self.banned.load(Ordering::SeqCst) {
            return Ok(HttpResponse {
                status: 403,
                body: BANNED_BODY.as_bytes().to_vec(),
            });
        }
        Ok(self.issue(&request.body))
    }
}
