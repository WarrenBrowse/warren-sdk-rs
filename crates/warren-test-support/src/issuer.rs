//! A port-entitlement and session-token issuer behind the [`HttpTransport`]
//! seam, so the SDK's real `PortEntitlementManager` and `TokenManager` mint,
//! pair and vend credentials in a test without a network.
//!
//! It serves the two entitlement endpoints the way warren-api does (warren-core
//! docs 99 and 105): a per-epoch blind-signing key directory with the
//! attribution verifying key, and an issue call answering one blind signature
//! and one signed attribution tag per blinded message. The tag's ciphertext is
//! filler: only warren-api can open a tag, and no client ever tries.
//!
//! It also keeps the account's device registry (warren-core doc 115):
//! `/v1/devices` registers, lists, renames and revokes, and a revoked device
//! is refused its registration.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand010::SeedableRng;
use rand010::rngs::StdRng;
use warren_api::transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
use warren_api::{
    AttributionTag, DeviceId, DeviceListResponse, DeviceRegistration, DeviceRename, DeviceView,
    PubkeyHex, TokenEpochResponse, TokenIssueRequest, TokenIssueResponse, TokenIssuerDirectory,
    TokenIssuerKey,
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
    devices: Mutex<BTreeMap<String, DeviceRegistration>>,
    revoked_devices: Mutex<HashSet<DeviceId>>,
    registered_names: Mutex<Vec<String>>,
    device_limit_reached: AtomicBool,
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
            devices: Mutex::new(BTreeMap::new()),
            revoked_devices: Mutex::new(HashSet::new()),
            registered_names: Mutex::new(Vec::new()),
            device_limit_reached: AtomicBool::new(false),
        }
    }

    /// The registration the registry holds for `id`, as last registered or
    /// renamed.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the registry.
    #[must_use]
    pub fn device(&self, id: DeviceId) -> Option<DeviceRegistration> {
        self.devices
            .lock()
            .expect("registry")
            .get(&String::from(id))
            .cloned()
    }

    /// The name every registration carried, in order.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the registry.
    #[must_use]
    pub fn registered_names(&self) -> Vec<String> {
        self.registered_names.lock().expect("registry").clone()
    }

    /// Answers every later registration of a device the registry does not
    /// know with 409, as warren-api does past the active-device cap.
    pub fn reach_device_limit(&self) {
        self.device_limit_reached.store(true, Ordering::SeqCst);
    }

    /// Revokes `id`, as another device of the account does.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the registry.
    pub fn revoke_device(&self, id: DeviceId) {
        self.revoked_devices.lock().expect("registry").insert(id);
    }

    /// Whether `id` was revoked.
    ///
    /// # Panics
    ///
    /// When a test panicked while holding the registry.
    #[must_use]
    pub fn is_revoked(&self, id: DeviceId) -> bool {
        self.revoked_devices.lock().expect("registry").contains(&id)
    }

    fn devices_route(&self, request: &HttpRequest) -> HttpResponse {
        let path = request
            .url
            .split_once("/v1/devices")
            .map_or("", |(_, rest)| rest);
        match (request.method, path.strip_prefix('/')) {
            (Method::Post, None) => {
                let registration: DeviceRegistration =
                    serde_json::from_slice(&request.body).expect("a registration");
                self.registered_names
                    .lock()
                    .expect("registry")
                    .push(registration.name.clone());
                if self.is_revoked(registration.device_id) {
                    return HttpResponse::new(403, br#"{"error":"device_revoked"}"#.to_vec());
                }
                let mut devices = self.devices.lock().expect("registry");
                let key = String::from(registration.device_id);
                if !devices.contains_key(&key) && self.device_limit_reached.load(Ordering::SeqCst) {
                    return HttpResponse::new(409, Vec::new());
                }
                // warren-api keeps a known device's name: a rename goes
                // through PATCH, from whichever device of the account.
                let kept = devices
                    .entry(key)
                    .and_modify(|known| {
                        known.platform = registration.platform;
                        known.app_version.clone_from(&registration.app_version);
                    })
                    .or_insert(registration);
                let view = view_of(kept, true);
                HttpResponse::new(200, serde_json::to_vec(&view).expect("serializes"))
            }
            (Method::Get, None) => {
                let this = path.strip_prefix("?device_id=").unwrap_or_default();
                let revoked = self.revoked_devices.lock().expect("registry").clone();
                let devices = self
                    .devices
                    .lock()
                    .expect("registry")
                    .iter()
                    .filter(|(_, d)| !revoked.contains(&d.device_id))
                    .map(|(id, d)| view_of(d, id == this))
                    .collect();
                let list = DeviceListResponse {
                    devices,
                    older_client_seen_on: None,
                };
                HttpResponse::new(200, serde_json::to_vec(&list).expect("serializes"))
            }
            (Method::Patch, Some(id)) => {
                let rename: DeviceRename = serde_json::from_slice(&request.body).expect("a rename");
                match self.devices.lock().expect("registry").get_mut(id) {
                    Some(device) => {
                        device.name = rename.name;
                        HttpResponse::new(204, Vec::new())
                    }
                    None => HttpResponse::new(404, Vec::new()),
                }
            }
            (Method::Delete, Some(id)) => {
                let id = DeviceId::try_from(id.to_owned()).expect("a device id");
                self.revoke_device(id);
                HttpResponse::new(204, Vec::new())
            }
            _ => HttpResponse::new(405, Vec::new()),
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
            route_admission: None,
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
        HttpResponse::new(
            200,
            serde_json::to_vec(&TokenIssueResponse { epochs }).expect("serializes"),
        )
    }
}

fn view_of(registration: &DeviceRegistration, this_device: bool) -> DeviceView {
    DeviceView {
        device_id: registration.device_id,
        name: registration.name.clone(),
        platform: registration.platform,
        app_version: registration.app_version.clone(),
        registered_on: "2026-10-28".to_owned(),
        last_seen_on: "2026-10-28".to_owned(),
        this_device,
    }
}

impl HttpTransport for FakeEntitlementIssuer {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        if request.url.contains("/v1/devices") {
            return Ok(self.devices_route(&request));
        }
        if request.url.ends_with("/v1/port-entitlements/keys")
            || request.url.ends_with("/v1/tokens/keys")
        {
            self.directory_fetches.fetch_add(1, Ordering::SeqCst);
            return Ok(HttpResponse::new(
                200,
                serde_json::to_vec(&self.directory()).expect("serializes"),
            ));
        }
        assert!(
            request.url.ends_with("/v1/port-entitlements/issue")
                || request.url.ends_with("/v1/tokens/issue"),
            "a credential client must never reach {}",
            request.url
        );
        if self.banned.load(Ordering::SeqCst) {
            return Ok(HttpResponse::new(403, BANNED_BODY.as_bytes().to_vec()));
        }
        Ok(self.issue(&request.body))
    }
}
