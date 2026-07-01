//! Locks in the facade's anti-freeze (`expires_at`) and anti-rollback
//! (`generation`) enforcement on the live-fetch path (security audit HIGH-1).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_sdk::discovery::{
    ExitQuery, JsonEgress, JsonEndpoint, JsonListener, JsonLocation, JsonNode, sign_relay_list,
};
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::{GenerationStore, SdkError, ServerKeyStore, WarrenClient};

const FAR_FUTURE: u64 = 4_000_000_000; // year 2096
const LONG_AGO: u64 = 1_000; // 1970

/// Returns canned bodies in order, one per request.
struct QueueTransport {
    bodies: Mutex<VecDeque<String>>,
}

impl HttpTransport for QueueTransport {
    async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let body = self.bodies.lock().unwrap().pop_front().unwrap_or_default();
        Ok(HttpResponse {
            status: 200,
            body: body.into_bytes(),
        })
    }
}

fn signed_list(server: &SigningKey, generation: u64, expires_at: u64) -> String {
    let node = JsonNode {
        id: "11".repeat(32),
        exit_id: warren_sdk::discovery::warren_types::ExitId::from_bytes([0xa1; 16]),
        location: JsonLocation {
            country: "RO".to_owned(),
            city: "Bucharest".to_owned(),
        },
        weight: 100,
        active: true,
        egress: JsonEgress {
            ipv4: true,
            ipv6: false,
        },
        endpoints: vec![JsonEndpoint {
            addr: "198.51.100.7".to_owned(),
            family: "ipv4".to_owned(),
            listeners: vec![JsonListener {
                port: 443,
                transport: "quic".to_owned(),
                alpn: "h3".to_owned(),
            }],
        }],
        cover_domain: None,
    };
    // Keep the signed validity window within the verifier's cap (7 days).
    let signed_at = expires_at.saturating_sub(86_400);
    let signed = sign_relay_list(vec![node], server, generation, signed_at, expires_at);
    serde_json::to_string(&signed).unwrap()
}

fn client_with(server: &SigningKey, bodies: Vec<String>) -> WarrenClient<QueueTransport> {
    client_with_store(server, bodies, Arc::new(SeededStore::default()))
}

fn client_with_store(
    server: &SigningKey,
    bodies: Vec<String>,
    store: Arc<dyn GenerationStore>,
) -> WarrenClient<QueueTransport> {
    let pin = hex::encode(server.verifying_key().to_bytes());
    let (identity, _m) = WarrenIdentity::generate();
    WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .server_pubkey_pin(pin)
        .generation_store(store)
        .build_with_transport(QueueTransport {
            bodies: Mutex::new(bodies.into()),
        })
        .expect("build")
}

/// A persistent-style store seeded with a prior high-water mark, standing in for
/// the cross-restart anti-rollback floor.
#[derive(Default)]
struct SeededStore(AtomicU64);

impl GenerationStore for SeededStore {
    fn load_floor(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
    fn store_floor(&self, generation: u64) {
        self.0.fetch_max(generation, Ordering::AcqRel);
    }
}

#[tokio::test]
async fn fresh_list_is_accepted() {
    let server = SigningKey::from_bytes(&[0x42; 32]);
    let client = client_with(&server, vec![signed_list(&server, 5, FAR_FUTURE)]);
    let selector = client.fetch_exits().await.expect("fresh list accepted");
    let exit = selector
        .select(&ExitQuery::country("RO"))
        .expect("one exit");
    assert_eq!(exit.location().country_code(), "ro");
}

#[tokio::test]
async fn expired_list_is_rejected() {
    let server = SigningKey::from_bytes(&[0x42; 32]);
    let client = client_with(&server, vec![signed_list(&server, 5, LONG_AGO)]);
    assert!(matches!(
        client.fetch_exits().await,
        Err(SdkError::StaleRelayList)
    ));
}

#[tokio::test]
async fn rolled_back_generation_is_rejected() {
    let server = SigningKey::from_bytes(&[0x42; 32]);
    // First fetch trusts generation 5; the second serves a valid but older
    // generation 3, which must be rejected as a rollback.
    let client = client_with(
        &server,
        vec![
            signed_list(&server, 5, FAR_FUTURE),
            signed_list(&server, 3, FAR_FUTURE),
        ],
    );
    client.fetch_exits().await.expect("first fetch ok");
    assert!(matches!(
        client.fetch_exits().await,
        Err(SdkError::RolledBackRelayList { got: 3, floor: 5 })
    ));
}

#[tokio::test]
async fn persisted_floor_rejects_rollback_on_a_fresh_client() {
    // A persistent store carries the floor across client (restart) boundaries:
    // a brand-new client whose store already knows generation 9 must reject a
    // validly signed generation-4 list without ever having fetched a newer one.
    let server = SigningKey::from_bytes(&[0x42; 32]);
    let store = Arc::new(SeededStore::default());
    store.store_floor(9);

    let client = client_with_store(&server, vec![signed_list(&server, 4, FAR_FUTURE)], store);
    assert!(matches!(
        client.fetch_exits().await,
        Err(SdkError::RolledBackRelayList { got: 4, floor: 9 })
    ));
}

#[tokio::test]
async fn fetch_advances_the_persistent_floor() {
    let server = SigningKey::from_bytes(&[0x42; 32]);
    let store = Arc::new(SeededStore::default());
    let client = client_with_store(
        &server,
        vec![signed_list(&server, 12, FAR_FUTURE)],
        store.clone(),
    );
    client.fetch_exits().await.expect("fetch ok");
    assert_eq!(store.load_floor(), 12);
}

/// A TOFU pin store, standing in for persistent storage.
#[derive(Default)]
struct KeyStore(Mutex<Option<String>>);

impl ServerKeyStore for KeyStore {
    fn load_pin(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn store_pin(&self, server_pubkey_hex: &str) {
        *self.0.lock().unwrap() = Some(server_pubkey_hex.to_owned());
    }
}

#[tokio::test]
async fn tofu_pins_the_first_server_key_and_rejects_a_different_one() {
    let server_a = SigningKey::from_bytes(&[0x42; 32]);
    let server_b = SigningKey::from_bytes(&[0x99; 32]);
    let key_store = Arc::new(KeyStore::default());
    let (identity, _m) = WarrenIdentity::generate();

    let client = WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .server_key_store(key_store.clone())
        .build_with_transport(QueueTransport {
            bodies: Mutex::new(
                vec![
                    signed_list(&server_a, 5, FAR_FUTURE),
                    signed_list(&server_b, 6, FAR_FUTURE),
                ]
                .into(),
            ),
        })
        .expect("build");

    // First fetch: no pin yet, any self-consistent signature is accepted and the
    // key is remembered.
    client
        .fetch_exits()
        .await
        .expect("first use trusts server A");
    assert_eq!(
        key_store.load_pin().as_deref(),
        Some(hex::encode(server_a.verifying_key().to_bytes()).as_str())
    );

    // Second fetch: validly signed by a different server, but we are now pinned
    // to A, so it must be rejected.
    assert!(matches!(
        client.fetch_exits().await,
        Err(SdkError::Discovery(_))
    ));
}
