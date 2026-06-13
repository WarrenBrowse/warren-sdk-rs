//! Locks in the facade's anti-freeze (`expires_at`) and anti-rollback
//! (`generation`) enforcement on the live-fetch path (security audit HIGH-1).

use std::collections::VecDeque;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use warren_sdk::SdkError;
use warren_sdk::WarrenClient;
use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_sdk::discovery::{ExitId, ExitQuery, JsonRelay, sign_relay_list};
use warren_sdk::identity::WarrenIdentity;

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
    let relay = JsonRelay {
        endpoint_id: "11".repeat(32),
        exit_id: ExitId::from_bytes([0xa1; 16]),
        ip_addrs: vec!["198.51.100.7:443".to_owned()],
        country: "RO".to_owned(),
        city: "Bucharest".to_owned(),
        weight: 100,
        active: true,
        ipv6_egress: false,
    };
    let signed = sign_relay_list(vec![relay], server, generation, 1, expires_at);
    serde_json::to_string(&signed).unwrap()
}

fn client_with(server: &SigningKey, bodies: Vec<String>) -> WarrenClient<QueueTransport> {
    let pin = hex::encode(server.verifying_key().to_bytes());
    let (identity, _m) = WarrenIdentity::generate();
    WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .server_pubkey_pin(pin)
        .build_with_transport(QueueTransport {
            bodies: Mutex::new(bodies.into()),
        })
}

#[tokio::test]
async fn fresh_list_is_accepted() {
    let server = SigningKey::from_bytes(&[0x42; 32]);
    let client = client_with(&server, vec![signed_list(&server, 5, FAR_FUTURE)]);
    let selector = client.fetch_exits().await.expect("fresh list accepted");
    let exit = selector
        .select(&ExitQuery::country("RO"))
        .expect("one exit");
    assert_eq!(exit.location().country_code(), "RO");
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
