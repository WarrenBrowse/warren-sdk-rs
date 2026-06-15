//! Facade behavior unique to the multihop directory fetch: a `404` (no directory
//! published) maps to `SdkError::NoMultihopDirectory` rather than a transport
//! error. The freshness (`expires_at`) and anti-rollback (`generation`) paths
//! share their code with the signed-exit-list path (see `discovery_enforcement`)
//! and the directory's PKI/signature checks are unit-tested in warren-discovery.

use ed25519_dalek::SigningKey;
use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_sdk::discovery::DirectoryError;
use warren_sdk::discovery::multihop_directory::test_helpers::mint_directory_json;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::{SdkError, WarrenClient};

/// Always answers `404` (the API publishes no directory).
struct NotFoundTransport;

impl HttpTransport for NotFoundTransport {
    async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
        Ok(HttpResponse {
            status: 404,
            body: b"not found".to_vec(),
        })
    }
}

/// Serves a fixed directory JSON body on every request.
struct DirectoryTransport(String);

impl HttpTransport for DirectoryTransport {
    async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
        Ok(HttpResponse {
            status: 200,
            body: self.0.clone().into_bytes(),
        })
    }
}

fn pin(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

/// A fresh validity window (signed just now, expiring within the 7-day cap) so
/// neither the freshness bound nor the validity-window cap masks the PKI-chain
/// assertions. The facade verifies against the real wall clock.
fn window() -> (u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (now - 60, now + 6 * 86_400)
}

fn client_with_roots(
    json: String,
    server: &SigningKey,
    roots: &[&SigningKey],
) -> WarrenClient<DirectoryTransport> {
    let (identity, _m) = WarrenIdentity::generate();
    let mut builder = WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .server_pubkey_pin(pin(server));
    for r in roots {
        builder = builder.multihop_root_pubkey_pin(pin(r));
    }
    builder
        .build_with_transport(DirectoryTransport(json))
        .expect("build")
}

#[tokio::test]
async fn missing_directory_maps_to_no_multihop_directory() {
    let (identity, _m) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .allow_any_server_key()
        .build_with_transport(NotFoundTransport)
        .expect("build");

    match client.fetch_multihop_directory().await {
        Err(SdkError::NoMultihopDirectory) => {}
        other => panic!("expected NoMultihopDirectory, got {other:?}"),
    }
}

#[tokio::test]
async fn configured_root_pin_rejects_a_directory_certified_by_another_root() {
    // The whole point of the offline root anchor: a holder of the online server
    // key alone (here a foreign root signs the operational cert) must NOT be able
    // to mint a directory the client accepts when a root pin is configured.
    let (root, foreign_root, op, server) = (
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[9; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    );
    let (signed_at, expires_at) = window();
    let json = mint_directory_json(&foreign_root, &op, &server, 1, signed_at, expires_at);
    let client = client_with_roots(json, &server, &[&root]);

    match client.fetch_multihop_directory().await {
        Err(SdkError::MultihopDirectory(DirectoryError::BadOperationalCert)) => {}
        other => panic!("expected BadOperationalCert, got {other:?}"),
    }
}

#[tokio::test]
async fn configured_root_pin_accepts_a_directory_certified_by_that_root() {
    let (root, op, server) = (
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    );
    let (signed_at, expires_at) = window();
    let json = mint_directory_json(&root, &op, &server, 1, signed_at, expires_at);
    let client = client_with_roots(json, &server, &[&root]);

    let exits = client
        .fetch_multihop_directory()
        .await
        .expect("the pinned root vouches for the operational key");
    assert_eq!(exits.len(), 2, "both fully-vouched exits returned");
}

#[tokio::test]
async fn without_a_root_pin_the_chain_is_accepted_on_tofu_terms() {
    // Regression guard: omitting the root pin keeps the documented TOFU behavior
    // (the operational cert is not anchored), so an unconfigured client still works.
    let (any_root, op, server) = (
        SigningKey::from_bytes(&[7; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    );
    let (signed_at, expires_at) = window();
    let json = mint_directory_json(&any_root, &op, &server, 1, signed_at, expires_at);
    let client = client_with_roots(json, &server, &[]);

    let exits = client
        .fetch_multihop_directory()
        .await
        .expect("TOFU accepts any self-consistent chain");
    assert_eq!(exits.len(), 2);
}
