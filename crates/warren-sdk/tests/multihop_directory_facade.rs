//! Facade behavior unique to the multihop directory fetch: a `404` (no directory
//! published) maps to `SdkError::NoMultihopDirectory` rather than a transport
//! error. The freshness (`expires_at`) and anti-rollback (`generation`) paths
//! share their code with the signed-exit-list path (see `discovery_enforcement`)
//! and the directory's PKI/signature checks are unit-tested in warren-discovery.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_sdk::discovery::DirectoryError;
use warren_sdk::discovery::multihop_directory::test_helpers::mint_directory_json;
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::{GenerationStore, SdkError, WarrenClient};

/// A [`GenerationStore`] pinned to a fixed anti-rollback floor (test fixture).
struct FixedFloor(u64);

impl GenerationStore for FixedFloor {
    fn load_floor(&self) -> u64 {
        self.0
    }
    fn store_floor(&self, _generation: u64) {}
}

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

#[tokio::test]
async fn an_expired_directory_is_rejected_as_stale() {
    // Distinct from the signed-list freshness path: the directory has its own
    // expires_at check in the facade. signed two days ago, expired yesterday.
    let (root, op, server) = (
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let json = mint_directory_json(&root, &op, &server, 1, now - 2 * 86_400, now - 86_400);
    let client = client_with_roots(json, &server, &[&root]);

    match client.fetch_multihop_directory().await {
        Err(SdkError::StaleMultihopDirectory) => {}
        other => panic!("expected StaleMultihopDirectory, got {other:?}"),
    }
}

#[tokio::test]
async fn a_directory_below_the_generation_floor_is_rejected_as_rolled_back() {
    // The directory keeps its OWN anti-rollback floor (a separate sequence from the
    // signed exit list): a generation below the trusted floor is a replay.
    let (root, op, server) = (
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    );
    let (signed_at, expires_at) = window();
    let json = mint_directory_json(&root, &op, &server, 1, signed_at, expires_at);
    let (identity, _m) = WarrenIdentity::generate();
    let client = WarrenClient::builder()
        .identity(identity)
        .api_base("https://api.example.test")
        .server_pubkey_pin(pin(&server))
        .multihop_root_pubkey_pin(pin(&root))
        .multihop_generation_store(Arc::new(FixedFloor(10)))
        .build_with_transport(DirectoryTransport(json))
        .expect("build");

    match client.fetch_multihop_directory().await {
        Err(SdkError::RolledBackMultihopDirectory { got: 1, floor: 10 }) => {}
        other => panic!("expected RolledBackMultihopDirectory, got {other:?}"),
    }
}

#[tokio::test]
async fn full_fetch_exposes_entries_for_entry_selected_circuits() {
    let (root, op, server) = (
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    );
    let (signed_at, expires_at) = window();
    let json = mint_directory_json(&root, &op, &server, 1, signed_at, expires_at);
    let client = client_with_roots(json, &server, &[&root]);

    let dir = client
        .fetch_multihop_directory_full()
        .await
        .expect("verified directory");
    assert_eq!(dir.exits.len(), 2);
    assert_eq!(dir.entries.len(), 2, "every node doubles as an entry hop");

    // The minted fixture has an RO and an NL node: compose the cross circuit.
    let exit = dir
        .exits
        .iter()
        .find(|e| e.country == "RO")
        .expect("RO exit");
    let entry = dir
        .entries
        .iter()
        .find(|e| e.country == "NL")
        .expect("NL entry");
    let dialed = exit
        .via_entry(entry, &dir.policy)
        .expect("distinct cross-country circuit");
    assert_eq!(dialed.endpoint, entry.endpoint);
    assert_eq!(dialed.exit_id, exit.exit_id);
}

#[tokio::test]
async fn sdk_selected_circuit_respects_country_and_as_diversity() {
    use warren_sdk::discovery::{CircuitPolicy, VerifiedEntry, VerifiedExit};

    fn exit(tag: u8, country: &str, asn: u32) -> VerifiedExit {
        VerifiedExit {
            exit_id: [tag; 16],
            exit_ed25519_pubkey: [tag; 32],
            exit_x25519_multihop_pubkey: [tag; 32],
            endpoint: format!("198.51.100.{tag}:443").parse().unwrap(),
            country: country.to_owned(),
            asn,
            city: "City".to_owned(),
            weight: 100,
            dns_disabled: false,
            cover_domain: None,
            tcp_fallback: false,
            edge_cert_sha256: None,
            exit_mlkem768_pubkey: None,
        }
    }
    fn entry(tag: u8, country: &str, asn: u32) -> VerifiedEntry {
        VerifiedEntry {
            relay_ed25519_pubkey: [tag; 32],
            endpoint: format!("198.51.100.{tag}:443").parse().unwrap(),
            country: country.to_owned(),
            asn,
            city: "City".to_owned(),
            weight: 100,
            cover_domain: None,
            tcp_fallback: false,
            edge_cert_sha256: None,
            exit_id: [tag; 16],
        }
    }

    // Fleet spans AS100 and AS200, so AS diversity is mandatory.
    let de = exit(1, "DE", 100);
    let same_country = entry(2, "DE", 200);
    let same_as = entry(3, "NL", 100);
    let diverse = entry(4, "NL", 200);
    let policy = CircuitPolicy::from_asns([100, 200]);

    assert!(
        de.via_entry(&same_country, &policy).is_none(),
        "an SDK client must not build a same-country circuit"
    );
    assert!(
        de.via_entry(&same_as, &policy).is_none(),
        "an SDK client must not build a same-AS circuit on a multi-AS fleet"
    );
    assert!(
        de.via_entry(&diverse, &policy).is_some(),
        "a country- and AS-diverse pair still composes"
    );
}
