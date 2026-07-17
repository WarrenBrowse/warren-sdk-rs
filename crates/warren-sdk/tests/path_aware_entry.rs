//! Facade behavior of the path-aware entry selection: the advisory fetch is
//! best-effort (missing endpoint or garbage body must read as "no
//! advisory", never an error), and the entry pick composes a
//! `via_entry` circuit under the shared diversity policy, falling back to
//! today's weight ordering when no signal exists.

use ed25519_dalek::SigningKey;
use warren_sdk::WarrenClient;
use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_sdk::discovery::multihop_directory::test_helpers::mint_directory_json;
use warren_sdk::identity::WarrenIdentity;

/// Serves the minted directory on the directory path and a programmed
/// response on the path-quality path.
struct SplitTransport {
    directory_json: String,
    path_quality_status: u16,
    path_quality_body: String,
}

impl HttpTransport for SplitTransport {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        if req.url.ends_with("/v1/multihop/path-quality") {
            return Ok(HttpResponse {
                status: self.path_quality_status,
                body: self.path_quality_body.clone().into_bytes(),
            });
        }
        Ok(HttpResponse {
            status: 200,
            body: self.directory_json.clone().into_bytes(),
        })
    }
}

fn window() -> (u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (now - 60, now + 6 * 86_400)
}

fn client_with(
    path_quality_status: u16,
    path_quality_body: &str,
) -> (WarrenClient<SplitTransport>, SigningKey) {
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
        .server_pubkey_pin(hex::encode(server.verifying_key().to_bytes()))
        .multihop_root_pubkey_pin(hex::encode(root.verifying_key().to_bytes()))
        .build_with_transport(SplitTransport {
            directory_json: json,
            path_quality_status,
            path_quality_body: path_quality_body.to_owned(),
        })
        .expect("build");
    (client, server)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn fetch_path_quality_is_none_on_404_and_on_garbage() {
    let (client, _) = client_with(404, "not found");
    assert!(
        client.fetch_path_quality().await.is_none(),
        "an API without the endpoint means no advisory, never an error"
    );

    let (client, _) = client_with(200, "{ not json");
    assert!(
        client.fetch_path_quality().await.is_none(),
        "a garbage body means no advisory, never an error"
    );

    let future_version = r#"{"version":99,"generated_at":0,"entries":[]}"#;
    let (client, _) = client_with(200, future_version);
    assert!(
        client.fetch_path_quality().await.is_none(),
        "an unknown advisory version means no advisory"
    );
}

#[tokio::test]
async fn fetch_path_quality_parses_a_valid_advisory() {
    let body = format!(
        r#"{{"version":1,"generated_at":{now},"entries":[{{"relay_id":"{r}","legs":[{{"exit_id":"{x}","rtt_ms":28,"degraded":false,"sampled_at":{now}}}]}}]}}"#,
        now = now_secs(),
        r = hex::encode([10u8; 16]),
        x = hex::encode([20u8; 16]),
    );
    let (client, _) = client_with(200, &body);
    let adv = client
        .fetch_path_quality()
        .await
        .expect("a valid advisory parses");
    assert_eq!(adv.entries.len(), 1);
    assert_eq!(adv.entries[0].legs[0].rtt_ms, 28);
}

#[tokio::test]
async fn select_multihop_entry_composes_a_policy_legal_circuit() {
    // The minted fleet is two nodes (RO node id [10;16], NL node id
    // [20;16]): for the RO exit, the only policy-legal entry is the NL
    // node, and the circuit view must dial the ENTRY's endpoint while
    // keeping the exit's routing identity.
    let (client, _) = client_with(404, "");
    let dir = client
        .fetch_multihop_directory_full()
        .await
        .expect("directory verifies");
    let exit = dir
        .exits
        .iter()
        .find(|x| x.exit_id == [10; 16])
        .expect("RO exit present")
        .clone();

    let circuit = client
        .select_multihop_entry(&dir, &exit, None, None)
        .expect("a legal entry exists");
    assert_eq!(circuit.exit_id, [10; 16], "exit identity is preserved");
    assert_eq!(
        circuit.endpoint,
        "198.51.100.20:443".parse().unwrap(),
        "the circuit dials the selected ENTRY"
    );
}

#[tokio::test]
async fn a_degraded_only_candidate_is_still_selected_never_fail_closed() {
    let now = now_secs();
    let body = format!(
        r#"{{"version":1,"generated_at":{now},"entries":[{{"relay_id":"{r}","legs":[{{"exit_id":"{x}","rtt_ms":350,"degraded":true,"sampled_at":{now}}}]}}]}}"#,
        r = hex::encode([20u8; 16]),
        x = hex::encode([10u8; 16]),
    );
    let (client, _) = client_with(200, &body);
    let dir = client
        .fetch_multihop_directory_full()
        .await
        .expect("directory verifies");
    let exit = dir
        .exits
        .iter()
        .find(|x| x.exit_id == [10; 16])
        .expect("RO exit present")
        .clone();
    let advisory = client.fetch_path_quality().await;

    let circuit = client
        .select_multihop_entry(&dir, &exit, advisory.as_ref(), None)
        .expect("a degraded sole candidate still forms a circuit");
    assert_eq!(circuit.endpoint, "198.51.100.20:443".parse().unwrap());
}
