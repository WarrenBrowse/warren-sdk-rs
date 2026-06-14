//! Facade behavior unique to the multihop directory fetch: a `404` (no directory
//! published) maps to `SdkError::NoMultihopDirectory` rather than a transport
//! error. The freshness (`expires_at`) and anti-rollback (`generation`) paths
//! share their code with the signed-exit-list path (see `discovery_enforcement`)
//! and the directory's PKI/signature checks are unit-tested in warren-discovery.

use warren_sdk::api::{HttpRequest, HttpResponse, HttpTransport, TransportError};
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
