//! Replays `vectors/device_revocation_v1.json` through the client: the
//! revocation it signs, and what it concludes from each 403 `device_revoked`
//! body. Only the genuine statement may let a revoked device erase its
//! identity; every other case disconnects it and keeps the identity.

use ed25519_dalek::SigningKey;
use warren_api::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use warren_api::{
    ClientError, DeviceId, DeviceRevocation, DeviceRevocationError, TokenIssueRequest,
    WarrenApiClient,
};
use warren_identity::WarrenIdentity;

#[derive(serde::Deserialize)]
struct Vector {
    wallet: Wallet,
    device_id: DeviceIdCase,
    revoked_at_unix_secs: u64,
    signature_hex: String,
    refusal_json: String,
    invalid: Vec<Invalid>,
}

#[derive(serde::Deserialize)]
struct Wallet {
    signing_seed_hex: String,
}

#[derive(serde::Deserialize)]
struct DeviceIdCase {
    b64url: String,
}

#[derive(serde::Deserialize)]
struct Invalid {
    name: String,
    refusal_json: String,
    expect: String,
}

fn vector() -> Vector {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/device_revocation_v1.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path} ({e}); run `git submodule update --init vectors`"));
    serde_json::from_str(&raw).expect("device_revocation_v1.json parses")
}

/// Answers every request with one canned response.
struct Canned(u16, String);

impl HttpTransport for Canned {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, TransportError> {
        Ok(HttpResponse::new(self.0, self.1.clone().into_bytes()))
    }
}

fn wallet_client(v: &Vector, status: u16, body: &str) -> WarrenApiClient<Canned> {
    let mut seed = [0u8; 32];
    hex::decode_to_slice(&v.wallet.signing_seed_hex, &mut seed).expect("seed hex");
    WarrenApiClient::new(
        "https://api.example.test",
        WarrenIdentity::from_signing_key(SigningKey::from_bytes(&seed)),
        Canned(status, body.to_owned()),
    )
}

fn device(v: &Vector) -> DeviceId {
    DeviceId::try_from(v.device_id.b64url.clone()).expect("device id parses")
}

/// What the client concludes from the refusal `body` of an issuance this
/// device asked for.
async fn verdict(v: &Vector, body: &str) -> Result<(), DeviceRevocationError> {
    let client = wallet_client(v, 403, body);
    let request = TokenIssueRequest {
        epochs: Vec::new(),
        device_id: Some(device(v)),
    };
    let err = client.issue_tokens(&request).await.expect_err("refused");
    let ClientError::DeviceRevoked { revocation } = err else {
        panic!("a device_revoked body must stay a revocation: {err:?}");
    };
    client.verify_device_revocation(revocation.as_ref(), device(v))
}

#[tokio::test]
async fn the_genuine_statement_lets_the_device_erase_itself() {
    let v = vector();
    assert_eq!(verdict(&v, &v.refusal_json).await, Ok(()));
}

#[tokio::test]
async fn every_refused_case_keeps_the_identity() {
    let v = vector();
    assert!(!v.invalid.is_empty());
    for case in &v.invalid {
        let expected = match case.expect.as_str() {
            "unsigned" => DeviceRevocationError::Unsigned,
            "malformed" => DeviceRevocationError::Malformed,
            "bad_signature" => DeviceRevocationError::BadSignature,
            other => panic!("{}: unknown outcome {other}", case.name),
        };
        assert_eq!(
            verdict(&v, &case.refusal_json).await,
            Err(expected),
            "{}",
            case.name
        );
    }
}

#[test]
fn the_statement_this_client_would_send_is_the_vectors() {
    let v = vector();
    let client = wallet_client(&v, 204, "");
    let statement = DeviceRevocation {
        revoked_at_unix_secs: v.revoked_at_unix_secs,
        signature_hex: v.signature_hex.clone(),
    };
    assert_eq!(
        client.verify_device_revocation(Some(&statement), device(&v)),
        Ok(())
    );
}
