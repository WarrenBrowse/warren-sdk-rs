//! Replays the shared signed relay list golden vector in `vectors/relays.json`.

use serde::Deserialize;
use warren_discovery::{ExitId, verify_signed_relay_list};

#[derive(Deserialize)]
struct Vectors {
    signed_version: u32,
    server_pubkey_hex: String,
    signed_json: String,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    relay_count: usize,
    relays: Vec<ExpectedRelay>,
}

#[derive(Deserialize)]
struct ExpectedRelay {
    endpoint_id_hex: String,
    exit_id_hex: String,
    country: String,
    city: String,
    weight: u64,
    ipv6_egress: bool,
    addrs: Vec<String>,
}

fn load() -> Vectors {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/relays.json");
    let raw = std::fs::read_to_string(path).expect("read vectors/relays.json");
    serde_json::from_str(&raw).expect("parse vectors/relays.json")
}

#[test]
fn signed_relay_list_vector_verifies_and_resolves() {
    let v = load();
    assert_eq!(v.signed_version, warren_discovery::SIGNED_VERSION);

    // Pinned verification must accept the frozen JSON.
    let verified = verify_signed_relay_list(&v.signed_json, Some(&v.server_pubkey_hex))
        .expect("frozen signed list must verify against the pinned pubkey");

    assert_eq!(verified.generation, v.expected.generation);
    assert_eq!(verified.signed_at, v.expected.signed_at);
    assert_eq!(verified.expires_at, v.expected.expires_at);
    assert_eq!(verified.relays.len(), v.expected.relay_count);

    for (got, exp) in verified.relays.relays().iter().zip(&v.expected.relays) {
        assert_eq!(hex::encode(got.endpoint_id()), exp.endpoint_id_hex);
        assert_eq!(got.exit_id(), ExitId::from_hex(&exp.exit_id_hex).unwrap());
        // The verifier normalizes the country to lower-case ASCII (stable geo
        // filtering); the golden vector keeps the wire case, so compare loosely.
        assert!(
            got.location()
                .country_code()
                .eq_ignore_ascii_case(&exp.country),
            "country {} != vector {}",
            got.location().country_code(),
            exp.country
        );
        assert_eq!(got.location().city(), exp.city);
        assert_eq!(got.weight(), exp.weight);
        assert_eq!(got.ipv6_egress(), exp.ipv6_egress);
        let got_addrs: Vec<String> = got.addrs().iter().map(ToString::to_string).collect();
        assert_eq!(got_addrs, exp.addrs);
    }
}

#[test]
fn frozen_vector_listeners_advertise_the_h3_alpn_contract() {
    // ALPN `h3` over QUIC is a FROZEN wire contract (see ARCHITECTURE.md). The
    // SDK dials `h3` unconditionally rather than sourcing the per-listener `alpn`
    // field, so this pins the assumption: a future v6 list whose dialable
    // listeners diverge from quic/h3 fails here and forces a deliberate decision
    // instead of a silent ALPN mismatch at TLS time.
    let v = load();
    let list: warren_discovery::SignedRelayList =
        serde_json::from_str(&v.signed_json).expect("parse signed_json");
    let mut dialable = 0;
    for node in &list.nodes {
        for ep in &node.endpoints {
            for l in &ep.listeners {
                assert_eq!(l.transport, "quic", "only QUIC listeners are dialable");
                assert_eq!(l.alpn, "h3", "ALPN h3 is the frozen TLS contract");
                dialable += 1;
            }
        }
    }
    assert!(
        dialable > 0,
        "vector must exercise at least one dialable listener"
    );
}

#[test]
fn wrong_pin_rejects_the_frozen_vector() {
    let v = load();
    let wrong = "00".repeat(32);
    assert!(verify_signed_relay_list(&v.signed_json, Some(&wrong)).is_err());
}
