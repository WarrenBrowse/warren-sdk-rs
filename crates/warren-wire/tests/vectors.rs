//! Replays the shared handshake golden vectors in `vectors/handshake.json`.

use serde::Deserialize;
use warren_wire::{
    DEVICE_ID_LEN, Setup, SetupAck, decode_setup, decode_setup_ack, encode_setup, encode_setup_ack,
};

#[derive(Deserialize)]
struct Vectors {
    protocol_version: u8,
    setup: SetupSection,
    setup_ack: SetupAckSection,
}

#[derive(Deserialize)]
struct SetupSection {
    vectors: Vec<SetupVec>,
}

#[derive(Deserialize)]
struct SetupVec {
    protocol_version: u8,
    features: u32,
    connection_index: u8,
    total_connections: u8,
    daita_support: bool,
    device_id_hex: String,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct SetupAckSection {
    vectors: Vec<SetupAckVec>,
}

#[derive(Deserialize)]
struct SetupAckVec {
    protocol_version: u8,
    tunnel_ipv4: [u8; 4],
    tunnel_ipv6_hex: Option<String>,
    exit_pubkey_hex: String,
    max_mtu: u16,
    multiconn_attached: bool,
    bytes_hex: String,
}

fn load() -> Vectors {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/handshake.json");
    let raw = std::fs::read_to_string(path).expect("read vectors/handshake.json");
    serde_json::from_str(&raw).expect("parse vectors/handshake.json")
}

fn device_id(s: &str) -> [u8; DEVICE_ID_LEN] {
    hex::decode(s).expect("hex").try_into().expect("16 bytes")
}

#[test]
fn setup_vectors_match() {
    let v = load();
    assert_eq!(
        v.protocol_version,
        warren_wire::PROTOCOL_VERSION,
        "vector file pins a different PROTOCOL_VERSION than the crate"
    );
    for vec in &v.setup.vectors {
        let s = Setup {
            protocol_version: vec.protocol_version,
            features: vec.features,
            connection_index: vec.connection_index,
            total_connections: vec.total_connections,
            daita_support: vec.daita_support,
            device_id: device_id(&vec.device_id_hex),
        };
        assert_eq!(
            hex::encode(encode_setup(&s).expect("encode")),
            vec.bytes_hex,
            "Setup encode bytes drifted"
        );
        let decoded = decode_setup(&hex::decode(&vec.bytes_hex).expect("hex")).expect("decode");
        assert_eq!(decoded, s, "Setup decode drifted");
    }
}

#[test]
fn setup_ack_vectors_match() {
    let v = load();
    for vec in &v.setup_ack.vectors {
        let exit_pubkey: [u8; 32] = hex::decode(&vec.exit_pubkey_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let tunnel_ipv6 = vec
            .tunnel_ipv6_hex
            .as_ref()
            .map(|h| hex::decode(h).expect("hex").try_into().expect("16 bytes"));
        let a = SetupAck {
            protocol_version: vec.protocol_version,
            tunnel_ipv4: vec.tunnel_ipv4,
            tunnel_ipv6,
            exit_pubkey,
            max_mtu: vec.max_mtu,
            multiconn_attached: vec.multiconn_attached,
            daita_spec: None,
        };
        assert_eq!(
            hex::encode(encode_setup_ack(&a).expect("encode")),
            vec.bytes_hex,
            "SetupAck encode bytes drifted"
        );
        let decoded = decode_setup_ack(&hex::decode(&vec.bytes_hex).expect("hex")).expect("decode");
        assert_eq!(decoded, a, "SetupAck decode drifted");
    }
}
