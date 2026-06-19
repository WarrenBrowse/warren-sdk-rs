//! Warren TLS 1.3 configuration backed by raw Ed25519 public keys (RFC 7250).
//!
//! This is now a thin re-export of the engine's `warrenguard-tls`, so a single
//! RPK TLS implementation is shared with warren-core: the quinn client/server
//! configs, the SNI pubkey codec ([`name`]), and the authenticated-peer-key
//! extraction ([`peer_pubkey`]). There is no PKI: the peer pubkey is encoded in
//! the TLS server name (SNI) and the verifier checks the presented raw key
//! against it. 0-RTT is disabled and TLS 1.2 is rejected.

pub use warrenguard_tls::{
    WarrenPubkey, WarrenTlsError, default_crypto_provider, make_client_config, make_server_config,
    name, peer_pubkey,
};
