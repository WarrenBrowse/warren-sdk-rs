//! Warren TLS 1.3 configuration backed by raw Ed25519 public keys (RFC 7250).
//!
//! This is now a thin re-export of the engine's `warrenguard-tls`, so a single
//! RPK TLS implementation is shared with warren-core: the quinn client/server
//! configs, the SNI pubkey codec ([`name`]), and the channel-binding helper
//! ([`channel_binding`]) that anchors the in-band entry-relay identity proof
//! ([`verify_relay_auth`]). There is no PKI on the RPK path: the EXIT pubkey is
//! encoded in the TLS server name (SNI) and the client's verifier checks the
//! presented raw key against it. Since protocol v5 the exit requests no client
//! certificate. 0-RTT is disabled and TLS 1.2 is rejected.

pub use warrenguard_tls::{
    WarrenPubkey, WarrenTlsError, channel_binding, default_crypto_provider, make_client_config,
    make_client_config_webpki, make_server_config, mozilla_root_store, name, verify_relay_auth,
};
