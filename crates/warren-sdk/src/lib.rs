//! Warren VPN client SDK: the single crate applications depend on.
//!
//! The SDK is split into portable layers (identity, wire codecs, account API,
//! discovery, transport, networking backends). This umbrella crate re-exports
//! them and, from Phase P8, will expose the high-level [`WarrenClient`] facade
//! that orchestrates the full flow:
//!
//! ```ignore
//! let (identity, mnemonic) = warren_sdk::identity::WarrenIdentity::generate();
//! let client = WarrenClient::builder()
//!     .identity(identity)
//!     .api_base("https://api.warrenbrowse.com")
//!     .server_pubkey_pin(PINNED_HEX)
//!     .build().await?;
//! let exit = client.select_exit(ExitQuery::country("RO"))?;
//! let session = client.connect(exit, ConnectMode::default()).await?; // non-root proxy
//! ```
//!
//! Today only the identity layer is implemented and re-exported below.

/// Non-custodial Ed25519 identity (BIP39 mnemonic, SS58 `wb…` address, request
/// signing). Re-exported from the `warren-identity` crate.
pub use warren_identity as identity;

#[cfg(test)]
mod tests {
    use super::identity::WarrenIdentity;

    #[test]
    fn reexports_identity_layer() {
        let (id, phrase) = WarrenIdentity::generate();
        assert!(id.address().starts_with("wb"));
        let restored = WarrenIdentity::from_mnemonic(&phrase).expect("valid mnemonic");
        assert_eq!(id.public_key(), restored.public_key());
    }
}
