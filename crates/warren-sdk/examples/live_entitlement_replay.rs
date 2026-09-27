//! Live proof that the issuer serves a wallet's port-entitlement batch again
//! to a second process, because the batch is derived from the wallet
//! (`BlindingKey::port_entitlement`), where a batch drawn from the CSPRNG was
//! answered `already_issued` for the whole 48 h prefetch window.
//!
//! Run it twice, as two processes, against the same epoch (beta):
//! `WARREN_API_URL=https://api.beta.warrenbrowse.com
//! WARREN_MNEMONIC="word1 ... word12"
//! cargo run -p warren-sdk --example live_entitlement_replay`
//!
//! It mints one epoch of the port-entitlement class, by default the newest
//! the directory publishes (the one least likely to be reserved already by a
//! batch another build blinded otherwise); `ENTITLEMENT_EPOCH` picks another.
//! Every tag is verified at mint time against the published attribution key.
//!
//! Printed per run: the epoch, the count, and a digest of the entitlements
//! and of the tags. Two runs print the same entitlement digest (the issuer
//! re-served the batch) and different tag digests (the tags are minted
//! afresh at every service). Nothing printed names an entitlement, a tag or
//! the wallet: the digests only let two runs be compared.

use std::hash::{Hash, Hasher};

use warren_sdk::api::{
    BlindingKey, CredentialClass, ReqwestTransport, TokenClientError, WarrenApiClient, mint_tokens,
};
use warren_sdk::identity::{WarrenIdentity, seed_from_mnemonic};

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A digest to compare two runs by, not a commitment: the fixed-key SipHash
/// of `std`, the same in every process.
fn digest<'a>(items: impl Iterator<Item = &'a [u8]>) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for item in items {
        item.hash(&mut hasher);
    }
    hasher.finish()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::var("WARREN_MNEMONIC")
        .map_err(|_| "set WARREN_MNEMONIC to a subscribed account's words")?;
    let api_base = std::env::var(warren_sdk::product::API_URL_ENV)
        .unwrap_or_else(|_| warren_sdk::product::API_URL.to_owned());
    let seed = seed_from_mnemonic(phrase.trim())?;
    let client = WarrenApiClient::new(
        api_base,
        WarrenIdentity::from_seed(&seed),
        ReqwestTransport::try_new()?,
    );

    let directory = client
        .token_keys_for(CredentialClass::PortEntitlement)
        .await?;
    let epoch = match std::env::var("ENTITLEMENT_EPOCH") {
        Ok(epoch) => epoch.parse()?,
        Err(_) => directory
            .keys
            .iter()
            .map(|k| k.epoch)
            .max()
            .ok_or("the directory publishes no epoch")?,
    };

    let minted = mint_tokens(
        &client,
        &directory,
        &[epoch],
        &BlindingKey::port_entitlement(&seed),
    )
    .await;
    match minted {
        Ok(batches) => {
            let batch = batches.first().ok_or("no batch in the answer")?;
            let entitlements: Vec<_> = batch.tokens.iter().map(|t| t.serialize()).collect();
            println!(
                "{} epoch {epoch}: served {} entitlement(s), tags verified; entitlements {:016x}, tags {:016x}",
                now_unix_secs(),
                entitlements.len(),
                digest(entitlements.iter().map(|t| t.as_slice())),
                digest(
                    batch
                        .attribution_tags
                        .iter()
                        .map(|t| t.as_bytes().as_slice())
                ),
            );
        }
        Err(TokenClientError::EpochRefused { reason, .. }) => {
            println!(
                "{} epoch {epoch}: refused ({})",
                now_unix_secs(),
                reason.as_deref().unwrap_or("no reason")
            );
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
