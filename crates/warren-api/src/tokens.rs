//! Anonymous session-token client (Privacy Pass, ADR-0006 / doc 64).
//!
//! Minting flow: fetch the issuer directory ([`crate::WarrenApiClient::token_keys`],
//! unsigned), blind a fixed-size batch per epoch against that epoch's
//! published key, submit the blinded batches (wallet-signed
//! [`crate::WarrenApiClient::issue_tokens`] - the only step that names the
//! wallet), then finalize and verify the tokens locally. The finalized tokens
//! are unlinkable to the wallet by the blind-RSA construction.
//!
//! The client hardcodes NO protocol policy: epoch length, batch quota and the
//! challenge context label all come from the self-describing directory, and
//! the frozen challenge derivation itself lives in the engine
//! (`TokenChallenge::for_epoch`). The only local inputs are the current time
//! and an RNG (an injected system boundary, per the shared TDD rules).
//!
//! Anti-correlation guidance (doc 64): mint on unlock or on a timer, never at
//! connect time, so issuance timing does not mirror session timing.

use std::collections::BTreeMap;

use data_encoding::BASE64URL_NOPAD;
use rand010::CryptoRng;
use warrenguard_token::{IssuerPublicKey, Token, TokenChallenge, TokenError};

use crate::client::{ClientError, WarrenApiClient};
use crate::dto::{TokenEpochRequest, TokenIssueRequest, TokenIssuerDirectory};
use crate::transport::HttpTransport;

/// Error from the token-minting flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenClientError {
    /// The underlying API call failed.
    #[error(transparent)]
    Api(#[from] ClientError),
    /// The directory carries no key for a requested epoch (outside the
    /// published window).
    #[error("issuer directory has no key for epoch {epoch}")]
    MissingEpochKey {
        /// The epoch that has no published key.
        epoch: u64,
    },
    /// A directory entry is internally inconsistent (unparseable SPKI, or a
    /// `token_key_id` that does not match its key). A corrupt or tampered
    /// directory must fail closed before any blinding happens.
    #[error("issuer directory key for epoch {epoch} is invalid")]
    BadDirectoryKey {
        /// The epoch whose entry failed validation.
        epoch: u64,
    },
    /// The directory's policy fields are unusable (zero epoch length or a
    /// zero batch quota).
    #[error("issuer directory carries an unusable policy")]
    BadDirectoryPolicy,
    /// The issuer refused an epoch (not subscribed, already issued, out of
    /// window...). `reason` is the server's machine-readable reject code.
    #[error("issuance refused for epoch {epoch}")]
    EpochRefused {
        /// The refused epoch.
        epoch: u64,
        /// Machine-readable reject code from the issuer, when present.
        reason: Option<String>,
    },
    /// The response batch does not line up with the request (missing epoch,
    /// wrong signature count, or an undecodable signature).
    #[error("issuance response batch mismatch for epoch {epoch}")]
    BatchMismatch {
        /// The epoch whose response batch is malformed.
        epoch: u64,
    },
    /// A token-crypto operation failed (blinding, finalization, or a token
    /// that does not verify under the key it was requested from).
    #[error(transparent)]
    Crypto(#[from] TokenError),
}

/// The finalized tokens minted for one epoch.
pub struct MintedEpoch {
    /// The epoch the tokens are spendable in.
    pub epoch: u64,
    /// The finalized, locally-verified tokens (one per device slot).
    pub tokens: Vec<Token>,
}

impl std::fmt::Debug for MintedEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Tokens are bearer credentials: render the count, never the bytes.
        f.debug_struct("MintedEpoch")
            .field("epoch", &self.epoch)
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

/// The epoch index `now` falls in, per the directory's published epoch
/// length. `None` when the directory policy is unusable (zero length).
#[must_use]
pub fn current_epoch(directory: &TokenIssuerDirectory, now_unix_secs: u64) -> Option<u64> {
    (directory.epoch_secs > 0).then(|| now_unix_secs / directory.epoch_secs)
}

/// The validated public key for `epoch` from the directory: SPKI parsed and
/// its `token_key_id` cross-checked against the published one, so a corrupt
/// entry fails closed here rather than yielding tokens that never verify.
///
/// # Errors
/// [`TokenClientError::MissingEpochKey`] / [`TokenClientError::BadDirectoryKey`].
pub fn epoch_key(
    directory: &TokenIssuerDirectory,
    epoch: u64,
) -> Result<IssuerPublicKey, TokenClientError> {
    let entry = directory
        .keys
        .iter()
        .find(|k| k.epoch == epoch)
        .ok_or(TokenClientError::MissingEpochKey { epoch })?;
    let spki = BASE64URL_NOPAD
        .decode(entry.spki_b64.as_bytes())
        .map_err(|_| TokenClientError::BadDirectoryKey { epoch })?;
    let pk = IssuerPublicKey::from_spki(&spki)
        .map_err(|_| TokenClientError::BadDirectoryKey { epoch })?;
    if pk.key_id().to_hex() != entry.token_key_id {
        return Err(TokenClientError::BadDirectoryKey { epoch });
    }
    Ok(pk)
}

/// Mints the full token batch for each of `epochs`: blind against each
/// epoch's directory key, submit one wallet-signed issue request, finalize
/// and verify every token. All-or-nothing: any refused epoch or malformed
/// batch fails the whole call (the caller retries or narrows the epochs; a
/// partially-minted state is never returned).
///
/// # Errors
/// [`TokenClientError`]; see each variant.
pub async fn mint_tokens<T: HttpTransport, R: CryptoRng + ?Sized>(
    client: &WarrenApiClient<T>,
    directory: &TokenIssuerDirectory,
    epochs: &[u64],
    rng: &mut R,
) -> Result<Vec<MintedEpoch>, TokenClientError> {
    let quota = directory.quota_per_epoch as usize;
    if quota == 0 || directory.epoch_secs == 0 {
        return Err(TokenClientError::BadDirectoryPolicy);
    }

    // Blind locally, per epoch, before anything leaves the device.
    let mut per_epoch = Vec::with_capacity(epochs.len());
    let mut request_epochs = Vec::with_capacity(epochs.len());
    for &epoch in epochs {
        let pk = epoch_key(directory, epoch)?;
        let challenge =
            TokenChallenge::for_epoch(&directory.issuer_name, &directory.context_label, epoch)?;
        let mut blinded = Vec::with_capacity(quota);
        let mut states = Vec::with_capacity(quota);
        for _ in 0..quota {
            let (req, state) = pk.blind_token(rng, &challenge)?;
            blinded.push(BASE64URL_NOPAD.encode(&req));
            states.push(state);
        }
        request_epochs.push(TokenEpochRequest { epoch, blinded });
        per_epoch.push((epoch, pk, states));
    }

    let response = client
        .issue_tokens(&TokenIssueRequest {
            epochs: request_epochs,
        })
        .await?;

    // Finalize, matching response epochs by value (never by position).
    let mut minted = Vec::with_capacity(per_epoch.len());
    for (epoch, pk, states) in per_epoch {
        let out = response
            .epochs
            .iter()
            .find(|e| e.epoch == epoch)
            .ok_or(TokenClientError::BatchMismatch { epoch })?;
        if !out.issued {
            return Err(TokenClientError::EpochRefused {
                epoch,
                reason: out.reject_reason.clone(),
            });
        }
        if out.blind_signatures.len() != states.len() {
            return Err(TokenClientError::BatchMismatch { epoch });
        }
        let mut tokens = Vec::with_capacity(states.len());
        for (state, sig_b64) in states.into_iter().zip(&out.blind_signatures) {
            let sig = BASE64URL_NOPAD
                .decode(sig_b64.as_bytes())
                .map_err(|_| TokenClientError::BatchMismatch { epoch })?;
            let token = pk.finalize_token(state, &sig)?;
            // Belt and braces: a token that does not verify under the key we
            // requested it from must never enter the store.
            pk.verify_token(&token)?;
            tokens.push(token);
        }
        minted.push(MintedEpoch { epoch, tokens });
    }
    Ok(minted)
}

/// In-memory store of minted tokens, keyed by epoch. One token is consumed
/// per connection admission ([`TokenStore::take`] pops it); tokens for past
/// epochs are dead weight and are dropped by [`TokenStore::prune_before`].
///
/// Deliberately RAM-only: tokens are bearer credentials with a bounded
/// lifetime (the prefetch window), and a lost store is recovered by minting
/// at the next epoch, so persisting them would add a disk-theft surface for
/// no availability win.
#[derive(Default)]
pub struct TokenStore {
    per_epoch: BTreeMap<u64, Vec<Token>>,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Renders only epoch -> count, never token bytes (bearer credentials).
        let counts: Vec<(u64, usize)> = self.per_epoch.iter().map(|(e, v)| (*e, v.len())).collect();
        f.debug_struct("TokenStore")
            .field("epochs", &counts)
            .finish()
    }
}

impl TokenStore {
    /// Builds an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a minted batch. Tokens for an epoch accumulate (a re-mint after a
    /// partial spend keeps the remainder usable).
    pub fn insert(&mut self, minted: MintedEpoch) {
        self.per_epoch
            .entry(minted.epoch)
            .or_default()
            .extend(minted.tokens);
    }

    /// Pops one token for `epoch`, or `None` when none remain. Consuming here
    /// (rather than cloning) is what makes "one token = one device slot"
    /// locally true.
    pub fn take(&mut self, epoch: u64) -> Option<Token> {
        let tokens = self.per_epoch.get_mut(&epoch)?;
        let token = tokens.pop();
        if tokens.is_empty() {
            self.per_epoch.remove(&epoch);
        }
        token
    }

    /// Tokens remaining for `epoch`.
    #[must_use]
    pub fn available(&self, epoch: u64) -> usize {
        self.per_epoch.get(&epoch).map_or(0, Vec::len)
    }

    /// Epochs that still hold at least one token, ascending.
    #[must_use]
    pub fn epochs(&self) -> Vec<u64> {
        self.per_epoch.keys().copied().collect()
    }

    /// Drops every epoch strictly before `min_epoch` (spent time is spent).
    pub fn prune_before(&mut self, min_epoch: u64) {
        self.per_epoch = self.per_epoch.split_off(&min_epoch);
    }
}
