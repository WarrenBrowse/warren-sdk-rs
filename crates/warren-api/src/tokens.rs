//! Anonymous session-token client (Privacy Pass, ADR-0006).
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
//! Anti-correlation guidance: mint on unlock or on a timer, never at
//! connect time, so issuance timing does not mirror session timing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use data_encoding::BASE64URL_NOPAD;
use rand010::CryptoRng;
use serde::{Deserialize, Serialize};
use warrenguard_token::{IssuerPublicKey, TOKEN_LEN, Token, TokenChallenge, TokenError};

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
    /// A persisted token bundle ([`PersistedTokens`]) failed to parse or
    /// serialize. The body is never echoed (it carries bearer tokens).
    #[error("persisted token bundle is malformed")]
    BadPersistedBundle,
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
/// RAM-only by default: tokens are bearer credentials with a bounded
/// lifetime (the prefetch window), and a lost store is recovered by minting
/// at the next epoch, so persisting them adds a disk-theft surface for no
/// availability win. The documented exception is the seed-free
/// [`PersistedTokens`] bundle, for hosts where the process dies routinely
/// (Android VpnService, iOS app-group handoff): without it every process
/// death strands the already-issued epochs and downgrades sessions to the
/// wallet-identified v6 path.
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

    /// Non-consuming snapshot of every remaining token, serialized, keyed by
    /// epoch. Used to export the store for cross-process persistence (iOS
    /// app-group), where the consumer only needs the serialized bearer bytes.
    #[must_use]
    pub fn snapshot_serialized(&self) -> Vec<(u64, Vec<[u8; TOKEN_LEN]>)> {
        self.per_epoch
            .iter()
            .map(|(epoch, tokens)| (*epoch, tokens.iter().map(Token::serialize).collect()))
            .collect()
    }
}

/// The issuer's machine-readable reject code for its once-per-account-epoch
/// ledger (`warren-api/src/handlers/token.rs::reject_reason`). The only refusal
/// that is definitive for the rest of the epoch, hence the only one that
/// settles it client-side.
const REJECT_ALREADY_ISSUED: &str = "already_issued";

struct ManagerState {
    store: TokenStore,
    /// The published epoch length, learned from the issuer directory or from a
    /// restored bundle. Keeping it independent of the directory lets a
    /// restored store vend tokens before the first (possibly offline) refresh.
    epoch_secs: Option<u64>,
    /// Epochs settled this process: minted into the store, or definitively
    /// refused by the issuer's once-per-account-epoch ledger
    /// (`already_issued`). Transient failures are deliberately NOT recorded so
    /// the next refresh tick retries them; a settled epoch is never re-asked.
    minted: BTreeSet<u64>,
}

/// Keeps a [`TokenStore`] topped up and vends the per-session token stack the
/// app presents to the exit (as serialized token bytes; the tunnel layer wraps
/// each in its wire `SessionToken`).
///
/// Anti-correlation: drive [`Self::refresh`] on unlock and on a coarse
/// timer, never at connect time, so issuance timing does not mirror session
/// timing. [`Self::take_current_stack`] never mints (no issuer call at connect);
/// it only pops. On exhaustion it returns an empty stack, and the tunnel falls
/// back to the v6 wallet-signed path (availability over a temporary anonymity
/// downgrade; the per-epoch quota bounds concurrent sessions anyway).
pub struct TokenManager<T> {
    client: Arc<WarrenApiClient<T>>,
    state: Arc<Mutex<ManagerState>>,
    /// When set, [`Self::refresh`] mints only `current..=current + horizon`
    /// instead of the whole published window. `None` keeps the full-window
    /// prefetch.
    mint_horizon: Option<u64>,
}

impl<T: HttpTransport> TokenManager<T> {
    /// Builds a manager over a wallet-signed API client. Empty until the first
    /// [`Self::refresh`].
    #[must_use]
    pub fn new(client: Arc<WarrenApiClient<T>>) -> Self {
        Self {
            client,
            state: Arc::new(Mutex::new(ManagerState {
                store: TokenStore::new(),
                epoch_secs: None,
                minted: BTreeSet::new(),
            })),
            mint_horizon: None,
        }
    }

    /// Caps [`Self::refresh`] at `current + epochs` instead of the whole
    /// published window. For hosts whose process (and store) dies routinely: a
    /// lost narrow batch strands only `epochs + 1` already-issued epochs at the
    /// issuer (~hours of v6 fallback) where a lost full-window batch strands
    /// the entire prefetch window (~2 days). The issuer evaluates each
    /// requested epoch independently, so a narrowed request needs no
    /// server-side change.
    #[must_use]
    pub fn with_mint_horizon(mut self, epochs: u64) -> Self {
        self.mint_horizon = Some(epochs);
        self
    }

    /// Fetches the issuer directory, prunes spent epochs, and mints every
    /// published epoch from the current one forward that has not been settled
    /// yet. Per-epoch minting is isolated: one refused epoch (e.g. already
    /// issued by a previous run) does not block the others, and only a
    /// definitive `already_issued` refusal settles an epoch; a transient
    /// failure is left retryable for the next tick.
    ///
    /// # Errors
    /// [`TokenClientError`] only when the directory fetch itself fails; a
    /// per-epoch mint refusal or transport error is swallowed.
    pub async fn refresh<R: CryptoRng + ?Sized>(
        &self,
        now_unix_secs: u64,
        rng: &mut R,
    ) -> Result<(), TokenClientError> {
        let directory = self.client.token_keys().await?;
        let Some(current) = current_epoch(&directory, now_unix_secs) else {
            return Err(TokenClientError::BadDirectoryPolicy);
        };

        // Snapshot which epochs still need minting under the lock, then mint
        // WITHOUT holding it (mint_tokens awaits the network).
        let horizon_end = self
            .mint_horizon
            .map_or(u64::MAX, |h| current.saturating_add(h));
        let targets: Vec<u64> = {
            let mut st = self.state.lock().expect("token manager mutex poisoned");
            st.store.prune_before(current);
            st.minted.retain(|&e| e >= current);
            st.epoch_secs = Some(directory.epoch_secs);
            directory
                .keys
                .iter()
                .map(|k| k.epoch)
                .filter(|&e| e >= current && e <= horizon_end && !st.minted.contains(&e))
                .collect()
        };

        for epoch in targets {
            match mint_tokens(&self.client, &directory, &[epoch], rng).await {
                Ok(mut batches) => {
                    let mut st = self.state.lock().expect("token manager mutex poisoned");
                    st.minted.insert(epoch);
                    if let Some(batch) = batches.pop() {
                        st.store.insert(batch);
                    }
                }
                Err(TokenClientError::EpochRefused { reason, .. })
                    if reason.as_deref() == Some(REJECT_ALREADY_ISSUED) =>
                {
                    // The issuer's once-per-account-epoch ledger already holds
                    // this account (a previous run minted the batch): re-asking
                    // can never succeed, so settle the epoch and stop asking.
                    self.state
                        .lock()
                        .expect("token manager mutex poisoned")
                        .minted
                        .insert(epoch);
                }
                Err(_) => {
                    // Anything else (transport error, 5xx, a refusal that can
                    // heal like not_subscribed, a malformed response) proves
                    // nothing about the ledger. Settling the epoch here would
                    // silently downgrade every session of that epoch to the v6
                    // wallet-signed path after one transient failure, so leave
                    // it un-settled and let the next refresh tick retry; if the
                    // issuer HAD recorded the issuance, that retry is answered
                    // by the definitive already_issued refusal above.
                }
            }
        }
        Ok(())
    }

    /// [`Self::refresh`] with an OS-seeded CSPRNG built internally, so callers
    /// (the daemon's refresh task) need no `rand` dependency of their own.
    ///
    /// # Errors
    /// As [`Self::refresh`].
    pub async fn refresh_auto(&self, now_unix_secs: u64) -> Result<(), TokenClientError> {
        use rand010::SeedableRng;
        // Seed synchronously (the !Send thread rng never crosses the await).
        let mut rng = rand010::rngs::StdRng::from_rng(&mut rand010::rng());
        self.refresh(now_unix_secs, &mut rng).await
    }

    /// Tokens currently available for `epoch` (test/observability).
    #[must_use]
    pub fn available(&self, epoch: u64) -> usize {
        self.state
            .lock()
            .expect("token manager mutex poisoned")
            .store
            .available(epoch)
    }

    /// Pops ONE token for the epoch `now` falls in and returns it serialized (a
    /// single-element stack; the tunnel presents the same stack on every bonded
    /// connection so they share one anonymous serial). An empty vec means "no
    /// token this epoch": the tunnel then uses the v6 path. Never mints.
    #[must_use]
    pub fn take_current_stack(&self, now_unix_secs: u64) -> Vec<[u8; TOKEN_LEN]> {
        let mut st = self.state.lock().expect("token manager mutex poisoned");
        let Some(epoch) = st.epoch_secs.filter(|&s| s > 0).map(|s| now_unix_secs / s) else {
            return Vec::new();
        };
        match st.store.take(epoch) {
            Some(token) => vec![token.serialize()],
            None => Vec::new(),
        }
    }

    /// Loads a previously exported bundle ([`Self::export_persistable`]) back
    /// into the store, so a replacement process vends its predecessor's
    /// unspent tokens instead of riding the v6 wallet-signed fallback until a
    /// fresh epoch opens (issuance is once per account and epoch). Malformed
    /// entries are skipped; epochs are NOT settled here, so the next refresh
    /// re-asks and lets the issuer's definitive `already_issued` answer settle
    /// them (correct even if the bundle came from another account's mint).
    /// Returns the number of tokens restored (observability; safe to ignore,
    /// hence no `#[must_use]`).
    #[allow(clippy::must_use_candidate)]
    pub fn restore_persisted(&self, bundle: &PersistedTokens) -> usize {
        let mut st = self.state.lock().expect("token manager mutex poisoned");
        if st.epoch_secs.is_none() && bundle.epoch_secs > 0 {
            st.epoch_secs = Some(bundle.epoch_secs);
        }
        let mut restored = 0;
        for (&epoch, encoded) in &bundle.epochs {
            let tokens: Vec<Token> = encoded
                .iter()
                .filter_map(|e| BASE64URL_NOPAD.decode(e.as_bytes()).ok())
                .filter_map(|bytes| Token::parse(&bytes).ok())
                .collect();
            restored += tokens.len();
            st.store.insert(MintedEpoch { epoch, tokens });
        }
        restored
    }

    /// Exports the current token store as a self-contained, seed-free bundle for
    /// cross-process persistence (iOS app-group container,
    /// anti-correlation): the main app mints on unlock/timer and persists this,
    /// the Network Extension loads it and CONSUMES pre-minted tokens WITHOUT
    /// minting at connect from the device's real IP.
    ///
    /// Returns `None` until the epoch length is known, i.e. after the first
    /// [`Self::refresh`] or a [`Self::restore_persisted`] (the bundle carries
    /// the epoch length so the consumer needs no directory of its own). The
    /// bundle holds only anonymous bearer tokens, never the wallet seed or
    /// pubkey.
    #[must_use]
    pub fn export_persistable(&self) -> Option<PersistedTokens> {
        let st = self.state.lock().expect("token manager mutex poisoned");
        let epoch_secs = st.epoch_secs?;
        Some(PersistedTokens::from_snapshot(
            epoch_secs,
            st.store.snapshot_serialized(),
        ))
    }
}

/// A self-contained, seed-free bundle of pre-minted anonymous tokens.
///
/// Two consumers: the iOS app-group handoff (main app mints, the Network
/// Extension consumes pre-minted tokens without minting at connect time, the
/// anti-correlation requirement), and Android app-private persistence across
/// VpnService process death ([`TokenManager::restore_persisted`]). It holds
/// only anonymous bearer tokens (never the wallet seed or pubkey) plus the
/// published epoch length, so the consumer maps "now" to the current epoch
/// with no issuer-directory fetch and no network. Double-spend within the
/// prefetch window is the accepted price of unlinkability (ADR-0006), bounded
/// by the issuance quota.
#[derive(Clone, Serialize, Deserialize)]
pub struct PersistedTokens {
    /// Published epoch length in seconds; the current epoch is `now / epoch_secs`.
    epoch_secs: u64,
    /// Serialized tokens (base64url, no pad) keyed by epoch.
    epochs: BTreeMap<u64, Vec<String>>,
}

impl std::fmt::Debug for PersistedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Tokens are bearer credentials: render epoch -> count, never the bytes.
        let counts: Vec<(u64, usize)> = self.epochs.iter().map(|(e, v)| (*e, v.len())).collect();
        f.debug_struct("PersistedTokens")
            .field("epoch_secs", &self.epoch_secs)
            .field("epochs", &counts)
            .finish()
    }
}

impl PersistedTokens {
    fn from_snapshot(epoch_secs: u64, snapshot: Vec<(u64, Vec<[u8; TOKEN_LEN]>)>) -> Self {
        let epochs = snapshot
            .into_iter()
            .map(|(epoch, tokens)| {
                let encoded = tokens
                    .iter()
                    .map(|t| BASE64URL_NOPAD.encode(t))
                    .collect::<Vec<_>>();
                (epoch, encoded)
            })
            .collect();
        Self { epoch_secs, epochs }
    }

    /// Parses a persisted bundle from its JSON form.
    ///
    /// # Errors
    /// [`TokenClientError::BadPersistedBundle`] if the body is not the expected
    /// JSON shape (kept typed and no-log; the untrusted body is never echoed).
    pub fn from_json(body: &str) -> Result<Self, TokenClientError> {
        serde_json::from_str(body).map_err(|_| TokenClientError::BadPersistedBundle)
    }

    /// Serializes the bundle to JSON for persistence into the app-group file.
    ///
    /// # Errors
    /// [`TokenClientError::BadPersistedBundle`] on the (practically unreachable)
    /// serialization failure.
    pub fn to_json(&self) -> Result<String, TokenClientError> {
        serde_json::to_string(self).map_err(|_| TokenClientError::BadPersistedBundle)
    }

    /// Tokens remaining for the epoch `now` falls in.
    #[must_use]
    pub fn available(&self, now_unix_secs: u64) -> usize {
        match self.current_epoch(now_unix_secs) {
            Some(epoch) => self.epochs.get(&epoch).map_or(0, Vec::len),
            None => 0,
        }
    }

    /// Pops ONE pre-minted token for the current epoch, consume-only (no mint,
    /// no network), matching [`TokenManager::take_current_stack`]. An empty vec
    /// means "no pre-minted token this epoch"; the tunnel then rides the v6 path.
    #[must_use]
    pub fn take_current_stack(&mut self, now_unix_secs: u64) -> Vec<[u8; TOKEN_LEN]> {
        let Some(epoch) = self.current_epoch(now_unix_secs) else {
            return Vec::new();
        };
        let Some(tokens) = self.epochs.get_mut(&epoch) else {
            return Vec::new();
        };
        // Skip any entry that fails to decode (corrupt persisted blob) rather
        // than handing malformed bytes to the wire.
        while let Some(encoded) = tokens.pop() {
            if let Ok(bytes) = BASE64URL_NOPAD.decode(encoded.as_bytes())
                && let Ok(token) = <[u8; TOKEN_LEN]>::try_from(bytes)
            {
                if tokens.is_empty() {
                    self.epochs.remove(&epoch);
                }
                return vec![token];
            }
        }
        self.epochs.remove(&epoch);
        Vec::new()
    }

    fn current_epoch(&self, now_unix_secs: u64) -> Option<u64> {
        (self.epoch_secs > 0).then(|| now_unix_secs / self.epoch_secs)
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    // A well-formed (but cryptographically meaningless) token: only the byte
    // layout matters for the persistence codec, which never verifies. `marker`
    // varies the nonce so distinct tokens are distinguishable.
    fn fake_token(marker: u8) -> Token {
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[0..2].copy_from_slice(&0x0002u16.to_be_bytes());
        bytes[2] = marker;
        Token::parse(&bytes).expect("well-formed token bytes parse")
    }

    #[test]
    fn store_snapshot_serializes_every_token_non_destructively() {
        let mut store = TokenStore::new();
        store.insert(MintedEpoch {
            epoch: 7,
            tokens: vec![fake_token(1), fake_token(2)],
        });
        let snap = store.snapshot_serialized();
        assert_eq!(
            snap,
            vec![(
                7,
                vec![fake_token(1).serialize(), fake_token(2).serialize()]
            )]
        );
        // Non-destructive: the store still holds both tokens.
        assert_eq!(store.available(7), 2);
    }

    #[test]
    fn persisted_bundle_round_trips_through_json_and_pops_one_token() {
        let bundle = PersistedTokens::from_snapshot(
            100,
            vec![(
                5,
                vec![fake_token(1).serialize(), fake_token(2).serialize()],
            )],
        );
        let json = bundle.to_json().expect("serialize");
        let mut restored = PersistedTokens::from_json(&json).expect("parse");
        // now=550 falls in epoch 5 (550/100).
        assert_eq!(restored.available(550), 2);
        let stack = restored.take_current_stack(550);
        assert_eq!(stack.len(), 1);
        assert_eq!(restored.available(550), 1);
    }

    #[test]
    fn persisted_bundle_empties_the_epoch_and_then_yields_nothing() {
        let mut bundle =
            PersistedTokens::from_snapshot(60, vec![(2, vec![fake_token(9).serialize()])]);
        // now=150 -> epoch 2.
        assert_eq!(bundle.take_current_stack(150).len(), 1);
        assert!(bundle.take_current_stack(150).is_empty());
    }

    #[test]
    fn persisted_bundle_yields_nothing_for_an_epoch_without_tokens() {
        let mut bundle =
            PersistedTokens::from_snapshot(60, vec![(2, vec![fake_token(9).serialize()])]);
        // now=600 -> epoch 10, which holds no tokens.
        assert!(bundle.take_current_stack(600).is_empty());
    }

    #[test]
    fn persisted_bundle_with_zero_epoch_length_is_inert() {
        let mut bundle =
            PersistedTokens::from_snapshot(0, vec![(0, vec![fake_token(1).serialize()])]);
        assert!(bundle.take_current_stack(123).is_empty());
        assert_eq!(bundle.available(123), 0);
    }

    #[test]
    fn persisted_bundle_debug_never_renders_token_bytes() {
        let bundle =
            PersistedTokens::from_snapshot(60, vec![(2, vec![fake_token(0xAB).serialize()])]);
        let rendered = format!("{bundle:?}");
        // Only epoch -> count is shown, never the base64 token payload.
        assert!(rendered.contains("epoch_secs"));
        assert!(!rendered.contains(&BASE64URL_NOPAD.encode(&fake_token(0xAB).serialize())));
    }

    #[test]
    fn persisted_bundle_at_rest_carries_only_epoch_secs_and_epochs() {
        // The at-rest schema is pinned seed-free: any new field (a wallet
        // hint, a device id, key material) would extend what a disk-theft or
        // backup exfiltration learns, so its addition must be a deliberate,
        // reviewed break of this test.
        let bundle = PersistedTokens::from_snapshot(60, vec![(2, vec![fake_token(1).serialize()])]);
        let value: serde_json::Value =
            serde_json::from_str(&bundle.to_json().expect("serialize")).expect("json");
        let mut keys: Vec<&String> = value.as_object().expect("object").keys().collect();
        keys.sort();
        assert_eq!(keys, ["epoch_secs", "epochs"]);
    }

    #[test]
    fn rejects_a_malformed_persisted_body() {
        assert!(matches!(
            PersistedTokens::from_json("not json"),
            Err(TokenClientError::BadPersistedBundle)
        ));
    }
}
