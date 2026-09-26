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
//! and the blinding material: derived from the wallet for the session and
//! browser-proxy classes ([`BlindingKey`], so every client of a wallet sends
//! the same batch and is served), drawn from the CSPRNG for port entitlements.
//!
//! Anti-correlation guidance: mint on unlock or on a timer, never at
//! connect time, so issuance timing does not mirror session timing.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::VerifyingKey;
use rand010::{CryptoRng, SeedableRng};
use serde::{Deserialize, Serialize};
use warren_contract::pf_attribution::{AttributionTag, AttributionTagError, EntitlementEnvelope};
use warrenguard_token::{
    ClientState, IssuerPublicKey, TOKEN_LEN, Token, TokenChallenge, TokenError, TokenSerial,
};
use zeroize::Zeroizing;

use crate::client::{ClientError, WarrenApiClient};
use crate::dto::{TokenEpochRequest, TokenIssueRequest, TokenIssuerDirectory};
use crate::route_admission::RouteAdmission;
use crate::token_blinding::BlindingKey;
use crate::transport::HttpTransport;

// The envelope declares the entitlement length itself so the contract does not
// pull the RSA stack; the two must agree for a minted token to fit it.
const _: () = assert!(TOKEN_LEN == warren_contract::pf_attribution::TOKEN_LEN);

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
    /// The engine drew its blinding material in another order than the
    /// wallet-derived batch is defined by. Raised before anything is sent: a
    /// batch built anyway could not be rebuilt by any other client of the
    /// wallet, and it would spend the epoch for this one alone.
    #[error("token blinding no longer draws its material in the derived order")]
    BlindingDrawOrder,
    /// The port-entitlement directory publishes no attribution verifying key,
    /// or one that is not an Ed25519 public key. Raised before anything is
    /// blinded: issuance is once per account and epoch, and a batch whose tags
    /// cannot be checked would spend it for credentials no exit accepts.
    #[error("port-entitlement directory carries no usable attribution key")]
    BadAttributionKey,
    /// A port-entitlement batch does not carry exactly one attribution tag per
    /// blind signature. An entitlement without its tag is refused by every
    /// exit.
    #[error(
        "port-entitlement batch for epoch {epoch} carries {tags} attribution tags for {signatures} signatures"
    )]
    AttributionTagCount {
        /// The epoch whose batch is malformed.
        epoch: u64,
        /// Blind signatures in the batch.
        signatures: usize,
        /// Attribution tags in the batch.
        tags: usize,
    },
    /// An attribution tag was minted for another epoch than the entitlement
    /// it travels with. The exit refuses the pair.
    #[error("attribution tag in the batch for epoch {epoch} names another epoch")]
    AttributionTagEpoch {
        /// The epoch the batch was requested for.
        epoch: u64,
    },
    /// An attribution tag does not verify under the published attribution
    /// key.
    #[error("attribution tag in the batch for epoch {epoch} does not verify")]
    AttributionTagInvalid {
        /// The epoch whose batch carries the tag.
        epoch: u64,
        /// Why the tag was refused.
        #[source]
        source: AttributionTagError,
    },
}

/// The finalized tokens minted for one epoch.
pub struct MintedEpoch {
    /// The epoch the tokens are spendable in.
    pub epoch: u64,
    /// The finalized, locally-verified tokens (one per device slot).
    pub tokens: Vec<Token>,
    /// Port-entitlement class only: the verified attribution tag minted beside
    /// each token, `attribution_tags[i]` travelling with `tokens[i]`. Empty for
    /// every other class.
    pub attribution_tags: Vec<AttributionTag>,
}

impl std::fmt::Debug for MintedEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Tokens are bearer credentials: render the count, never the bytes.
        f.debug_struct("MintedEpoch")
            .field("epoch", &self.epoch)
            .field("tokens", &self.tokens.len())
            .field("attribution_tags", &self.attribution_tags.len())
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

/// The key attribution tags verify under, from a port-entitlement directory.
fn attribution_key(directory: &TokenIssuerDirectory) -> Result<VerifyingKey, TokenClientError> {
    let published = directory
        .attribution_verifying_key_hex
        .as_ref()
        .ok_or(TokenClientError::BadAttributionKey)?;
    warren_contract::pf_attribution::verifying_key(published)
        .map_err(|_| TokenClientError::BadAttributionKey)
}

/// The checks the exit runs on a tag before it spends the entitlement, run at
/// mint time so a broken issuer surfaces as a mint error on the device rather
/// than as every Map request refused later.
fn verify_attribution_tag(
    tag: &AttributionTag,
    epoch: u64,
    key: &VerifyingKey,
) -> Result<(), TokenClientError> {
    if tag.epoch() != epoch {
        return Err(TokenClientError::AttributionTagEpoch { epoch });
    }
    tag.verify(key)
        .map_err(|source| TokenClientError::AttributionTagInvalid { epoch, source })
}

/// One tag per blind signature, each verified, in the issuer's order.
fn checked_attribution_tags(
    epoch: u64,
    tags: Vec<AttributionTag>,
    signatures: usize,
    key: &VerifyingKey,
) -> Result<Vec<AttributionTag>, TokenClientError> {
    if tags.len() != signatures {
        return Err(TokenClientError::AttributionTagCount {
            epoch,
            signatures,
            tags: tags.len(),
        });
    }
    for tag in &tags {
        verify_attribution_tag(tag, epoch, key)?;
    }
    Ok(tags)
}

/// Mints the full token batch for each of `epochs` in `key`'s class: blind
/// against each epoch's directory key with the material `key` derives, submit
/// one wallet-signed issue request, finalize and verify every token.
/// All-or-nothing: any refused epoch or malformed batch fails the whole call
/// (the caller retries or narrows the epochs; a partially-minted state is never
/// returned).
///
/// Every client of the wallet derives the same batch for an epoch, so the
/// issuer serves each of them the credentials the account already holds.
///
/// # Errors
/// [`TokenClientError`]; see each variant.
pub async fn mint_tokens<T: HttpTransport>(
    client: &WarrenApiClient<T>,
    directory: &TokenIssuerDirectory,
    epochs: &[u64],
    key: &BlindingKey,
) -> Result<Vec<MintedEpoch>, TokenClientError> {
    mint_batches(
        key.class(),
        client,
        directory,
        epochs,
        |pk, challenge, epoch, index| key.blind_slot(pk, challenge, epoch, index),
    )
    .await
}

/// [`mint_tokens`] for port entitlements, whose batches are drawn from `rng`:
/// an entitlement is assigned to one forwarded port, and two clients holding
/// the same batch would present one credential for two ports.
///
/// # Errors
/// [`TokenClientError`]; see each variant.
pub async fn mint_port_entitlements<T: HttpTransport, R: CryptoRng + ?Sized>(
    client: &WarrenApiClient<T>,
    directory: &TokenIssuerDirectory,
    epochs: &[u64],
    rng: &mut R,
) -> Result<Vec<MintedEpoch>, TokenClientError> {
    mint_batches(
        CredentialClass::PortEntitlement,
        client,
        directory,
        epochs,
        |pk, challenge, _, _| Ok(pk.blind_token(&mut *rng, challenge)?),
    )
    .await
}

async fn mint_batches<T: HttpTransport>(
    class: CredentialClass,
    client: &WarrenApiClient<T>,
    directory: &TokenIssuerDirectory,
    epochs: &[u64],
    mut blind: impl FnMut(
        &IssuerPublicKey,
        &TokenChallenge,
        u64,
        u32,
    ) -> Result<(Vec<u8>, ClientState), TokenClientError>,
) -> Result<Vec<MintedEpoch>, TokenClientError> {
    let quota = directory.quota_per_epoch as usize;
    if quota == 0 || directory.epoch_secs == 0 {
        return Err(TokenClientError::BadDirectoryPolicy);
    }
    let attribution_key = match class {
        CredentialClass::PortEntitlement => Some(attribution_key(directory)?),
        CredentialClass::Session | CredentialClass::BrowserProxy => None,
    };

    // Blind locally, per epoch, before anything leaves the device.
    let mut per_epoch = Vec::with_capacity(epochs.len());
    let mut request_epochs = Vec::with_capacity(epochs.len());
    for &epoch in epochs {
        let pk = epoch_key(directory, epoch)?;
        let challenge =
            TokenChallenge::for_epoch(&directory.issuer_name, &directory.context_label, epoch)?;
        let mut blinded = Vec::with_capacity(quota);
        let mut states = Vec::with_capacity(quota);
        for index in 0..directory.quota_per_epoch {
            let (req, state) = blind(&pk, &challenge, epoch, index)?;
            blinded.push(BASE64URL_NOPAD.encode(&req));
            states.push(state);
        }
        request_epochs.push(TokenEpochRequest { epoch, blinded });
        per_epoch.push((epoch, pk, states));
    }

    let mut response = client
        .issue_tokens_for(
            class,
            &TokenIssueRequest {
                epochs: request_epochs,
            },
        )
        .await?;

    // Finalize, matching response epochs by value (never by position).
    let mut minted = Vec::with_capacity(per_epoch.len());
    for (epoch, pk, states) in per_epoch {
        let out = response
            .epochs
            .iter_mut()
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
        let attribution_tags = match &attribution_key {
            Some(key) => checked_attribution_tags(
                epoch,
                std::mem::take(&mut out.attribution_tags),
                out.blind_signatures.len(),
                key,
            )?,
            None => Vec::new(),
        };
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
        minted.push(MintedEpoch {
            epoch,
            tokens,
            attribution_tags,
        });
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
    per_epoch: BTreeMap<u64, Vec<Stored>>,
}

/// A token and, for a port entitlement, the tag minted beside it, stored as
/// one entry so [`TokenStore::take_envelope`] pops the pair together. The
/// bare-token surfaces ([`TokenStore::take`], the snapshot) ignore the tag;
/// `TokenManager` keeps a port-entitlement store off them.
struct Stored {
    token: Token,
    tag: Option<AttributionTag>,
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
        let mut tags = minted.attribution_tags.into_iter();
        self.per_epoch
            .entry(minted.epoch)
            .or_default()
            .extend(minted.tokens.into_iter().map(|token| Stored {
                token,
                tag: tags.next(),
            }));
    }

    fn pop(&mut self, epoch: u64) -> Option<Stored> {
        let entries = self.per_epoch.get_mut(&epoch)?;
        let entry = entries.pop();
        if entries.is_empty() {
            self.per_epoch.remove(&epoch);
        }
        entry
    }

    /// Pops one token for `epoch`, or `None` when none remain. Consuming here
    /// (rather than cloning) is what makes "one token = one device slot"
    /// locally true.
    pub fn take(&mut self, epoch: u64) -> Option<Token> {
        self.pop(epoch).map(|entry| entry.token)
    }

    /// Pops one entitlement for `epoch` together with its tag, as the envelope
    /// the exit takes. An entry without a tag is discarded, never presented:
    /// every exit refuses a bare entitlement.
    pub(crate) fn take_envelope(&mut self, epoch: u64) -> Option<EntitlementEnvelope> {
        while let Some(entry) = self.pop(epoch) {
            if let Some(tag) = entry.tag {
                let token = Zeroizing::new(entry.token.serialize());
                return Some(
                    EntitlementEnvelope::new(token.as_slice(), tag)
                        .expect("a minted token has the envelope's token length"),
                );
            }
        }
        None
    }

    /// Tokens remaining for `epoch`.
    #[must_use]
    pub fn available(&self, epoch: u64) -> usize {
        self.per_epoch.get(&epoch).map_or(0, Vec::len)
    }

    /// The tokens held for `epoch`, in mint order, left in the store.
    fn tokens(&self, epoch: u64) -> impl Iterator<Item = &Token> {
        self.per_epoch
            .get(&epoch)
            .into_iter()
            .flatten()
            .map(|entry| &entry.token)
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
            .map(|(epoch, entries)| {
                (
                    *epoch,
                    entries
                        .iter()
                        .map(|entry| entry.token.serialize())
                        .collect(),
                )
            })
            .collect()
    }
}

/// Which credential the issuer endpoints refer to.
///
/// The classes share the whole minting flow and differ only in their endpoints,
/// which hold different per-epoch keys: a session token admits a tunnel session,
/// a port entitlement buys one forwarded port (warren-core doc 99), a
/// browser-proxy credential admits a browser at a CONNECT ingress (doc 103).
/// Blinding against the wrong directory mints credentials the server refuses,
/// so the class travels with the client call rather than being implied by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CredentialClass {
    /// Admits a tunnel session.
    #[default]
    Session,
    /// Buys one forwarded port.
    PortEntitlement,
    /// Admits a browser through an exit's CONNECT proxy ingress (warren-core
    /// doc 103). Its own class so a running tunnel client cannot take the
    /// account's whole issuance horizon out from under a browser.
    BrowserProxy,
}

impl CredentialClass {
    /// Public issuer directory for this class.
    #[must_use]
    pub const fn keys_path(self) -> &'static str {
        match self {
            Self::Session => "/v1/tokens/keys",
            Self::PortEntitlement => "/v1/port-entitlements/keys",
            Self::BrowserProxy => "/v1/browser-proxy/keys",
        }
    }

    /// Wallet-signed issuance endpoint for this class.
    #[must_use]
    pub const fn issue_path(self) -> &'static str {
        match self {
            Self::Session => "/v1/tokens/issue",
            Self::PortEntitlement => "/v1/port-entitlements/issue",
            Self::BrowserProxy => "/v1/browser-proxy/issue",
        }
    }
}

/// The usable route admission block of a session directory. An unusable one
/// reads as none: it must never cost the main session its tokens.
fn route_admission_of(
    class: CredentialClass,
    directory: &TokenIssuerDirectory,
) -> Option<RouteAdmission> {
    if class != CredentialClass::Session {
        return None;
    }
    RouteAdmission::from_directory(directory).ok().flatten()
}

/// Whether a mint failure gives every remaining epoch the same answer, so a
/// refresh must stop and return it: swallowed, it would read as a refresh that
/// went fine and stocked nothing. A ban; an issuer whose attribution tags
/// cannot pass the exit's checks; a token crate that no longer blinds in the
/// derived order, which would leave every tick with no batch at all.
fn answers_every_epoch_alike(err: &TokenClientError) -> bool {
    matches!(
        err,
        TokenClientError::Api(ClientError::Banned { .. })
            | TokenClientError::BadAttributionKey
            | TokenClientError::AttributionTagCount { .. }
            | TokenClientError::AttributionTagEpoch { .. }
            | TokenClientError::AttributionTagInvalid { .. }
            | TokenClientError::BlindingDrawOrder
    )
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
    /// The route admission block of the last directory fetched, validated.
    /// `None` until then, and whenever the directory carries none or one this
    /// build cannot use.
    route_admission: Option<RouteAdmission>,
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
    blinding: Blinding,
    state: Arc<Mutex<ManagerState>>,
    /// When set, [`Self::refresh`] mints only `current..=current + horizon`
    /// instead of the whole published window. `None` keeps the full-window
    /// prefetch.
    mint_horizon: Option<u64>,
    /// The serials this process's live sessions were admitted on
    /// ([`Self::claim`]), left out of every [`Self::session_stack`].
    live: Arc<LiveSerials>,
    /// Where [`Self::session_stack`] starts in the epoch's batch, drawn once
    /// per manager. Every client of a wallet holds the same batch in the same
    /// order, so a fixed start would send all of them to the first serial.
    rotation: usize,
}

/// The serials held by the live sessions of one [`TokenManager`].
#[derive(Default)]
struct LiveSerials(Mutex<HashSet<TokenSerial>>);

impl LiveSerials {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<TokenSerial>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A live session's hold on the serial it presents
/// ([`TokenManager::claim`]). While any clone lives, the serial stays out of
/// the manager's [`TokenManager::session_stack`]; the last drop releases it.
/// Bonded legs of one session clone the lease of the leg that was admitted.
#[derive(Clone)]
pub struct SerialLease {
    _held: Arc<Held>,
}

struct Held {
    serial: TokenSerial,
    live: Arc<LiveSerials>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.live.lock().remove(&self.serial);
    }
}

impl std::fmt::Debug for SerialLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The serial keys a live session in the exit's ledger: never render it.
        f.write_str("SerialLease(..)")
    }
}

/// Where a manager's batches draw their blinding material.
enum Blinding {
    /// From the wallet: every client of the wallet sends the same batch.
    Derived(BlindingKey),
    /// From the CSPRNG, for port entitlements only.
    Random,
}

impl<T: HttpTransport> TokenManager<T> {
    /// Builds a manager over a wallet-signed API client for `key`'s class,
    /// minting the batches `key` derives. Empty until the first
    /// [`Self::refresh`].
    ///
    /// `key` must come from the same wallet as the client's identity: the
    /// issuer serves an account the batch it first signed for that account.
    #[must_use]
    pub fn new(client: Arc<WarrenApiClient<T>>, key: BlindingKey) -> Self {
        Self::with_blinding(client, Blinding::Derived(key))
    }

    /// The manager inside [`PortEntitlementManager`]. It mints and counts its
    /// batch but vends nothing through [`Self::take_current_stack`] and never
    /// exports or restores a bundle: those carry bare tokens, and every exit
    /// refuses an entitlement without its tag.
    fn port_entitlements(client: Arc<WarrenApiClient<T>>) -> Self {
        Self::with_blinding(client, Blinding::Random)
    }

    fn with_blinding(client: Arc<WarrenApiClient<T>>, blinding: Blinding) -> Self {
        Self {
            client,
            blinding,
            state: Arc::new(Mutex::new(ManagerState {
                store: TokenStore::new(),
                epoch_secs: None,
                minted: BTreeSet::new(),
                route_admission: None,
            })),
            mint_horizon: None,
            live: Arc::default(),
            rotation: rand::random(),
        }
    }

    #[cfg(test)]
    fn with_rotation(mut self, rotation: usize) -> Self {
        self.rotation = rotation;
        self
    }

    fn class(&self) -> CredentialClass {
        match &self.blinding {
            Blinding::Derived(key) => key.class(),
            Blinding::Random => CredentialClass::PortEntitlement,
        }
    }

    /// The epoch `now` falls in, once a refresh (or a restored bundle) has
    /// taught the manager the published epoch length. `None` before that: a
    /// manager that has never seen the issuer cannot place a timestamp.
    #[must_use]
    pub fn epoch_at(&self, now_unix_secs: u64) -> Option<u64> {
        self.state
            .lock()
            .expect("token manager mutex poisoned")
            .epoch_secs
            .filter(|&s| s > 0)
            .map(|s| now_unix_secs / s)
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
    /// [`TokenClientError`] when the directory fetch itself fails; when the
    /// issuer refuses the wallet as banned
    /// (`TokenClientError::Api(ClientError::Banned { .. })`); and, for port
    /// entitlements, when the directory carries no usable attribution key or
    /// a batch's tags fail the checks (`BadAttributionKey`,
    /// `AttributionTag*`). The pass stops there, leaving that epoch and the
    /// later ones unsettled, so the next tick asks again. Any other per-epoch
    /// mint refusal or transport error is swallowed.
    pub async fn refresh(&self, now_unix_secs: u64) -> Result<(), TokenClientError> {
        let directory = self.client.token_keys_for(self.class()).await?;
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
            st.route_admission = route_admission_of(self.class(), &directory);
            directory
                .keys
                .iter()
                .map(|k| k.epoch)
                .filter(|&e| e >= current && e <= horizon_end && !st.minted.contains(&e))
                .collect()
        };

        for epoch in targets {
            let minted = match &self.blinding {
                Blinding::Derived(key) => {
                    mint_tokens(&self.client, &directory, &[epoch], key).await
                }
                Blinding::Random => {
                    // Seeded synchronously: the !Send thread rng never crosses
                    // the await.
                    let mut rng = rand010::rngs::StdRng::from_rng(&mut rand010::rng());
                    mint_port_entitlements(&self.client, &directory, &[epoch], &mut rng).await
                }
            };
            match minted {
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
                // The failed epoch stays unsettled: a lifted ban mints at the
                // next tick, and an epoch the issuer did record is settled
                // then by its already_issued answer.
                Err(e) if answers_every_epoch_alike(&e) => return Err(e),
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

    /// The route admission block of the last directory a [`Self::refresh`]
    /// fetched (warren-core doc 107), validated. `None` before the first
    /// fetch, when the server has route admission off, and when the block is
    /// one this build cannot use: routes then run on tokens. Always `None`
    /// outside the session class.
    #[must_use]
    pub fn route_admission(&self) -> Option<RouteAdmission> {
        self.state
            .lock()
            .expect("token manager mutex poisoned")
            .route_admission
            .clone()
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
        if self.class() == CredentialClass::PortEntitlement {
            return Vec::new();
        }
        let mut st = self.state.lock().expect("token manager mutex poisoned");
        let Some(epoch) = st.epoch_secs.filter(|&s| s > 0).map(|s| now_unix_secs / s) else {
            return Vec::new();
        };
        match st.store.take(epoch) {
            Some(token) => vec![token.serialize()],
            None => Vec::new(),
        }
    }

    /// Every token of the epoch `now` falls in, serialized, for ONE session to
    /// present in this order: starting at this manager's rotation, and leaving
    /// out the serials this process's live sessions hold ([`Self::claim`]).
    /// Nothing is consumed and nothing is minted.
    ///
    /// Every client of the wallet holds the same tokens, and the exit refuses
    /// a serial another session holds anywhere in the fleet, so a session
    /// walks this stack: it claims the lead, and on a refusal moves to the next
    /// token. An empty stack means no token is free this epoch.
    #[must_use]
    pub fn session_stack(&self, now_unix_secs: u64) -> Vec<[u8; TOKEN_LEN]> {
        if self.class() == CredentialClass::PortEntitlement {
            return Vec::new();
        }
        let st = self.state.lock().expect("token manager mutex poisoned");
        let Some(epoch) = st.epoch_secs.filter(|&s| s > 0).map(|s| now_unix_secs / s) else {
            return Vec::new();
        };
        let mut tokens: Vec<&Token> = st.store.tokens(epoch).collect();
        if !tokens.is_empty() {
            let start = self.rotation % tokens.len();
            tokens.rotate_left(start);
        }
        let held = self.live.lock();
        tokens
            .into_iter()
            .filter(|token| !held.contains(&token.serial()))
            .map(Token::serialize)
            .collect()
    }

    /// Holds `token`'s serial for a session about to present it, so no other
    /// session of this process leads with it while the returned lease lives.
    /// `None` when a live session already holds it, or when the bytes are no
    /// token.
    #[must_use]
    pub fn claim(&self, token: &[u8; TOKEN_LEN]) -> Option<SerialLease> {
        let serial = Token::parse(token).ok()?.serial();
        if !self.live.lock().insert(serial) {
            return None;
        }
        Some(SerialLease {
            _held: Arc::new(Held {
                serial,
                live: Arc::clone(&self.live),
            }),
        })
    }

    /// Pops one port entitlement for the epoch `now` falls in, paired with
    /// its attribution tag. Never mints.
    fn take_current_envelope(&self, now_unix_secs: u64) -> Option<EntitlementEnvelope> {
        let mut st = self.state.lock().expect("token manager mutex poisoned");
        let epoch = st
            .epoch_secs
            .filter(|&s| s > 0)
            .map(|s| now_unix_secs / s)?;
        st.store.take_envelope(epoch)
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
        if self.class() == CredentialClass::PortEntitlement {
            return 0;
        }
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
            st.store.insert(MintedEpoch {
                epoch,
                tokens,
                attribution_tags: Vec::new(),
            });
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
        if self.class() == CredentialClass::PortEntitlement {
            return None;
        }
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
            attribution_tags: Vec::new(),
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

#[cfg(test)]
mod session_stack_tests {
    //! The stack a session presents: every token of the current epoch, in the
    //! manager's own rotation, minus the serials this process's live sessions
    //! hold. Every client of a wallet holds the same batch in the same order,
    //! so where each one starts is what keeps two of them off one serial.

    use warren_identity::WarrenIdentity;

    use super::*;
    use crate::transport::{HttpRequest, HttpResponse, TransportError};

    /// Never reached: the store is filled by hand.
    struct Offline;

    impl HttpTransport for Offline {
        async fn execute(&self, _: HttpRequest) -> Result<HttpResponse, TransportError> {
            Err(TransportError::Connect("offline".to_owned()))
        }
    }

    const EPOCH_SECS: u64 = 3600;
    const EPOCH: u64 = 100;
    const NOW: u64 = EPOCH * EPOCH_SECS + 10;

    /// A well-formed token whose nonce starts with `marker`, so each marker
    /// has its own serial.
    fn token(marker: u8) -> Token {
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[0..2].copy_from_slice(&0x0002u16.to_be_bytes());
        bytes[2] = marker;
        Token::parse(&bytes).expect("well-formed token bytes parse")
    }

    fn manager() -> TokenManager<Offline> {
        TokenManager::new(
            Arc::new(WarrenApiClient::new(
                "https://api.example.test",
                WarrenIdentity::from_seed(&[0x52; 32]),
                Offline,
            )),
            BlindingKey::session(&[0x52; 32]),
        )
    }

    /// A manager holding `markers` for `epoch`, in that (mint) order.
    fn stocked(epoch: u64, markers: &[u8]) -> TokenManager<Offline> {
        let manager = manager();
        stock(&manager, epoch, markers);
        manager
    }

    fn stock(manager: &TokenManager<Offline>, epoch: u64, markers: &[u8]) {
        let mut st = manager.state.lock().expect("fresh mutex");
        st.epoch_secs = Some(EPOCH_SECS);
        st.store.insert(MintedEpoch {
            epoch,
            tokens: markers.iter().map(|&m| token(m)).collect(),
            attribution_tags: Vec::new(),
        });
    }

    fn markers(stack: &[[u8; TOKEN_LEN]]) -> Vec<u8> {
        stack.iter().map(|t| t[2]).collect()
    }

    #[test]
    fn the_stack_carries_every_current_token_and_consumes_none() {
        let manager = stocked(EPOCH, &[1, 2, 3]).with_rotation(0);

        assert_eq!(markers(&manager.session_stack(NOW)), [1, 2, 3]);
        assert_eq!(markers(&manager.session_stack(NOW)), [1, 2, 3]);
        assert_eq!(manager.available(EPOCH), 3);
    }

    #[test]
    fn the_stack_starts_at_the_manager_rotation() {
        let manager = stocked(EPOCH, &[1, 2, 3]).with_rotation(4);

        assert_eq!(markers(&manager.session_stack(NOW)), [2, 3, 1]);
    }

    #[test]
    fn managers_of_one_wallet_do_not_all_lead_with_the_same_token() {
        // Every client of a wallet holds the same batch in the same order: a
        // fixed start would put all of them on the first serial.
        let leads: BTreeSet<u8> = (0..64)
            .map(|_| stocked(EPOCH, &[1, 2, 3]).session_stack(NOW)[0][2])
            .collect();

        assert!(leads.len() > 1, "every manager led with {leads:?}");
    }

    #[test]
    fn the_stack_holds_only_the_current_epoch() {
        let manager = stocked(EPOCH, &[1, 2]).with_rotation(0);
        stock(&manager, EPOCH + 1, &[7, 8]);

        assert_eq!(markers(&manager.session_stack(NOW + EPOCH_SECS)), [7, 8]);
    }

    #[test]
    fn the_stack_leaves_out_a_serial_a_live_session_holds_until_it_ends() {
        let manager = stocked(EPOCH, &[1, 2, 3]).with_rotation(0);
        let lease = manager
            .claim(&token(2).serialize())
            .expect("an unheld serial is claimed");

        assert_eq!(markers(&manager.session_stack(NOW)), [1, 3]);
        drop(lease);
        assert_eq!(markers(&manager.session_stack(NOW)), [1, 2, 3]);
    }

    #[test]
    fn a_held_serial_is_claimed_again_only_once_its_last_holder_is_gone() {
        // Bonded legs share the lease of the session they joined: the serial
        // stays held while any of them lives.
        let manager = stocked(EPOCH, &[1]);
        let first = manager.claim(&token(1).serialize()).expect("unheld");
        let joined = first.clone();

        assert!(manager.claim(&token(1).serialize()).is_none());
        drop(first);
        assert!(manager.claim(&token(1).serialize()).is_none());
        drop(joined);
        assert!(manager.claim(&token(1).serialize()).is_some());
    }

    #[test]
    fn bytes_that_are_no_token_are_never_claimed() {
        let manager = stocked(EPOCH, &[1]);

        assert!(manager.claim(&[0u8; TOKEN_LEN]).is_none());
    }

    #[test]
    fn a_lease_renders_no_serial() {
        let manager = stocked(EPOCH, &[1]);
        let lease = manager.claim(&token(1).serialize()).expect("unheld");
        let serial = token(1).serial().to_hex();

        let rendered = format!("{lease:?}");

        assert!(rendered.starts_with("SerialLease"), "{rendered}");
        assert!(!rendered.contains(&serial[..8]), "{rendered}");
    }
}

#[cfg(test)]
mod port_entitlement_guard_tests {
    //! The bare-token surfaces of the manager inside
    //! [`PortEntitlementManager`] hand nothing out: every exit refuses an
    //! entitlement without its tag, and a persisted bundle carries none.

    use warren_identity::WarrenIdentity;

    use super::*;
    use crate::transport::{HttpRequest, HttpResponse, TransportError};

    /// Never reached: the store is filled by hand.
    struct Offline;

    impl HttpTransport for Offline {
        async fn execute(&self, _: HttpRequest) -> Result<HttpResponse, TransportError> {
            Err(TransportError::Connect("offline".to_owned()))
        }
    }

    const EPOCH_SECS: u64 = 3600;

    fn token() -> Token {
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[0..2].copy_from_slice(&0x0002u16.to_be_bytes());
        Token::parse(&bytes).expect("well-formed token bytes parse")
    }

    fn entitlements() -> TokenManager<Offline> {
        TokenManager::port_entitlements(Arc::new(WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x51; 32]),
            Offline,
        )))
    }

    fn stocked_entitlements() -> TokenManager<Offline> {
        let manager = entitlements();
        {
            let mut st = manager.state.lock().expect("fresh mutex");
            st.epoch_secs = Some(EPOCH_SECS);
            st.store.insert(MintedEpoch {
                epoch: 100,
                tokens: vec![token()],
                attribution_tags: Vec::new(),
            });
        }
        manager
    }

    #[test]
    fn a_port_entitlement_manager_never_vends_a_bare_token() {
        let manager = stocked_entitlements();

        assert!(manager.take_current_stack(100 * EPOCH_SECS).is_empty());
        assert!(manager.session_stack(100 * EPOCH_SECS).is_empty());
        assert_eq!(
            manager.available(100),
            1,
            "the batch stays for the envelope surface"
        );
    }

    #[test]
    fn a_port_entitlement_batch_is_never_exported_for_persistence() {
        assert!(stocked_entitlements().export_persistable().is_none());
    }

    #[test]
    fn a_blinding_drift_stops_the_refresh_pass_like_a_ban() {
        // Deterministic on every epoch and every tick: swallowed, the manager
        // would stock nothing for good while reporting success.
        assert!(answers_every_epoch_alike(
            &TokenClientError::BlindingDrawOrder
        ));
        assert!(!answers_every_epoch_alike(
            &TokenClientError::BatchMismatch { epoch: 100 }
        ));
    }

    #[test]
    fn a_persisted_bundle_restores_no_port_entitlement() {
        let bundle =
            PersistedTokens::from_snapshot(EPOCH_SECS, vec![(100, vec![token().serialize()])]);
        let manager = entitlements();

        assert_eq!(manager.restore_persisted(&bundle), 0);
        assert_eq!(manager.available(100), 0);
    }
}

/// Hands each port-forwarding rule the entitlement it presents (warren-core
/// docs 99 and 105).
///
/// A wrapper over [`TokenManager`] rather than a second minting flow: what an
/// entitlement needs on top is an ASSIGNMENT. The exit spends a credential the
/// first time it sees it and renews the spend afterwards, so a rule that
/// presented a different credential on each mapping refresh would spend the
/// subscriber's whole batch on one port. Slot `n` therefore keeps its
/// credential for the whole epoch, and moves to the next epoch's batch when
/// the current one stops being spendable anywhere.
///
/// What a slot presents is the [`EntitlementEnvelope`]: the entitlement and
/// the attribution tag the issuer minted beside it, verified at mint time.
/// The batch lives in RAM only and is never persisted: a bundle carries bare
/// tokens, and every exit refuses an entitlement without its tag.
pub struct PortEntitlementManager<T> {
    inner: TokenManager<T>,
    assigned: Mutex<Assigned>,
}

#[derive(Default)]
struct Assigned {
    /// The epoch `slots` was filled for. A credential verifies against its own
    /// epoch's issuer key and no other, so the whole map is dead at a boundary.
    epoch: Option<u64>,
    slots: BTreeMap<usize, EntitlementEnvelope>,
}

impl<T: HttpTransport> PortEntitlementManager<T> {
    /// Builds a manager over a wallet-signed API client. Empty until the first
    /// [`Self::refresh_auto`].
    #[must_use]
    pub fn new(client: Arc<WarrenApiClient<T>>) -> Self {
        Self {
            inner: TokenManager::port_entitlements(client),
            assigned: Mutex::new(Assigned::default()),
        }
    }

    /// Tops the batch up, on the same coarse timer as session tokens.
    ///
    /// # Errors
    /// As [`TokenManager::refresh`]: a failed directory fetch, a banned wallet
    /// (`TokenClientError::Api(ClientError::Banned { .. })`, which the app
    /// shows as the revocation), or an issuer whose attribution tags the exit
    /// would refuse.
    pub async fn refresh_auto(&self, now_unix_secs: u64) -> Result<(), TokenClientError> {
        self.inner.refresh(now_unix_secs).await
    }

    /// The credential rule `slot` presents right now: the encoded
    /// [`EntitlementEnvelope`], or `None` when the subscriber has none left
    /// for this epoch.
    ///
    /// On `None` the rule's Map request goes out without a credential, which
    /// the exit refuses. Handing out an already-assigned credential instead
    /// would make two rules read as one port at the exit.
    #[must_use]
    pub fn credential_for_slot(&self, slot: usize, now_unix_secs: u64) -> Option<Vec<u8>> {
        let epoch = self.inner.epoch_at(now_unix_secs)?;
        let mut assigned = self
            .assigned
            .lock()
            .expect("port entitlement manager mutex poisoned");
        if assigned.epoch != Some(epoch) {
            assigned.epoch = Some(epoch);
            assigned.slots.clear();
        }
        if let Some(held) = assigned.slots.get(&slot) {
            return Some(held.encode().to_vec());
        }
        // Popping is what makes "one entitlement, one port" locally true: the
        // credential leaves the store for good and no other slot can draw it.
        let envelope = self.inner.take_current_envelope(now_unix_secs)?;
        let credential = envelope.encode().to_vec();
        assigned.slots.insert(slot, envelope);
        Some(credential)
    }
}

#[cfg(test)]
mod attribution_tests {
    //! Replays `vectors/pf_attribution.json` through the SDK's own path: the
    //! checks a minted batch goes through and the store that pairs a token
    //! with its tag. The contract replays the layouts themselves.

    use serde_json::Value;
    use warren_contract::pf_attribution::verifying_key;

    use super::*;
    use crate::dto::{PubkeyHex, TokenEpochResponse};

    fn corpus() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/pf_attribution.json"
        );
        let body = std::fs::read_to_string(path).expect("the vectors submodule is checked out");
        serde_json::from_str(&body).expect("pf_attribution.json is JSON")
    }

    fn bytes(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().expect("hex string")).expect("valid hex")
    }

    fn key(v: &Value) -> VerifyingKey {
        let published = PubkeyHex::try_from(v.as_str().expect("hex string")).expect("32-byte hex");
        verifying_key(&published).expect("an Ed25519 key")
    }

    #[test]
    fn the_store_presents_the_vector_envelope_for_the_vector_token_and_tag() {
        let v = corpus();
        let token = Token::parse(&bytes(&v["envelope"]["token_hex"])).expect("vector token");
        let tag = AttributionTag::from_bytes(&bytes(&v["tag"]["tag_hex"])).expect("vector tag");
        let epoch = tag.epoch();
        let mut store = TokenStore::new();
        store.insert(MintedEpoch {
            epoch,
            tokens: vec![token],
            attribution_tags: vec![tag],
        });

        let envelope = store.take_envelope(epoch).expect("a paired entitlement");

        assert_eq!(
            envelope.encode().as_slice(),
            bytes(&v["envelope"]["envelope_hex"]).as_slice()
        );
    }

    #[test]
    fn the_vector_tag_passes_the_mint_checks_and_every_forged_one_fails_them() {
        let v = corpus();
        let good = AttributionTag::from_bytes(&bytes(&v["tag"]["tag_hex"])).expect("vector tag");
        let published = key(&v["keys"]["verifying_key_hex"]);
        let epoch = v["tag"]["epoch"].as_u64().expect("epoch");

        verify_attribution_tag(&good, epoch, &published).expect("the vector tag verifies");
        assert!(matches!(
            verify_attribution_tag(&good, epoch + 1, &published),
            Err(TokenClientError::AttributionTagEpoch { .. })
        ));

        for case in v["invalid_tags"].as_array().expect("invalid_tags") {
            let name = case["name"].as_str().expect("name");
            let raw = bytes(&case["tag_hex"]);
            match case["expect"].as_str().expect("expect") {
                "bad_signature" => {
                    let tag = AttributionTag::from_bytes(&raw).expect(name);
                    assert!(
                        matches!(
                            verify_attribution_tag(
                                &tag,
                                tag.epoch(),
                                &key(&case["verifying_key_hex"])
                            ),
                            Err(TokenClientError::AttributionTagInvalid { .. })
                        ),
                        "{name}"
                    );
                }
                "wrong_length" | "unsupported_version" => {
                    // Such a tag never reaches the checks: the issue response
                    // carrying it does not deserialize.
                    let response = serde_json::json!({
                        "epoch": epoch,
                        "issued": true,
                        "blind_signatures": ["AA"],
                        "attribution_tags": [BASE64URL_NOPAD.encode(&raw)],
                    });
                    assert!(
                        serde_json::from_value::<TokenEpochResponse>(response).is_err(),
                        "{name}"
                    );
                }
                other => panic!("unknown invalid_tags expectation {other} ({name})"),
            }
        }
    }

    #[test]
    fn an_entitlement_stored_without_its_tag_is_skipped_never_presented() {
        let v = corpus();
        let token = Token::parse(&bytes(&v["envelope"]["token_hex"])).expect("vector token");
        let tag = AttributionTag::from_bytes(&bytes(&v["tag"]["tag_hex"])).expect("vector tag");
        let epoch = tag.epoch();
        let mut store = TokenStore::new();
        store.insert(MintedEpoch {
            epoch,
            tokens: vec![token.clone()],
            attribution_tags: vec![tag],
        });
        // Pushed last, so popped first.
        store.insert(MintedEpoch {
            epoch,
            tokens: vec![token],
            attribution_tags: Vec::new(),
        });

        let envelope = store.take_envelope(epoch).expect("the paired entry");

        assert_eq!(
            envelope.encode().as_slice(),
            bytes(&v["envelope"]["envelope_hex"]).as_slice()
        );
        assert!(store.take_envelope(epoch).is_none());
    }
}
