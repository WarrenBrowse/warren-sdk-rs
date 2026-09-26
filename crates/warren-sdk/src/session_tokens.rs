//! The wallet's anonymous session tokens for the SDK's own dials (warren-core
//! doc 64), so an exit admits a session without learning the wallet.
//!
//! The shape mirrors warren-app's token providers: one manager per wallet and
//! API, shared by every client of that wallet in the process, opened with the
//! client and refreshed on a coarse timer, so a dial never asks the issuer for
//! anything. What differs is
//! what a dial draws: the whole current-epoch batch rather than one popped
//! token, because every client of a wallet holds the same batch (it is derived
//! from the wallet) and an exit leases each serial to one live session in the
//! fleet. A dial walks the batch from this manager's own starting point, past
//! the serials this process's sessions hold and past the ones the exit
//! refuses (`warren_transport::MultihopClientTunnel::with_session_tokens`).
//!
//! Nothing is persisted: a process that restarts derives the same batch, and
//! the issuer serves an account's batch again to whoever sends it bit for bit
//! (warren-core `PROD-READINESS.md` section 7).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use warren_api::{
    BlindingKey, HttpTransport, SerialLease, TokenClientError, TokenManager, WarrenApiClient,
};
use warren_transport::{
    MultihopClientTunnel, SESSION_TOKEN_LEN, SessionAdmission, SessionToken, SessionTokenSource,
    TokenHold,
};

/// How often the batch is topped up: the app's timer, for the same reason.
const REFRESH_PERIOD: Duration = Duration::from_secs(600);

/// How soon a refresh that left the current epoch without a token is tried
/// again, so a blip at launch does not hold every dial on the wallet for a
/// whole refresh period. What it costs while the epoch stays empty is one
/// unsigned directory fetch: an epoch the issuer answered is never re-asked.
const RETRY_PERIOD: Duration = Duration::from_secs(60);

/// How long a wallet's first dial waits for the issuer's first answer before
/// it dials with whatever the batch holds. Only the first: once the issuer has
/// answered, no dial waits on a refresh again.
const FIRST_ANSWER_WAIT: Duration = Duration::from_secs(10);

/// Epochs past the current one a refresh mints. The issuer serves a derived
/// batch again to whoever sends it, so a narrow window loses nothing across a
/// restart, and a launch costs a few signed requests rather than one per
/// published epoch.
const MINT_HORIZON: u64 = 2;

type RefreshFuture<'a> = Pin<Box<dyn Future<Output = Result<(), TokenClientError>> + Send + 'a>>;

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A wallet's session-token batch, erased over the HTTP transport.
trait TokenBatch: Send + Sync {
    fn stack(&self, now_unix_secs: u64) -> Vec<[u8; SESSION_TOKEN_LEN]>;
    fn claim(&self, token: &[u8; SESSION_TOKEN_LEN]) -> Option<SerialLease>;
    /// Whether the batch holds a token for the epoch `now` falls in, held by
    /// a live session or not.
    fn holds_current(&self, now_unix_secs: u64) -> bool;
    fn refresh(&self, now_unix_secs: u64) -> RefreshFuture<'_>;
}

impl<T: HttpTransport + 'static> TokenBatch for TokenManager<T> {
    fn stack(&self, now_unix_secs: u64) -> Vec<[u8; SESSION_TOKEN_LEN]> {
        self.session_stack(now_unix_secs)
    }

    fn claim(&self, token: &[u8; SESSION_TOKEN_LEN]) -> Option<SerialLease> {
        TokenManager::claim(self, token)
    }

    fn holds_current(&self, now_unix_secs: u64) -> bool {
        self.epoch_at(now_unix_secs)
            .is_some_and(|epoch| self.available(epoch) > 0)
    }

    fn refresh(&self, now_unix_secs: u64) -> RefreshFuture<'_> {
        Box::pin(TokenManager::refresh(self, now_unix_secs))
    }
}

/// One wallet's batch and its refresh.
struct Inner {
    batch: Arc<dyn TokenBatch>,
    clock: Clock,
    /// `true` once the first refresh has come back, whatever it answered.
    answered: tokio::sync::watch::Sender<bool>,
    refresh: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Inner {
    fn new(batch: Arc<dyn TokenBatch>, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            batch,
            clock,
            answered: tokio::sync::watch::channel(false).0,
            refresh: Mutex::new(None),
        })
    }

    /// Starts the refresh task unless one is running, which also restarts it
    /// when the runtime that ran it has gone (an embedder may tear its runtime
    /// down between sessions).
    fn ensure_refreshing(self: &Arc<Self>) {
        let mut task = self.refresh.lock().unwrap_or_else(PoisonError::into_inner);
        if task.as_ref().is_some_and(|t| !t.is_finished()) {
            return;
        }
        let batch = Arc::downgrade(self);
        *task = Some(tokio::spawn(async move {
            loop {
                let Some(inner) = batch.upgrade() else {
                    return;
                };
                if let Err(error) = inner.batch.refresh((inner.clock)()).await {
                    // The tokens already held stay usable; the next tick asks
                    // again. The error names epochs and API verdicts, never a
                    // token or the wallet.
                    tracing::debug!(%error, "session token refresh failed");
                }
                inner.answered.send_replace(true);
                let next = if inner.batch.holds_current((inner.clock)()) {
                    REFRESH_PERIOD
                } else {
                    RETRY_PERIOD
                };
                drop(inner);
                tokio::time::sleep(next).await;
            }
        }));
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(task) = self
            .refresh
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

/// Every wallet batch alive in this process, by API and wallet. Weak: a batch
/// lives as long as a client or a session of its wallet does, and is rebuilt
/// (and re-served by the issuer) after that.
static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<Inner>>>> = OnceLock::new();

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The wallet's session tokens as a client sees them. Cheap to clone.
#[derive(Clone)]
pub(crate) struct SessionTokens {
    inner: Arc<Inner>,
}

impl SessionTokens {
    /// The session tokens of the wallet `api` signs for, shared with every
    /// other client of the same wallet and API in the process, so their
    /// sessions never lead with each other's serial. `key` must be that
    /// wallet's session blinding key; it is dropped when a batch is already
    /// open.
    pub(crate) fn for_wallet<T: HttpTransport + 'static>(
        registry_key: String,
        api: &Arc<WarrenApiClient<T>>,
        key: BlindingKey,
    ) -> Self {
        let mut registry = REGISTRY
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let inner = match registry.get(&registry_key).and_then(Weak::upgrade) {
            Some(inner) => inner,
            None => {
                registry.retain(|_, batch| batch.strong_count() > 0);
                let manager =
                    TokenManager::new(Arc::clone(api), key).with_mint_horizon(MINT_HORIZON);
                let inner = Inner::new(Arc::new(manager), Arc::new(now_unix_secs));
                registry.insert(registry_key, Arc::downgrade(&inner));
                inner
            }
        };
        // Opened with the client, so the first mint does not wait for (and
        // does not line up with) the first dial. Outside a runtime, the first
        // dial opens it instead.
        if tokio::runtime::Handle::try_current().is_ok() {
            inner.ensure_refreshing();
        }
        Self { inner }
    }

    /// A batch outside the registry, for tests that must not share one.
    #[cfg(test)]
    fn unregistered(batch: Arc<dyn TokenBatch>, clock: Clock) -> Self {
        Self {
            inner: Inner::new(batch, clock),
        }
    }

    /// The source a dial presents. Makes sure the batch is being refreshed
    /// (restarting a refresh whose runtime has gone), then waits, bounded, for
    /// the issuer's first answer, so the wallet's first session does not race
    /// its first mint.
    pub(crate) async fn source(&self) -> Arc<dyn SessionTokenSource> {
        self.inner.ensure_refreshing();
        let mut answered = self.inner.answered.subscribe();
        let _ = tokio::time::timeout(FIRST_ANSWER_WAIT, answered.wait_for(|done| *done)).await;
        Arc::new(DialSource(Arc::clone(&self.inner)))
    }
}

/// What a dial draws from: the batch at the moment of dialing.
struct DialSource(Arc<Inner>);

impl SessionTokenSource for DialSource {
    fn stack(&self) -> Vec<SessionToken> {
        self.0
            .batch
            .stack((self.0.clock)())
            .into_iter()
            .map(SessionToken)
            .collect()
    }

    fn claim(&self, token: &SessionToken) -> Option<TokenHold> {
        let lease = self.0.batch.claim(&token.0)?;
        // The hold keeps the batch, and so its refresh, alive for as long as
        // the session lives, even past the client that dialed it.
        Some(TokenHold::new((lease, Arc::clone(&self.0))))
    }
}

/// How a client's dials are admitted at the exit: the wallet key the
/// wallet-signed request proves, the wallet's session tokens when the client
/// could derive them, and the policy between the two.
#[derive(Clone)]
pub(crate) struct DialAuth {
    pub(crate) signing: warren_identity::ed25519_dalek::SigningKey,
    pub(crate) tokens: Option<SessionTokens>,
    pub(crate) admission: SessionAdmission,
}

impl DialAuth {
    /// Admission on the wallet-signed request alone.
    #[cfg(test)]
    pub(crate) fn wallet(signing: warren_identity::ed25519_dalek::SigningKey) -> Self {
        Self {
            signing,
            tokens: None,
            admission: SessionAdmission::default(),
        }
    }

    /// A tunnel dialer carrying this admission.
    pub(crate) async fn tunnel(&self) -> MultihopClientTunnel {
        let tunnel = MultihopClientTunnel::new(self.signing.clone())
            .with_session_admission(self.admission.clone());
        match &self.tokens {
            Some(tokens) => tunnel.with_session_tokens(tokens.source().await),
            None => tunnel,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A batch whose refresh answers after `delay` (never, for `None`) and
    /// stocks `stack` when it does.
    struct ScriptedBatch {
        delay: Option<Duration>,
        stack: Vec<[u8; SESSION_TOKEN_LEN]>,
        stocked: std::sync::atomic::AtomicBool,
        refreshes: AtomicUsize,
        /// The refresh (1-based) that stocks the batch.
        stock_from: AtomicUsize,
    }

    impl ScriptedBatch {
        fn answering_after(delay: Option<Duration>, markers: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                delay,
                stack: markers.iter().map(|&m| [m; SESSION_TOKEN_LEN]).collect(),
                stocked: std::sync::atomic::AtomicBool::new(false),
                refreshes: AtomicUsize::new(0),
                stock_from: AtomicUsize::new(1),
            })
        }
    }

    impl TokenBatch for ScriptedBatch {
        fn stack(&self, _now: u64) -> Vec<[u8; SESSION_TOKEN_LEN]> {
            if self.stocked.load(Ordering::SeqCst) {
                self.stack.clone()
            } else {
                Vec::new()
            }
        }

        fn claim(&self, _token: &[u8; SESSION_TOKEN_LEN]) -> Option<SerialLease> {
            None
        }

        fn holds_current(&self, _now: u64) -> bool {
            self.stocked.load(Ordering::SeqCst)
        }

        fn refresh(&self, _now: u64) -> RefreshFuture<'_> {
            Box::pin(async move {
                let nth = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
                match self.delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending::<()>().await,
                }
                if nth >= self.stock_from.load(Ordering::SeqCst) {
                    self.stocked.store(true, Ordering::SeqCst);
                }
                Ok(())
            })
        }
    }

    fn tokens(batch: &Arc<ScriptedBatch>) -> SessionTokens {
        SessionTokens::unregistered(Arc::clone(batch) as Arc<dyn TokenBatch>, Arc::new(|| 0))
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_dial_waits_for_the_first_mint_and_presents_its_batch() {
        let batch = ScriptedBatch::answering_after(Some(Duration::from_secs(2)), &[1, 2]);

        let source = tokens(&batch).source().await;

        assert_eq!(source.stack().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_dial_stops_waiting_on_an_issuer_that_never_answers() {
        let batch = ScriptedBatch::answering_after(None, &[1]);
        let started = tokio::time::Instant::now();

        let source = tokens(&batch).source().await;

        assert_eq!(started.elapsed(), FIRST_ANSWER_WAIT);
        assert!(source.stack().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_refresh_that_left_no_current_token_is_retried_within_a_minute() {
        // A blip at launch must not leave every dial on the wallet for the
        // whole refresh period.
        let batch = ScriptedBatch::answering_after(Some(Duration::from_millis(10)), &[1]);
        batch.stock_from.store(2, Ordering::SeqCst);
        let tokens = tokens(&batch);
        assert!(tokens.source().await.stack().is_empty());

        tokio::time::sleep(RETRY_PERIOD + Duration::from_secs(1)).await;

        assert_eq!(batch.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(tokens.source().await.stack().len(), 1);
    }

    #[tokio::test]
    async fn clients_of_one_wallet_share_its_batch_until_the_last_one_is_gone() {
        let api = Arc::new(WarrenApiClient::new(
            "https://api.example.test",
            warren_identity::WarrenIdentity::from_seed(&[0x7c; 32]),
            Unreachable,
        ));
        let open = || {
            SessionTokens::for_wallet(
                "registry-test\nwallet".to_owned(),
                &api,
                BlindingKey::session(&[0x7c; 32]),
            )
        };
        let first = open();
        let second = open();
        assert!(Arc::ptr_eq(&first.inner, &second.inner));

        let old = Arc::downgrade(&first.inner);
        drop((first, second));
        let reopened = open();

        assert!(
            old.upgrade().is_none(),
            "the batch went with its last client"
        );
        assert!(reopened.inner.batch.stack(0).is_empty());
    }

    /// Answers nothing: the registry test never mints.
    struct Unreachable;

    impl HttpTransport for Unreachable {
        async fn execute(
            &self,
            _: warren_api::HttpRequest,
        ) -> Result<warren_api::HttpResponse, warren_api::TransportError> {
            Err(warren_api::TransportError::Connect(
                "unreachable".to_owned(),
            ))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn later_dials_never_refresh_and_the_timer_does() {
        let batch = ScriptedBatch::answering_after(Some(Duration::from_millis(10)), &[1]);
        let tokens = tokens(&batch);
        let _ = tokens.source().await;
        let _ = tokens.source().await;

        assert_eq!(batch.refreshes.load(Ordering::SeqCst), 1);
        tokio::time::sleep(REFRESH_PERIOD + Duration::from_secs(1)).await;
        assert_eq!(batch.refreshes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn the_refresh_stops_with_the_last_holder_of_the_batch() {
        let batch = ScriptedBatch::answering_after(Some(Duration::from_millis(1)), &[1]);
        let tokens = tokens(&batch);
        let _ = tokens.source().await;
        let task = tokens
            .inner
            .refresh
            .lock()
            .expect("refresh lock")
            .as_ref()
            .map(tokio::task::JoinHandle::abort_handle)
            .expect("a refresh task");

        drop(tokens);
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(task.is_finished());
    }
}
