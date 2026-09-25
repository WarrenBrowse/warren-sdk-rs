//! Port-forward entitlements for the SDK's own NAT-PMP path (warren-core docs
//! 99 and 105).
//!
//! An exit that enforces doc 105 refuses a Map request presenting no
//! entitlement envelope, so every forward this SDK makes draws one from the
//! wallet's [`PortEntitlementManager`]. The shape mirrors warren-app's NAT-PMP
//! controller: one manager per wallet for the life of the process, a refresh
//! on a coarse timer so issuance timing never mirrors what the user does, and
//! one SLOT per forwarding rule, the lowest free one, held for the rule's life
//! and freed with it. A slot keeps its credential for the whole epoch, so a
//! renewal re-presents the entitlement the exit already spent, and two rules
//! never draw the same one.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use warren_api::{
    BanReasonCode, ClientError, HttpTransport, PortEntitlementManager, TokenClientError,
};
use warren_net::{CredentialProvider, PortForwardError};

use crate::error::SdkError;

/// How often the batch is topped up: the app's timer, for the same reason.
const REFRESH_PERIOD: Duration = Duration::from_secs(600);

/// How long a wallet's first forward waits for the issuer's first answer
/// before it sends its request anyway. Past it, the request goes out with
/// whatever the batch holds (possibly nothing), and the exit's answer decides.
const FIRST_ANSWER_WAIT: Duration = Duration::from_secs(15);

type RefreshFuture<'a> = Pin<Box<dyn Future<Output = Result<(), TokenClientError>> + Send + 'a>>;

/// A wallet's entitlement batch, erased over the HTTP transport so the
/// non-generic forwarders can carry it.
trait EntitlementSource: Send + Sync {
    fn credential_for_slot(&self, slot: usize, now_unix_secs: u64) -> Option<Vec<u8>>;
    fn refresh(&self, now_unix_secs: u64) -> RefreshFuture<'_>;
}

impl<T: HttpTransport + 'static> EntitlementSource for PortEntitlementManager<T> {
    fn credential_for_slot(&self, slot: usize, now_unix_secs: u64) -> Option<Vec<u8>> {
        PortEntitlementManager::credential_for_slot(self, slot, now_unix_secs)
    }

    fn refresh(&self, now_unix_secs: u64) -> RefreshFuture<'_> {
        Box::pin(self.refresh_auto(now_unix_secs))
    }
}

/// A ban the issuer answered, kept so a refused forward can say why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ban {
    reason_code: BanReasonCode,
    lapses_at_unix_secs: Option<u64>,
}

/// What the issuer last answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Issuance {
    /// No refresh has finished yet.
    Pending,
    /// The last refresh that proved anything did not find the wallet banned.
    Answered,
    /// The issuer refuses the wallet.
    Banned(Ban),
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The wallet's entitlements as a forwarder sees them. Cheap to clone.
///
/// The batch behind it is opened at the first slot claim, not before: a
/// client that never forwards a port mints nothing, registers nothing, and
/// keeps nothing of its wallet past its own life.
#[derive(Clone)]
pub(crate) struct PortEntitlements {
    wallet: Arc<Wallet>,
}

struct Wallet {
    open: Box<dyn Fn() -> Arc<Inner> + Send + Sync>,
    batch: OnceLock<Arc<Inner>>,
}

/// One wallet's batch, its slot table and its refresh.
struct Inner {
    source: Arc<dyn EntitlementSource>,
    clock: Clock,
    slots: Mutex<BTreeSet<usize>>,
    issuance: tokio::sync::watch::Sender<Issuance>,
    refresh: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Inner {
    fn new(source: Arc<dyn EntitlementSource>, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            source,
            clock,
            slots: Mutex::new(BTreeSet::new()),
            issuance: tokio::sync::watch::channel(Issuance::Pending).0,
            refresh: Mutex::new(None),
        })
    }

    fn holds_no_slot(&self) -> bool {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    /// Starts the refresh task unless one is running, which also restarts it
    /// when the runtime that ran it has gone (an embedder may tear its runtime
    /// down between sessions) or when it stopped for want of a rule.
    fn ensure_refreshing(self: &Arc<Self>) {
        let mut task = self
            .refresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if task.as_ref().is_some_and(|t| !t.is_finished()) {
            return;
        }
        let batch = Arc::downgrade(self);
        *task = Some(tokio::spawn(async move {
            loop {
                let Some(inner) = batch.upgrade() else {
                    return;
                };
                let answer = inner.source.refresh((inner.clock)()).await;
                inner
                    .issuance
                    .send_modify(|state| *state = next_issuance(*state, &answer));
                drop(inner);
                tokio::time::sleep(REFRESH_PERIOD).await;
                // Every refresh is a request signed by the wallet: once no
                // rule holds a slot, stop making them. The next claim starts
                // the loop again.
                if batch.upgrade().is_none_or(|inner| inner.holds_no_slot()) {
                    return;
                }
            }
        }));
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(task) = self
            .refresh
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Every wallet batch opened in this process, by API and wallet.
static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Inner>>>> = OnceLock::new();

impl PortEntitlements {
    /// The entitlements of the wallet `api` signs for, against the API it
    /// talks to: one batch per wallet and API, opened at the first slot claim
    /// and kept for the life of the process from then on, as warren-app keeps
    /// its managers.
    ///
    /// Kept rather than dropped with the last client because issuance is
    /// once per account and epoch, across the whole prefetch window: a batch
    /// dropped and reopened is answered `already_issued` for every epoch the
    /// first one prefetched, and the wallet's forwards would be refused until
    /// that window ran out. The cost is that a wallet which forwarded a port
    /// keeps its API client, and so its signing key, in memory until the
    /// process exits; its refresh stops once no rule holds a slot.
    pub(crate) fn for_wallet<T: HttpTransport + 'static>(
        registry_key: String,
        api: &Arc<warren_api::WarrenApiClient<T>>,
    ) -> Self {
        let api = Arc::clone(api);
        Self {
            wallet: Arc::new(Wallet {
                open: Box::new(move || {
                    let mut registry = REGISTRY
                        .get_or_init(|| Mutex::new(HashMap::new()))
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    Arc::clone(registry.entry(registry_key.clone()).or_insert_with(|| {
                        Inner::new(
                            Arc::new(PortEntitlementManager::new(Arc::clone(&api))),
                            Arc::new(now_unix_secs),
                        )
                    }))
                }),
                batch: OnceLock::new(),
            }),
        }
    }

    /// A batch outside the registry, for tests that must not share one.
    #[cfg(test)]
    fn unregistered(source: Arc<dyn EntitlementSource>, clock: Clock) -> Self {
        let batch = Inner::new(source, clock);
        Self {
            wallet: Arc::new(Wallet {
                open: Box::new(move || Arc::clone(&batch)),
                batch: OnceLock::new(),
            }),
        }
    }

    /// Opens the batch, registering it on first use.
    fn batch(&self) -> &Arc<Inner> {
        self.wallet.batch.get_or_init(|| (self.wallet.open)())
    }

    /// Claims the lowest slot no live rule holds. Reusing a freed slot keeps
    /// the rules inside the batch: slots that only ever grew would run past it
    /// after a few rule changes.
    fn claim(&self) -> SlotLease {
        let owner = Arc::clone(self.batch());
        let mut slots = owner
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = (0..).find(|n| !slots.contains(n)).unwrap_or(usize::MAX);
        slots.insert(slot);
        drop(slots);
        SlotLease {
            slot,
            owner,
            presented: AtomicBool::new(false),
        }
    }

    /// The ban the issuer last answered, if any. Never opens the batch: a
    /// wallet that has not forwarded has not asked.
    fn ban(&self) -> Option<Ban> {
        match *self.wallet.batch.get()?.issuance.borrow() {
            Issuance::Banned(ban) => Some(ban),
            Issuance::Pending | Issuance::Answered => None,
        }
    }
}

/// Folds one refresh result into the issuance state. Only a success clears a
/// ban (a lifted one mints at the next tick); a transient failure proves
/// nothing either way and keeps the state, except that it ends `Pending`, so a
/// first forward stops waiting on an issuer that is down.
fn next_issuance(state: Issuance, answer: &Result<(), TokenClientError>) -> Issuance {
    match answer {
        Ok(()) => Issuance::Answered,
        Err(TokenClientError::Api(ClientError::Banned {
            reason_code,
            lapses_at_unix_secs,
        })) => Issuance::Banned(Ban {
            reason_code: *reason_code,
            lapses_at_unix_secs: *lapses_at_unix_secs,
        }),
        Err(_) if state == Issuance::Pending => Issuance::Answered,
        Err(_) => state,
    }
}

/// A rule's hold on one slot. Dropping it frees the slot.
pub(crate) struct SlotLease {
    slot: usize,
    owner: Arc<Inner>,
    /// Whether the last credential asked for this slot existed, so a refusal
    /// can tell "presented nothing" from "presented one the exit refused".
    presented: AtomicBool,
}

impl SlotLease {
    /// The provider a forward's refresh cycles ask: this slot's credential at
    /// the moment of asking, so an epoch rollover reaches the next renewal.
    fn provider(self: &Arc<Self>) -> CredentialProvider {
        let lease = Arc::clone(self);
        Arc::new(move || {
            let credential = lease
                .owner
                .source
                .credential_for_slot(lease.slot, (lease.owner.clock)());
            lease
                .presented
                .store(credential.is_some(), Ordering::SeqCst);
            credential
        })
    }
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        self.owner
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.slot);
    }
}

/// A forwarding rule's slot: claimed at the rule's first mapping and held
/// across every reconnect, so the rule keeps presenting the credential the
/// exit already spent for it. Freed when the last clone and the last forward
/// built on it are gone.
#[derive(Clone, Default)]
pub(crate) struct RuleSlot(Arc<OnceLock<Arc<SlotLease>>>);

impl RuleSlot {
    /// The credential provider for one mapping of this rule, or `None` when
    /// the forwarder carries no entitlements. Makes sure the batch is being
    /// refreshed on every call, not only at the claim, since a rule outlives
    /// the runtime its refresh was started on. Then waits, bounded, for the
    /// wallet's first issuance answer, so a rule's very first request does
    /// not race it.
    pub(crate) async fn provider(
        &self,
        entitlements: Option<&PortEntitlements>,
    ) -> Option<(CredentialProvider, Arc<SlotLease>)> {
        let entitlements = entitlements?;
        let lease = Arc::clone(self.0.get_or_init(|| Arc::new(entitlements.claim())));
        lease.owner.ensure_refreshing();
        let mut issuance = lease.owner.issuance.subscribe();
        let _ = tokio::time::timeout(
            FIRST_ANSWER_WAIT,
            issuance.wait_for(|state| *state != Issuance::Pending),
        )
        .await;
        Some((lease.provider(), lease))
    }
}

/// Maps a forward failure to the SDK error, typing the exit's refusal.
///
/// A `NotAuthorized` answer from an enforcing exit means the request presented
/// no entitlement, or one the exit would not spend. When the issuer has
/// answered that the wallet is banned, the ban is the reason and is what the
/// caller sees; otherwise the refusal says whether anything was presented.
pub(crate) fn forward_error(
    err: PortForwardError,
    entitlements: Option<&PortEntitlements>,
    lease: Option<&SlotLease>,
) -> SdkError {
    if !err.is_not_authorized() {
        return SdkError::PortForward(err);
    }
    if let Some(ban) = entitlements.and_then(PortEntitlements::ban) {
        return SdkError::Api(ClientError::Banned {
            reason_code: ban.reason_code,
            lapses_at_unix_secs: ban.lapses_at_unix_secs,
        });
    }
    SdkError::PortForwardRefused {
        entitlement_presented: lease.is_some_and(|l| l.presented.load(Ordering::SeqCst)),
    }
}

#[cfg(test)]
mod tests {
    //! The SDK's forward path end to end: the wallet's real
    //! `PortEntitlementManager` minting against a fake issuer (the HTTP
    //! boundary), the real `PacketForwarder`, and the engine's NAT-PMP server
    //! behind an authority that requires a credential.

    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU64;

    use bytes::Bytes;
    use tokio::net::UdpSocket;
    use warren_api::{EntitlementEnvelope, WarrenApiClient};
    use warren_identity::WarrenIdentity;
    use warren_net::error::NetError;
    use warren_net::{MapProto, UdpFlow, UdpOpener};
    use warren_test_support::issuer::{EPOCH_SECS, FakeEntitlementIssuer};
    use warren_test_support::natpmp::EngineNatPmp;

    use super::*;
    use crate::portfollow::{PortFollowConfig, PortFollowOutcome};
    use crate::supervisor::{PacketForwarder, ReleaseGate, supervise_forward};

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
    const EPOCH: u64 = 100;

    /// Opens kernel UDP sockets that stand in for the tunnel's flows to the
    /// in-tunnel gateway, delivering to the loopback engine server.
    struct Loopback {
        server: SocketAddr,
    }

    struct LoopbackFlow {
        sock: UdpSocket,
        server: SocketAddr,
    }

    impl UdpOpener for Loopback {
        type Flow = LoopbackFlow;

        async fn open_udp(&self) -> Result<LoopbackFlow, NetError> {
            let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(NetError::Io)?;
            Ok(LoopbackFlow {
                sock,
                server: self.server,
            })
        }
    }

    impl UdpFlow for LoopbackFlow {
        async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
            assert_eq!(dst.ip(), GATEWAY);
            self.sock
                .send_to(&data, self.server)
                .await
                .map(|_| ())
                .map_err(NetError::Io)
        }

        async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
            let mut buf = vec![0u8; 1100];
            loop {
                let (n, src) = self.sock.recv_from(&mut buf).await.ok()?;
                if src == self.server {
                    return Some((
                        Bytes::copy_from_slice(&buf[..n]),
                        SocketAddr::from((GATEWAY, 5351)),
                    ));
                }
            }
        }
    }

    type Api = Arc<WarrenApiClient<FakeEntitlementIssuer>>;

    /// The wallet's entitlements over `issuer`, read at the time `clock` holds.
    fn wallet(issuer: FakeEntitlementIssuer, clock: &Arc<AtomicU64>) -> (PortEntitlements, Api) {
        let api = Arc::new(WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x61; 32]),
            issuer,
        ));
        let clock = Arc::clone(clock);
        let entitlements = PortEntitlements::unregistered(
            Arc::new(PortEntitlementManager::new(Arc::clone(&api))),
            Arc::new(move || clock.load(Ordering::SeqCst)),
        );
        (entitlements, api)
    }

    fn at_epoch(epoch: u64) -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(epoch * EPOCH_SECS + 10))
    }

    fn forwarder(server: &EngineNatPmp, entitlements: &PortEntitlements) -> PacketForwarder {
        PacketForwarder {
            udp: Arc::new(Loopback {
                server: server.addr(),
            }),
            gateway: GATEWAY,
            entitlements: Some(entitlements.clone()),
        }
    }

    /// Waits until the server has seen `count` presentations. A raw forward
    /// renews once right after its grant, from its own task, so reading
    /// `presented` before that renewal lands would race it.
    async fn until_presented(server: &EngineNatPmp, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.presented().len() < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the presentations arrive");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_forward_presents_its_slot_envelope_which_the_exit_can_verify() {
        let issuer = FakeEntitlementIssuer::new(&[EPOCH, EPOCH + 1], 5);
        let attribution_key = issuer.attribution_key();
        let (entitlements, _api) = wallet(issuer, &at_epoch(EPOCH));
        let server = EngineNatPmp::spawn().await;

        let port = forwarder(&server, &entitlements)
            .forward_port_with_suggested(MapProto::Tcp, 8080, 0)
            .await
            .expect("the exit grants a forward that presents an entitlement");

        let presented = server.presented();
        let envelope =
            EntitlementEnvelope::parse(&presented[0]).expect("the trailer is an envelope");
        envelope
            .tag()
            .verify(&attribution_key)
            .expect("its tag verifies under the published attribution key");
        assert_eq!(envelope.tag().epoch(), EPOCH);
        port.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn live_forwards_draw_distinct_slots_and_a_freed_slot_is_reused_lowest_first() {
        let (entitlements, _api) =
            wallet(FakeEntitlementIssuer::new(&[EPOCH], 5), &at_epoch(EPOCH));
        let server = EngineNatPmp::spawn().await;
        let fwd = forwarder(&server, &entitlements);

        let first = fwd
            .forward_port_with_suggested(MapProto::Tcp, 8080, 0)
            .await
            .expect("first forward");
        until_presented(&server, 2).await;
        let slot0 = server.presented()[0].clone();
        let second = fwd
            .forward_port_with_suggested(MapProto::Tcp, 8081, 0)
            .await
            .expect("second forward");
        until_presented(&server, 4).await;
        let slot1 = server.presented()[2].clone();
        assert_ne!(
            slot0, slot1,
            "two live rules must never present one entitlement"
        );

        first.shutdown().await;
        let mark = server.presented().len();
        let third = fwd
            .forward_port_with_suggested(MapProto::Tcp, 8082, 0)
            .await
            .expect("third forward");

        assert_eq!(
            server.presented()[mark],
            slot0,
            "the freed lowest slot is reused, with the entitlement it already holds"
        );
        second.shutdown().await;
        third.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_forward_past_the_batch_is_refused_with_the_typed_error() {
        let (entitlements, _api) =
            wallet(FakeEntitlementIssuer::new(&[EPOCH], 1), &at_epoch(EPOCH));
        let server = EngineNatPmp::spawn().await;
        let fwd = forwarder(&server, &entitlements);
        let held = fwd
            .forward_port_with_suggested(MapProto::Tcp, 8080, 0)
            .await
            .expect("the one entitlement buys the first port");

        let err = fwd
            .forward_port_with_suggested(MapProto::Tcp, 8081, 0)
            .await
            .expect_err("no entitlement is left for a second port");

        assert!(
            matches!(
                err,
                SdkError::PortForwardRefused {
                    entitlement_presented: false
                }
            ),
            "{err:?}"
        );
        held.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_entitlement_the_exit_will_not_spend_is_refused_as_presented() {
        // The exit verifies and spends the token with the API: one it cannot
        // spend (already live on another exit, say) is refused too, and the
        // caller must be able to tell that from having none to present.
        let (entitlements, _api) =
            wallet(FakeEntitlementIssuer::new(&[EPOCH], 5), &at_epoch(EPOCH));
        let server = EngineNatPmp::spawn_granting(0).await;

        let err = forwarder(&server, &entitlements)
            .forward_port_with_suggested(MapProto::Tcp, 8080, 0)
            .await
            .expect_err("the exit refuses the entitlement");

        assert!(
            matches!(
                err,
                SdkError::PortForwardRefused {
                    entitlement_presented: true
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_refusal_explained_by_a_ban_publishes_the_banned_outcome() {
        let err = SdkError::Api(ClientError::Banned {
            reason_code: BanReasonCode::PortForwardingAbuse,
            lapses_at_unix_secs: Some(7),
        });

        assert_eq!(
            PortFollowOutcome::from_failure(&err),
            PortFollowOutcome::Banned {
                reason_code: BanReasonCode::PortForwardingAbuse,
                lapses_at_unix_secs: Some(7),
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_banned_wallet_sees_the_ban_when_the_exit_refuses_its_forward() {
        let issuer = FakeEntitlementIssuer::new(&[EPOCH], 5);
        issuer.ban();
        let (entitlements, _api) = wallet(issuer, &at_epoch(EPOCH));
        let server = EngineNatPmp::spawn().await;

        let err = forwarder(&server, &entitlements)
            .forward_port_with_suggested(MapProto::Tcp, 8080, 0)
            .await
            .expect_err("a banned wallet holds no entitlement");

        assert!(
            matches!(
                err,
                SdkError::Api(ClientError::Banned {
                    reason_code: BanReasonCode::PortForwardingAbuse,
                    lapses_at_unix_secs: Some(1_790_000_000),
                })
            ),
            "{err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_epoch_rollover_presents_the_next_batch_at_the_next_cycle() {
        let clock = at_epoch(EPOCH);
        let (entitlements, _api) =
            wallet(FakeEntitlementIssuer::new(&[EPOCH, EPOCH + 1], 5), &clock);
        let server = EngineNatPmp::spawn().await;
        let rule = RuleSlot::default();
        let (provider, _lease) = rule
            .provider(Some(&entitlements))
            .await
            .expect("the forwarder carries entitlements");
        let mut flow = Loopback {
            server: server.addr(),
        }
        .open_udp()
        .await
        .expect("flow");

        let first = warren_net::map_cycle(
            &mut flow,
            GATEWAY,
            &[MapProto::Tcp],
            8080,
            0,
            3600,
            Some(&provider),
        )
        .await
        .expect("granted in the first epoch");
        clock.store((EPOCH + 1) * EPOCH_SECS + 10, Ordering::SeqCst);
        warren_net::map_cycle(
            &mut flow,
            GATEWAY,
            &[MapProto::Tcp],
            8080,
            first[0].external_port,
            3600,
            Some(&provider),
        )
        .await
        .expect("renewed in the next epoch");

        let epochs: Vec<u64> = server
            .presented()
            .iter()
            .map(|raw| {
                EntitlementEnvelope::parse(raw)
                    .expect("envelope")
                    .tag()
                    .epoch()
            })
            .collect();
        assert_eq!(epochs, vec![EPOCH, EPOCH + 1]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rule_keeps_one_slot_across_its_mappings_and_frees_it_when_gone() {
        let (entitlements, _api) =
            wallet(FakeEntitlementIssuer::new(&[EPOCH], 5), &at_epoch(EPOCH));
        let rule = RuleSlot::default();

        let (first, lease_a) = rule.provider(Some(&entitlements)).await.expect("slot");
        let (again, lease_b) = rule.provider(Some(&entitlements)).await.expect("slot");
        assert_eq!(
            lease_a.slot, lease_b.slot,
            "a reconnect keeps the rule's slot"
        );
        assert_eq!(first(), again(), "and so the entitlement the exit spent");

        let other = RuleSlot::default();
        let (_, other_lease) = other.provider(Some(&entitlements)).await.expect("slot");
        assert_ne!(other_lease.slot, lease_a.slot);

        drop((first, again, lease_a, lease_b, rule));
        let (_, reclaimed) = RuleSlot::default()
            .provider(Some(&entitlements))
            .await
            .expect("slot");
        assert_eq!(reclaimed.slot, 0, "the ended rule's slot is free again");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_supervised_rule_past_the_batch_publishes_the_not_authorized_outcome() {
        let (entitlements, _api) =
            wallet(FakeEntitlementIssuer::new(&[EPOCH], 1), &at_epoch(EPOCH));
        let server = EngineNatPmp::spawn().await;
        let fwd = forwarder(&server, &entitlements);
        let held = fwd
            .forward_port_with_suggested(MapProto::Tcp, 8080, 0)
            .await
            .expect("the one entitlement is held by another rule");

        let (fwd_tx, fwd_rx) = tokio::sync::watch::channel(Some(fwd));
        let (ext_tx, _ext_rx) = tokio::sync::watch::channel(None);
        let (out_tx, mut out_rx) = tokio::sync::watch::channel(None);
        let rule = RuleSlot::default();
        let task = tokio::spawn(supervise_forward(
            fwd_rx,
            ext_tx,
            out_tx,
            PortFollowConfig::default(),
            ReleaseGate::default(),
            move |f: PacketForwarder, suggested| {
                let rule = rule.clone();
                async move {
                    f.forward_port_for_rule(MapProto::Tcp, 8081, suggested, &rule)
                        .await
                }
            },
        ));

        let outcome =
            tokio::time::timeout(Duration::from_secs(10), out_rx.wait_for(|o| o.is_some()))
                .await
                .expect("an outcome within the budget")
                .expect("outcome channel open")
                .expect("some outcome");
        assert_eq!(
            outcome,
            PortFollowOutcome::NotAuthorized {
                entitlement_presented: false
            }
        );
        task.abort();
        drop(fwd_tx);
        held.shutdown().await;
    }

    fn registered(key: &str) -> bool {
        REGISTRY
            .get()
            .is_some_and(|r| r.lock().unwrap().contains_key(key))
    }

    fn api_for(issuer: FakeEntitlementIssuer) -> Api {
        Arc::new(WarrenApiClient::new(
            "https://api.example.test",
            WarrenIdentity::from_seed(&[0x62; 32]),
            issuer,
        ))
    }

    #[tokio::test]
    async fn a_client_that_never_forwards_opens_no_batch() {
        // Nothing of the wallet outlives a client that never forwarded, and
        // no batch is taken from the wallet's other devices.
        let key = "never-forwards".to_owned();
        let api = api_for(FakeEntitlementIssuer::new(&[EPOCH], 5));
        let entitlements = PortEntitlements::for_wallet(key.clone(), &api);

        assert!(!registered(&key), "opened before any forward");
        let _lease = entitlements.claim();
        assert!(registered(&key), "the first claim opens the batch");
    }

    #[tokio::test]
    async fn two_clients_of_one_wallet_share_one_batch() {
        // A second manager for the wallet would be answered already_issued
        // and hold nothing: every client of the wallet draws from one batch.
        let key = "shared-wallet".to_owned();
        let first = PortEntitlements::for_wallet(
            key.clone(),
            &api_for(FakeEntitlementIssuer::new(&[EPOCH], 5)),
        );
        let second =
            PortEntitlements::for_wallet(key, &api_for(FakeEntitlementIssuer::new(&[EPOCH], 5)));

        let a = first.claim();
        let b = second.claim();

        assert!(Arc::ptr_eq(&a.owner, &b.owner));
        assert_ne!(a.slot, b.slot, "one slot table for the wallet");
    }

    #[tokio::test(start_paused = true)]
    async fn the_refresh_stops_once_no_rule_holds_a_slot_and_restarts_with_one() {
        // Each refresh is a request signed by the wallet: after the last
        // forward ends (a logout, a wallet switch), none may follow.
        let api = api_for(FakeEntitlementIssuer::new(&[EPOCH], 5));
        let clock = at_epoch(EPOCH);
        let entitlements = PortEntitlements::unregistered(
            Arc::new(PortEntitlementManager::new(Arc::clone(&api))),
            Arc::new(move || clock.load(Ordering::SeqCst)),
        );
        let rule = RuleSlot::default();
        let held = rule.provider(Some(&entitlements)).await.expect("slot");
        assert_eq!(api.transport().directory_fetches(), 1);
        tokio::time::sleep(REFRESH_PERIOD + Duration::from_secs(1)).await;
        assert_eq!(
            api.transport().directory_fetches(),
            2,
            "a live rule keeps it fresh"
        );

        drop((held, rule));
        tokio::time::sleep(REFRESH_PERIOD * 4).await;
        assert_eq!(
            api.transport().directory_fetches(),
            2,
            "no request after the last rule ended"
        );

        let _again = RuleSlot::default()
            .provider(Some(&entitlements))
            .await
            .expect("slot");
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            api.transport().directory_fetches(),
            3,
            "a new rule restarts it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_live_rule_restarts_a_refresh_whose_task_died() {
        // An embedder may tear down the runtime the refresh ran on while its
        // rules live on: the next mapping of such a rule restarts it, or the
        // rule would present nothing from the next epoch on.
        let api = api_for(FakeEntitlementIssuer::new(&[EPOCH], 5));
        let clock = at_epoch(EPOCH);
        let entitlements = PortEntitlements::unregistered(
            Arc::new(PortEntitlementManager::new(Arc::clone(&api))),
            Arc::new(move || clock.load(Ordering::SeqCst)),
        );
        let rule = RuleSlot::default();
        let (_, lease) = rule.provider(Some(&entitlements)).await.expect("slot");
        let task = lease.owner.refresh.lock().unwrap().take().expect("running");
        task.abort();
        let _ = task.await;
        *lease.owner.refresh.lock().unwrap() = Some(tokio::spawn(async {}));
        tokio::time::sleep(Duration::from_secs(1)).await;

        let _ = rule.provider(Some(&entitlements)).await.expect("slot");
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            api.transport().directory_fetches(),
            2,
            "the rule's next mapping restarted the refresh"
        );
    }

    #[test]
    fn only_a_success_clears_a_ban_and_a_failure_ends_the_first_wait() {
        let ban = Issuance::Banned(Ban {
            reason_code: BanReasonCode::Other,
            lapses_at_unix_secs: None,
        });
        let down = || Err(TokenClientError::BadDirectoryPolicy);

        assert_eq!(next_issuance(ban, &down()), ban, "an outage proves no lift");
        assert_eq!(next_issuance(ban, &Ok(())), Issuance::Answered);
        assert_eq!(
            next_issuance(Issuance::Pending, &down()),
            Issuance::Answered,
            "a first forward must not wait out an issuer that is down"
        );
    }
}
