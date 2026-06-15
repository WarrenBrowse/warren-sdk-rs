//! Multihop QUIC client tunnel (the handshake real exits actually require).
//!
//! Production exits read an HPKE-sealed [`WarrenMultihopFrame`] as the first
//! frame on every connection (single-hop included), not a bare
//! [`Setup`](warren_wire::Setup): a raw Setup is rejected with `malformed setup
//! frame`. This module implements that path:
//!
//! 1. QUIC + TLS raw-public-key handshake against the dialed peer (the exit for
//!    single-hop; a relay for true multihop), pinned by `exit_pubkey`.
//! 2. Open a reliable bidi stream and send the sealed setup frame, whose inner
//!    plaintext is an [`IpRequest`](warren_wire::WarrenControlMessage) carrying
//!    the account pubkey and a proof of possession over the session's
//!    `encapsulated_key`. The exit replies with a sealed
//!    [`IpAssign`](warren_wire::WarrenControlMessage) (or `Rejected` /
//!    `IpExhausted`).
//! 3. IP packets then ride per-packet sealed `WarrenMultihopFrame`s on the QUIC
//!    datagram plane, forward seq continuing from `1` (the setup frame was the
//!    first forward frame, `seq = 0`).
//!
//! The live [`MultihopSession`] can rotate its HPKE epoch in place
//! ([`MultihopSession::rekey`]) without tearing down the connection: a fresh KEM
//! (new `encapsulated_key`), epoch `+1`, the forward sequence restarted at `0`,
//! and the previous epoch retained for an overlap window. The exit re-derives its
//! receiver context implicitly on the new `encapsulated_key` (no rekey control
//! message). [`RekeyPolicy`] carries the warren-core doctrine (rotate within 8 h,
//! 5-second overlap); a supervisor drives it. The whole rotation is validated
//! live against the real `warren-core` exit (see the `real_exit_tests` module).
//! The reverse direction is anti-replay-protected by a per-epoch sliding window,
//! so the new epoch's low sequence numbers are not mistaken for replays.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use warren_multihop::{ClientSession as HpkeSession, IpAssignment, ReplayWindow, SetupError};
use warren_wire::control::{CONTROL_FIRST_BYTE, try_decode_control};
use warren_wire::multihop::{EXIT_ID_LEN, WarrenMultihopFrame};

use crate::client::{QuicDialError, dial_quic, effective_bind};
use crate::tls;

/// Largest sealed setup frame accepted on the reliable stream (matches the data
/// frame ceiling; the setup payload is a few hundred bytes in practice).
const MAX_SETUP_FRAME_BYTES: usize = 65536;
/// DAITA dummy first byte (padding traffic), dropped on the receive path.
const DAITA_DUMMY_FIRST_BYTE: u8 = 0xFF;

/// Errors from the multihop tunnel handshake and data plane.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultihopError {
    /// Binding the local UDP socket failed.
    #[error("bind local endpoint failed")]
    Bind(#[source] std::io::Error),
    /// Configuring the QUIC client (TLS provider / RPK) failed.
    #[error("tls configuration failed")]
    Tls(#[source] tls::WarrenTlsError),
    /// Starting the QUIC connection failed (bad address / config).
    #[error("connect setup failed")]
    Connect(#[source] quinn::ConnectError),
    /// A QUIC connection or stream error occurred.
    #[error("quic error during {context}")]
    Quic {
        /// Which step failed.
        context: &'static str,
        /// The underlying quinn error.
        #[source]
        source: quinn::ConnectionError,
    },
    /// The authenticated peer key did not match the pinned exit identity.
    #[error("exit identity mismatch")]
    ExitIdentityMismatch,
    /// Writing or reading the sealed setup frame on the reliable stream failed.
    #[error("setup stream i/o error during {context}")]
    SetupIo {
        /// Which step failed.
        context: &'static str,
        /// The underlying error (boxed: open/write/read types differ).
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The multihop frame failed to encode or decode.
    #[error("multihop frame codec error")]
    Frame(#[source] warren_wire::multihop::MultihopFrameError),
    /// The HPKE setup exchange failed (seal/open, policy rejection, exhaustion).
    #[error("multihop setup failed")]
    Setup(#[source] SetupError),
    /// Sending a datagram failed (too large, or the connection is closing).
    #[error("send datagram failed")]
    SendDatagram(#[source] quinn::SendDatagramError),
    /// Reading a datagram failed (the connection closed).
    #[error("read datagram failed")]
    ReadDatagram(#[source] quinn::ConnectionError),
}

impl From<QuicDialError> for MultihopError {
    fn from(e: QuicDialError) -> Self {
        match e {
            QuicDialError::Tls(x) => MultihopError::Tls(x),
            QuicDialError::Bind(x) => MultihopError::Bind(x),
            QuicDialError::Connect(x) => MultihopError::Connect(x),
            QuicDialError::Quic(source) => MultihopError::Quic {
                context: "connect",
                source,
            },
            QuicDialError::IdentityMismatch => MultihopError::ExitIdentityMismatch,
        }
    }
}

/// Builder/dialer for a multihop client tunnel.
pub struct MultihopClientTunnel {
    /// Account signing key: the TLS raw-public-key identity AND the key that
    /// signs the setup proof of possession.
    signing_key: SigningKey,
    bind_local_ip: Option<SocketAddr>,
    auto_local_ip: bool,
    wants_ipv6: bool,
}

impl MultihopClientTunnel {
    /// Create a tunnel dialer bound to the given account key.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            bind_local_ip: None,
            auto_local_ip: false,
            wants_ipv6: false,
        }
    }

    /// Override the local bind address (defaults to the unspecified address with
    /// an OS-chosen port, matching the dialed address family).
    #[must_use]
    pub fn with_bind_local_ip(mut self, addr: SocketAddr) -> Self {
        self.bind_local_ip = Some(addr);
        self
    }

    /// Auto-detect the default-route source IP for the exit and bind to it
    /// (multi-NIC determinism). Ignored when [`with_bind_local_ip`](Self::with_bind_local_ip)
    /// is set; falls back to an unspecified bind if detection fails.
    #[must_use]
    pub fn with_auto_local_ip(mut self) -> Self {
        self.auto_local_ip = true;
        self
    }

    /// Request a dual-stack IPv6 assignment alongside the IPv4. The exit may
    /// still decline (the reply's `ipv6` is the capability echo).
    #[must_use]
    pub fn with_ipv6(mut self, enable: bool) -> Self {
        self.wants_ipv6 = enable;
        self
    }

    /// The account public key (TLS identity and PoP key).
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Connect to a dialed peer and complete the multihop setup exchange.
    ///
    /// `exit_pubkey` is the Ed25519 identity to pin on the TLS peer (the exit
    /// for single-hop). `exit_x25519` and `exit_id` come from the verified
    /// multihop directory: the HPKE recipient key and the cleartext routing tag.
    ///
    /// # Errors
    ///
    /// See [`MultihopError`]. In particular [`MultihopError::Setup`] wraps a
    /// policy rejection ([`SetupError::Rejected`]) or pool exhaustion
    /// ([`SetupError::IpExhausted`]).
    pub async fn connect(
        &self,
        exit_pubkey: [u8; 32],
        exit_x25519: [u8; 32],
        exit_id: [u8; EXIT_ID_LEN],
        exit_addr: SocketAddr,
    ) -> Result<MultihopSession, MultihopError> {
        let (endpoint, conn) = dial_quic(
            &self.signing_key,
            exit_pubkey,
            exit_addr,
            effective_bind(self.bind_local_ip, self.auto_local_ip, exit_addr),
        )
        .await?;

        // Build the per-session HPKE context (one KEM ECDH against the exit's
        // X25519 multihop key); its encapsulated key rides every frame.
        let session = HpkeSession::new(
            &exit_x25519,
            exit_id,
            &mut rand_core::UnwrapErr(rand_core::OsRng),
        )
        .map_err(|e| MultihopError::Setup(SetupError::Session(e)))?;

        // Seal the setup IpRequest as the first forward frame (epoch 0, seq 0)
        // and send it on a reliable bidi stream; read the sealed reply.
        let request = session
            .seal_setup_request(Some(&self.signing_key), None, self.wants_ipv6, 0, 0)
            .map_err(MultihopError::Setup)?;
        let request_bytes = request.encode().map_err(MultihopError::Frame)?;

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| MultihopError::Quic {
            context: "open_bi",
            source: e,
        })?;
        send.write_all(&request_bytes)
            .await
            .map_err(|e| MultihopError::SetupIo {
                context: "write request",
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| MultihopError::SetupIo {
            context: "finish request",
            source: Box::new(e),
        })?;
        let reply_bytes =
            recv.read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .map_err(|e| MultihopError::SetupIo {
                    context: "read reply",
                    source: Box::new(e),
                })?;

        let reply_frame =
            WarrenMultihopFrame::decode(&reply_bytes).map_err(MultihopError::Frame)?;
        // Authenticate the reply (open_setup_reply) before committing its seq to
        // the reverse window.
        let assignment = session
            .open_setup_reply(&reply_frame)
            .map_err(MultihopError::Setup)?;
        let mut replay = EpochReplay::new();
        // The setup reply cannot be a replay (fresh window), but recording it
        // keeps a later data datagram from reusing that (epoch, seq).
        let _ = replay.check_and_record(reply_frame.seq, reply_frame.epoch);

        Ok(MultihopSession {
            _endpoint: endpoint,
            conn,
            session: RwLock::new(session),
            exit_id,
            // Setup consumed forward seq 0; data starts at 1.
            seq_send: AtomicU64::new(1),
            replay: Mutex::new(replay),
            assignment,
            metrics: Arc::new(MultihopMetrics::new(0)),
            last_rekey_at: Mutex::new(Instant::now()),
        })
    }
}

/// Live data-plane counters for a multihop session, cheaply shareable (`Arc`):
/// a clone can be held past the session (e.g. by a proxy handle) to read totals.
#[derive(Debug)]
pub struct MultihopMetrics {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    packets_sent: AtomicU64,
    packets_recv: AtomicU64,
    cover_packets_sent: AtomicU64,
    epoch: AtomicU32,
    connected_since: Instant,
}

impl MultihopMetrics {
    fn new(epoch: u32) -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            cover_packets_sent: AtomicU64::new(0),
            epoch: AtomicU32::new(epoch),
            connected_since: Instant::now(),
        }
    }

    /// A point-in-time snapshot of the counters.
    #[must_use]
    pub fn snapshot(&self) -> MultihopMetricsSnapshot {
        MultihopMetricsSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            cover_packets_sent: self.cover_packets_sent.load(Ordering::Relaxed),
            epoch: self.epoch.load(Ordering::Relaxed),
            uptime_secs: self.connected_since.elapsed().as_secs(),
        }
    }
}

/// A serializable point-in-time view of a session's counters. Plain scalars so it
/// maps cleanly across the FFI boundary to the sibling-language SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MultihopMetricsSnapshot {
    /// Total inner IP bytes sealed and sent.
    pub bytes_sent: u64,
    /// Total inner IP bytes received and opened.
    pub bytes_recv: u64,
    /// Total IP packets sent.
    pub packets_sent: u64,
    /// Total IP packets received.
    pub packets_recv: u64,
    /// Total DAITA cover-traffic (dummy) frames sent (not app data).
    pub cover_packets_sent: u64,
    /// Current HPKE epoch (rotates on rekey).
    pub epoch: u32,
    /// Seconds since the session was established.
    pub uptime_secs: u64,
}

/// How many epochs' reverse anti-replay windows are retained at once. Mirrors
/// the exit's bound (`REPLAY_EPOCHS_KEPT`): the current epoch plus a few recent
/// ones cover any in-flight old-epoch reverse frame during a rekey overlap.
const REKEY_EPOCHS_KEPT: usize = 4;

/// Reverse anti-replay across epochs: each epoch has its own seq space (the
/// exit restarts the reverse counter per epoch), so a single sliding window
/// would spuriously reject the new epoch's low seqs after a rekey. This keeps
/// one [`ReplayWindow`] per epoch, evicting the oldest beyond
/// [`REKEY_EPOCHS_KEPT`].
struct EpochReplay {
    windows: BTreeMap<u32, ReplayWindow>,
}

impl EpochReplay {
    fn new() -> Self {
        Self {
            windows: BTreeMap::new(),
        }
    }

    /// Probe `seq` for `epoch` without recording. An epoch never seen yet
    /// accepts (its window is created on the matching record).
    fn check(&self, seq: u64, epoch: u32) -> Result<(), warren_multihop::SessionError> {
        match self.windows.get(&epoch) {
            Some(w) => w.check(seq, epoch),
            None => Ok(()),
        }
    }

    /// Record `seq` for `epoch`, creating the epoch's window on first use and
    /// evicting the oldest epoch once more than [`REKEY_EPOCHS_KEPT`] are held.
    fn check_and_record(
        &mut self,
        seq: u64,
        epoch: u32,
    ) -> Result<(), warren_multihop::SessionError> {
        let result = self
            .windows
            .entry(epoch)
            .or_default()
            .check_and_record(seq, epoch);
        while self.windows.len() > REKEY_EPOCHS_KEPT {
            // pop_first removes the lowest epoch key: the oldest, safe to forget.
            self.windows.pop_first();
        }
        result
    }
}

/// The session rekey doctrine (warren-core doc 19 § 11.6): rotate the HPKE
/// context within `interval` to bound a long-lived session's AEAD exposure, and
/// keep the previous epoch openable for `overlap` so in-flight reverse frames
/// sealed just before the rotation still decrypt (the exit's session cache TTL).
///
/// This is a pure policy value; a supervisor drives it:
/// `if policy.is_due(session.since_last_rekey()) { session.rekey()?;
/// sleep(policy.overlap()); session.prune_old_epoch(); }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyPolicy {
    interval: Duration,
    overlap: Duration,
}

impl RekeyPolicy {
    /// The warren-core doctrine: rekey before 8 hours, 5-second overlap (the
    /// exit's `SESSION_CACHE_TTL`).
    #[must_use]
    pub const fn doctrine() -> Self {
        Self {
            interval: Duration::from_secs(8 * 60 * 60),
            overlap: Duration::from_secs(5),
        }
    }

    /// Override the rotation interval (kept at or below the 8-hour doctrine cap).
    #[must_use]
    pub const fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Override the overlap window.
    #[must_use]
    pub const fn with_overlap(mut self, overlap: Duration) -> Self {
        self.overlap = overlap;
        self
    }

    /// The rotation interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// The overlap window during which the previous epoch stays openable.
    #[must_use]
    pub const fn overlap(&self) -> Duration {
        self.overlap
    }

    /// Whether a rekey is due given the time since the last rotation.
    #[must_use]
    pub fn is_due(&self, since_last_rekey: Duration) -> bool {
        since_last_rekey >= self.interval
    }
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self::doctrine()
    }
}

/// An established multihop session: IP packets travel as per-packet sealed
/// `WarrenMultihopFrame`s over QUIC datagrams.
///
/// The session can rotate its HPKE epoch in place ([`rekey`](Self::rekey)) while
/// the datapath keeps sealing under `&self`: the inner [`ClientSession`] sits
/// behind an `RwLock` (seals take a read lock, a rekey takes the write lock), so
/// no datagram is sealed against a half-rotated context.
pub struct MultihopSession {
    // Held so the endpoint outlives the connection.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    session: RwLock<HpkeSession>,
    exit_id: [u8; EXIT_ID_LEN],
    seq_send: AtomicU64,
    replay: Mutex<EpochReplay>,
    assignment: IpAssignment,
    metrics: Arc<MultihopMetrics>,
    /// When the current epoch was installed (construction or last rekey); drives
    /// [`RekeyPolicy::is_due`].
    last_rekey_at: Mutex<Instant>,
}

impl MultihopSession {
    /// The exit's IP assignment for this session.
    #[must_use]
    pub fn assignment(&self) -> &IpAssignment {
        &self.assignment
    }

    /// The assigned tunnel IPv4.
    #[must_use]
    pub fn assigned_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.assignment.ipv4)
    }

    /// The assigned tunnel IPv6, if the exit granted dual-stack.
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<Ipv6Addr> {
        self.assignment.ipv6.map(Ipv6Addr::from)
    }

    /// The largest datagram payload the current path can carry, if known.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// The largest inner IP packet that fits in one sealed datagram: the path
    /// datagram size minus the worst-case frame overhead. Falls back to the
    /// 1280-byte base MTU before the first PMTU probe.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        const BASE_MTU: usize = 1280;
        let path = self.conn.max_datagram_size().unwrap_or(BASE_MTU);
        path.saturating_sub(warren_wire::MULTIHOP_FRAME_MAX_OVERHEAD)
    }

    /// The underlying quinn connection (for advanced callers / the pump).
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Seal one IP packet and send it as a QUIC datagram.
    ///
    /// # Errors
    ///
    /// [`MultihopError::Setup`] if sealing fails, [`MultihopError::Frame`] if
    /// the frame fails to encode, [`MultihopError::SendDatagram`] if quinn
    /// refuses the datagram.
    pub fn send_packet(&self, ip_packet: &[u8]) -> Result<(), MultihopError> {
        self.seal_and_send(ip_packet)?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(ip_packet.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Seals `plaintext` as the next forward frame and sends it as a datagram,
    /// advancing the forward sequence. Shared by real packets and cover traffic;
    /// does not touch the app-data metrics (the caller owns that distinction).
    fn seal_and_send(&self, plaintext: &[u8]) -> Result<(), MultihopError> {
        // Read-lock the session for the whole seal: a concurrent rekey holds the
        // write lock, so the epoch read and the seq bump cannot straddle a
        // rotation (no frame is sealed at the new epoch with a stale seq, nor at
        // the old epoch after the seq reset).
        let guard = self.session.read().unwrap_or_else(|e| e.into_inner());
        let epoch = guard.epoch();
        let seq = self.seq_send.fetch_add(1, Ordering::AcqRel);
        let frame = guard
            .seal(plaintext, epoch, seq)
            .map_err(|e| MultihopError::Setup(SetupError::Session(e)))?;
        drop(guard);
        let bytes = frame.encode().map_err(MultihopError::Frame)?;
        self.conn
            .send_datagram(bytes.into())
            .map_err(MultihopError::SendDatagram)
    }

    /// Rotate the HPKE context: a fresh KEM (new `encapsulated_key`), epoch `+1`,
    /// the forward sequence restarted at `0` (warren-core doc 19 § 5.4), and the
    /// previous epoch retained for the overlap so the exit's just-sent reverse
    /// frames still open. The exit re-derives its receiver context implicitly on
    /// the new `encapsulated_key`; there is no rekey control message.
    ///
    /// Close the overlap with [`prune_old_epoch`](Self::prune_old_epoch) once the
    /// policy's overlap window elapses.
    ///
    /// # Errors
    ///
    /// [`MultihopError::Setup`] if the fresh `setup_sender` fails.
    pub fn rekey(&self) -> Result<u32, MultihopError> {
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let mut guard = self.session.write().unwrap_or_else(|e| e.into_inner());
        let new_epoch = guard
            .rekey(&mut rng)
            .map_err(|e| MultihopError::Setup(SetupError::Session(e)))?;
        // Publish the seq reset and epoch under the write lock, before any seal
        // can observe the new epoch (the write lock excludes all read-lock seals).
        self.seq_send.store(0, Ordering::SeqCst);
        self.metrics.epoch.store(new_epoch, Ordering::Relaxed);
        drop(guard);
        *self.last_rekey_at.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        Ok(new_epoch)
    }

    /// End the rekey overlap: drop the previous-epoch context so old-epoch reverse
    /// frames no longer open. Call once the [`RekeyPolicy::overlap`] deadline
    /// elapses. Idempotent.
    pub fn prune_old_epoch(&self) {
        self.session
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .prune_old_epoch();
    }

    /// The current HPKE epoch (starts at `0`, `+1` per [`rekey`](Self::rekey)).
    #[must_use]
    pub fn current_epoch(&self) -> u32 {
        self.session
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .epoch()
    }

    /// Time since the current epoch was installed (construction or last rekey).
    /// Feed it to [`RekeyPolicy::is_due`] to decide when to rotate.
    #[must_use]
    pub fn since_last_rekey(&self) -> Duration {
        self.last_rekey_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
    }

    /// Sends a DAITA cover-traffic (dummy) frame: a sealed frame whose plaintext
    /// begins with the dummy tag (`0xFF`) followed by `padding_len` zero bytes,
    /// which the exit drops on receipt (it is not an IP packet). Client-unilateral
    /// traffic shaping to blur real-traffic timing/volume; carries no app data and
    /// is not counted in the app-data metrics. This is the cover-traffic building
    /// block; a full DAITA defense schedule that decides WHEN to emit dummies is
    /// driven above this seam (and validated against a real exit before relied on).
    ///
    /// # Errors
    ///
    /// Same as [`send_packet`](Self::send_packet) (seal, encode, or datagram send).
    pub fn send_cover_traffic(&self, padding_len: usize) -> Result<(), MultihopError> {
        let mut dummy = Vec::with_capacity(1 + padding_len);
        dummy.push(DAITA_DUMMY_FIRST_BYTE);
        dummy.resize(1 + padding_len, 0);
        self.seal_and_send(&dummy)?;
        self.metrics
            .cover_packets_sent
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// A cheap, cloneable handle to this session's live counters. Hold it past the
    /// session (e.g. a proxy handle) to read totals without the session itself.
    #[must_use]
    pub fn metrics(&self) -> Arc<MultihopMetrics> {
        Arc::clone(&self.metrics)
    }

    /// A point-in-time snapshot of this session's counters.
    #[must_use]
    pub fn metrics_snapshot(&self) -> MultihopMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Await the next inbound IP packet, opening sealed datagrams and skipping
    /// DAITA dummies, control messages, and frames that fail the exit-id pin,
    /// the anti-replay window, or the AEAD open.
    ///
    /// # Errors
    ///
    /// [`MultihopError::ReadDatagram`] if the connection closed.
    pub async fn recv_packet(&self) -> Result<Vec<u8>, MultihopError> {
        loop {
            let datagram = self
                .conn
                .read_datagram()
                .await
                .map_err(MultihopError::ReadDatagram)?;
            let Ok(frame) = WarrenMultihopFrame::decode(&datagram) else {
                continue;
            };
            if frame.exit_id != self.exit_id {
                continue;
            }
            // Verify-then-record: probe the window, open (authenticate), then
            // commit the seq. A frame failing any step is dropped, never fatal.
            {
                // Recover rather than panic on a poisoned lock: the replay window
                // is plain integer state and stays consistent across a panic, and a
                // library must not unwind into an FFI embedder.
                let replay = self.replay.lock().unwrap_or_else(|e| e.into_inner());
                if replay.check(frame.seq, frame.epoch).is_err() {
                    continue;
                }
            }
            let opened = self
                .session
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .open_response(&frame);
            let Ok(plaintext) = opened else {
                continue;
            };
            {
                let mut replay = self.replay.lock().unwrap_or_else(|e| e.into_inner());
                if replay.check_and_record(frame.seq, frame.epoch).is_err() {
                    continue;
                }
            }
            match plaintext.first() {
                // DAITA padding or a control message: not an IP packet.
                Some(&DAITA_DUMMY_FIRST_BYTE) | Some(&CONTROL_FIRST_BYTE) => {
                    // A stray control message on the data plane is ignored
                    // (the client setup is already complete).
                    let _ = try_decode_control(&plaintext);
                    continue;
                }
                Some(_) => {
                    self.metrics.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .bytes_recv
                        .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                    return Ok(plaintext);
                }
                None => continue,
            }
        }
    }

    /// Close the connection cleanly.
    pub fn disconnect(&self) {
        self.conn.close(0u32.into(), b"client disconnect");
    }
}

#[cfg(test)]
impl MultihopSession {
    /// Builds a session over an already-dialed raw connection, skipping the
    /// setup/IpAssign exchange. Used to drive the multihop echo exit (which does
    /// not run the setup stream) through the live rekey datapath in tests.
    fn from_raw_for_test(
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        session: HpkeSession,
        exit_id: [u8; EXIT_ID_LEN],
    ) -> Self {
        Self {
            _endpoint: endpoint,
            conn,
            session: RwLock::new(session),
            exit_id,
            seq_send: AtomicU64::new(0),
            replay: Mutex::new(EpochReplay::new()),
            assignment: IpAssignment::placeholder_for_test(),
            metrics: Arc::new(MultihopMetrics::new(0)),
            last_rekey_at: Mutex::new(Instant::now()),
        }
    }
}

/// Wire-compatibility validation against the genuine `warren-core` exit.
///
/// These tests spawn the real `warren-exit` binary in multihop echo mode (the
/// reference implementation, not the in-repo fake) and drive its HPKE datagram
/// plane with this SDK's [`ClientSession`](warren_multihop::ClientSession). They
/// are the authoritative wire-compat oracle: if the per-packet key derivation,
/// the AAD layout, the encapsulated-key serialization, the postcard frame shape,
/// or the rekey contract drift from the reference, the round-trip stops opening.
///
/// They are gated on the `WARREN_EXIT_BIN` env var (absolute path to a built
/// `warren-exit`); without it each test returns immediately so `cargo test`
/// stays green on machines that do not have the reference checkout. Build the
/// binary with `cargo build -p warren-exit` in the `warren-core` checkout and
/// point `WARREN_EXIT_BIN` at `target/debug/warren-exit`.
#[cfg(test)]
mod real_exit_tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use warren_multihop::ClientSession;

    /// Frozen BIP39 test vector. The exit derives BOTH its Ed25519 QUIC RPK
    /// (via the identity HKDF) and its long-lived X25519 multihop key from this
    /// mnemonic; we re-derive the RPK locally to pin the TLS peer.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// Matches the `--multihop-exit-id` hex we pass the exit.
    const TEST_EXIT_ID: [u8; EXIT_ID_LEN] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const TEST_EXIT_ID_HEX: &str = "00112233445566778899aabbccddeeff";
    /// Deterministic client identity (the value is irrelevant in permissive mode).
    const CLIENT_SEED: [u8; 32] = [0x77; 32];

    /// Kills the spawned exit on drop so a panicking test never leaks the process.
    struct ExitGuard(Child);
    impl Drop for ExitGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A bound-then-released loopback UDP port. Small TOCTOU window before the
    /// exit rebinds it; acceptable for a serial, opt-in integration test.
    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind ephemeral udp")
            .local_addr()
            .expect("local_addr")
            .port()
    }

    /// Spawns the real exit in multihop echo mode. Returns `None` when
    /// `WARREN_EXIT_BIN` is unset (the test then no-ops to keep CI green).
    /// On success: the running exit, its address, its X25519 multihop pubkey,
    /// and its Ed25519 RPK (re-derived here from the same mnemonic).
    fn spawn_real_exit() -> Option<(ExitGuard, SocketAddr, [u8; 32], [u8; 32])> {
        let bin = std::env::var("WARREN_EXIT_BIN").ok()?;

        let dir = tempfile::tempdir().expect("tempdir");
        let mnemonic_file = dir.path().join("mnemonic.txt");
        std::fs::write(&mnemonic_file, format!("{TEST_MNEMONIC}\n")).expect("write mnemonic");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mnemonic_file, std::fs::Permissions::from_mode(0o600))
                .expect("chmod mnemonic");
        }
        let pubkey_out = dir.path().join("multihop_pub.hex");
        let port = free_udp_port();

        let child = Command::new(&bin)
            .arg("--multihop")
            .arg("--allow-anonymous-clients")
            .arg("--bind-addr")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--mnemonic-file")
            .arg(&mnemonic_file)
            .arg("--multihop-exit-id")
            .arg(TEST_EXIT_ID_HEX)
            .arg("--multihop-pubkey-out")
            .arg(&pubkey_out)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn warren-exit (is WARREN_EXIT_BIN a valid path?)");
        let guard = ExitGuard(child);

        // The exit writes its X25519 pubkey just before binding the endpoint, so
        // poll for it as a readiness signal (then still retry the QUIC dial).
        let mut exit_x25519 = [0u8; 32];
        let mut ready = false;
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&pubkey_out) {
                let s = s.trim();
                if s.len() == 64 && hex::decode_to_slice(s, &mut exit_x25519).is_ok() {
                    ready = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(ready, "exit did not publish its X25519 multihop pubkey");

        // Re-derive the exit's Ed25519 RPK from the same mnemonic (identical
        // frozen identity derivation): pinning it proves both ends agree.
        let exit_rpk = warren_identity::WarrenIdentity::from_mnemonic(TEST_MNEMONIC)
            .expect("derive exit identity")
            .public_key();

        Some((
            guard,
            (Ipv4Addr::LOCALHOST, port).into(),
            exit_x25519,
            exit_rpk,
        ))
    }

    /// Dials the exit's raw multihop QUIC plane, retrying until it is listening.
    async fn dial_with_retry(
        client_key: &SigningKey,
        exit_rpk: [u8; 32],
        addr: SocketAddr,
    ) -> (quinn::Endpoint, quinn::Connection) {
        for attempt in 0..50u32 {
            match crate::client::dial_quic(
                client_key,
                exit_rpk,
                addr,
                effective_bind(None, false, addr),
            )
            .await
            {
                Ok(pair) => return pair,
                Err(_) if attempt < 49 => tokio::time::sleep(Duration::from_millis(100)).await,
                Err(e) => panic!("dial_quic never succeeded: {e:?}"),
            }
        }
        unreachable!()
    }

    /// One sealed forward datagram, echoed back and opened. Asserts the exit
    /// returned our exact plaintext through the reverse HPKE direction.
    async fn echo_roundtrip(
        conn: &quinn::Connection,
        session: &ClientSession,
        epoch: u32,
        seq: u64,
        payload: &[u8],
    ) {
        let frame = session.seal(payload, epoch, seq).expect("seal");
        conn.send_datagram(frame.encode().expect("encode").into())
            .expect("send_datagram");
        let resp = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("echo within 5s")
            .expect("read_datagram");
        let resp_frame = WarrenMultihopFrame::decode(&resp).expect("decode echo");
        let opened = session.open_response(&resp_frame).expect("open echo");
        assert_eq!(
            opened, payload,
            "echo must match the sealed payload byte-for-byte"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rekey_round_trips_across_epochs_against_the_real_exit() {
        let Some((_exit, addr, exit_x25519, exit_rpk)) = spawn_real_exit() else {
            eprintln!("skipping: WARREN_EXIT_BIN not set");
            return;
        };

        let client_key = SigningKey::from_bytes(&CLIENT_SEED);
        let (endpoint, conn) = dial_with_retry(&client_key, exit_rpk, addr).await;

        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let mut session =
            ClientSession::new(&exit_x25519, TEST_EXIT_ID, &mut rng).expect("HPKE setup_sender");

        // Epoch 0: a handful of frames open cleanly (baseline datapath).
        for seq in 0..8u64 {
            let payload: Vec<u8> = (0..200).map(|i| (i as u64 ^ seq) as u8).collect();
            echo_roundtrip(&conn, &session, 0, seq, &payload).await;
        }

        // Rekey: a fresh encapsulated_key makes the exit's session cache MISS and
        // run a brand new `setup_receiver`. The new-epoch datapath must round-trip.
        let new_epoch = session.rekey(&mut rng).expect("rekey");
        assert_eq!(new_epoch, 1);
        for seq in 0..8u64 {
            let payload: Vec<u8> = (0..200).map(|i| (i as u64 ^ seq ^ 0xA5) as u8).collect();
            echo_roundtrip(&conn, &session, new_epoch, seq, &payload).await;
        }

        // Overlap window: the exit keeps the previous encapsulated_key's session
        // briefly (its cache TTL), so an in-flight OLD-epoch frame still opens.
        echo_roundtrip(
            &conn,
            &session,
            0,
            100,
            b"old-epoch frame in the overlap window",
        )
        .await;

        // Closing the overlap drops the old context client-side: sealing at the
        // retired epoch is now refused (no key material to reuse a stale nonce).
        session.prune_old_epoch();
        assert!(
            session.seal(b"after prune", 0, 101).is_err(),
            "old epoch must be unusable once the overlap window is pruned"
        );

        // The current epoch is unaffected by the prune.
        echo_roundtrip(&conn, &session, new_epoch, 8, b"current epoch still works").await;

        conn.close(0u32.into(), b"done");
        drop(endpoint);
    }

    /// Sends an IP-looking packet through the live session and asserts the exit
    /// echoes it back through `recv_packet` (so the whole driver, not just the
    /// raw `ClientSession`, survives the round-trip).
    async fn session_echo(sess: &MultihopSession, payload: &[u8]) {
        sess.send_packet(payload).expect("send_packet");
        let got = tokio::time::timeout(Duration::from_secs(5), sess.recv_packet())
            .await
            .expect("echo within 5s")
            .expect("recv_packet");
        assert_eq!(
            got, payload,
            "echo must match the sent packet byte-for-byte"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_session_rekeys_in_place_against_the_real_exit() {
        let Some((_exit, addr, exit_x25519, exit_rpk)) = spawn_real_exit() else {
            eprintln!("skipping: WARREN_EXIT_BIN not set");
            return;
        };

        let client_key = SigningKey::from_bytes(&CLIENT_SEED);
        let (endpoint, conn) = dial_with_retry(&client_key, exit_rpk, addr).await;

        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let hpke =
            ClientSession::new(&exit_x25519, TEST_EXIT_ID, &mut rng).expect("HPKE setup_sender");
        let session = MultihopSession::from_raw_for_test(endpoint, conn, hpke, TEST_EXIT_ID);

        // An IPv4-looking packet (first nibble 4) so recv_packet returns it
        // instead of dropping it as DAITA padding or a control message.
        let make_pkt = |tag: u8| -> Vec<u8> {
            let mut p = vec![0x45u8];
            p.extend((0..160u16).map(|i| (i as u8) ^ tag));
            p
        };

        assert_eq!(session.current_epoch(), 0);
        for tag in 0..6u8 {
            session_echo(&session, &make_pkt(tag)).await;
        }

        // Rotate the live session in place under &self: fresh KEM, epoch+1, the
        // forward sequence restarts at 0. The datapath must keep working without
        // tearing down the connection.
        let new_epoch = session.rekey().expect("rekey");
        assert_eq!(new_epoch, 1);
        assert_eq!(session.current_epoch(), 1);
        assert_eq!(
            session.metrics_snapshot().epoch,
            1,
            "metrics reflect the rotated epoch"
        );

        for tag in 6..12u8 {
            session_echo(&session, &make_pkt(tag)).await;
        }

        // A second rotation works too (epoch counter keeps climbing).
        assert_eq!(session.rekey().expect("rekey 2"), 2);
        session_echo(&session, &make_pkt(0xC3)).await;

        // Pruning the overlap is safe and leaves the current epoch usable.
        session.prune_old_epoch();
        session_echo(&session, &make_pkt(0xD4)).await;

        session.disconnect();
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn rekey_policy_doctrine_is_eight_hours_with_five_second_overlap() {
        let p = RekeyPolicy::doctrine();
        assert_eq!(p.interval(), Duration::from_secs(8 * 60 * 60));
        assert_eq!(p.overlap(), Duration::from_secs(5));
        assert_eq!(RekeyPolicy::default(), p);
    }

    #[test]
    fn rekey_policy_is_due_only_past_the_interval() {
        let p = RekeyPolicy::doctrine().with_interval(Duration::from_secs(100));
        assert!(!p.is_due(Duration::from_secs(99)));
        assert!(p.is_due(Duration::from_secs(100)));
        assert!(p.is_due(Duration::from_secs(101)));
    }

    #[test]
    fn epoch_replay_isolates_seq_spaces_across_epochs() {
        let mut r = EpochReplay::new();
        // Same seq in two different epochs is NOT a replay (separate windows).
        r.check_and_record(0, 0).expect("epoch 0 seq 0");
        r.check_and_record(0, 1)
            .expect("epoch 1 seq 0 is independent");
        // But repeating a seq within one epoch is a replay.
        assert!(r.check_and_record(0, 0).is_err(), "epoch 0 seq 0 replay");
        assert!(r.check_and_record(0, 1).is_err(), "epoch 1 seq 0 replay");
    }

    #[test]
    fn epoch_replay_evicts_oldest_epochs_beyond_the_cap() {
        let mut r = EpochReplay::new();
        // Fill more than the retention cap, then the lowest epoch's window is gone,
        // so its seqs are accepted again (treated as a fresh epoch).
        for epoch in 0..(REKEY_EPOCHS_KEPT as u32 + 1) {
            r.check_and_record(5, epoch).expect("record");
        }
        assert!(
            r.check_and_record(5, 0).is_ok(),
            "evicted epoch 0 window forgets its seqs"
        );
    }
}
