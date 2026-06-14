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
//! Rekey/epoch rotation is out of scope here: the session stays at `epoch = 0`,
//! matching warren-core's single-epoch setup path. The reverse direction is
//! anti-replay-protected by a sliding window.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use warren_multihop::{ClientSession as HpkeSession, IpAssignment, ReplayWindow, SetupError};
use warren_wire::control::{CONTROL_FIRST_BYTE, try_decode_control};
use warren_wire::multihop::{EXIT_ID_LEN, WarrenMultihopFrame};

use crate::client::warren_transport_config;
use crate::tls;

/// ALPN protocol identifier ("h3"), matching warren-core's exits.
const ALPN_H3: &[u8] = b"h3";
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

/// Builder/dialer for a multihop client tunnel.
pub struct MultihopClientTunnel {
    /// Account signing key: the TLS raw-public-key identity AND the key that
    /// signs the setup proof of possession.
    signing_key: SigningKey,
    bind_local_ip: Option<SocketAddr>,
    wants_ipv6: bool,
}

impl MultihopClientTunnel {
    /// Create a tunnel dialer bound to the given account key.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            bind_local_ip: None,
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
        let mut client_cfg = tls::make_client_config(
            &self.signing_key,
            tls::default_crypto_provider(),
            &[ALPN_H3],
        )
        .map_err(MultihopError::Tls)?;
        client_cfg.transport_config(Arc::new(warren_transport_config()));

        let bind = self.bind_local_ip.unwrap_or_else(|| {
            if exit_addr.is_ipv6() {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
            }
        });
        let mut endpoint = quinn::Endpoint::client(bind).map_err(MultihopError::Bind)?;
        endpoint.set_default_client_config(client_cfg);

        let server_name = tls::name::encode(&exit_pubkey);
        let conn = endpoint
            .connect(exit_addr, &server_name)
            .map_err(MultihopError::Connect)?
            .await
            .map_err(|e| MultihopError::Quic {
                context: "connect",
                source: e,
            })?;

        match tls::peer_pubkey(&conn) {
            Some(pk) if pk == exit_pubkey => {}
            _ => return Err(MultihopError::ExitIdentityMismatch),
        }

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
        let mut replay = ReplayWindow::new();
        // The setup reply cannot be a replay (fresh window), but recording it
        // keeps a later data datagram from reusing that (epoch, seq).
        let _ = replay.check_and_record(reply_frame.seq, reply_frame.epoch);

        Ok(MultihopSession {
            _endpoint: endpoint,
            conn,
            session,
            exit_id,
            epoch: 0,
            // Setup consumed forward seq 0; data starts at 1.
            seq_send: AtomicU64::new(1),
            replay: Mutex::new(replay),
            assignment,
        })
    }
}

/// An established multihop session: IP packets travel as per-packet sealed
/// `WarrenMultihopFrame`s over QUIC datagrams.
pub struct MultihopSession {
    // Held so the endpoint outlives the connection.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    session: HpkeSession,
    exit_id: [u8; EXIT_ID_LEN],
    epoch: u32,
    seq_send: AtomicU64,
    replay: Mutex<ReplayWindow>,
    assignment: IpAssignment,
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
        let seq = self.seq_send.fetch_add(1, Ordering::AcqRel);
        let frame = self
            .session
            .seal(ip_packet, self.epoch, seq)
            .map_err(|e| MultihopError::Setup(SetupError::Session(e)))?;
        let bytes = frame.encode().map_err(MultihopError::Frame)?;
        self.conn
            .send_datagram(bytes.into())
            .map_err(MultihopError::SendDatagram)
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
                let replay = self.replay.lock().expect("replay window poisoned");
                if replay.check(frame.seq, frame.epoch).is_err() {
                    continue;
                }
            }
            let Ok(plaintext) = self.session.open_response(&frame) else {
                continue;
            };
            {
                let mut replay = self.replay.lock().expect("replay window poisoned");
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
                Some(_) => return Ok(plaintext),
                None => continue,
            }
        }
    }

    /// Close the connection cleanly.
    pub fn disconnect(&self) {
        self.conn.close(0u32.into(), b"client disconnect");
    }
}
