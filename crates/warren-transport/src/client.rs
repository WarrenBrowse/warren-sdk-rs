//! Identity-bound QUIC client tunnel: handshake and datagram session.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warren_wire::{DEVICE_ID_LEN, MAX_SETUP_FRAME_BYTES, Setup, decode_setup_ack, encode_setup};

use crate::tls;

/// ALPN offered by the client: IETF HTTP/3, mimicking a casual h3 dial.
const ALPN_H3: &[u8] = b"h3";

/// Client-side QUIC tuning for a VPN datagram workload. Mirrors warren-core's
/// pinned constants: large datagram buffers to absorb internet jitter, an idle
/// timeout and keepalive to detect dead peers and survive NAT expiry, and an
/// initial MTU of 1280 (IPv6 minimum, safe on every path) to start PMTU
/// discovery one round trip ahead.
const DATAGRAM_RECV_BUFFER: usize = 8 * 1024 * 1024;
const DATAGRAM_SEND_BUFFER: usize = 4 * 1024 * 1024;
const MAX_IDLE_TIMEOUT_SECS: u64 = 180;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 20;
const INITIAL_MTU: u16 = 1280;

pub(crate) fn warren_transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
    tc.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    tc.keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)));
    tc.initial_mtu(INITIAL_MTU);
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS)) {
        tc.max_idle_timeout(Some(idle));
    }
    tc
}

/// Errors from establishing or driving a tunnel.
///
/// Underlying causes are attached via [`std::error::Error::source`] rather than
/// formatted into the message: this keeps the top-level `Display` free of any
/// address or peer detail (no-log discipline) while preserving the full chain
/// for callers that opt into deeper diagnostics.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// Building the TLS configuration failed.
    #[error("tls config error")]
    Tls(#[from] tls::WarrenTlsError),
    /// Binding the local UDP socket / endpoint failed.
    #[error("endpoint bind failed")]
    Bind(#[source] std::io::Error),
    /// The QUIC connection could not be set up (bad address or config).
    #[error("connect setup failed")]
    Connect(#[source] quinn::ConnectError),
    /// A QUIC stream or connection error occurred mid-handshake.
    #[error("quic error: {context}")]
    Quic {
        /// Where the error happened.
        context: &'static str,
        /// Underlying quinn connection error.
        #[source]
        source: quinn::ConnectionError,
    },
    /// Writing or reading the Setup/SetupAck frame failed. The source is one of
    /// quinn's stream error types, kept behind a boxed `dyn Error`.
    #[error("handshake i/o error: {context}")]
    HandshakeIo {
        /// Which handshake step failed.
        context: &'static str,
        /// Underlying quinn stream error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The Setup/SetupAck frame did not decode.
    #[error("handshake frame error")]
    Frame(#[from] warren_wire::ProtocolError),
    /// The exit's authenticated pubkey did not match the expected one.
    #[error("exit identity mismatch (possible MITM)")]
    ExitIdentityMismatch,
    /// Sending a datagram failed (too large, or connection closing).
    #[error("send datagram failed")]
    SendDatagram(#[source] quinn::SendDatagramError),
    /// Reading a datagram failed (connection closed).
    #[error("read datagram failed")]
    ReadDatagram(#[source] quinn::ConnectionError),
}

/// Builder for an identity-bound client tunnel.
#[derive(Debug, Clone)]
pub struct ClientTunnel {
    signing_key: SigningKey,
    features: u32,
    daita_support: bool,
    device_id: [u8; DEVICE_ID_LEN],
    bind_local_ip: Option<SocketAddr>,
}

impl ClientTunnel {
    /// Builds a tunnel for the given identity, default features off.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            features: 0,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            bind_local_ip: None,
        }
    }

    /// Sets the requested feature bitmask (see `warren_wire::features`).
    #[must_use]
    pub fn with_features(mut self, features: u32) -> Self {
        self.features = features;
        self
    }

    /// Advertises DAITA v2 support in the handshake.
    #[must_use]
    pub fn with_daita(mut self, enable: bool) -> Self {
        self.daita_support = enable;
        self
    }

    /// Sets the per-run device id (16 bytes).
    #[must_use]
    pub fn with_device_id(mut self, device_id: [u8; DEVICE_ID_LEN]) -> Self {
        self.device_id = device_id;
        self
    }

    /// Forces the local bind address (multi-NIC). Defaults to `0.0.0.0:0`.
    #[must_use]
    pub fn with_bind_local_ip(mut self, addr: SocketAddr) -> Self {
        self.bind_local_ip = Some(addr);
        self
    }

    /// The client's 32-byte Ed25519 public key.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Connects to an exit and completes the Setup/SetupAck handshake.
    ///
    /// `exit_pubkey` is the exit's expected Ed25519 identity (from discovery);
    /// it is encoded into the SNI and re-checked against the authenticated peer
    /// key after the handshake.
    ///
    /// # Errors
    ///
    /// See [`TunnelError`].
    pub async fn connect(
        &self,
        exit_pubkey: [u8; 32],
        exit_addr: SocketAddr,
    ) -> Result<ClientSession, TunnelError> {
        let mut client_cfg = tls::make_client_config(
            &self.signing_key,
            tls::default_crypto_provider(),
            &[ALPN_H3],
        )?;
        client_cfg.transport_config(Arc::new(warren_transport_config()));

        let bind = self.bind_local_ip.unwrap_or_else(|| {
            if exit_addr.is_ipv6() {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
            }
        });
        let mut endpoint = quinn::Endpoint::client(bind).map_err(TunnelError::Bind)?;
        endpoint.set_default_client_config(client_cfg);

        let server_name = tls::name::encode(&exit_pubkey);
        let conn = endpoint
            .connect(exit_addr, &server_name)
            .map_err(TunnelError::Connect)?
            .await
            .map_err(|e| TunnelError::Quic {
                context: "connect",
                source: e,
            })?;

        // Confirm the authenticated peer key matches the expected exit identity.
        match tls::peer_pubkey(&conn) {
            Some(pk) if pk == exit_pubkey => {}
            _ => return Err(TunnelError::ExitIdentityMismatch),
        }

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| TunnelError::Quic {
            context: "open_bi",
            source: e,
        })?;

        let setup = Setup {
            protocol_version: warren_wire::PROTOCOL_VERSION,
            features: self.features,
            connection_index: 0,
            total_connections: 1,
            daita_support: self.daita_support,
            device_id: self.device_id,
        };
        send.write_all(&encode_setup(&setup)?)
            .await
            .map_err(|e| TunnelError::HandshakeIo {
                context: "write setup",
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::HandshakeIo {
            context: "finish setup",
            source: Box::new(e),
        })?;

        let ack_bytes = recv.read_to_end(MAX_SETUP_FRAME_BYTES).await.map_err(|e| {
            TunnelError::HandshakeIo {
                context: "read setup_ack",
                source: Box::new(e),
            }
        })?;
        let ack = decode_setup_ack(&ack_bytes)?;

        Ok(ClientSession {
            _endpoint: endpoint,
            conn,
            assigned_ipv4: Ipv4Addr::from(ack.tunnel_ipv4),
            assigned_ipv6: ack.tunnel_ipv6.map(Ipv6Addr::from),
            assigned_max_mtu: ack.max_mtu,
            exit_pubkey,
        })
    }
}

/// An established tunnel session over which IP packets travel as QUIC datagrams.
#[derive(Debug)]
pub struct ClientSession {
    // Held so the endpoint outlives the connection.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    assigned_ipv4: Ipv4Addr,
    assigned_ipv6: Option<Ipv6Addr>,
    assigned_max_mtu: u16,
    exit_pubkey: [u8; 32],
}

impl ClientSession {
    /// The tunnel IPv4 the exit assigned to this session.
    #[must_use]
    pub fn assigned_ipv4(&self) -> Ipv4Addr {
        self.assigned_ipv4
    }

    /// The tunnel IPv6 the exit assigned, if any.
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<Ipv6Addr> {
        self.assigned_ipv6
    }

    /// The negotiated maximum MTU.
    #[must_use]
    pub fn assigned_max_mtu(&self) -> u16 {
        self.assigned_max_mtu
    }

    /// The exit's authenticated pubkey.
    #[must_use]
    pub fn exit_pubkey(&self) -> [u8; 32] {
        self.exit_pubkey
    }

    /// The largest datagram payload the current path can carry, if known.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// The underlying quinn connection (for the pump and advanced callers).
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Sends one IP packet as a QUIC datagram (unreliable, unordered).
    ///
    /// Accepts anything convertible into [`bytes::Bytes`] so the caller can pass
    /// a `Bytes` slice without an intermediate copy.
    ///
    /// # Errors
    ///
    /// [`TunnelError::SendDatagram`] if the datagram is too large or the
    /// connection is closing.
    pub fn send_datagram(&self, payload: impl Into<bytes::Bytes>) -> Result<(), TunnelError> {
        self.conn
            .send_datagram(payload.into())
            .map_err(TunnelError::SendDatagram)
    }

    /// Awaits the next inbound datagram, returning the zero-copy [`bytes::Bytes`]
    /// from quinn directly (no per-packet allocation).
    ///
    /// # Errors
    ///
    /// [`TunnelError::ReadDatagram`] if the connection closed.
    pub async fn read_datagram(&self) -> Result<bytes::Bytes, TunnelError> {
        self.conn
            .read_datagram()
            .await
            .map_err(TunnelError::ReadDatagram)
    }

    /// Closes the connection cleanly.
    pub fn disconnect(&self) {
        self.conn.close(0u32.into(), b"client disconnect");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn typed_errors_preserve_their_source() {
        let bind = TunnelError::Bind(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "addr in use",
        ));
        assert!(bind.source().is_some(), "Bind must chain its io::Error");

        let send = TunnelError::SendDatagram(quinn::SendDatagramError::TooLarge);
        assert!(
            send.source().is_some(),
            "SendDatagram must chain its quinn error"
        );

        let handshake = TunnelError::HandshakeIo {
            context: "write setup",
            source: Box::new(std::io::Error::other("stream closed")),
        };
        assert!(
            handshake.source().is_some(),
            "HandshakeIo must chain its boxed source"
        );
    }

    #[test]
    fn top_level_display_omits_the_underlying_detail() {
        // No-log discipline: the address-bearing cause stays in source(), not in
        // the Display the embedder is most likely to log.
        let bind = TunnelError::Bind(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "198.51.100.7:443 already in use",
        ));
        assert!(!bind.to_string().contains("198.51.100.7"));
    }
}
