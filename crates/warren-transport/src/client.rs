//! Identity-bound QUIC client tunnel: handshake and datagram session.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use ed25519_dalek::SigningKey;
use warren_wire::{DEVICE_ID_LEN, MAX_SETUP_FRAME_BYTES, Setup, decode_setup_ack, encode_setup};

use crate::tls;

/// ALPN offered by the client: IETF HTTP/3, mimicking a casual h3 dial.
const ALPN_H3: &[u8] = b"h3";

/// Errors from establishing or driving a tunnel.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// Building the TLS configuration failed.
    #[error("tls config error: {0}")]
    Tls(#[from] tls::WarrenTlsError),
    /// Binding the local UDP socket / endpoint failed.
    #[error("endpoint bind failed: {0}")]
    Bind(String),
    /// The QUIC connection could not be established.
    #[error("connect failed: {0}")]
    Connect(String),
    /// A QUIC stream or connection error occurred mid-handshake.
    #[error("quic error: {context}: {source}")]
    Quic {
        /// Where the error happened.
        context: &'static str,
        /// Underlying quinn connection error.
        #[source]
        source: quinn::ConnectionError,
    },
    /// Writing or reading the Setup/SetupAck frame failed.
    #[error("handshake i/o error: {0}")]
    HandshakeIo(String),
    /// The Setup/SetupAck frame did not decode.
    #[error("handshake frame error: {0}")]
    Frame(#[from] warren_wire::ProtocolError),
    /// The exit's authenticated pubkey did not match the expected one.
    #[error("exit identity mismatch (possible MITM)")]
    ExitIdentityMismatch,
    /// Sending a datagram failed (too large, or connection closing).
    #[error("send datagram failed: {0}")]
    SendDatagram(String),
    /// Reading a datagram failed (connection closed).
    #[error("read datagram failed: {0}")]
    ReadDatagram(String),
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
        let client_cfg = tls::make_client_config(
            &self.signing_key,
            tls::default_crypto_provider(),
            &[ALPN_H3],
        )?;

        let bind = self.bind_local_ip.unwrap_or_else(|| {
            if exit_addr.is_ipv6() {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
            }
        });
        let mut endpoint =
            quinn::Endpoint::client(bind).map_err(|e| TunnelError::Bind(e.to_string()))?;
        endpoint.set_default_client_config(client_cfg);

        let server_name = tls::name::encode(&exit_pubkey);
        let conn = endpoint
            .connect(exit_addr, &server_name)
            .map_err(|e| TunnelError::Connect(e.to_string()))?
            .await
            .map_err(|e| TunnelError::Connect(e.to_string()))?;

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
            .map_err(|e| TunnelError::HandshakeIo(e.to_string()))?;
        send.finish()
            .map_err(|e| TunnelError::HandshakeIo(e.to_string()))?;

        let ack_bytes = recv
            .read_to_end(MAX_SETUP_FRAME_BYTES)
            .await
            .map_err(|e| TunnelError::HandshakeIo(e.to_string()))?;
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
    /// # Errors
    ///
    /// [`TunnelError::SendDatagram`] if the datagram is too large or the
    /// connection is closing.
    pub fn send_datagram(&self, payload: Vec<u8>) -> Result<(), TunnelError> {
        self.conn
            .send_datagram(bytes::Bytes::from(payload))
            .map_err(|e| TunnelError::SendDatagram(e.to_string()))
    }

    /// Awaits the next inbound datagram.
    ///
    /// # Errors
    ///
    /// [`TunnelError::ReadDatagram`] if the connection closed.
    pub async fn read_datagram(&self) -> Result<Vec<u8>, TunnelError> {
        self.conn
            .read_datagram()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TunnelError::ReadDatagram(e.to_string()))
    }

    /// Closes the connection cleanly.
    pub fn disconnect(&self) {
        self.conn.close(0u32.into(), b"client disconnect");
    }
}
