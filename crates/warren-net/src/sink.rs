//! The packet-plane seam shared by both datapaths.
//!
//! A [`PacketSink`] moves inner IP packets between a datapath (a TUN device, or
//! a userspace netstack) and the QUIC tunnel. The TUN backend reads packets from
//! the OS and writes them to the sink; the netstack/proxy backend synthesizes
//! packets from terminated L4 flows and does the same. [`QuicPacketSink`] is the
//! tunnel-side implementation over a [`warren_transport::ClientSession`].

use warren_transport::ClientSession;

use crate::error::NetError;

/// Moves inner IP packets to and from the tunnel.
pub trait PacketSink: Send + Sync {
    /// Sends one inner IP packet toward the exit.
    fn send_packet(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<(), NetError>> + Send;

    /// Awaits the next inner IP packet from the exit.
    fn recv_packet(&self) -> impl std::future::Future<Output = Result<Vec<u8>, NetError>> + Send;

    /// The largest packet payload the current path can carry.
    fn max_payload(&self) -> usize;
}

/// A [`PacketSink`] backed by a QUIC tunnel session (RFC 9221 datagrams).
#[derive(Debug)]
pub struct QuicPacketSink {
    session: ClientSession,
}

impl QuicPacketSink {
    /// Wraps an established session.
    #[must_use]
    pub fn new(session: ClientSession) -> Self {
        Self { session }
    }

    /// The underlying session.
    #[must_use]
    pub fn session(&self) -> &ClientSession {
        &self.session
    }
}

impl PacketSink for QuicPacketSink {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
        self.session
            .send_datagram(packet.to_vec())
            .map_err(|e| NetError::Tunnel(e.to_string()))
    }

    async fn recv_packet(&self) -> Result<Vec<u8>, NetError> {
        self.session
            .read_datagram()
            .await
            .map_err(|e| NetError::Tunnel(e.to_string()))
    }

    fn max_payload(&self) -> usize {
        // Fall back to the RFC 9000 minimum guarantee when the path MTU is not
        // yet known.
        self.session.max_datagram_size().unwrap_or(1200)
    }
}
