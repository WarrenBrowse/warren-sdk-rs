//! The packet-plane seam shared by both datapaths.
//!
//! A [`PacketSink`] moves inner IP packets between a datapath (a TUN device, or
//! a userspace netstack) and the QUIC tunnel. The TUN backend reads packets from
//! the OS and writes them to the sink; the netstack/proxy backend synthesizes
//! packets from terminated L4 flows and does the same. [`QuicPacketSink`] is the
//! tunnel-side implementation over a [`warren_transport::ClientSession`].

use bytes::Bytes;
use warren_transport::ClientSession;

use crate::error::NetError;

/// Moves inner IP packets to and from the tunnel.
pub trait PacketSink: Send + Sync {
    /// Sends one inner IP packet toward the exit.
    fn send_packet(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<(), NetError>> + Send;

    /// Awaits the next inner IP packet from the exit, returned zero-copy as
    /// [`Bytes`].
    fn recv_packet(&self) -> impl std::future::Future<Output = Result<Bytes, NetError>> + Send;

    /// The largest packet payload the current path can carry.
    fn max_payload(&self) -> usize;

    /// Sends a batch of packets. The default forwards them one by one; a
    /// GSO-aware implementation can override this to coalesce the syscall.
    fn send_batch(
        &self,
        packets: &[&[u8]],
    ) -> impl std::future::Future<Output = Result<(), NetError>> + Send {
        async move {
            for packet in packets {
                self.send_packet(packet).await?;
            }
            Ok(())
        }
    }

    /// Receives at least one and at most `max` packets, blocking for the first.
    /// The default returns a single packet; a GRO-aware implementation can
    /// return several harvested from one syscall.
    fn recv_batch(
        &self,
        max: usize,
    ) -> impl std::future::Future<Output = Result<Vec<Bytes>, NetError>> + Send {
        async move {
            let first = self.recv_packet().await?;
            let mut out = Vec::with_capacity(max.max(1));
            out.push(first);
            Ok(out)
        }
    }
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
        // One copy into the refcounted Bytes quinn needs; no intermediate Vec.
        self.session
            .send_datagram(Bytes::copy_from_slice(packet))
            .map_err(NetError::Tunnel)
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        self.session.read_datagram().await.map_err(NetError::Tunnel)
    }

    fn max_payload(&self) -> usize {
        // Honor both the path MTU (once probed) and the exit's policy MTU from
        // the handshake; before the first PMTU probe, fall back to the policy.
        let policy = usize::from(self.session.assigned_max_mtu());
        self.session
            .max_datagram_size()
            .map_or(policy, |path| path.min(policy))
    }
}
