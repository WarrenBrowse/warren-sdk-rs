//! The per-epoch device seam: a datapath that receives one sink per
//! (re)connect.
//!
//! The proxy datapath rebuilds a netstack on every reconnect; a device that
//! carries raw IP packets (a TUN interface, a local gateway serving its own
//! clients) instead has state that outlives the tunnel and must be told when
//! one epoch replaces another. [`EpochPacketDevice`] is that notification: the
//! supervisor calls [`begin_epoch`](EpochPacketDevice::begin_epoch) with the
//! addresses the exit assigned and gets back this epoch's packet sink plus the
//! UDP path its control plane rides.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::netstack::Ipv6Addressing;
use crate::sink::PacketSink;
use crate::udp::UdpOpener;

/// Opaque stable identifier of the exit an epoch was dialed to.
///
/// Carried so a device can tell "the same exit came back" from "we moved", and
/// deliberately without a `Debug` of its bytes: it identifies a node, and the
/// no-log discipline keeps it out of traces.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExitId([u8; EXIT_ID_LEN]);

/// Length of an [`ExitId`], the wire identifier's own length.
pub const EXIT_ID_LEN: usize = 16;

impl ExitId {
    /// The identifier of a datapath that has no exit behind it (an in-process
    /// device, a session that carries no stable id).
    pub const UNKNOWN: Self = Self([0u8; EXIT_ID_LEN]);

    /// Wraps the raw identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EXIT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw identifier, for a device that keys state on it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EXIT_ID_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for ExitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Renders the fact, never the identifier.
        f.write_str(if *self == Self::UNKNOWN {
            "ExitId(unknown)"
        } else {
            "ExitId(set)"
        })
    }
}

/// Which epoch a device is serving: the exit it was dialed to, plus a counter
/// the supervisor bumps on every (re)connect.
///
/// The counter is what makes a stale epoch recognizable: a sink stamped with an
/// older generation belongs to a tunnel that is gone, and a device that carries
/// state across epochs uses it to make that sink inert instead of letting it
/// write into the live one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochId {
    /// The exit this epoch reached.
    pub exit: ExitId,
    /// Bumped on every (re)connect; starts at 1 for the first epoch.
    pub generation: u64,
}

/// The addresses one epoch was assigned, and which epoch they belong to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EpochAddressing {
    /// Which epoch these addresses belong to.
    pub epoch: EpochId,
    /// The tunnel-assigned IPv4 address.
    pub ipv4: Ipv4Addr,
    /// Its subnet prefix length.
    pub prefix: u8,
    /// The exit-side gateway (the NAT-PMP server and the DNS forwarder).
    pub gateway: Ipv4Addr,
    /// The dual-stack half, when the exit granted one.
    pub ipv6: Option<Ipv6Addressing>,
}

impl EpochAddressing {
    /// The assigned IPv6 address, when the exit granted dual-stack.
    #[must_use]
    pub fn ipv6_address(&self) -> Option<Ipv6Addr> {
        self.ipv6.map(|v6| v6.local_ip)
    }
}

impl std::fmt::Debug for EpochAddressing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The assigned addresses are what identifies this client at the exit,
        // so the epoch is rendered and the addresses are not.
        f.debug_struct("EpochAddressing")
            .field("generation", &self.epoch.generation)
            .field("exit", &self.epoch.exit)
            .field("dual_stack", &self.ipv6.is_some())
            .finish()
    }
}

/// A device that is handed one packet sink per epoch.
///
/// Implementors own whatever must survive a reconnect (a TUN interface, a NAT
/// table, connected clients) and are told, through
/// [`begin_epoch`](Self::begin_epoch), which addresses the fresh tunnel
/// assigned.
pub trait EpochPacketDevice: Send + Sync + 'static {
    /// The device side of the epoch's packet plane: the supervisor pumps it
    /// against the tunnel sink.
    type Sink: PacketSink + 'static;
    /// The device's own UDP path, for the in-tunnel control plane (NAT-PMP,
    /// the egress probe).
    type Udp: UdpOpener + Clone;

    /// Starts an epoch on `addressing` and returns its packet sink and UDP
    /// path.
    ///
    /// Called on every (re)connect. Dropping the returned sink ends the epoch
    /// on the device side, and only when it is still the current generation: a
    /// sink from an older epoch must be inert, because the supervisor may drop
    /// it after the next one has already started.
    fn begin_epoch(&self, addressing: EpochAddressing) -> (Self::Sink, Self::Udp);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use bytes::Bytes;

    use crate::error::NetError;
    use crate::proxy::UdpFlow;

    #[test]
    fn an_exit_id_never_renders_its_bytes() {
        let id = ExitId::from_bytes([0xab; EXIT_ID_LEN]);
        let rendered = format!("{id:?}");
        assert!(
            !rendered.contains("ab") && !rendered.contains("171"),
            "the identifier must not reach a trace: {rendered}"
        );
        assert_eq!(id.as_bytes(), &[0xab; EXIT_ID_LEN], "the bytes are kept");
        assert_eq!(format!("{:?}", ExitId::UNKNOWN), "ExitId(unknown)");
    }

    #[test]
    fn addressing_renders_its_epoch_and_not_its_addresses() {
        let addressing = EpochAddressing {
            epoch: EpochId {
                exit: ExitId::UNKNOWN,
                generation: 4,
            },
            ipv4: Ipv4Addr::new(10, 66, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            ipv6: None,
        };
        let rendered = format!("{addressing:?}");
        assert!(
            !rendered.contains("10.66.0.2"),
            "the assigned address must not reach a trace: {rendered}"
        );
        assert!(rendered.contains('4'), "the epoch is what is renderable");
        assert_eq!(addressing.ipv6_address(), None);
    }

    /// A device that records the addressing of each epoch it was started on.
    #[derive(Default)]
    struct RecordingDevice {
        generation: Arc<AtomicU64>,
    }

    struct RecordingSink(u64);

    impl PacketSink for RecordingSink {
        async fn send_packet(&self, _packet: &[u8]) -> Result<(), NetError> {
            Ok(())
        }
        async fn recv_packet(&self) -> Result<Bytes, NetError> {
            std::future::pending().await
        }
        fn max_payload(&self) -> usize {
            1280
        }
    }

    #[derive(Clone)]
    struct RecordingUdp(Ipv4Addr);

    struct DeadFlow;

    impl UdpFlow for DeadFlow {
        async fn send_to(&self, _data: Bytes, _dst: std::net::SocketAddr) -> Result<(), NetError> {
            Ok(())
        }
        async fn recv_from(&mut self) -> Option<(Bytes, std::net::SocketAddr)> {
            None
        }
    }

    impl UdpOpener for RecordingUdp {
        type Flow = DeadFlow;

        async fn open_udp(&self) -> Result<DeadFlow, NetError> {
            Ok(DeadFlow)
        }
    }

    impl EpochPacketDevice for RecordingDevice {
        type Sink = RecordingSink;
        type Udp = RecordingUdp;

        fn begin_epoch(&self, addressing: EpochAddressing) -> (RecordingSink, RecordingUdp) {
            self.generation
                .store(addressing.epoch.generation, Ordering::SeqCst);
            (
                RecordingSink(addressing.epoch.generation),
                RecordingUdp(addressing.gateway),
            )
        }
    }

    /// The supervisor's side of the seam, written once over the trait.
    fn start_epoch<D: EpochPacketDevice>(
        device: &D,
        addressing: EpochAddressing,
    ) -> (D::Sink, D::Udp) {
        device.begin_epoch(addressing)
    }

    #[test]
    fn beginning_an_epoch_hands_the_device_its_addressing() {
        let device = RecordingDevice::default();
        let addressing = EpochAddressing {
            epoch: EpochId {
                exit: ExitId::from_bytes([7; EXIT_ID_LEN]),
                generation: 2,
            },
            ipv4: Ipv4Addr::new(10, 66, 0, 9),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            ipv6: None,
        };
        let (sink, udp) = start_epoch(&device, addressing);
        assert_eq!(
            device.generation.load(Ordering::SeqCst),
            2,
            "the device learns which epoch it is serving"
        );
        assert_eq!(sink.0, 2, "the sink is stamped with that epoch");
        assert_eq!(
            udp.0,
            Ipv4Addr::new(10, 66, 0, 1),
            "the control plane is pointed at this epoch's gateway"
        );
    }
}
