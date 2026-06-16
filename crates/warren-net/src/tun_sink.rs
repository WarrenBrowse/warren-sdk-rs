//! Privileged TUN datapath packet sink.
//!
//! Bridges a [`warren_tun::RawTunDevice`] to the async [`PacketSink`] seam. The
//! sink side is channels (so `&self` async send/recv work); a worker owns the
//! device and shuttles framed packets between it and the channels.
//!
//! This crate stays `unsafe_code = forbid`: the bridge is safe and works over any
//! `RawTunDevice`, including an in-memory mock (so the framing/channel logic is
//! unit-tested here). The real kernel device is opened by `warren-tun` behind its
//! `experimental-tun` feature, and the full privileged datapath has NOT YET been
//! validated against a real exit (per CLAUDE.md, that needs root + a device).

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use warren_tun::{Framing, RawTunDevice};

use crate::error::NetError;
use crate::sink::PacketSink;

/// Channel depth for each direction (bounds memory under a burst; backpressure
/// is `try_send`-drop on egress, matching the netstack's TX behavior).
const TUN_CHANNEL_DEPTH: usize = 1024;

/// An async [`PacketSink`] over a TUN device's channels.
///
/// `send_packet` enqueues toward the device; `recv_packet` dequeues packets the
/// worker read from the device. The worker (see [`TunBridge`]) must be driven for
/// packets to flow.
#[derive(Debug)]
pub struct TunPacketSink {
    to_device: mpsc::Sender<Vec<u8>>,
    from_device: Mutex<mpsc::Receiver<Bytes>>,
    mtu: usize,
}

/// The device-side worker: owns the [`RawTunDevice`] and the channel ends.
///
/// Drive it with [`Self::pump_inbound_once`] / [`Self::pump_outbound_once`] (one
/// step each, used by tests) or, with a real device, two blocking loops (one per
/// direction, since a kernel TUN fd is full-duplex). The loop driver lives behind
/// `experimental-tun` because it only makes sense on a real device.
#[derive(Debug)]
pub struct TunBridge<D: RawTunDevice> {
    device: D,
    framing: Framing,
    read_buf: Vec<u8>,
    inbound: mpsc::Sender<Bytes>,
    outbound: mpsc::Receiver<Vec<u8>>,
}

/// Wires `device` (using `framing`, sized for `mtu`) to a new [`TunPacketSink`]
/// and its [`TunBridge`].
#[must_use]
pub fn tun_channels<D: RawTunDevice>(
    device: D,
    framing: Framing,
    mtu: u16,
) -> (TunPacketSink, TunBridge<D>) {
    let (to_device_tx, to_device_rx) = mpsc::channel(TUN_CHANNEL_DEPTH);
    let (from_device_tx, from_device_rx) = mpsc::channel(TUN_CHANNEL_DEPTH);
    let sink = TunPacketSink {
        to_device: to_device_tx,
        from_device: Mutex::new(from_device_rx),
        mtu: mtu as usize,
    };
    let bridge = TunBridge {
        device,
        framing,
        read_buf: vec![0u8; mtu as usize + 4],
        inbound: from_device_tx,
        outbound: to_device_rx,
    };
    (sink, bridge)
}

impl<D: RawTunDevice> TunBridge<D> {
    /// Reads one frame from the device and forwards the deframed packet to the
    /// sink. Returns `Ok(false)` if the sink's receiver was dropped (stop).
    ///
    /// # Errors
    ///
    /// A device read error. An undecodable frame is dropped (not fatal).
    pub fn pump_inbound_once(&mut self) -> std::io::Result<bool> {
        let n = self.device.read_frame(&mut self.read_buf)?;
        if let Some(packet) = self.framing.decode(&self.read_buf[..n])
            && self.inbound.try_send(Bytes::from(packet)).is_err()
        {
            // Receiver dropped or full: dropping a packet is acceptable (IP is
            // lossy); a closed channel means the datapath is gone.
            return Ok(!self.inbound.is_closed());
        }
        Ok(true)
    }

    /// Frames one queued egress packet and writes it to the device. Returns
    /// `Ok(false)` when the egress channel is closed and drained (stop).
    ///
    /// # Errors
    ///
    /// A device write error. An unframable packet is dropped (not fatal).
    pub fn pump_outbound_once(&mut self) -> std::io::Result<bool> {
        match self.outbound.try_recv() {
            Ok(packet) => {
                if let Some(frame) = self.framing.encode(&packet) {
                    self.device.write_frame(&frame)?;
                }
                Ok(true)
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(true),
            Err(mpsc::error::TryRecvError::Disconnected) => Ok(false),
        }
    }
}

/// The real-fd async duplex datapath loop (Unix), EXPERIMENTAL and feature-gated.
///
/// A kernel TUN fd is full-duplex, so one task multiplexes both directions with
/// `tokio`'s `AsyncFd` readiness: on readable, drain inbound frames to the sink;
/// in parallel, drain the egress channel to the device. The blocking `pump_*`
/// primitives above are the tested core; this wires them to fd readiness. It
/// needs a real device (and root), so it is compile-checked on Unix but NOT
/// unit-tested and NOT yet validated against a real exit.
#[cfg(all(unix, feature = "experimental-tun"))]
impl<D> TunBridge<D>
where
    D: warren_tun::RawTunDevice + std::os::fd::AsRawFd + Send + 'static,
{
    /// Runs the duplex loop until the device errors fatally or the sink is
    /// dropped (both channel directions closed).
    ///
    /// # Errors
    ///
    /// A fatal device read/write error (anything other than `WouldBlock`), or the
    /// failure to register the fd with the async reactor.
    pub async fn run(self) -> std::io::Result<()> {
        use std::io::ErrorKind::WouldBlock;
        use tokio::io::Interest;
        use tokio::io::unix::AsyncFd;

        // Destructure into disjoint locals so the two select arms borrow
        // different fields (egress channel vs device/inbound) without conflict.
        let TunBridge {
            mut device,
            framing,
            mut read_buf,
            inbound,
            mut outbound,
        } = self;

        let raw = device.as_raw_fd();
        warren_tun::device::set_nonblocking(raw)?;
        // Register the bare fd for readiness only; `device` still owns and closes
        // it. A newtype because AsyncFd needs an AsRawFd value of its own.
        struct FdRef(std::os::fd::RawFd);
        impl std::os::fd::AsRawFd for FdRef {
            fn as_raw_fd(&self) -> std::os::fd::RawFd {
                self.0
            }
        }
        let afd = AsyncFd::with_interest(FdRef(raw), Interest::READABLE | Interest::WRITABLE)?;

        loop {
            tokio::select! {
                // The device has bytes to read: drain ready frames to the sink.
                guard = afd.readable() => {
                    let mut guard = guard?;
                    loop {
                        match device.read_frame(&mut read_buf) {
                            Ok(n) => {
                                if let Some(packet) = framing.decode(&read_buf[..n])
                                    && inbound.try_send(Bytes::from(packet)).is_err()
                                    && inbound.is_closed()
                                {
                                    return Ok(()); // sink dropped
                                }
                            }
                            Err(ref e) if e.kind() == WouldBlock => {
                                guard.clear_ready();
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                // An egress packet is queued: frame it and write it. A write
                // WouldBlock waits for writability before retrying.
                pkt = outbound.recv() => {
                    let Some(packet) = pkt else { return Ok(()); }; // sink dropped
                    if let Some(frame) = framing.encode(&packet) {
                        loop {
                            match device.write_frame(&frame) {
                                Ok(()) => break,
                                Err(ref e) if e.kind() == WouldBlock => {
                                    afd.writable().await?.clear_ready();
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
            }
        }
    }
}

impl PacketSink for TunPacketSink {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
        self.to_device.send(packet.to_vec()).await.map_err(|_| {
            NetError::Tun(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tun device worker stopped",
            ))
        })
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        self.from_device.lock().await.recv().await.ok_or_else(|| {
            NetError::Tun(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tun device worker stopped",
            ))
        })
    }

    fn max_payload(&self) -> usize {
        self.mtu
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// In-memory packet-atomic device (a `warren_tun::RawTunDevice`) for testing
    /// the bridge without a kernel.
    #[derive(Default)]
    struct MockDevice {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
    }

    impl RawTunDevice for MockDevice {
        fn read_frame(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let frame = self
                .inbound
                .pop_front()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"))?;
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }

        fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
            self.outbound.push(frame.to_vec());
            Ok(())
        }
    }

    fn ipv4_packet() -> Vec<u8> {
        let mut p = vec![0x45u8];
        p.extend_from_slice(&[9u8; 19]);
        p
    }

    #[tokio::test]
    async fn inbound_device_frames_reach_the_sink() {
        let mut dev = MockDevice::default();
        dev.inbound.push_back(ipv4_packet());
        let (sink, mut bridge) = tun_channels(dev, Framing::Bare, 1280);
        assert!(bridge.pump_inbound_once().unwrap());
        assert_eq!(
            sink.recv_packet().await.unwrap(),
            Bytes::from(ipv4_packet())
        );
    }

    #[tokio::test]
    async fn egress_sink_packets_reach_the_device_framed() {
        let (sink, mut bridge) = tun_channels(MockDevice::default(), Framing::DarwinUtun, 1280);
        sink.send_packet(&ipv4_packet()).await.unwrap();
        assert!(bridge.pump_outbound_once().unwrap());
        let dev = bridge.device;
        assert_eq!(dev.outbound.len(), 1);
        // utun framing prepended a 4-byte header.
        assert_eq!(dev.outbound[0].len(), ipv4_packet().len() + 4);
        assert_eq!(&dev.outbound[0][4..], ipv4_packet().as_slice());
    }

    #[tokio::test]
    async fn recv_errors_once_the_worker_is_gone() {
        let (sink, bridge) = tun_channels(MockDevice::default(), Framing::Bare, 1280);
        drop(bridge); // the worker (and its inbound sender) is gone
        let err = sink.recv_packet().await.unwrap_err();
        assert!(matches!(err, NetError::Tun(_)));
    }

    #[tokio::test]
    async fn send_errors_once_the_worker_is_gone() {
        let (sink, bridge) = tun_channels(MockDevice::default(), Framing::Bare, 1280);
        drop(bridge);
        let err = sink.send_packet(&ipv4_packet()).await.unwrap_err();
        assert!(matches!(err, NetError::Tun(_)));
    }

    #[tokio::test]
    async fn outbound_pump_stops_when_the_sink_is_dropped_and_drained() {
        let (sink, mut bridge) = tun_channels(MockDevice::default(), Framing::Bare, 1280);
        drop(sink);
        // Nothing queued and the sender is gone: the pump signals stop.
        assert!(!bridge.pump_outbound_once().unwrap());
    }

    #[test]
    fn max_payload_reports_the_mtu() {
        let (sink, _bridge) = tun_channels(MockDevice::default(), Framing::Bare, 1280);
        assert_eq!(sink.max_payload(), 1280);
    }
}
