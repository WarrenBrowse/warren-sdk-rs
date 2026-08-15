//! Privileged TUN datapath packet sink.
//!
//! Bridges a [`warren_tun_core::RawTunDevice`] to the async [`PacketSink`] seam. The
//! sink side is channels (so `&self` async send/recv work); a worker owns the
//! device and shuttles framed packets between it and the channels.
//!
//! This crate stays `unsafe_code = forbid`: the bridge is safe and works over any
//! `RawTunDevice`, including an in-memory mock (so the framing/channel logic is
//! unit-tested here). The real kernel device is opened by `warren-tun` behind its
//! `experimental-tun` feature. On macOS the full privileged datapath riding this
//! bridge is real-exit validated (egress via the exit, DNS through the tunnel,
//! clean restore); on Linux and Windows it is not yet.

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use warren_tun_core::{Framing, RawTunDevice};
use warrenguard_transport_core::{
    clamp_downlink_syn, clamp_uplink_syn, is_tcp_syn, uplink_frag_needed,
};

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

/// Forwards device -> tunnel (the uplink: the local OS is the sender of
/// everything on this leg). Rides the single-homed clamp/PTB policy in
/// [`warrenguard_transport_core::inner_mtu`], shared with the engine's
/// supervised pump: an outbound SYN/SYN-ACK has its MSS option clamped to
/// the tunnel's current budget minus the shared uplink proxy-budget margin,
/// and a packet the tunnel's CURRENT budget cannot carry is turned back into
/// an ICMP Fragmentation-Needed / Packet-Too-Big written into the device
/// instead of being sent (and silently dropped): the local OS's own PMTUD
/// then converges on later packets rather than the flow black-holing.
async fn pump_uplink<D: PacketSink, T: PacketSink>(
    device: &D,
    tunnel: &T,
    stats: &PumpStats,
) -> Result<(), NetError> {
    loop {
        let packet = device.recv_packet().await?;
        let budget = u16::try_from(tunnel.max_payload()).unwrap_or(u16::MAX);
        if packet.len() > usize::from(budget) {
            if let Some(ptb) = uplink_frag_needed(&packet, budget) {
                // Best-effort: a failure to write the PTB back just leaves the
                // sender waiting for its own retransmit/timeout, no worse than
                // before this fix existed.
                let _ = device.send_packet(&ptb).await;
            }
            continue;
        }
        let sent = if is_tcp_syn(&packet) {
            let mut owned = packet.to_vec();
            let _ = clamp_uplink_syn(&mut owned, budget);
            tunnel.send_packet(&owned).await
        } else {
            tunnel.send_packet(&packet).await
        };
        // The budget read above and the send below are two moments: a DPLPMTUD
        // shrink in between refuses this packet over a session that is still
        // carrying. Dropping it costs one packet (IP is lossy); ending the run
        // would cost the whole datapath, which for a device fronting several
        // clients is every one of them at once.
        if let Err(e) = sent {
            if !e.is_per_packet() {
                return Err(e);
            }
            stats.dropped_uplink_send();
        }
    }
}

/// Forwards tunnel -> device (the downlink). Rides the single-homed clamp
/// policy: an inbound SYN/SYN-ACK has its MSS option clamped to the tunnel's
/// current budget EXACTLY (this node's own transmit budget, known precisely,
/// unlike the uplink leg's), so a locally-initiated flow's peer never learns
/// an MSS larger than this client's own tunnel-bound segments can later
/// carry.
async fn pump_downlink<T: PacketSink, D: PacketSink>(
    tunnel: &T,
    device: &D,
) -> Result<(), NetError> {
    loop {
        let packet = tunnel.recv_packet().await?;
        if is_tcp_syn(&packet) {
            let budget = u16::try_from(tunnel.max_payload()).unwrap_or(u16::MAX);
            let mut owned = packet.to_vec();
            let _ = clamp_downlink_syn(&mut owned, budget);
            device.send_packet(&owned).await?;
        } else {
            device.send_packet(&packet).await?;
        }
    }
}

/// Forwards raw IP packets in BOTH directions between two packet sinks until
/// either side closes. This is the privileged TUN datapath glue: wire a
/// [`TunPacketSink`] (device side) to a tunnel sink (for example
/// [`MultihopPacketSink`](crate::MultihopPacketSink)) so packets flow
/// `device <-> exit`. Generic over [`PacketSink`], so it is unit-tested over
/// in-memory mock sinks (no device or live tunnel needed); the real datapath
/// pairs it with a TUN bridge worker and a multihop session.
///
/// # Errors
///
/// The first [`NetError`] from either direction; the other direction is then
/// cancelled (the datapath has stopped).
pub async fn forward_bidirectional<A: PacketSink, B: PacketSink>(
    device: A,
    tunnel: B,
) -> Result<(), NetError> {
    forward_bidirectional_with_stats(device, tunnel, &PumpStats::default()).await
}

/// [`forward_bidirectional`] with the counters of the run kept by the caller,
/// so the packets the uplink drops on a per-packet tunnel refusal are
/// observable rather than silent.
///
/// # Errors
///
/// The first fatal [`NetError`] from either direction; the other direction is
/// then cancelled (the datapath has stopped).
pub async fn forward_bidirectional_with_stats<A: PacketSink, B: PacketSink>(
    device: A,
    tunnel: B,
    stats: &PumpStats,
) -> Result<(), NetError> {
    tokio::try_join!(
        pump_uplink(&device, &tunnel, stats),
        pump_downlink(&tunnel, &device)
    )
    .map(|_| ())
}

/// What one packet-forwarding run dropped rather than carried.
///
/// A drop is invisible by construction (the sender learns nothing), so the
/// count is the only evidence a datapath has that its uplink is shedding
/// packets instead of an exit losing them.
#[derive(Debug, Default)]
pub struct PumpStats {
    uplink_send_dropped: std::sync::atomic::AtomicU64,
}

impl PumpStats {
    /// Uplink packets the tunnel refused per-packet, dropped and counted.
    #[must_use]
    pub fn uplink_send_dropped(&self) -> u64 {
        self.uplink_send_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn dropped_uplink_send(&self) {
        self.uplink_send_dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
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

    /// A channel-backed mock `PacketSink`: `recv_packet` pops `inbound`,
    /// `send_packet` pushes `outbound`. Lets `forward_bidirectional` be tested
    /// without a device or a live tunnel.
    struct MockSink {
        inbound: Mutex<mpsc::Receiver<Bytes>>,
        outbound: mpsc::Sender<Vec<u8>>,
    }

    impl PacketSink for MockSink {
        async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
            self.outbound.send(packet.to_vec()).await.map_err(|_| {
                NetError::Tun(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            })
        }

        async fn recv_packet(&self) -> Result<Bytes, NetError> {
            self.inbound.lock().await.recv().await.ok_or_else(|| {
                NetError::Tun(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            })
        }

        fn max_payload(&self) -> usize {
            1280
        }
    }

    #[tokio::test]
    async fn forward_bidirectional_relays_packets_both_ways() {
        // device <-> tunnel: a packet read from the device must reach the tunnel,
        // and a packet from the tunnel must reach the device.
        let (dev_in_tx, dev_in_rx) = mpsc::channel::<Bytes>(8);
        let (dev_out_tx, mut dev_out_rx) = mpsc::channel::<Vec<u8>>(8);
        let (tun_in_tx, tun_in_rx) = mpsc::channel::<Bytes>(8);
        let (tun_out_tx, mut tun_out_rx) = mpsc::channel::<Vec<u8>>(8);
        let device = MockSink {
            inbound: Mutex::new(dev_in_rx),
            outbound: dev_out_tx,
        };
        let tunnel = MockSink {
            inbound: Mutex::new(tun_in_rx),
            outbound: tun_out_tx,
        };

        let task = tokio::spawn(forward_bidirectional(device, tunnel));

        // Device -> tunnel.
        dev_in_tx.send(Bytes::from(ipv4_packet())).await.unwrap();
        assert_eq!(tun_out_rx.recv().await.unwrap(), ipv4_packet());

        // Tunnel -> device.
        let other = vec![0x45u8, 1, 2, 3];
        tun_in_tx.send(Bytes::from(other.clone())).await.unwrap();
        assert_eq!(dev_out_rx.recv().await.unwrap(), other);

        task.abort();
    }

    #[tokio::test]
    async fn forward_bidirectional_stops_when_a_side_closes() {
        let (_dev_in_tx, dev_in_rx) = mpsc::channel::<Bytes>(1);
        let (dev_out_tx, _dev_out_rx) = mpsc::channel::<Vec<u8>>(1);
        let (tun_in_tx, tun_in_rx) = mpsc::channel::<Bytes>(1);
        let (tun_out_tx, _tun_out_rx) = mpsc::channel::<Vec<u8>>(1);
        let device = MockSink {
            inbound: Mutex::new(dev_in_rx),
            outbound: dev_out_tx,
        };
        let tunnel = MockSink {
            inbound: Mutex::new(tun_in_rx),
            outbound: tun_out_tx,
        };
        // Drop the device's inbound sender: device.recv_packet errors, so the
        // forwarder returns rather than hanging.
        drop(_dev_in_tx);
        drop(tun_in_tx);
        let result = forward_bidirectional(device, tunnel).await;
        assert!(matches!(result, Err(NetError::Tun(_))));
    }

    /// Like `MockSink` but with a settable `max_payload`, needed to exercise
    /// the budget-dependent clamp/reflect decisions in
    /// `pump_uplink`/`pump_downlink`.
    struct ConfigurableSink {
        inbound: Mutex<mpsc::Receiver<Bytes>>,
        outbound: mpsc::Sender<Vec<u8>>,
        payload: usize,
    }

    impl PacketSink for ConfigurableSink {
        async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
            self.outbound.send(packet.to_vec()).await.map_err(|_| {
                NetError::Tun(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            })
        }

        async fn recv_packet(&self) -> Result<Bytes, NetError> {
            self.inbound.lock().await.recv().await.ok_or_else(|| {
                NetError::Tun(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            })
        }

        fn max_payload(&self) -> usize {
            self.payload
        }
    }

    /// A tunnel sink whose sends fail on a script: one entry is popped per
    /// send, an error entry is returned as-is, and anything past the script is
    /// recorded. `recv_packet` parks, so the uplink leg alone decides the run.
    struct ScriptedTunnel {
        script: std::sync::Mutex<VecDeque<NetError>>,
        sent: mpsc::Sender<Vec<u8>>,
    }

    impl PacketSink for ScriptedTunnel {
        async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
            if let Some(err) = self.script.lock().expect("script lock").pop_front() {
                return Err(err);
            }
            let _ = self.sent.send(packet.to_vec()).await;
            Ok(())
        }

        async fn recv_packet(&self) -> Result<Bytes, NetError> {
            std::future::pending().await
        }

        fn max_payload(&self) -> usize {
            1280
        }
    }

    /// Wires a device fed from `packets` (then closed) to a tunnel running
    /// `script`, and returns the pump verdict, what reached the tunnel and the
    /// drop count.
    async fn run_uplink(
        packets: Vec<Vec<u8>>,
        script: VecDeque<NetError>,
    ) -> (Result<(), NetError>, Vec<Vec<u8>>, u64) {
        let (dev_in_tx, dev_in_rx) = mpsc::channel::<Bytes>(4);
        let (dev_out_tx, _dev_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (tun_out_tx, mut tun_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let device = MockSink {
            inbound: Mutex::new(dev_in_rx),
            outbound: dev_out_tx,
        };
        let tunnel = ScriptedTunnel {
            script: std::sync::Mutex::new(script),
            sent: tun_out_tx,
        };
        for packet in packets {
            dev_in_tx.send(Bytes::from(packet)).await.expect("queued");
        }
        drop(dev_in_tx); // the device ends once the queue is drained
        let stats = PumpStats::default();
        let verdict = forward_bidirectional_with_stats(device, tunnel, &stats).await;
        let mut forwarded = Vec::new();
        while let Ok(packet) = tun_out_rx.try_recv() {
            forwarded.push(packet);
        }
        (verdict, forwarded, stats.uplink_send_dropped())
    }

    #[tokio::test]
    async fn a_per_packet_send_failure_is_dropped_and_counted_not_fatal() {
        // The budget can shrink between the size check and the send, so the
        // tunnel refuses THAT packet over a session that is still carrying. For
        // a gateway that is every peer at once, ending the epoch there would
        // drop every peer, flush the uplink and re-arm the port forward.
        let (verdict, forwarded, dropped) = run_uplink(
            vec![vec![0x45, 1], vec![0x45, 2]],
            VecDeque::from(vec![NetError::Multihop(
                warren_transport::MultihopError::SendDatagram(quinn::SendDatagramError::TooLarge),
            )]),
        )
        .await;

        assert_eq!(dropped, 1, "the refused packet is counted");
        assert_eq!(
            forwarded,
            vec![vec![0x45, 2]],
            "the pump kept serving and carried the next packet"
        );
        assert!(
            matches!(verdict, Err(NetError::Tun(_))),
            "the run ended on the device closing, not on the refused packet: {verdict:?}"
        );
    }

    #[tokio::test]
    async fn a_session_level_send_failure_still_ends_the_pump() {
        let (verdict, forwarded, dropped) = run_uplink(
            vec![vec![0x45, 1], vec![0x45, 2]],
            VecDeque::from(vec![NetError::Multihop(
                warren_transport::MultihopError::SendDatagram(
                    quinn::SendDatagramError::ConnectionLost(quinn::ConnectionError::LocallyClosed),
                ),
            )]),
        )
        .await;

        assert_eq!(dropped, 0, "a dead session is not a counted packet drop");
        assert!(
            forwarded.is_empty(),
            "nothing may be sent after the session is gone"
        );
        assert!(
            matches!(verdict, Err(NetError::Multihop(_))),
            "the session error must end the epoch: {verdict:?}"
        );
    }

    /// A minimal IPv4 TCP SYN with a single MSS option. Neither `is_tcp_syn`
    /// nor `clamp_syn_mss` verify the checksum before rewriting, so this test
    /// packet never bothers computing a valid one.
    fn syn_packet(mss: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 44]; // 20-byte IPv4 header + 20-byte TCP header + 4-byte MSS option
        pkt[0] = 0x45; // version 4, IHL 5 (20 bytes, no options)
        pkt[9] = 6; // protocol = TCP
        let tcp = 20;
        pkt[tcp + 12] = 6 << 4; // data offset = 24 bytes (20 + the MSS option)
        pkt[tcp + 13] = 0x02; // SYN
        pkt[tcp + 20] = 2; // option kind = MSS
        pkt[tcp + 21] = 4; // option length
        pkt[tcp + 22..tcp + 24].copy_from_slice(&mss.to_be_bytes());
        pkt
    }

    /// Reads back the MSS option `syn_packet` wrote (or `clamp_syn_mss` rewrote).
    fn syn_mss(frame: &[u8]) -> u16 {
        u16::from_be_bytes([frame[20 + 22], frame[20 + 23]])
    }

    #[tokio::test]
    async fn pump_uplink_clamps_a_syn_with_the_asymmetry_margin() {
        let (dev_in_tx, dev_in_rx) = mpsc::channel::<Bytes>(4);
        let (dev_out_tx, _dev_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (_tun_in_tx, tun_in_rx) = mpsc::channel::<Bytes>(4);
        let (tun_out_tx, mut tun_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let device = ConfigurableSink {
            inbound: Mutex::new(dev_in_rx),
            outbound: dev_out_tx,
            payload: 1280,
        };
        let tunnel = ConfigurableSink {
            inbound: Mutex::new(tun_in_rx),
            outbound: tun_out_tx,
            payload: 1000,
        };

        dev_in_tx.send(Bytes::from(syn_packet(1460))).await.unwrap();
        drop(dev_in_tx); // ends the pump's loop after this one packet

        let _ = pump_uplink(&device, &tunnel, &PumpStats::default()).await;

        let forwarded = tun_out_rx.try_recv().expect("the SYN reached the tunnel");
        assert_eq!(
            syn_mss(&forwarded),
            1000 - warrenguard_transport_core::PROXY_BUDGET_MARGIN - 40,
            "clamped to the tunnel's budget minus the shared uplink margin, minus the v4 header overhead"
        );
    }

    #[tokio::test]
    async fn pump_uplink_reflects_a_too_large_packet_as_ptb_and_drops_it() {
        let (dev_in_tx, dev_in_rx) = mpsc::channel::<Bytes>(4);
        let (dev_out_tx, mut dev_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (_tun_in_tx, tun_in_rx) = mpsc::channel::<Bytes>(4);
        let (tun_out_tx, mut tun_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let device = ConfigurableSink {
            inbound: Mutex::new(dev_in_rx),
            outbound: dev_out_tx,
            payload: 1280,
        };
        let tunnel = ConfigurableSink {
            inbound: Mutex::new(tun_in_rx),
            outbound: tun_out_tx,
            payload: 1000,
        };

        // A well-formed-enough IPv4 packet (unicast source, no ICMP error) that
        // exceeds the tunnel's 1000-byte budget.
        let mut too_big = vec![0u8; 2000];
        too_big[0] = 0x45;
        too_big[9] = 6;
        too_big[12..16].copy_from_slice(&[10, 66, 0, 5]);
        dev_in_tx.send(Bytes::from(too_big)).await.unwrap();
        drop(dev_in_tx);

        let _ = pump_uplink(&device, &tunnel, &PumpStats::default()).await;

        assert!(
            tun_out_rx.try_recv().is_err(),
            "an over-budget packet must never reach the tunnel"
        );
        let ptb = dev_out_rx
            .recv()
            .await
            .expect("a PTB was reflected back to the device");
        assert_eq!(ptb[0] >> 4, 4, "IPv4");
        assert_eq!(ptb[9], 1, "ICMP");
        assert_eq!(
            u16::from_be_bytes([ptb[26], ptb[27]]),
            1000,
            "next-hop MTU carries the tunnel's current budget"
        );
    }

    #[tokio::test]
    async fn pump_downlink_clamps_a_syn_exactly_with_no_margin() {
        let (_dev_in_tx, dev_in_rx) = mpsc::channel::<Bytes>(4);
        let (dev_out_tx, mut dev_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (tun_in_tx, tun_in_rx) = mpsc::channel::<Bytes>(4);
        let (tun_out_tx, _tun_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let device = ConfigurableSink {
            inbound: Mutex::new(dev_in_rx),
            outbound: dev_out_tx,
            payload: 1280,
        };
        let tunnel = ConfigurableSink {
            inbound: Mutex::new(tun_in_rx),
            outbound: tun_out_tx,
            payload: 1000,
        };

        tun_in_tx.send(Bytes::from(syn_packet(1460))).await.unwrap();
        drop(tun_in_tx);

        let _ = pump_downlink(&tunnel, &device).await;

        let forwarded = dev_out_rx.try_recv().expect("the SYN reached the device");
        assert_eq!(
            syn_mss(&forwarded),
            1000 - 40,
            "clamped to the tunnel's budget EXACTLY: no asymmetry margin on this leg"
        );
    }
}

/// Tests for the real-fd duplex loop (`TunBridge::run`). Gated like the method
/// itself; a `UnixStream` pair stands in for the kernel TUN fd so the `AsyncFd`
/// readiness wiring and shutdown paths run with no device and no root. The peer
/// end stays alive and silent, so the device fd is never spuriously readable and
/// the loop terminates only via the egress channel closing (a clean EOF on a
/// stream would otherwise read `Ok(0)` forever, which a kernel TUN fd never
/// does).
#[cfg(all(unix, feature = "experimental-tun"))]
#[cfg(test)]
mod run_loop_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// A [`RawTunDevice`] over one end of a `UnixStream` pair: a real, pollable
    /// fd that `run`'s `AsyncFd` can register without a kernel device.
    struct FdDevice(UnixStream);
    impl RawTunDevice for FdDevice {
        fn read_frame(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
        fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
            self.0.write_all(frame)
        }
    }
    impl AsRawFd for FdDevice {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    #[tokio::test]
    async fn run_returns_ok_when_the_sink_is_dropped() {
        let (dev_end, _peer) = UnixStream::pair().expect("socketpair");
        let (sink, bridge) = tun_channels(FdDevice(dev_end), Framing::Bare, 1500);
        let handle = tokio::spawn(bridge.run());

        // Dropping the sink closes the egress sender; `outbound.recv()` then
        // resolves to `None` and the loop exits cleanly.
        drop(sink);

        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must terminate promptly after the sink drops")
            .expect("run task joins");
        assert!(res.is_ok(), "clean shutdown must return Ok, got {res:?}");
    }

    #[tokio::test]
    async fn run_forwards_a_readable_device_frame_to_the_sink() {
        let (dev_end, mut peer) = UnixStream::pair().expect("socketpair");
        let (sink, bridge) = tun_channels(FdDevice(dev_end), Framing::Bare, 1500);
        let handle = tokio::spawn(bridge.run());

        // A minimal well-formed IPv4 header (version/IHL = 0x45, total length 20).
        let packet = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        peer.write_all(&packet)
            .expect("write makes the device fd readable");

        let got = tokio::time::timeout(Duration::from_secs(5), sink.recv_packet())
            .await
            .expect("the forwarded packet arrives")
            .expect("recv_packet ok");
        assert_eq!(
            &got[..],
            &packet[..],
            "run must deframe and forward the packet"
        );

        // Keep `peer` alive (no EOF); drop the sink to end the loop.
        drop(sink);
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        drop(peer);
    }
}
