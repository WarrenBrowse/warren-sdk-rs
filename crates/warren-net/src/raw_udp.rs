//! UDP flows over a raw IP packet plane.
//!
//! A device that carries bare IP packets has no stack to open a socket on, so
//! the in-tunnel control plane (NAT-PMP, the egress probe) has to build its own
//! datagrams and pick its own replies out of the downlink. This module is that
//! plane: [`RawUdpDemux`] hands out [`RawUdpFlow`]s bound to a source port,
//! [`RawUdpFlow`] builds the IP + UDP packet and pushes it into the device's
//! uplink, and [`RawUdpDemux::deliver`] routes a downlink packet back to the
//! flow that owns its destination port.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::error::NetError;
use crate::proxy::UdpFlow;

/// IANA protocol number for UDP.
const PROTO_UDP: u8 = 17;
/// Fixed IPv4 header length used here (no options).
const IPV4_HEADER_LEN: usize = 20;
/// Fixed IPv6 header length (no extension headers).
const IPV6_HEADER_LEN: usize = 40;
/// UDP header length.
const UDP_HEADER_LEN: usize = 8;
/// Hop budget of a control datagram, which never leaves the tunnel.
const TTL: u8 = 64;
/// Inbound depth per flow: the control plane is request/response, so a queue
/// this deep already absorbs a burst, and a flood is bounded rather than
/// unbounded.
const FLOW_INBOX_DEPTH: usize = 64;

/// Folds a one's-complement sum and returns the checksum field value.
fn checksum_from(mut sum: u32) -> u16 {
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(u16::try_from(sum).unwrap_or(u16::MAX))
}

/// Adds `bytes` to a one's-complement sum, as 16-bit big-endian words.
fn sum_bytes(sum: &mut u32, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        *sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        *sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
}

/// Builds one UDP datagram inside its IP packet, ready to ride the tunnel.
///
/// Both families are built with a UDP checksum: mandatory over IPv6, and over
/// IPv4 the exit-side resolver and NAT-PMP gateway are ordinary sockets that
/// verify it when it is present.
///
/// Returns `None` when the two endpoints are of different families, or when the
/// payload cannot fit an IP packet.
#[must_use]
pub fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN.checked_add(payload.len())?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(IPV4_HEADER_LEN + udp_len).ok()?;
            let mut packet = Vec::with_capacity(IPV4_HEADER_LEN + udp_len);
            packet.push(0x45); // version 4, no options
            packet.push(0); // DSCP / ECN
            packet.extend_from_slice(&total.to_be_bytes());
            packet.extend_from_slice(&[0, 0]); // identification
            packet.extend_from_slice(&[0, 0]); // flags / fragment offset
            packet.push(TTL);
            packet.push(PROTO_UDP);
            packet.extend_from_slice(&[0, 0]); // header checksum, filled below
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
            let mut header_sum = 0u32;
            sum_bytes(&mut header_sum, &packet[..IPV4_HEADER_LEN]);
            let header_checksum = checksum_from(header_sum);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

            let mut pseudo = 0u32;
            sum_bytes(&mut pseudo, &s.octets());
            sum_bytes(&mut pseudo, &d.octets());
            pseudo += u32::from(PROTO_UDP);
            pseudo += u32::from(udp_len_u16);
            push_udp(
                &mut packet,
                src.port(),
                dst.port(),
                payload,
                udp_len_u16,
                pseudo,
            );
            Some(packet)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut packet = Vec::with_capacity(IPV6_HEADER_LEN + udp_len);
            packet.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, no traffic class or flow label
            packet.extend_from_slice(&udp_len_u16.to_be_bytes());
            packet.push(PROTO_UDP);
            packet.push(TTL);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());

            let mut pseudo = 0u32;
            sum_bytes(&mut pseudo, &s.octets());
            sum_bytes(&mut pseudo, &d.octets());
            pseudo += u32::from(udp_len_u16);
            pseudo += u32::from(PROTO_UDP);
            push_udp(
                &mut packet,
                src.port(),
                dst.port(),
                payload,
                udp_len_u16,
                pseudo,
            );
            Some(packet)
        }
        _ => None,
    }
}

/// Appends the UDP header and payload, checksummed over `pseudo` (the
/// family's pseudo-header sum).
fn push_udp(
    packet: &mut Vec<u8>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    udp_len: u16,
    pseudo: u32,
) {
    let header_at = packet.len();
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // checksum, filled below
    packet.extend_from_slice(payload);
    let mut sum = pseudo;
    sum_bytes(&mut sum, &packet[header_at..]);
    let checksum = checksum_from(sum);
    // RFC 768: an all-zero checksum means "not computed", so a computed zero is
    // transmitted as all-ones.
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };
    packet[header_at + 6..header_at + 8].copy_from_slice(&checksum.to_be_bytes());
}

/// The source, destination and payload of a UDP packet, or `None` when the
/// packet is not a UDP datagram this plane can read (a fragment, an unsupported
/// family, an IPv6 extension header, a truncated header).
fn parse_udp(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, &[u8])> {
    let (src_ip, dst_ip, udp) = match packet.first()? >> 4 {
        4 => {
            let ihl = usize::from(packet.first()? & 0x0F) * 4;
            if ihl < IPV4_HEADER_LEN || packet.len() < ihl {
                return None;
            }
            if packet.get(9)? != &PROTO_UDP {
                return None;
            }
            // A fragment carries no complete UDP header, and the control plane
            // never sends or expects one.
            let frag = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
            if frag & 0x1FFF != 0 || frag & 0x2000 != 0 {
                return None;
            }
            let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            (IpAddr::from(src), IpAddr::from(dst), packet.get(ihl..)?)
        }
        6 => {
            if packet.len() < IPV6_HEADER_LEN || packet.get(6)? != &PROTO_UDP {
                return None;
            }
            let src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            (
                IpAddr::from(src),
                IpAddr::from(dst),
                packet.get(IPV6_HEADER_LEN..)?,
            )
        }
        _ => return None,
    };
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    Some((
        SocketAddr::new(src_ip, src_port),
        SocketAddr::new(dst_ip, dst_port),
        &udp[UDP_HEADER_LEN..],
    ))
}

/// One flow's registration: the identity of the registration itself, so a
/// superseded flow can tell its own entry from the one that replaced it, and
/// the inbox its datagrams are queued on.
type Registration = (u64, mpsc::Sender<(Bytes, SocketAddr)>);

/// The registered flows of one device, keyed by the local port they own.
type Registrations = Arc<Mutex<HashMap<u16, Registration>>>;

/// Routes downlink UDP datagrams to the flows that own their destination port.
///
/// One demux serves one device: [`register`](Self::register) opens a flow on a
/// local port, [`deliver`](Self::deliver) hands it the packets addressed to it,
/// and [`close_all`](Self::close_all) ends every flow at once, which is how an
/// epoch tells its control plane that it is over.
pub struct RawUdpDemux {
    flows: Registrations,
    /// The device's uplink: every flow's datagram is pushed here as a whole IP
    /// packet.
    injector: mpsc::Sender<Vec<u8>>,
    /// Stamps each registration, so the port alone never decides whose entry a
    /// dropped flow is looking at.
    next_token: std::sync::atomic::AtomicU64,
}

impl RawUdpDemux {
    /// Builds a demux whose flows inject their packets into `injector`.
    #[must_use]
    pub fn new(injector: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            flows: Registrations::default(),
            injector,
            next_token: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Opens a flow sourced at `local`, accepting datagrams from
    /// `expected_remote` alone.
    ///
    /// The remote is pinned because the control-plane clients above match their
    /// answers loosely (NAT-PMP has no transaction id, the egress probe matches
    /// on a query id): without it, anything that can reach this device's
    /// address on the control port could answer for the gateway.
    ///
    /// A second registration on a port replaces the first, which is what a
    /// re-registration after an epoch change means.
    #[must_use]
    pub fn register(&self, local: SocketAddr, expected_remote: SocketAddr) -> RawUdpFlow {
        let (tx, rx) = mpsc::channel(FLOW_INBOX_DEPTH);
        let token = self
            .next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.flows
            .lock()
            .expect("raw udp registrations lock")
            .insert(local.port(), (token, tx));
        RawUdpFlow {
            local,
            expected_remote,
            token,
            injector: self.injector.clone(),
            inbox: rx,
            flows: Arc::clone(&self.flows),
        }
    }

    /// Offers one downlink packet to the registered flows.
    ///
    /// Returns `true` when the packet was addressed to a registered port (the
    /// device must not route it anywhere else), whether it was queued or
    /// dropped for a full queue.
    #[must_use]
    pub fn deliver(&self, packet: &[u8]) -> bool {
        let Some((src, dst, payload)) = parse_udp(packet) else {
            return false;
        };
        let sender = {
            let flows = self.flows.lock().expect("raw udp registrations lock");
            flows.get(&dst.port()).map(|(_, tx)| tx.clone())
        };
        let Some(sender) = sender else {
            return false;
        };
        // A full inbox drops, like any UDP queue: the control plane retransmits.
        let _ = sender.try_send((Bytes::copy_from_slice(payload), src));
        true
    }

    /// Ends every flow: their `recv_from` returns `None`, which the control
    /// plane reads as "this epoch is over".
    pub fn close_all(&self) {
        self.flows
            .lock()
            .expect("raw udp registrations lock")
            .clear();
    }
}

/// One UDP flow over a raw IP plane (see [`RawUdpDemux`]).
///
/// Dropping it frees its local port at the demux.
pub struct RawUdpFlow {
    local: SocketAddr,
    expected_remote: SocketAddr,
    /// Which registration on this port is this flow's own.
    token: u64,
    injector: mpsc::Sender<Vec<u8>>,
    inbox: mpsc::Receiver<(Bytes, SocketAddr)>,
    flows: Registrations,
}

impl RawUdpFlow {
    /// The address datagrams are sourced from.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Drop for RawUdpFlow {
    fn drop(&mut self) {
        // Only ever this flow's own registration: a re-registration across an
        // epoch change replaces the entry, and this flow is dropped after the
        // live one exists.
        if let Ok(mut flows) = self.flows.lock()
            && flows
                .get(&self.local.port())
                .is_some_and(|(token, _)| *token == self.token)
        {
            flows.remove(&self.local.port());
        }
    }
}

impl UdpFlow for RawUdpFlow {
    async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
        let Some(packet) = build_udp_packet(self.local, dst, &data) else {
            // A destination this flow cannot address (wrong family, oversized):
            // lossy like any UDP send, never an epoch-ending error.
            return Ok(());
        };
        match self.injector.try_send(packet) {
            Ok(()) => Ok(()),
            // A full uplink drops the datagram, as a congested link would.
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(NetError::EngineStopped),
        }
    }

    async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
        loop {
            let (payload, from) = self.inbox.recv().await?;
            if from == self.expected_remote {
                return Some((payload, from));
            }
            // Addressed to this port from somewhere else: the exit forwards
            // between its own clients, so this is reachable, and the control
            // plane above would accept it as an answer.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use bytes::Bytes;
    use tokio::sync::mpsc;

    use crate::proxy::UdpFlow;

    const CLIENT: &str = "10.66.0.2:61000";
    const GATEWAY: &str = "10.66.0.1:5351";

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address")
    }

    /// The endpoints of a built packet, read back through the parser the demux
    /// routes with.
    fn endpoints_of(packet: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
        super::parse_udp(packet).map(|(src, dst, _)| (src, dst))
    }

    /// Sums a packet as 16-bit big-endian words, the way a checksum is
    /// verified: a correct one makes the total wrap to all-ones.
    fn ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut chunks = bytes.chunks_exact(2);
        for c in &mut chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        u16::try_from(sum).expect("folded")
    }

    /// The IPv4 pseudo-header + UDP datagram sum, which must be all-ones on a
    /// packet whose checksum is right.
    fn v4_udp_checksum_ok(packet: &[u8]) -> bool {
        let ihl = usize::from(packet[0] & 0x0F) * 4;
        let udp = &packet[ihl..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[12..20]); // src + dst
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(u16::try_from(udp.len()).expect("len")).to_be_bytes());
        pseudo.extend_from_slice(udp);
        ones_complement_sum(&pseudo) == 0xFFFF
    }

    #[test]
    fn a_built_datagram_carries_valid_checksums() {
        let packet =
            build_udp_packet(addr(CLIENT), addr(GATEWAY), b"hello").expect("a v4 datagram");
        assert_eq!(packet[0] >> 4, 4, "IPv4");
        assert_eq!(packet[9], 17, "UDP");
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]),
            u16::try_from(packet.len()).expect("len"),
            "the total length covers the whole packet"
        );
        assert_eq!(
            ones_complement_sum(&packet[..20]),
            0xFFFF,
            "the IPv4 header checksum verifies"
        );
        assert!(
            v4_udp_checksum_ok(&packet),
            "the UDP checksum verifies over the pseudo-header"
        );
        assert_eq!(&packet[28..], b"hello", "the payload rides last");
    }

    #[test]
    fn a_v6_datagram_is_built_with_a_mandatory_checksum() {
        let packet = build_udp_packet(
            addr("[fdcc:f:1::2]:61000"),
            addr("[fdcc:f:1::1]:53"),
            b"query",
        )
        .expect("a v6 datagram");
        assert_eq!(packet[0] >> 4, 6, "IPv6");
        assert_eq!(packet[6], 17, "next header is UDP");
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]),
            13,
            "the payload length covers the UDP header and its payload"
        );
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[8..40]);
        pseudo.extend_from_slice(&13u32.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&packet[40..]);
        assert_eq!(
            ones_complement_sum(&pseudo),
            0xFFFF,
            "the v6 UDP checksum verifies"
        );
    }

    #[test]
    fn a_mixed_family_datagram_is_refused() {
        assert!(
            build_udp_packet(addr(CLIENT), addr("[fdcc:f:1::1]:53"), b"x").is_none(),
            "a v4 source cannot address a v6 destination"
        );
    }

    /// A demux wired to a channel standing in for the device's uplink.
    fn demux() -> (RawUdpDemux, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(8);
        (RawUdpDemux::new(tx), rx)
    }

    /// Turns an uplink packet into its own reply (source and destination
    /// swapped), the way the gateway answers.
    fn reply_to(packet: &[u8], payload: &[u8]) -> Vec<u8> {
        let (src, dst) = endpoints_of(packet).expect("the uplink packet parses");
        build_udp_packet(dst, src, payload).expect("reply")
    }

    #[tokio::test]
    async fn a_flow_round_trips_through_the_demux() {
        let (demux, mut uplink) = demux();
        let mut flow = demux.register(addr(CLIENT), addr(GATEWAY));

        flow.send_to(Bytes::from_static(b"map"), addr(GATEWAY))
            .await
            .expect("the datagram is injected");
        let sent = uplink.recv().await.expect("the uplink carries the packet");
        let (src, dst) = endpoints_of(&sent).expect("parses");
        assert_eq!(src, addr(CLIENT), "sourced from the flow's own address");
        assert_eq!(dst, addr(GATEWAY), "addressed to the gateway");

        assert!(
            demux.deliver(&reply_to(&sent, b"granted")),
            "a packet for a registered port is consumed by the demux"
        );
        let (payload, from) = flow.recv_from().await.expect("the reply arrives");
        assert_eq!(payload, Bytes::from_static(b"granted"));
        assert_eq!(from, addr(GATEWAY), "the reply names its sender");
    }

    #[tokio::test]
    async fn a_datagram_from_an_unexpected_remote_never_reaches_the_flow() {
        // A peer of this device can address the assigned tunnel address on the
        // control port through the exit's own forwarding, and the NAT-PMP
        // client and the egress probe both match replies loosely. The expected
        // remote is what keeps a stranger's datagram out.
        let (demux, _uplink) = demux();
        let mut flow = demux.register(addr(CLIENT), addr(GATEWAY));

        let spoofed = build_udp_packet(addr("10.66.0.9:5351"), addr(CLIENT), b"spoof")
            .expect("a datagram from another tunnel client");
        assert!(
            demux.deliver(&spoofed),
            "the port is registered, so the demux owns the packet"
        );
        let legit =
            build_udp_packet(addr(GATEWAY), addr(CLIENT), b"real").expect("the gateway's answer");
        assert!(demux.deliver(&legit));

        let (payload, from) = flow.recv_from().await.expect("a datagram arrives");
        assert_eq!(
            payload,
            Bytes::from_static(b"real"),
            "only the expected remote is delivered"
        );
        assert_eq!(from, addr(GATEWAY));
    }

    #[tokio::test]
    async fn a_packet_for_no_registered_port_is_not_consumed() {
        let (demux, _uplink) = demux();
        let _flow = demux.register(addr(CLIENT), addr(GATEWAY));
        let elsewhere = build_udp_packet(addr(GATEWAY), addr("10.66.0.2:53"), b"x").expect("built");
        assert!(
            !demux.deliver(&elsewhere),
            "an unclaimed port leaves the packet to the rest of the device"
        );
    }

    #[tokio::test]
    async fn closing_the_demux_ends_every_flow() {
        // How an epoch reports its own end to the control plane: the NAT-PMP
        // exchange and the egress probe both read a closed flow as a dead
        // epoch.
        let (demux, _uplink) = demux();
        let mut flow = demux.register(addr(CLIENT), addr(GATEWAY));
        demux.close_all();
        assert!(
            flow.recv_from().await.is_none(),
            "a closed flow ends rather than parking forever"
        );
    }

    #[tokio::test]
    async fn a_flow_reports_a_dead_uplink_on_send() {
        let (demux, uplink) = demux();
        let flow = demux.register(addr(CLIENT), addr(GATEWAY));
        drop(uplink);
        assert!(
            matches!(
                flow.send_to(Bytes::from_static(b"map"), addr(GATEWAY))
                    .await,
                Err(crate::error::NetError::EngineStopped)
            ),
            "a gone uplink is reported, never silently swallowed"
        );
    }

    #[tokio::test]
    async fn dropping_a_superseded_flow_leaves_its_replacement_registered() {
        // A re-registration after an epoch change replaces the flow on that
        // port, and the flow of the epoch that ended is dropped afterwards.
        // Freeing the port then would silently end the LIVE flow, which the
        // control plane above reads as "this epoch is over".
        let (demux, _uplink) = demux();
        let stale = demux.register(addr(CLIENT), addr(GATEWAY));
        let mut live = demux.register(addr(CLIENT), addr(GATEWAY));
        drop(stale);

        let answer = build_udp_packet(addr(GATEWAY), addr(CLIENT), b"granted").expect("built");
        assert!(
            demux.deliver(&answer),
            "the port is still owned by the live flow"
        );
        let (payload, _) = live
            .recv_from()
            .await
            .expect("the live flow still receives");
        assert_eq!(payload, Bytes::from_static(b"granted"));
    }

    #[tokio::test]
    async fn a_registration_is_released_when_its_flow_is_dropped() {
        let (demux, _uplink) = demux();
        {
            let _flow = demux.register(addr(CLIENT), addr(GATEWAY));
        }
        let late = build_udp_packet(addr(GATEWAY), addr(CLIENT), b"late").expect("built");
        assert!(
            !demux.deliver(&late),
            "the port is free once its flow is gone"
        );
    }
}
