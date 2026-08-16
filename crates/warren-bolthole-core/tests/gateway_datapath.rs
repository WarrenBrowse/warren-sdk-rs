//! The two halves of the gateway, driven end to end by a stock initiator.
//!
//! A peer keeps its own interface address, and the exit refuses any inner
//! packet whose source is not the address it assigned to the session. So the
//! only thing that makes a stock WireGuard client usable through Warren is the
//! pair below working together: the responder decrypts and vouches for the
//! source, the NAPT rewrites it onto the assigned address, and the answer has
//! to find its way back to the peer that owns the flow. Neither half proves
//! that alone.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use ip_network::IpNetwork;
use warren_bolthole_core::{
    EpochId, ExitId, GatewayConf, GatewayKey, Inbound, Napt, NatConfig, PeerConf, PeerLabel,
    PeerPlan, PeerPublicKey, PresharedKey, Responder, ResponderOptions, ScratchBuf, parse_ip,
    read_ports,
};

const EXIT: ExitId = ExitId::from_bytes([7u8; 16]);
const ASSIGNED_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
const ASSIGNED_V6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 2);

struct Gateway {
    responder: Responder,
    nat: Napt,
    client: Tunn,
    client_addr: SocketAddr,
    peer_v4: Ipv4Addr,
    peer_v6: Ipv6Addr,
    scratch: ScratchBuf,
}

fn gateway() -> Gateway {
    let key = GatewayKey::generate();
    let gateway_public = x25519::PublicKey::from(*key.public().as_bytes());
    let plan = PeerPlan::default();
    let (peer_v4, peer_v6) = plan.address_for(2).expect("the first peer address");
    let secret = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PeerPublicKey::from_bytes(x25519::PublicKey::from(&secret).to_bytes());
    let psk = PresharedKey::generate();
    let client = Tunn::new(
        secret,
        gateway_public,
        Some(*psk.as_bytes()),
        Some(25),
        42,
        None,
    );
    let conf = GatewayConf {
        key,
        peers: vec![PeerConf {
            label: PeerLabel::new("peer2").unwrap(),
            public,
            psk: Some(psk),
            allowed: vec![
                IpNetwork::new(IpAddr::V4(peer_v4), 32).unwrap(),
                IpNetwork::new(IpAddr::V6(peer_v6), 128).unwrap(),
            ],
        }],
    };
    let mut responder =
        Responder::new(&conf, plan, ResponderOptions::default()).expect("a valid configuration");
    responder.set_gate(true, 1);

    let mut nat = Napt::new(NatConfig::default());
    // The responder is the one place that knows which peer owns which address,
    // and the NAT refuses any source outside that view: this is the seam the
    // two halves meet on.
    nat.set_ownership(responder.ownership());
    nat.set_external(
        EpochId {
            exit: EXIT,
            generation: 1,
        },
        ASSIGNED_V4,
        Some(ASSIGNED_V6),
    );

    let mut gateway = Gateway {
        responder,
        nat,
        client,
        client_addr: SocketAddr::from(([192, 168, 4, 20], 51820)),
        peer_v4,
        peer_v6,
        scratch: ScratchBuf::new(),
    };
    gateway.handshake();
    gateway
}

impl Gateway {
    fn handshake(&mut self) {
        let now = Instant::now();
        let mut buf = vec![0u8; 2048];
        let initiation = match self.client.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        let response = match self.responder.handle_datagram(
            self.client_addr,
            &initiation,
            now,
            &mut self.scratch,
        ) {
            Inbound::Reply(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        let mut buf = vec![0u8; 2048];
        let keepalive = match self.client.decapsulate(None, &response, &mut buf) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        match self
            .responder
            .handle_datagram(self.client_addr, &keepalive, now, &mut self.scratch)
        {
            Inbound::Consumed => {}
            other => panic!("{other:?}"),
        }
    }

    /// One packet from the peer, all the way to what the tunnel would carry.
    fn uplink(&mut self, packet: &[u8]) -> Vec<u8> {
        let now = Instant::now();
        let mut buf = vec![0u8; 4096];
        let datagram = match self.client.encapsulate(packet, &mut buf) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        let (peer, mut out) = match self.responder.handle_datagram(
            self.client_addr,
            &datagram,
            now,
            &mut self.scratch,
        ) {
            Inbound::Uplink { peer, packet } => (peer, packet.to_vec()),
            other => panic!("the responder did not release the packet: {other:?}"),
        };
        self.nat
            .translate_uplink(peer, &mut out, now)
            .expect("a flow the peer owns");
        out
    }

    /// One packet from the tunnel, all the way to what the peer decrypts.
    fn downlink(&mut self, packet: &[u8]) -> Vec<u8> {
        let now = Instant::now();
        let mut out = packet.to_vec();
        let translated = self
            .nat
            .translate_downlink(&mut out, now)
            .expect("an answer to a live flow");
        let datagram =
            match self
                .responder
                .encapsulate_to(translated.destination, &out, &mut self.scratch)
            {
                Ok(warren_bolthole_core::Encapsulated::Sent(to, bytes)) => {
                    assert_eq!(to, self.client_addr);
                    bytes.to_vec()
                }
                other => panic!("the answer did not reach the peer: {other:?}"),
            };
        let mut buf = vec![0u8; 4096];
        match self.client.decapsulate(None, &datagram, &mut buf) {
            TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                bytes.to_vec()
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn carries_a_peer_flow_out_through_the_assigned_address_and_back() {
    let mut gateway = gateway();
    let remote = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let query = udp(IpAddr::V4(gateway.peer_v4), 4000, remote, 53, b"question");

    let uplink = gateway.uplink(&query);

    let header = parse_ip(&uplink).expect("an IP packet");
    assert_eq!(
        header.src,
        IpAddr::V4(ASSIGNED_V4),
        "the exit would have refused this source"
    );
    assert_eq!(header.dst, remote);
    let (external_port, destination_port) =
        read_ports(&uplink, header.l4_offset).expect("a UDP header");
    assert_eq!(destination_port, 53);
    assert_ne!(external_port, 4000, "a port outside the pool is replaced");
    assert!(checksums_valid(&uplink), "the rewritten packet is corrupt");
    assert_eq!(&uplink[header.l4_offset + 8..], b"question");

    let answer = udp(
        remote,
        53,
        IpAddr::V4(ASSIGNED_V4),
        external_port,
        b"the answer",
    );
    let delivered = gateway.downlink(&answer);

    let header = parse_ip(&delivered).expect("an IP packet");
    assert_eq!(header.src, remote);
    assert_eq!(header.dst, IpAddr::V4(gateway.peer_v4));
    assert_eq!(
        read_ports(&delivered, header.l4_offset).unwrap(),
        (53, 4000),
        "the peer sees the port it sent from"
    );
    assert!(checksums_valid(&delivered));
    assert_eq!(&delivered[header.l4_offset + 8..], b"the answer");
}

#[test]
fn carries_an_ipv6_peer_flow_the_same_way() {
    let mut gateway = gateway();
    let remote = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    let query = udp(IpAddr::V6(gateway.peer_v6), 40000, remote, 53, b"question");

    let uplink = gateway.uplink(&query);
    let header = parse_ip(&uplink).expect("an IP packet");
    assert_eq!(header.src, IpAddr::V6(ASSIGNED_V6));
    let (external_port, _) = read_ports(&uplink, header.l4_offset).unwrap();
    assert_eq!(
        external_port, 40000,
        "a port inside the pool is preserved when it is free"
    );
    assert!(checksums_valid(&uplink));

    let answer = udp(
        remote,
        53,
        IpAddr::V6(ASSIGNED_V6),
        external_port,
        b"the answer",
    );
    let delivered = gateway.downlink(&answer);
    let header = parse_ip(&delivered).expect("an IP packet");
    assert_eq!(header.dst, IpAddr::V6(gateway.peer_v6));
    assert_eq!(
        read_ports(&delivered, header.l4_offset).unwrap(),
        (53, 40000)
    );
    assert!(checksums_valid(&delivered));
}

#[test]
fn refuses_an_answer_to_a_flow_no_peer_opened() {
    let mut gateway = gateway();
    let unsolicited = udp(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        1234,
        IpAddr::V4(ASSIGNED_V4),
        40001,
        b"unsolicited",
    );
    let mut packet = unsolicited.clone();
    assert!(
        gateway
            .nat
            .translate_downlink(&mut packet, Instant::now())
            .is_err()
    );
    assert_eq!(packet, unsolicited, "a refused packet is left untouched");
}

// Packet builders and an independent checksum oracle: a test that asked the
// code under test whether its own arithmetic was right would prove nothing.

fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::with_capacity(8 + payload.len());
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(payload);
    let checksum = ones_sum(pseudo(src, dst, 17, l4.len()), &l4);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    l4[6..8].copy_from_slice(&checksum.to_be_bytes());
    frame(src, dst, 17, &l4)
}

fn frame(src: IpAddr, dst: IpAddr, protocol: u8, l4: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut pkt = vec![0u8; 20 + l4.len()];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&u16::try_from(20 + l4.len()).unwrap().to_be_bytes());
            pkt[8] = 64;
            pkt[9] = protocol;
            pkt[12..16].copy_from_slice(&src.octets());
            pkt[16..20].copy_from_slice(&dst.octets());
            let checksum = ones_sum(0, &pkt[..20]);
            pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
            pkt[20..].copy_from_slice(l4);
            pkt
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut pkt = vec![0u8; 40 + l4.len()];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&u16::try_from(l4.len()).unwrap().to_be_bytes());
            pkt[6] = protocol;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&src.octets());
            pkt[24..40].copy_from_slice(&dst.octets());
            pkt[40..].copy_from_slice(l4);
            pkt
        }
        _ => panic!("a packet cannot mix address families"),
    }
}

fn pseudo(src: IpAddr, dst: IpAddr, protocol: u8, l4_len: usize) -> u64 {
    let mut sum = 0u64;
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            for address in [src.octets(), dst.octets()] {
                sum += u64::from(u16::from_be_bytes([address[0], address[1]]));
                sum += u64::from(u16::from_be_bytes([address[2], address[3]]));
            }
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            for address in [src.octets(), dst.octets()] {
                for pair in address.chunks(2) {
                    sum += u64::from(u16::from_be_bytes([pair[0], pair[1]]));
                }
            }
        }
        _ => panic!("a packet cannot mix address families"),
    }
    sum + u64::from(protocol) + l4_len as u64
}

fn ones_sum(seed: u64, data: &[u8]) -> u16 {
    let mut sum = seed;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u64::from(u16::from_be_bytes([data[index], data[index + 1]]));
        index += 2;
    }
    if index < data.len() {
        sum += u64::from(data[index]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksums_valid(packet: &[u8]) -> bool {
    let header = parse_ip(packet).expect("an IP packet");
    if !header.is_v6() && ones_sum(0, &packet[..header.l4_offset]) != 0 {
        return false;
    }
    let l4 = &packet[header.l4_offset..header.total_len];
    ones_sum(
        pseudo(header.src, header.dst, header.protocol, l4.len()),
        l4,
    ) == 0
}
