//! The datapath micro-bench: decapsulate, route, translate, on one thread.
//!
//! This is the number the concurrency design rests on. One mutex around the
//! responder and one around the NAT is only defensible while a single thread
//! carries more packets than the tunnel ever will, so the figure is measured
//! before any async shell exists rather than inferred from a live download,
//! where the QUIC seal and the socket would hide it.
//!
//! It runs under the ordinary test harness rather than a bench harness so the
//! crate carries no extra dependency and CI's default lane stays fast: the
//! cases are `#[ignore]`d and the operator runs them deliberately.
//!
//! ```text
//! cargo test -p warren-bolthole-core --release --test nat_path -- --ignored --nocapture
//! ```
//!
//! A debug build measures the borrow checks and the unelided copies, not the
//! datapath, so the floor is asserted only when the build is optimised; the
//! measurement itself is printed either way.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use ip_network::IpNetwork;
use warren_bolthole_core::{
    EpochId, ExitId, GatewayConf, GatewayKey, Inbound, Napt, NatConfig, PeerConf, PeerLabel,
    PeerPlan, PeerPublicKey, PresharedKey, Responder, ResponderOptions, ScratchBuf,
};

/// What the design's phase-1 gate demands of one thread on 1280-byte packets.
const FLOOR_PPS: f64 = 200_000.0;
/// Payload size: the inner MTU a peer sees through a Warren tunnel, rounded to
/// the size the design's gate names.
const PACKET_LEN: usize = 1280;
/// Long enough to swamp the timer's own resolution, short enough that the whole
/// file stays a few seconds.
const ROUNDS: u32 = 20_000;

const EXIT: ExitId = ExitId::from_bytes([7u8; 16]);
const ASSIGNED_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);

struct Bench {
    responder: Responder,
    nat: Napt,
    client: Tunn,
    client_addr: SocketAddr,
    peer_v4: Ipv4Addr,
    scratch: ScratchBuf,
}

fn bench(config: NatConfig) -> Bench {
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
            label: PeerLabel::new("peer2").expect("a valid label"),
            public,
            psk: Some(psk),
            allowed: vec![
                IpNetwork::new(IpAddr::V4(peer_v4), 32).expect("a host route"),
                IpNetwork::new(IpAddr::V6(peer_v6), 128).expect("a host route"),
            ],
        }],
    };
    let mut responder =
        Responder::new(&conf, plan, ResponderOptions::default()).expect("a valid configuration");
    responder.set_gate(true, 1);

    let mut nat = Napt::new(config);
    nat.set_ownership(responder.ownership());
    nat.set_external(
        EpochId {
            exit: EXIT,
            generation: 1,
        },
        ASSIGNED_V4,
        None,
    );

    let mut bench = Bench {
        responder,
        nat,
        client,
        client_addr: SocketAddr::from(([192, 168, 4, 20], 51820)),
        peer_v4,
        scratch: ScratchBuf::new(),
    };
    bench.handshake();
    bench
}

impl Bench {
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

    /// Encrypts one packet the way a peer would, outside the measured window.
    fn datagram(&mut self, source_port: u16, remote: Ipv4Addr, remote_port: u16) -> Vec<u8> {
        let packet = udp(
            self.peer_v4,
            source_port,
            remote,
            remote_port,
            PACKET_LEN - 28,
        );
        let mut buf = vec![0u8; PACKET_LEN + 128];
        match self.client.encapsulate(&packet, &mut buf) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        }
    }

    /// One packet through both halves, which is what a pump does per packet.
    fn carry(&mut self, datagram: &[u8], now: Instant) {
        let (peer, packet) =
            match self
                .responder
                .handle_datagram(self.client_addr, datagram, now, &mut self.scratch)
            {
                Inbound::Uplink { peer, packet } => (peer, packet),
                other => panic!("the responder did not release the packet: {other:?}"),
            };
        let mut out = packet.to_vec();
        self.nat
            .translate_uplink(peer, &mut out, now)
            .expect("a flow the peer owns");
    }
}

/// Prints one measurement and returns it, asserting the design's absolute
/// floor only when the caller asked for it.
///
/// The floor is a property of a quiet machine. On the shared CI runners the
/// same code measures a third of what it measures idle, so an absolute
/// assertion there would report the fleet's load as a datapath regression. CI
/// runs the ratios below instead, which are machine-independent, and the number
/// the design's gate wants is produced by a deliberate run:
/// `WARREN_BOLTHOLE_BENCH_FLOOR=1 cargo test --release ... -- --ignored`.
fn measured(name: &str, packets: u32, elapsed: Duration) -> f64 {
    let pps = f64::from(packets) / elapsed.as_secs_f64();
    println!("{name}: {pps:.0} packets per second ({packets} in {elapsed:?})");
    if cfg!(debug_assertions) || std::env::var_os("WARREN_BOLTHOLE_BENCH_FLOOR").is_none() {
        return pps;
    }
    assert!(
        pps >= FLOOR_PPS,
        "{name} carried {pps:.0} packets per second, under the {FLOOR_PPS:.0} floor"
    );
    pps
}

/// The ordinary path: several live flows, no peer near any cap.
fn measure_plain() -> f64 {
    let mut bench = bench(NatConfig::default());
    let now = Instant::now();
    // A handful of flows rather than one, so the tables are exercised and the
    // mapping lookup is not served by a single hot line. The warm-up datagrams
    // are their own: a replayed counter is refused, as it should be.
    let warmup: Vec<Vec<u8>> = (0..64)
        .map(|flow| bench.datagram(4000 + flow, Ipv4Addr::new(1, 1, 1, 1), 443))
        .collect();
    let datagrams: Vec<Vec<u8>> = (0..ROUNDS)
        .map(|round| {
            bench.datagram(
                4000 + u16::try_from(round % 64).expect("64 flows fit a port"),
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )
        })
        .collect();
    for datagram in &warmup {
        bench.carry(datagram, now);
    }
    let started = Instant::now();
    for datagram in &datagrams {
        bench.carry(datagram, now);
    }
    measured("64 flows", ROUNDS, started.elapsed())
}

/// A peer holding every mapping its cap allows, so each further packet opens a
/// flow that has to evict one. This is what a torrent client or a scanner
/// behind the gateway reaches on its own.
fn measure_at_cap() -> f64 {
    let config = NatConfig::default();
    let cap = u16::try_from(config.per_peer_mappings).expect("a cap that fits a port number");
    let mut bench = bench(config);
    let now = Instant::now();
    for flow in 0..cap {
        let datagram = bench.datagram(20_000 + flow, Ipv4Addr::new(1, 1, 1, 1), 443);
        bench.carry(&datagram, now);
    }
    let datagrams: Vec<Vec<u8>> = (0..ROUNDS)
        .map(|round| {
            bench.datagram(
                30_000 + u16::try_from(round).expect("the rounds fit a port"),
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )
        })
        .collect();
    let started = Instant::now();
    for datagram in &datagrams {
        bench.carry(datagram, now);
    }
    measured("a peer at its cap", ROUNDS, started.elapsed())
}

/// One source port talking to every remote a mapping tracks: a resolver behind
/// the gateway, a QUIC client migrating, or a peer under a scan. The mapping's
/// remote list is walked per packet, so a full list is the worst case of the
/// hot path itself.
fn measure_at_remote_cap() -> f64 {
    let mut bench = bench(NatConfig::default());
    let now = Instant::now();
    let remotes: Vec<Ipv4Addr> = (0..64).map(|n| Ipv4Addr::new(198, 51, 100, n)).collect();
    for remote in &remotes {
        let datagram = bench.datagram(4000, *remote, 443);
        bench.carry(&datagram, now);
    }
    let datagrams: Vec<Vec<u8>> = (0..ROUNDS)
        .map(|round| bench.datagram(4000, remotes[usize::try_from(round).unwrap_or(0) % 64], 443))
        .collect();
    let started = Instant::now();
    for datagram in &datagrams {
        bench.carry(datagram, now);
    }
    measured("a mapping at 64 remotes", ROUNDS, started.elapsed())
}

#[test]
#[ignore = "a measurement, run deliberately in release"]
fn the_worst_cases_stay_within_reach_of_the_ordinary_path() {
    // Three measurements in one process on one machine, so the comparison is
    // free of whatever else the host is doing. The ordinary path is the
    // reference; the two worst cases are read against it.
    let plain = measure_plain();
    let at_cap = measure_at_cap();
    let at_remote_cap = measure_at_remote_cap();

    // Evicting a peer's oldest mapping used to walk the whole table, which put
    // this ratio at 0.07 with the default cap of 4,096. Anything that
    // reintroduces a per-packet scan lands far below the bound; scheduler noise
    // on a loaded runner does not (0.34 measured on the busiest CI runner,
    // 0.74 idle).
    assert!(
        at_cap >= plain * 0.15,
        "a peer at its cap carried {at_cap:.0} against {plain:.0} for an uncontended peer"
    );
    assert!(
        at_remote_cap >= plain * 0.4,
        "a mapping at 64 remotes carried {at_remote_cap:.0} against {plain:.0}"
    );
}

// A packet builder with a correct checksum, so the NAT's incremental update
// starts from a valid one and the measurement is of the real arithmetic.

fn udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload_len: usize) -> Vec<u8> {
    let mut l4 = Vec::with_capacity(8 + payload_len);
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&u16::try_from(8 + payload_len).unwrap().to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.resize(8 + payload_len, 0x5a);
    let checksum = ones_sum(pseudo(src, dst, 17, l4.len()), &l4);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    l4[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut pkt = vec![0u8; 20 + l4.len()];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&u16::try_from(20 + l4.len()).unwrap().to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let checksum = ones_sum(0, &pkt[..20]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
    pkt[20..].copy_from_slice(&l4);
    pkt
}

fn pseudo(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, l4_len: usize) -> u64 {
    let mut sum = 0u64;
    for address in [src.octets(), dst.octets()] {
        sum += u64::from(u16::from_be_bytes([address[0], address[1]]));
        sum += u64::from(u16::from_be_bytes([address[2], address[3]]));
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
