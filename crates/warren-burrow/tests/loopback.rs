//! The gateway, end to end, over real UDP.
//!
//! The device here is the real one, bound on loopback, driven by a stock
//! boringtun initiator over a real socket and pumped against a fake exit that
//! enforces the one rule a real exit enforces: an inner packet whose source is
//! not the address it assigned is refused. Between those two ends sit every
//! piece the gateway is made of, and none of them is stubbed.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use bytes::Bytes;
use ip_network::IpNetwork;
use tokio::sync::mpsc;
use warren_burrow::device::{GatewayDevice, GatewayOptions, GatewayTasks};
use warren_burrow_core::{
    GatewayConf, GatewayKey, MapProto, PeerConf, PeerLabel, PeerPlan, PeerPublicKey, PresharedKey,
    ResponderOptions, parse_error_quote, parse_ip, read_icmp, read_ports,
};
use warren_sdk::net::{
    EpochAddressing, EpochId, EpochPacketDevice, ExitId, NetError, PacketSink, PumpStats,
    build_udp_packet, forward_bidirectional_with_stats,
};

const ASSIGNED_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
const OTHER_ASSIGNED_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 77);
const GATEWAY_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// The exit's inner budget in these tests: under the peers' own MTU, so the
/// oversize path is reachable without building a 1500-byte packet.
const EXIT_BUDGET: usize = 1100;

/// A short bound on everything that waits, so a regression fails instead of
/// hanging a CI runner.
const WAIT: Duration = Duration::from_secs(3);

/// The exit side of the tunnel.
///
/// It refuses a source it did not assign, exactly as the real exit's anti-spoof
/// gate does, and answers a UDP datagram by swapping the tuple, which is what
/// makes a round trip observable at the peer.
struct FakeExit {
    assigned: Ipv4Addr,
    budget: usize,
    seen: mpsc::UnboundedSender<Vec<u8>>,
    downlink: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    inject: mpsc::UnboundedSender<Vec<u8>>,
    echo: AtomicBool,
    refused: AtomicUsize,
}

impl FakeExit {
    fn new(assigned: Ipv4Addr, budget: usize) -> (Arc<Self>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (seen, seen_rx) = mpsc::unbounded_channel();
        let (inject, downlink) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                assigned,
                budget,
                seen,
                downlink: tokio::sync::Mutex::new(downlink),
                inject,
                echo: AtomicBool::new(true),
                refused: AtomicUsize::new(0),
            }),
            seen_rx,
        )
    }

    /// Pushes one packet down the tunnel, as the internet would.
    fn deliver(&self, packet: Vec<u8>) {
        let _ = self.inject.send(packet);
    }

    fn refused(&self) -> usize {
        self.refused.load(Ordering::Relaxed)
    }
}

impl PacketSink for FakeExit {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetError> {
        let Ok(header) = parse_ip(packet) else {
            return Ok(());
        };
        if header.src != IpAddr::V4(self.assigned) {
            // The exit's own anti-spoof gate: an inner source it never
            // assigned is dropped, and the client never learns it.
            self.refused.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let _ = self.seen.send(packet.to_vec());
        if self.echo.load(Ordering::Relaxed)
            && header.protocol == 17
            && let Ok((sport, dport)) = read_ports(packet, header.l4_offset)
        {
            let payload = packet[header.l4_offset + 8..].to_vec();
            if let Some(answer) = build_udp_packet(
                SocketAddr::new(header.dst, dport),
                SocketAddr::new(header.src, sport),
                &payload,
            ) {
                self.deliver(answer);
            }
        }
        Ok(())
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        self.downlink
            .lock()
            .await
            .recv()
            .await
            .map(Bytes::from)
            .ok_or(NetError::EngineStopped)
    }

    fn max_payload(&self) -> usize {
        self.budget
    }
}

/// A stock WireGuard-protocol client on a real socket.
struct StockClient {
    tunn: Tunn,
    socket: tokio::net::UdpSocket,
    gateway: SocketAddr,
    v4: Ipv4Addr,
}

impl StockClient {
    async fn send_datagram(&self, datagram: &[u8]) {
        self.socket
            .send_to(datagram, self.gateway)
            .await
            .expect("loopback takes it");
    }

    /// The next datagram the gateway sends back, or `None` within the bound.
    async fn next_datagram(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65_535];
        let read = tokio::time::timeout(WAIT, self.socket.recv_from(&mut buf)).await;
        read.ok()
            .and_then(Result::ok)
            .map(|(len, _)| buf[..len].to_vec())
    }

    /// Waits `budget` for a datagram, expecting none.
    async fn expect_silence(&self, budget: Duration) {
        let mut buf = vec![0u8; 65_535];
        let heard = tokio::time::timeout(budget, self.socket.recv_from(&mut buf)).await;
        assert!(
            heard.is_err(),
            "the gateway answered while it must have stayed silent"
        );
    }

    async fn handshake(&mut self) {
        let mut buf = vec![0u8; 2048];
        let initiation = match self.tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        self.send_datagram(&initiation).await;
        let response = self
            .next_datagram()
            .await
            .expect("the gateway answers a handshake");
        let mut buf = vec![0u8; 2048];
        match self.tunn.decapsulate(None, &response, &mut buf) {
            TunnResult::WriteToNetwork(keepalive) => {
                let keepalive = keepalive.to_vec();
                self.send_datagram(&keepalive).await;
            }
            other => panic!("{other:?}"),
        }
    }

    /// Encrypts one inner packet and puts it on the wire.
    async fn send_inner(&mut self, packet: &[u8]) {
        let mut buf = vec![0u8; 70_000];
        let datagram = match self.tunn.encapsulate(packet, &mut buf) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            other => panic!("{other:?}"),
        };
        self.send_datagram(&datagram).await;
    }

    /// The next inner packet the gateway delivers, decrypted.
    async fn next_inner(&mut self) -> Option<Vec<u8>> {
        loop {
            let datagram = self.next_datagram().await?;
            let mut buf = vec![0u8; 70_000];
            match self.tunn.decapsulate(None, &datagram, &mut buf) {
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                    return Some(bytes.to_vec());
                }
                // A keepalive or a queued handshake datagram: boringtun asks
                // for it to be written back, which is not what a caller
                // waiting for a packet wants.
                TunnResult::WriteToNetwork(reply) => {
                    let reply = reply.to_vec();
                    self.send_datagram(&reply).await;
                }
                TunnResult::Done => {}
                other => panic!("{other:?}"),
            }
        }
    }
}

/// One gateway, one peer, one fake exit, wired the way the daemon wires them.
struct Loopback {
    device: GatewayDevice,
    _tasks: GatewayTasks,
    client: StockClient,
    exit: Arc<FakeExit>,
    seen: mpsc::UnboundedReceiver<Vec<u8>>,
    pump: Option<tokio::task::JoinHandle<()>>,
    generation: u64,
}

async fn loopback() -> Loopback {
    loopback_with(ASSIGNED_V4, EXIT_BUDGET, true).await
}

async fn loopback_with(assigned: Ipv4Addr, budget: usize, start_epoch: bool) -> Loopback {
    let key = GatewayKey::generate();
    let gateway_public = x25519::PublicKey::from(*key.public().as_bytes());
    let plan = PeerPlan::default();
    let (peer_v4, peer_v6) = plan.address_for(2).expect("the first peer address");
    let secret = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PeerPublicKey::from_bytes(x25519::PublicKey::from(&secret).to_bytes());
    let psk = PresharedKey::generate();
    let tunn = Tunn::new(
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
                IpNetwork::new(IpAddr::V4(peer_v4), 32).expect("a host prefix"),
                IpNetwork::new(IpAddr::V6(peer_v6), 128).expect("a host prefix"),
            ],
        }],
    };

    let sockets = warren_burrow::socket::bind_all(&["127.0.0.1:0".parse().expect("literal")])
        .await
        .expect("loopback binds");
    let bound = sockets[0].local_addr().expect("a bound address");
    let options = GatewayOptions {
        responder: ResponderOptions::default(),
        client_mtu: 1280,
        ..GatewayOptions::default()
    };
    let device = GatewayDevice::new(&conf, plan, &options, sockets).expect("a valid configuration");
    let tasks = device.spawn();

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("the client binds");
    let (exit, seen) = FakeExit::new(assigned, budget);

    let mut loopback = Loopback {
        device,
        _tasks: tasks,
        client: StockClient {
            tunn,
            socket,
            gateway: bound,
            v4: peer_v4,
        },
        exit,
        seen,
        pump: None,
        generation: 0,
    };
    if start_epoch {
        loopback.begin_epoch(assigned).await;
    }
    loopback
}

impl Loopback {
    /// Starts an epoch and pumps it against the exit, as the supervisor does.
    async fn begin_epoch(&mut self, assigned: Ipv4Addr) {
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
        self.generation += 1;
        let addressing = EpochAddressing {
            epoch: EpochId {
                exit: ExitId::from_bytes([7u8; 16]),
                generation: self.generation,
            },
            ipv4: assigned,
            prefix: 16,
            gateway: GATEWAY_V4,
            ipv6: None,
        };
        let (sink, _control) = self.device.begin_epoch(addressing);
        let exit = Arc::clone(&self.exit);
        let stats = Arc::new(PumpStats::default());
        self.pump = Some(tokio::spawn(async move {
            let _ = forward_bidirectional_with_stats(sink, exit, &stats).await;
        }));
        assert!(
            self.device.open_gate_for(self.generation),
            "the epoch the daemon just began is the one it opens"
        );
        // The pump has to be polled once before the first packet, or the first
        // uplink races the task's own start.
        tokio::task::yield_now().await;
    }

    /// Waits for the peer's session to be live at the gateway. The handshake
    /// ends with a datagram the reader has yet to process when `handshake`
    /// returns, so asserting on the count without this races the reader.
    async fn wait_for_session(&self) {
        for _ in 0..300u32 {
            if self.device.snapshot().peers_with_session == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the peer never reached a live session");
    }

    /// The next packet the exit accepted, or `None` within the bound.
    async fn next_at_exit(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(WAIT, self.seen.recv()).await.ok()?
    }

    /// Waits `budget` for the exit to see a packet, expecting none.
    async fn expect_nothing_egresses(&mut self, budget: Duration) {
        let seen = tokio::time::timeout(budget, self.seen.recv()).await;
        assert!(
            seen.is_err(),
            "a packet reached the exit that must never have left the gateway"
        );
    }
}

fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Vec<u8> {
    build_udp_packet(
        SocketAddr::new(src, sport),
        SocketAddr::new(dst, dport),
        payload,
    )
    .expect("a valid packet")
}

/// The whole point, in one test: a stock client hands the gateway a packet
/// sourced at its own address, and what reaches the exit carries the address
/// the exit assigned, with the answer finding its way back to the peer.
#[tokio::test(flavor = "multi_thread")]
async fn a_stock_client_handshakes_and_carries_a_flow_both_ways() {
    let mut lo = loopback().await;
    lo.client.handshake().await;
    lo.wait_for_session().await;

    let peer_v4 = lo.client.v4;
    lo.client
        .send_inner(&udp(
            IpAddr::V4(peer_v4),
            4000,
            IpAddr::V4(REMOTE),
            53,
            b"question",
        ))
        .await;

    let uplink = lo.next_at_exit().await.expect("the exit accepts it");
    let header = parse_ip(&uplink).expect("an IP packet");
    assert_eq!(header.src, IpAddr::V4(ASSIGNED_V4));
    assert_eq!(header.dst, IpAddr::V4(REMOTE));
    let (external, dport) = read_ports(&uplink, header.l4_offset).expect("a UDP header");
    assert_eq!(dport, 53);
    assert_ne!(
        external, 4000,
        "the NAT gave the flow its own external port"
    );
    assert_eq!(&uplink[header.l4_offset + 8..], b"question");

    let answer = lo.client.next_inner().await.expect("the answer comes back");
    let header = parse_ip(&answer).expect("an IP packet");
    assert_eq!(header.src, IpAddr::V4(REMOTE));
    assert_eq!(
        header.dst,
        IpAddr::V4(peer_v4),
        "the peer sees its own address, not the assigned one"
    );
    assert_eq!(
        read_ports(&answer, header.l4_offset).unwrap(),
        (53, 4000),
        "and the port it sent from"
    );
}

/// Cryptokey routing vouches for the source, and the NAT refuses one the
/// sending peer does not own. Both walls are inside the gateway: once the NAT
/// has run, the exit's own gate can no longer see a spoof.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_sourcing_an_address_it_does_not_own_never_egresses() {
    let mut lo = loopback().await;
    lo.client.handshake().await;

    lo.client
        .send_inner(&udp(
            IpAddr::V4(Ipv4Addr::new(10, 67, 0, 9)),
            4000,
            IpAddr::V4(REMOTE),
            53,
            b"spoof",
        ))
        .await;

    lo.expect_nothing_egresses(Duration::from_millis(300)).await;
    let snapshot = lo.device.snapshot();
    assert_eq!(
        snapshot.responder.spoofed_source, 1,
        "the responder is the wall that caught it"
    );
    assert_eq!(
        lo.exit.refused(),
        0,
        "nothing reached the exit's own gate, which is the point"
    );
}

/// Fail-closed is structural: with no epoch the gateway has nowhere to put a
/// peer's packet, and it answers nothing at all, so the peer's own liveness
/// rule fires instead of being fed a heartbeat over a black hole.
#[tokio::test(flavor = "multi_thread")]
async fn with_no_tunnel_the_gateway_refuses_a_handshake_and_admits_one_afterwards() {
    let mut lo = loopback_with(ASSIGNED_V4, EXIT_BUDGET, false).await;

    let mut buf = vec![0u8; 2048];
    let initiation = match lo.client.tunn.format_handshake_initiation(&mut buf, true) {
        TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
        other => panic!("{other:?}"),
    };
    lo.client.send_datagram(&initiation).await;

    lo.client.expect_silence(Duration::from_millis(300)).await;
    let snapshot = lo.device.snapshot();
    assert_eq!(
        snapshot.responder.handshake_refused_gate_closed, 1,
        "the initiation was refused before any Diffie-Hellman"
    );
    assert_eq!(snapshot.peers_with_session, 0);

    lo.begin_epoch(ASSIGNED_V4).await;
    lo.client.handshake().await;
    lo.wait_for_session().await;
}

/// A peer packet the tunnel cannot carry is turned back into an ICMP error at
/// the peer, and the NAT has to rewrite the quote inside it or the peer's own
/// path discovery attributes the error to a flow it never opened.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_peer_packet_comes_back_as_a_packet_too_big() {
    let mut lo = loopback().await;
    lo.client.handshake().await;
    let peer_v4 = lo.client.v4;

    // Above the exit's budget, below the peers' own MTU.
    let payload = vec![0x5au8; EXIT_BUDGET];
    lo.client
        .send_inner(&udp(
            IpAddr::V4(peer_v4),
            4321,
            IpAddr::V4(REMOTE),
            443,
            &payload,
        ))
        .await;

    let error = lo
        .client
        .next_inner()
        .await
        .expect("the gateway reflects an ICMP error");
    let header = parse_ip(&error).expect("an IP packet");
    assert_eq!(header.protocol, 1, "an ICMPv4 error");
    assert_eq!(
        header.dst,
        IpAddr::V4(peer_v4),
        "the error is addressed to the peer that sent the packet"
    );
    let icmp = read_icmp(&error, header.l4_offset).expect("an ICMP header");
    assert_eq!(icmp.kind, 3, "destination unreachable");
    assert_eq!(icmp.code, 4, "fragmentation needed");
    let mtu = u16::from_be_bytes([error[header.l4_offset + 6], error[header.l4_offset + 7]]);
    assert_eq!(
        usize::from(mtu),
        EXIT_BUDGET,
        "the peer is told the budget the tunnel actually carries"
    );

    let quote = parse_error_quote(&error, &header).expect("a quoted packet");
    assert_eq!(
        quote.inner.src,
        IpAddr::V4(peer_v4),
        "the quote must name the peer's own packet, not the translated one"
    );
    assert_eq!(quote.inner.dst, IpAddr::V4(REMOTE));
    assert_eq!(
        quote.ports,
        Some((4321, 443)),
        "the peer matches the error to its flow by these ports"
    );
}

/// A redial or a failover must not cost every peer a handshake: the sessions
/// live in the responder, which outlives the tunnel under it.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_survives_a_redial_to_the_same_and_to_a_different_address() {
    let mut lo = loopback().await;
    lo.client.handshake().await;
    let peer_v4 = lo.client.v4;

    lo.begin_epoch(ASSIGNED_V4).await;
    lo.client
        .send_inner(&udp(
            IpAddr::V4(peer_v4),
            5000,
            IpAddr::V4(REMOTE),
            53,
            b"same-exit",
        ))
        .await;
    let uplink = lo.next_at_exit().await.expect("no handshake was needed");
    assert_eq!(
        parse_ip(&uplink).unwrap().src,
        IpAddr::V4(ASSIGNED_V4),
        "the same address came back"
    );
    assert_eq!(
        lo.device.snapshot().peers_with_session,
        1,
        "the peer never renegotiated"
    );

    // A different exit, so a different assigned address: the session is kept
    // and every packet now leaves under the new one.
    lo.exit = {
        let (exit, seen) = FakeExit::new(OTHER_ASSIGNED_V4, EXIT_BUDGET);
        lo.seen = seen;
        exit
    };
    lo.begin_epoch(OTHER_ASSIGNED_V4).await;
    lo.client
        .send_inner(&udp(
            IpAddr::V4(peer_v4),
            5001,
            IpAddr::V4(REMOTE),
            53,
            b"other-exit",
        ))
        .await;
    let uplink = lo.next_at_exit().await.expect("still no handshake");
    assert_eq!(
        parse_ip(&uplink).unwrap().src,
        IpAddr::V4(OTHER_ASSIGNED_V4),
        "the new exit assigned a new address, and the peer never noticed"
    );
    assert_eq!(lo.exit.refused(), 0);
}

/// The forwarded port is delivered by cryptokey routing: the exit DNATs to the
/// assigned address, and the pinned entry is what turns that into a peer.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_forward_delivers_an_inbound_packet_to_its_peer() {
    let mut lo = loopback().await;
    lo.client.handshake().await;
    let peer_v4 = lo.client.v4;
    lo.exit.echo.store(false, Ordering::Relaxed);

    lo.device
        .add_static_dnat(MapProto::Udp, 8080, SocketAddr::from((peer_v4, 9000)))
        .expect("a peer target and a free port");

    lo.exit.deliver(udp(
        IpAddr::V4(REMOTE),
        40000,
        IpAddr::V4(ASSIGNED_V4),
        8080,
        b"inbound",
    ));

    let delivered = lo
        .client
        .next_inner()
        .await
        .expect("the peer receives the inbound packet");
    let header = parse_ip(&delivered).expect("an IP packet");
    assert_eq!(header.src, IpAddr::V4(REMOTE));
    assert_eq!(header.dst, IpAddr::V4(peer_v4));
    assert_eq!(
        read_ports(&delivered, header.l4_offset).unwrap(),
        (40000, 9000),
        "the pinned entry names the port the application listens on"
    );
    assert_eq!(&delivered[header.l4_offset + 8..], b"inbound");
}

/// The gateway never writes a peer's packet anywhere except into the tunnel.
/// A host service on the same machine is the nearest thing a peer could reach
/// by mistake, and it must be unreachable however the packet is addressed.
///
/// The silence at that socket only means something while the datapath is
/// demonstrably alive, so the same peer's traffic to the internet is asserted
/// in the same test, and the counters say which rule refused each knock.
#[tokio::test(flavor = "multi_thread")]
async fn nothing_a_peer_sends_can_reach_the_host_stack() {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a host service");
    let echo_addr = echo.local_addr().expect("a bound address");

    let mut lo = loopback().await;
    lo.client.handshake().await;
    let peer_v4 = lo.client.v4;

    for destination in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(GATEWAY_V4),
        IpAddr::V4(ASSIGNED_V4),
    ] {
        lo.client
            .send_inner(&udp(
                IpAddr::V4(peer_v4),
                4000,
                destination,
                echo_addr.port(),
                b"knock",
            ))
            .await;
    }

    let mut buf = [0u8; 64];
    let heard = tokio::time::timeout(Duration::from_millis(500), echo.recv_from(&mut buf)).await;
    assert!(
        heard.is_err(),
        "a peer packet reached a socket on the host's own stack"
    );

    let snapshot = lo.device.snapshot();
    assert_eq!(
        snapshot.responder.non_unicast, 1,
        "the loopback destination is refused before anything is built for it"
    );
    assert_eq!(
        snapshot.responder.pool_destination, 2,
        "the tunnel's own addresses are the exit's, not this host's"
    );

    // The control: the same peer, on the same session, still egresses. Without
    // it a severed datapath would pass this test.
    lo.client
        .send_inner(&udp(
            IpAddr::V4(peer_v4),
            4001,
            IpAddr::V4(REMOTE),
            53,
            b"alive",
        ))
        .await;
    let uplink = lo
        .next_at_exit()
        .await
        .expect("the datapath carried the peer's traffic throughout");
    assert_eq!(
        parse_ip(&uplink).expect("an IP packet").src,
        IpAddr::V4(ASSIGNED_V4)
    );
}
