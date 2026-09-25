//! The SDK's NAT-PMP client against the engine's own NAT-PMP server, behind a
//! credential authority that requires a credential (warren-core doc 105).
//!
//! What an exit enforcing doc 105 owes the client, and the client owes it: a
//! Map request carries the entitlement envelope in its trailer, both legs of a
//! TCP+UDP pair carry the SAME one (the pair is one port), a request without
//! one is refused as not authorized, and each refresh cycle presents what the
//! provider holds at that moment so an epoch rollover reaches the exit.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::UdpSocket;
use warren_net::error::NetError;
use warren_net::portforward::{CredentialProvider, map_cycle};
use warren_net::{MapProto, UdpFlow};
use warren_test_support::natpmp::EngineNatPmp;

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
const NATPMP_PORT: u16 = 5351;

/// A kernel UDP socket posing as the tunnel's flow to the gateway: what the
/// client addresses to the in-tunnel gateway reaches the loopback server, and
/// the server's answers come back as if from the gateway.
struct LoopbackFlow {
    sock: UdpSocket,
    server: SocketAddr,
}

impl LoopbackFlow {
    async fn to(server: SocketAddr) -> Self {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind the client socket");
        Self { sock, server }
    }
}

impl UdpFlow for LoopbackFlow {
    async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
        assert_eq!(dst, SocketAddr::from((GATEWAY, NATPMP_PORT)));
        self.sock
            .send_to(&data, self.server)
            .await
            .map(|_| ())
            .map_err(NetError::Io)
    }

    async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
        let mut buf = vec![0u8; 1100];
        loop {
            let (n, src) = self.sock.recv_from(&mut buf).await.ok()?;
            if src == self.server {
                return Some((
                    Bytes::copy_from_slice(&buf[..n]),
                    SocketAddr::from((GATEWAY, NATPMP_PORT)),
                ));
            }
        }
    }
}

fn fixed(credential: Option<Vec<u8>>) -> CredentialProvider {
    Arc::new(move || credential.clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_exit_receives_the_credential_a_map_presents() {
    let server = EngineNatPmp::spawn().await;
    let mut flow = LoopbackFlow::to(server.addr()).await;
    let envelope = vec![0x5A; 500];

    let granted = map_cycle(
        &mut flow,
        GATEWAY,
        &[MapProto::Tcp],
        8080,
        0,
        3600,
        Some(&fixed(Some(envelope.clone()))),
    )
    .await
    .expect("the exit grants a map that presents a credential");

    assert_eq!(granted.len(), 1);
    assert_eq!(server.presented(), vec![envelope]);
}

#[tokio::test(flavor = "multi_thread")]
async fn both_legs_of_a_pair_present_one_credential_for_one_port() {
    let server = EngineNatPmp::spawn().await;
    let mut flow = LoopbackFlow::to(server.addr()).await;
    let envelope = vec![0x21; 500];

    let granted = map_cycle(
        &mut flow,
        GATEWAY,
        &[MapProto::Tcp, MapProto::Udp],
        8080,
        0,
        3600,
        Some(&fixed(Some(envelope.clone()))),
    )
    .await
    .expect("the exit grants both legs");

    assert_eq!(
        granted[0].external_port, granted[1].external_port,
        "a pair is one public port"
    );
    assert_eq!(
        server.presented(),
        vec![envelope.clone(), envelope],
        "both legs present the same envelope, so the exit counts one port"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_map_without_a_credential_is_refused_as_not_authorized() {
    // An exhausted batch (the provider answers `None`) and no provider at all
    // reach the exit identically: nothing in the trailer.
    let server = EngineNatPmp::spawn().await;
    let mut flow = LoopbackFlow::to(server.addr()).await;

    for provider in [None, Some(fixed(None))] {
        let err = map_cycle(
            &mut flow,
            GATEWAY,
            &[MapProto::Tcp],
            8080,
            0,
            3600,
            provider.as_ref(),
        )
        .await
        .expect_err("an enforcing exit refuses a map with no credential");

        assert!(err.is_not_authorized(), "{err:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pair_refused_on_its_second_leg_releases_its_first() {
    // The exit grants the first presentation and refuses the second: the pair
    // must not survive half-mapped, holding a port nobody can publish.
    let server = EngineNatPmp::spawn_granting(1).await;
    let mut flow = LoopbackFlow::to(server.addr()).await;

    let err = map_cycle(
        &mut flow,
        GATEWAY,
        &[MapProto::Tcp, MapProto::Udp],
        8080,
        0,
        3600,
        Some(&fixed(Some(vec![0x33; 500]))),
    )
    .await
    .expect_err("the second leg is refused");

    assert!(err.is_not_authorized(), "{err:?}");
    assert_eq!(server.active_mappings(), 0, "the first leg was left mapped");
}

#[tokio::test(flavor = "multi_thread")]
async fn each_cycle_presents_the_credential_its_provider_holds_then() {
    // An entitlement verifies against its own epoch's key only: after an
    // epoch boundary, the renewal must present the next batch's envelope.
    let server = EngineNatPmp::spawn().await;
    let mut flow = LoopbackFlow::to(server.addr()).await;
    let current = Arc::new(Mutex::new(vec![0x01; 500]));
    let held = Arc::clone(&current);
    let provider: CredentialProvider = Arc::new(move || Some(held.lock().unwrap().clone()));

    let first = map_cycle(
        &mut flow,
        GATEWAY,
        &[MapProto::Tcp],
        8080,
        0,
        3600,
        Some(&provider),
    )
    .await
    .expect("first cycle granted");
    *current.lock().unwrap() = vec![0x02; 500];
    let renewal = map_cycle(
        &mut flow,
        GATEWAY,
        &[MapProto::Tcp],
        8080,
        first[0].external_port,
        3600,
        Some(&provider),
    )
    .await
    .expect("renewal granted");

    assert_eq!(renewal[0].external_port, first[0].external_port);
    assert_eq!(server.presented(), vec![vec![0x01; 500], vec![0x02; 500]]);
}
