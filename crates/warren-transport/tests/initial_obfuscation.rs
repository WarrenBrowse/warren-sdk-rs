//! Behavioural proof that the SDK's DEFAULT transport config obfuscates the
//! client's Initial flight (anti-ossification Initial fragmentation), so every
//! SDK consumer, including the Dart proxy via `warren_sdk_frb`, presents the
//! same handshake shape as warren-app with zero configuration.
//!
//! The obfuscation lives at the QUIC Initial layer, before any authentication,
//! so this needs no exit, no wallet/secret and no privilege: a plain UDP "tap"
//! that never speaks QUIC captures the client's first flight via the public
//! `MultihopClientTunnel::connect` path (which applies `warren_transport_config`
//! by default, shared by every Warren datapath). A default upstream client would
//! emit a single ~1200-byte Initial; the obfuscated default emits a padded
//! (>= 1280) first datagram and splits the ClientHello across >= 2 datagrams, so
//! both assertions are real guards.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::net::UdpSocket;
use warren_transport::MultihopClientTunnel;

/// The fork pads the obfuscated client Initial to `initial_datagram_min_size`
/// (1280). The default upstream Initial is the RFC 9000 floor (1200).
const OBFUSCATED_MIN_FIRST_DATAGRAM: usize = 1280;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_default_client_initial_is_padded_and_split() {
    // A UDP socket that never answers: it only records the client's first
    // Initial flight. The handshake never completes, which is fine, the
    // assertion is on the first flight alone.
    let tap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind udp tap");
    let tap_addr: SocketAddr = tap.local_addr().expect("tap addr");

    // Public default path: no `with_transport_config`, so the connect applies
    // `warren_transport_config()` (the obfuscated default). The x25519 / exit_id
    // are dummies: the tap never speaks QUIC, so only the first flight is emitted.
    let tunnel = MultihopClientTunnel::new(SigningKey::from_bytes(&[1u8; 32]));
    let driver = tokio::spawn(async move {
        // Never resolves (the tap is silent); we want the Initial emission only.
        let _ = tunnel
            .connect([0x11u8; 32], [0x22u8; 32], [0x33u8; 16], tap_addr)
            .await;
    });

    let mut buf = [0u8; 4096];
    let first_len = tokio::time::timeout(Duration::from_secs(5), tap.recv_from(&mut buf))
        .await
        .expect("client emitted no Initial datagram within 5s")
        .expect("tap recv_from")
        .0;

    // Drain the rest of the immediate first flight with a short inter-packet
    // window (well below the ~1s initial PTO, so no retransmission folds in).
    let mut sizes = vec![first_len];
    loop {
        let mut b = [0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(250), tap.recv_from(&mut b)).await {
            Ok(Ok((n, _))) => sizes.push(n),
            _ => break,
        }
    }
    driver.abort();

    assert!(
        first_len >= OBFUSCATED_MIN_FIRST_DATAGRAM,
        "SDK default Initial must be padded to >= {OBFUSCATED_MIN_FIRST_DATAGRAM} bytes \
         (initial_datagram_min_size); got {first_len}. The SDK default lost its Initial \
         padding (obfuscation-by-default regression)."
    );
    assert!(
        sizes.len() >= 2,
        "SDK default must split the ClientHello across >= 2 Initial datagrams \
         (initial_crypto_first_fragment_size); first flight had {} datagram(s): {sizes:?}.",
        sizes.len()
    );
}
