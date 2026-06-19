//! Manual micro-benchmarks for the per-packet multihop hot path.
//!
//! No criterion: the workspace deliberately keeps its dependency tree minimal
//! and 1:1-mappable across the sibling-language SDKs, so this is a dependency-free
//! `harness = false` binary that times the client uplink primitives directly.
//! Run with `cargo bench -p warren-multihop`.
//!
//! What it measures, per outbound IP packet on a live tunnel:
//! - `seal`: one HKDF exporter derivation + one ChaCha20-Poly1305 pass.
//! - `seal + encode`: the full uplink (`MultihopSession::send_packet` minus the
//!   quinn datagram send), i.e. what the audit's "two allocations" finding flagged.
//! - `decode`: the downlink codec step (postcard parse + frame validation).

use std::hint::black_box;
use std::time::Instant;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use warren_multihop::{ClientSession, ExitId, parse_exit_x25519_pubkey};
use warren_wire::multihop::{EXIT_ID_LEN, WarrenMultihopFrame};

/// Times `f` over `iters` iterations after a warm-up, printing ns/op.
fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t.elapsed().as_nanos() as f64 / f64::from(iters);
    println!("{name:<26} {ns:>9.1} ns/op");
}

fn main() {
    // Deterministic setup so runs are comparable; the KEM keypair and exit key
    // are fixed (setup cost is one-time, outside the timed loops).
    let mut rng = ChaCha20Rng::seed_from_u64(0x5741_5252_454e);
    let exit_x = parse_exit_x25519_pubkey(&[7u8; 32]).expect("parse exit x25519");
    let exit_id = ExitId::from_bytes([0x11u8; EXIT_ID_LEN]);
    let session = ClientSession::new(&exit_x, exit_id, &mut rng).expect("session");

    // 64B: a bare ACK-sized packet. 576B: the classic minimum IPv4 MTU. 1280B:
    // the IPv6 minimum MTU and Warren's negotiated link MTU (the common full
    // packet, and what cover traffic pads to).
    for &size in &[64usize, 576, 1280] {
        let payload = vec![0xABu8; size];
        let iters = 300_000;
        println!("--- payload {size} B ---");
        // seal is benched on its own; the encode variants are isolated below on a
        // pre-sealed frame so seal's run-to-run noise does not pollute the encode
        // comparison. Two reps each: take the lower (least-perturbed) reading.
        for _ in 0..2 {
            bench("seal", iters, || {
                black_box(session.seal(black_box(&payload), 0, 1).expect("seal"));
            });
        }
        let frame = session.seal(&payload, 0, 1).expect("seal");
        for _ in 0..2 {
            // Baseline kept as evidence + a regression guard: `to_stdvec` grows a
            // fresh Vec from empty, the behavior `encode()` deliberately replaced.
            bench("  encode grow (to_stdvec)", iters, || {
                black_box(postcard::to_stdvec(black_box(&frame)).expect("to_stdvec"));
            });
            // The shipping path: `encode()` pre-sizes the output exactly, so the
            // serializer never reallocates. Should land well under the grow case.
            bench("  encode (presized)", iters, || {
                black_box(frame.encode().expect("encode"));
            });
        }
        let wire = frame.encode().expect("encode");
        bench("decode", iters, || {
            black_box(WarrenMultihopFrame::decode(black_box(&wire)).expect("decode"));
        });
    }
}
