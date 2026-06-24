//! ADR-0006 idle-cover end-to-end (SDK): the cover driver emits jittered,
//! size-varied dummies over a real loopback tunnel while idle, with the
//! keep-alive PING disabled (`with_idle_cover(true)` sets
//! `keep_alive_interval(None)`), so cover REPLACES the beacon rather than adding
//! to it.
//!
//! Primary proof: `IdleCoverDriver::covers_sent()` grows over a 35s idle window
//! (the scheduler fires at its 10-20s jittered interval) and each cover is a sent
//! datagram, while the connection stays alive on cover traffic alone. The
//! keep-alive disable itself is a deterministic quinn config setting
//! (`keep_alive_interval(None)`); this test also records `frame_tx.ping` for
//! observability.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::Notify;
use warren_test_support::spawn_fake_exit;
use warren_transport::{ClientTunnel, IdleCoverDriver};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "ADR-0006 idle cover ~35s idle; run with --ignored --nocapture"]
async fn idle_cover_emits_and_keeps_connection_alive() {
    let exit_key = SigningKey::from_bytes(&[9u8; 32]);
    let (exit_addr, exit_pubkey) = spawn_fake_exit(exit_key).await;

    // with_idle_cover(true) disables the keep-alive PING (keep_alive_interval None).
    let tunnel = ClientTunnel::new(SigningKey::from_bytes(&[1u8; 32])).with_idle_cover(true);
    let session = Arc::new(
        tunnel
            .connect(exit_pubkey, exit_addr)
            .await
            .expect("handshake must succeed"),
    );

    // Baseline after the handshake/MTU-probe settles.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let ping_start = session.connection().stats().frame_tx.ping;

    // Spawn the cover driver over the idle session (no real traffic flows).
    let driver = IdleCoverDriver::new(Arc::clone(&session));
    let stop = Arc::new(Notify::new());
    let run_driver = {
        let d = Arc::clone(&driver);
        let s = Arc::clone(&stop);
        tokio::spawn(async move { d.run(s).await })
    };

    tokio::time::sleep(Duration::from_secs(35)).await;

    let stats = session.connection().stats();
    let covers = driver.covers_sent();
    println!(
        "idle cover 35s: covers_sent={covers} frame_tx.datagram={} frame_tx.ping={} (baseline {ping_start})",
        stats.frame_tx.datagram, stats.frame_tx.ping
    );

    assert!(
        covers >= 1,
        "the cover driver must emit at least one dummy in 35s idle (jittered 10-20s interval), got {covers}"
    );
    assert!(
        stats.frame_tx.datagram >= covers,
        "each cover dummy is a sent QUIC datagram: datagram {} < covers_sent {covers}",
        stats.frame_tx.datagram
    );
    assert!(
        session.connection().close_reason().is_none(),
        "connection must stay alive on cover traffic alone (idle timeout must not fire): {:?}",
        session.connection().close_reason()
    );

    stop.notify_one();
    let _ = run_driver.await;
    session.disconnect();
}
