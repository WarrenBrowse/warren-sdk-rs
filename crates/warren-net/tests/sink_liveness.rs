//! The liveness watch returned by `spawn_over_sink` flips to `false` when the
//! tunnel read side closes, so the facade can surface a disconnect.

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Notify;
use warren_net::error::NetError;
use warren_net::{NetstackConfig, PacketSink, spawn_over_sink};

/// A packet sink whose `recv_packet` blocks until `close` fires, then errors,
/// modelling a tunnel whose read side goes away on demand.
struct ClosableSink {
    close: Arc<Notify>,
}

impl PacketSink for ClosableSink {
    async fn send_packet(&self, _packet: &[u8]) -> Result<(), NetError> {
        Ok(())
    }

    async fn recv_packet(&self) -> Result<Bytes, NetError> {
        self.close.notified().await;
        Err(NetError::EngineStopped)
    }

    fn max_payload(&self) -> usize {
        1280
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn liveness_flips_to_false_when_the_tunnel_read_side_closes() {
    let close = Arc::new(Notify::new());
    let sink = ClosableSink {
        close: Arc::clone(&close),
    };
    let config = NetstackConfig::new(
        "10.66.0.2".parse().unwrap(),
        24,
        "10.66.0.1".parse().unwrap(),
        1280,
    );

    let (_connector, mut alive) = spawn_over_sink(Arc::new(sink), config);
    assert!(*alive.borrow(), "datapath starts alive");

    // Close the tunnel read side.
    close.notify_one();

    tokio::time::timeout(std::time::Duration::from_secs(2), alive.changed())
        .await
        .expect("liveness change observed")
        .expect("watch sender alive");
    assert!(
        !*alive.borrow(),
        "liveness flips to false once the tunnel read side closes"
    );
}
