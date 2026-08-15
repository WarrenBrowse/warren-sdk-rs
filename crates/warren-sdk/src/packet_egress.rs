//! One-shot in-tunnel egress proof for a raw-IP datapath.
//!
//! A fail-closed launcher must not expose anything until the tunnel is proven
//! to carry traffic. The proxy datapath proves it through its own SOCKS5
//! listener ([`crate::socks_egress::verify_first_egress`]); a datapath with no
//! listener proves it the way the periodic probe does, with a DNS query to the
//! exit resolver over the epoch's UDP path, retried because the first packets
//! race the datapath warm-up right after connect.

use std::net::{Ipv4Addr, SocketAddr};

use bytes::Bytes;
use warren_net::{DynUdpOpener, UdpFlow};
use warren_transport::egress_probe::{PROBE_QNAME, build_dns_query, is_matching_response};

use crate::socks_egress::{FirstEgressDead, FirstEgressVerify};

/// The exit-side resolver port the probe queries.
const DNS_PORT: u16 = 53;

/// Proves the tunnel egresses: a DNS query to the exit resolver at `gateway`
/// over `udp`, retried per `options`.
///
/// # Errors
///
/// [`FirstEgressDead`] when every attempt failed or timed out. Its message
/// names the protocol step only, never an address.
pub async fn verify_first_egress(
    udp: &dyn DynUdpOpener,
    gateway: Ipv4Addr,
    options: FirstEgressVerify,
) -> Result<(), FirstEgressDead> {
    let resolver = SocketAddr::new(gateway.into(), DNS_PORT);
    let mut last_error = String::new();
    for attempt in 1..=options.attempts {
        // A distinct query id per attempt, so a late answer to a previous one
        // cannot pass for this attempt's proof.
        let txid = u16::try_from(attempt).unwrap_or(u16::MAX);
        match tokio::time::timeout(options.timeout, probe_once(udp, resolver, txid)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => last_error = e.to_owned(),
            Err(_) => last_error = "probe timeout".to_owned(),
        }
        if attempt < options.attempts && !options.gap.is_zero() {
            tokio::time::sleep(options.gap).await;
        }
    }
    Err(FirstEgressDead {
        attempts: options.attempts,
        last_error,
    })
}

/// One query and its answer. The caller bounds it with the attempt timeout, so
/// this waits rather than deciding a deadline of its own.
async fn probe_once(
    udp: &dyn DynUdpOpener,
    resolver: SocketAddr,
    txid: u16,
) -> Result<(), &'static str> {
    let mut flow = udp.open_udp_boxed().await.map_err(|_| "no udp flow")?;
    let query = Bytes::from(build_dns_query(txid, PROBE_QNAME));
    flow.send_to(query, resolver).await.map_err(|_| "send")?;
    loop {
        match flow.recv_from().await {
            Some((buf, _)) if is_matching_response(&buf, txid) => return Ok(()),
            // A stray datagram from an earlier probe: keep waiting inside this
            // attempt's budget rather than spending the attempt on it.
            Some(_) => {}
            None => return Err("flow closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use warren_net::{NetError, UdpOpener};

    const FAST: FirstEgressVerify = FirstEgressVerify {
        attempts: 3,
        timeout: Duration::from_millis(50),
        gap: Duration::ZERO,
    };

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    /// How a scripted flow behaves.
    #[derive(Clone, Copy)]
    enum Answer {
        /// Echo the query back with the response bit set, as a resolver does.
        Resolve,
        /// Answer a datagram that is not this query's response, then park.
        Stray,
        /// Never answer.
        Silent,
        /// End the flow (the epoch is over).
        Closed,
    }

    struct ScriptedFlow {
        answer: Answer,
        query: Option<Bytes>,
        served: bool,
    }

    impl UdpFlow for ScriptedFlow {
        async fn send_to(&self, data: Bytes, _dst: SocketAddr) -> Result<(), NetError> {
            // Interior state is not needed: the answer is built from the query
            // recorded by the opener wrapper below.
            let _ = data;
            Ok(())
        }

        async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
            let from = SocketAddr::new(GATEWAY.into(), DNS_PORT);
            match self.answer {
                Answer::Closed => None,
                Answer::Silent => std::future::pending().await,
                Answer::Stray if !self.served => {
                    self.served = true;
                    Some((Bytes::from_static(b"noise"), from))
                }
                Answer::Stray => std::future::pending().await,
                Answer::Resolve => {
                    let mut answer = self.query.clone()?.to_vec();
                    answer[2] |= 0x80;
                    Some((Bytes::from(answer), from))
                }
            }
        }
    }

    /// Records the query so the flow can answer it, and counts the opens.
    struct ScriptedOpener {
        answer: Answer,
        opens: Arc<AtomicUsize>,
        query: Arc<std::sync::Mutex<Option<Bytes>>>,
    }

    impl ScriptedOpener {
        fn new(answer: Answer) -> Self {
            Self {
                answer,
                opens: Arc::new(AtomicUsize::new(0)),
                query: Arc::new(std::sync::Mutex::new(None)),
            }
        }
    }

    /// A flow that records what it was asked to send before delegating.
    struct RecordingFlow {
        inner: ScriptedFlow,
        query: Arc<std::sync::Mutex<Option<Bytes>>>,
    }

    impl UdpFlow for RecordingFlow {
        async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
            *self.query.lock().expect("query lock") = Some(data.clone());
            self.inner.send_to(data, dst).await
        }

        async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
            self.inner.query = self.query.lock().expect("query lock").clone();
            self.inner.recv_from().await
        }
    }

    impl UdpOpener for ScriptedOpener {
        type Flow = RecordingFlow;

        async fn open_udp(&self) -> Result<RecordingFlow, NetError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(RecordingFlow {
                inner: ScriptedFlow {
                    answer: self.answer,
                    query: None,
                    served: false,
                },
                query: Arc::clone(&self.query),
            })
        }
    }

    #[tokio::test]
    async fn an_answering_resolver_proves_egress_on_the_first_attempt() {
        let opener = ScriptedOpener::new(Answer::Resolve);
        let opens = Arc::clone(&opener.opens);
        verify_first_egress(&opener, GATEWAY, FAST)
            .await
            .expect("the resolver answered through the tunnel");
        assert_eq!(opens.load(Ordering::SeqCst), 1, "one attempt sufficed");
    }

    #[tokio::test]
    async fn a_silent_resolver_reports_the_tunnel_dead_without_naming_an_address() {
        let opener = ScriptedOpener::new(Answer::Silent);
        let dead = verify_first_egress(&opener, GATEWAY, FAST)
            .await
            .expect_err("a silent exit proves nothing");
        assert_eq!(dead.attempts, 3, "the whole budget was spent");
        let rendered = dead.to_string();
        assert!(
            !rendered.contains("10.66.0.1"),
            "the failure must not carry the gateway address: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_stray_datagram_does_not_pass_for_a_proof() {
        // The probe matches on its own query id: anything else on the flow is
        // not evidence the exit forwarded.
        let opener = ScriptedOpener::new(Answer::Stray);
        assert!(
            verify_first_egress(&opener, GATEWAY, FAST).await.is_err(),
            "a datagram that is not the answer proves nothing"
        );
    }

    #[tokio::test]
    async fn a_closed_flow_ends_the_attempt_instead_of_hanging() {
        let opener = ScriptedOpener::new(Answer::Closed);
        let dead = tokio::time::timeout(
            Duration::from_secs(2),
            verify_first_egress(&opener, GATEWAY, FAST),
        )
        .await
        .expect("a dead epoch must be reported promptly")
        .expect_err("a closed flow cannot prove egress");
        assert!(dead.last_error.contains("flow closed"));
    }
}
