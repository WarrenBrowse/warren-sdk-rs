//! NAT-PMP port-forwarding client (RFC 6886) over a tunnel UDP flow.
//!
//! The wire codec lives in [`warren_wire::natpmp`]; this module is the client
//! behavior on top of it: request/response with RFC 6886 exponential-backoff
//! retransmission, the half-lifetime refresh loop, and graceful teardown.
//!
//! It speaks over the backend-agnostic [`UdpFlow`] seam, so the same client runs
//! over the userspace netstack (proxy datapath, datagrams egress at the exit) or,
//! later, a privileged TUN backend. The gateway is reached on the standard
//! NAT-PMP port, so a forwarded port maps at the exit, not on the host.
//!
//! Per CLAUDE.md this is validated in-process against a scripted gateway; the
//! real behavior must still be confirmed against a live Warren exit.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use warren_wire::natpmp::{self, MapProto, Request, Response, ResultCode};

use crate::error::NetError;
use crate::netstack::{NetstackListener, NetstackStream};
use crate::proxy::UdpFlow;

/// Standard NAT-PMP server port on the gateway (RFC 6886).
const NATPMP_PORT: u16 = 5351;
/// RFC 6886 initial retransmission timeout.
const INITIAL_RTO: Duration = Duration::from_millis(250);
/// RFC 6886 upper bound on the retransmission timeout.
const MAX_RTO: Duration = Duration::from_secs(64);
/// RFC 6886 retransmission attempts before giving up.
const MAX_ATTEMPTS: u32 = 9;

/// A mapping the client wants the gateway to create and keep alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSpec {
    /// TCP or UDP.
    pub proto: MapProto,
    /// Internal (tunnel-side) port to expose.
    pub internal_port: u16,
    /// Preferred external port (`0` lets the gateway choose).
    pub suggested_external_port: u16,
    /// Requested lifetime in seconds.
    pub lifetime_secs: u32,
}

/// A mapping the gateway granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    /// TCP or UDP.
    pub proto: MapProto,
    /// Internal port (echoed by the gateway).
    pub internal_port: u16,
    /// Allocated external port reachable at the exit.
    pub external_port: u16,
    /// Granted lifetime in seconds (may be shorter than requested).
    pub lifetime_secs: u32,
}

/// Failure of a NAT-PMP exchange.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PortForwardError {
    /// The UDP flow failed to send or closed underneath us.
    #[error("nat-pmp transport error")]
    Transport(#[source] NetError),
    /// The gateway answered with a non-success result code. The code names a
    /// protocol condition, not identity material, so it is safe to surface.
    #[error("nat-pmp gateway rejected the request: {0:?}")]
    Gateway(ResultCode),
    /// No usable reply arrived within the RFC 6886 retransmission budget.
    #[error("nat-pmp request timed out after retransmissions")]
    Timeout,
    /// The gateway replied to a different request than the one sent.
    #[error("nat-pmp gateway replied to the wrong request")]
    UnexpectedReply,
}

/// Renewal delay for a granted lifetime: half of it, per RFC 6886 section 3.3.
///
/// Clamped so a zero or tiny lifetime cannot turn the refresh loop into a busy
/// spin.
#[must_use]
pub fn refresh_after(lifetime_secs: u32) -> Duration {
    Duration::from_secs(u64::from(lifetime_secs.max(2)) / 2)
}

/// Sends `request` to the gateway and returns the reply for the same opcode,
/// retransmitting with RFC 6886 exponential backoff until one arrives or the
/// attempts are exhausted. Replies are correlated by opcode (NAT-PMP has no
/// transaction id); callers verify the echoed internal port. Datagrams from a
/// source other than the gateway's NAT-PMP port, replies to a different opcode,
/// and malformed frames are all ignored without spending the budget on an error,
/// so one stray or hostile datagram cannot abort a mapping attempt.
///
/// # Errors
///
/// [`PortForwardError::Transport`] if the flow send fails or the flow closes,
/// and [`PortForwardError::Timeout`] if no matching reply arrives in budget.
pub async fn exchange<F: UdpFlow>(
    flow: &mut F,
    gateway: Ipv4Addr,
    request: Request,
) -> Result<Response, PortForwardError> {
    let wire = natpmp::serialize_request(&request);
    let server = SocketAddr::from((gateway, NATPMP_PORT));
    let mut rto = INITIAL_RTO;

    for _ in 0..MAX_ATTEMPTS {
        flow.send_to(Bytes::copy_from_slice(&wire), server)
            .await
            .map_err(PortForwardError::Transport)?;

        let deadline = tokio::time::Instant::now() + rto;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, flow.recv_from()).await {
                // Window elapsed with no matching reply: retransmit.
                Err(_) => break,
                // The flow ended (tunnel down).
                Ok(None) => {
                    return Err(PortForwardError::Transport(NetError::EngineStopped));
                }
                Ok(Some((data, src))) => {
                    // Only the gateway's NAT-PMP port may answer.
                    if src != server {
                        continue;
                    }
                    // A malformed frame from the gateway endpoint must not abort
                    // the retransmission budget; ignore it and keep waiting.
                    let Ok(resp) = natpmp::parse_response(&data) else {
                        continue;
                    };
                    if response_matches(&request, &resp) {
                        return Ok(resp);
                    }
                    // A reply to some other opcode: keep waiting in this window.
                }
            }
        }
        rto = (rto * 2).min(MAX_RTO);
    }
    Err(PortForwardError::Timeout)
}

/// True when `resp` is the gateway's answer to `req` (same opcode/proto).
fn response_matches(req: &Request, resp: &Response) -> bool {
    match (req, resp) {
        (Request::ExternalAddress, Response::ExternalAddress { .. }) => true,
        (Request::Map { proto: rp, .. }, Response::Map { proto: sp, .. }) => rp == sp,
        _ => false,
    }
}

/// Creates or refreshes the mapping in `spec` and returns what the gateway
/// granted.
///
/// # Errors
///
/// [`PortForwardError::Gateway`] on a non-success result code,
/// [`PortForwardError::UnexpectedReply`] if the echoed internal port does not
/// match, plus the [`exchange`] errors.
pub async fn map<F: UdpFlow>(
    flow: &mut F,
    gateway: Ipv4Addr,
    spec: MapSpec,
) -> Result<PortMapping, PortForwardError> {
    let resp = exchange(
        flow,
        gateway,
        Request::Map {
            proto: spec.proto,
            internal_port: spec.internal_port,
            suggested_external_port: spec.suggested_external_port,
            lifetime_secs: spec.lifetime_secs,
        },
    )
    .await?;

    match resp {
        Response::Map {
            result_code: ResultCode::Success,
            internal_port,
            external_port,
            lifetime_secs,
            ..
        } => {
            // The gateway must echo the internal port it mapped; a mismatch means
            // the reply is for a different allocation.
            if internal_port != spec.internal_port {
                return Err(PortForwardError::UnexpectedReply);
            }
            Ok(PortMapping {
                proto: spec.proto,
                internal_port,
                external_port,
                lifetime_secs,
            })
        }
        Response::Map { result_code, .. } => Err(PortForwardError::Gateway(result_code)),
        _ => Err(PortForwardError::UnexpectedReply),
    }
}

/// Queries the gateway's public IPv4 address.
///
/// # Errors
///
/// [`PortForwardError::Gateway`] on a non-success result code, plus the
/// [`exchange`] errors.
pub async fn external_address<F: UdpFlow>(
    flow: &mut F,
    gateway: Ipv4Addr,
) -> Result<Ipv4Addr, PortForwardError> {
    match exchange(flow, gateway, Request::ExternalAddress).await? {
        Response::ExternalAddress {
            result_code: ResultCode::Success,
            external_ip,
            ..
        } => Ok(external_ip),
        Response::ExternalAddress { result_code, .. } => {
            Err(PortForwardError::Gateway(result_code))
        }
        _ => Err(PortForwardError::UnexpectedReply),
    }
}

/// Removes the mapping for `internal_port` (a Map with lifetime `0`, per RFC
/// 6886).
///
/// # Errors
///
/// [`PortForwardError::Gateway`] on a non-success result code,
/// [`PortForwardError::UnexpectedReply`] if the gateway acknowledges a different
/// internal port, plus the [`exchange`] errors.
pub async fn delete<F: UdpFlow>(
    flow: &mut F,
    gateway: Ipv4Addr,
    proto: MapProto,
    internal_port: u16,
) -> Result<(), PortForwardError> {
    let resp = exchange(
        flow,
        gateway,
        Request::Map {
            proto,
            internal_port,
            suggested_external_port: 0,
            lifetime_secs: 0,
        },
    )
    .await?;
    match resp {
        Response::Map {
            result_code: ResultCode::Success,
            internal_port: echoed,
            ..
        } => {
            // The ack must name the port we tore down, else it is for a different
            // allocation (opcode alone does not correlate; NAT-PMP has no id).
            if echoed == internal_port {
                Ok(())
            } else {
                Err(PortForwardError::UnexpectedReply)
            }
        }
        Response::Map { result_code, .. } => Err(PortForwardError::Gateway(result_code)),
        _ => Err(PortForwardError::UnexpectedReply),
    }
}

/// Keeps `spec` mapped: maps once, calls `on_update` with each grant, then renews
/// at half the granted lifetime, until `shutdown` resolves. On shutdown it makes
/// a best-effort delete so the exit reclaims the port promptly.
///
/// # Errors
///
/// Propagates the first [`map`] failure (the gateway went away or refused).
pub async fn run_refresh<F, U, S>(
    mut flow: F,
    gateway: Ipv4Addr,
    spec: MapSpec,
    mut on_update: U,
    shutdown: S,
) -> Result<(), PortForwardError>
where
    F: UdpFlow,
    U: FnMut(PortMapping) + Send,
    S: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown);
    loop {
        let mapping = map(&mut flow, gateway, spec).await?;
        on_update(mapping);
        tokio::select! {
            // Prefer shutdown if both are ready, so teardown is not skipped.
            biased;
            () = &mut shutdown => {
                let _ = delete(&mut flow, gateway, spec.proto, spec.internal_port).await;
                return Ok(());
            }
            () = tokio::time::sleep(refresh_after(mapping.lifetime_secs)) => {}
        }
    }
}

/// Relays one accepted inbound tunnel `stream` to a local TCP `target` (the
/// app's server), copying in both directions until either side closes. The
/// `target` is a host address reached with the OS stack, not the tunnel: it is
/// the local listener a forwarded port maps to.
pub async fn relay_to_local(mut stream: NetstackStream, target: SocketAddr) {
    if let Ok(mut local) = TcpStream::connect(target).await {
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut local).await;
    }
}

/// Maximum concurrent inbound relays, so an exit-forwarded connection burst
/// cannot fan out into unbounded host connects and tasks. At the cap, accepting
/// pauses, which lets the engine's bounded accept queue shed the excess.
const MAX_INBOUND_RELAYS: usize = 128;

/// Accepts inbound connections on `listener` (a tunnel-side forwarded port) and
/// relays each to the local `target`, one task per connection up to
/// [`MAX_INBOUND_RELAYS`] in flight. Returns when the listener ends (the engine
/// stopped).
pub async fn serve_inbound(mut listener: NetstackListener, target: SocketAddr) {
    let limit = Arc::new(Semaphore::new(MAX_INBOUND_RELAYS));
    while let Some(stream) = listener.accept().await {
        // Block accepting once the cap is reached: backpressure, not unbounded
        // fan-out. `acquire_owned` only errors on a closed semaphore (never here).
        let Ok(permit) = Arc::clone(&limit).acquire_owned().await else {
            break;
        };
        tokio::spawn(async move {
            let _permit = permit;
            relay_to_local(stream, target).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use natpmp::{NATPMP_VERSION, RESPONSE_BIT};

    const GW: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    fn server() -> SocketAddr {
        SocketAddr::from((GW, NATPMP_PORT))
    }

    /// How the scripted gateway answers each request.
    #[derive(Clone)]
    enum Behavior {
        /// Grant the requested mapping with this external port.
        Grant(u16),
        /// Answer a Map with this non-success result code.
        Reject(ResultCode),
        /// Answer an `ExternalAddress` request with this public IP.
        ExternalIp(Ipv4Addr),
        /// Never answer (drives the retransmit/timeout path).
        Silent,
        /// Answer correctly but from a spoofed source (must be ignored).
        WrongSource(u16),
        /// Grant, but echo the wrong internal port (the caller must reject it).
        GrantWrongInternal(u16),
        /// Reply with a malformed frame from the gateway (must be ignored).
        Garbage,
        /// The flow has ended: `recv_from` yields `None`.
        Closed,
    }

    /// A NAT-PMP gateway behind the [`UdpFlow`] seam. `send_to` parses the client
    /// request and enqueues the scripted reply; `recv_from` delivers it (or pends
    /// forever when silent, so the client's timeout fires).
    struct FakeGateway {
        behavior: Behavior,
        inbox: Arc<Mutex<VecDeque<(Bytes, SocketAddr)>>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl FakeGateway {
        fn new(behavior: Behavior) -> Self {
            Self {
                behavior,
                inbox: Arc::new(Mutex::new(VecDeque::new())),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    /// Builds a Map response frame echoing `internal`, granting `external` for
    /// `lifetime`, with `result` and `opcode` (1 = UDP, 2 = TCP).
    fn map_response(
        opcode: u8,
        result: u16,
        internal: u16,
        external: u16,
        lifetime: u32,
    ) -> Vec<u8> {
        let mut b = vec![NATPMP_VERSION, opcode | RESPONSE_BIT];
        b.extend_from_slice(&result.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // epoch
        b.extend_from_slice(&internal.to_be_bytes());
        b.extend_from_slice(&external.to_be_bytes());
        b.extend_from_slice(&lifetime.to_be_bytes());
        b
    }

    fn external_address_response(ip: Ipv4Addr) -> Vec<u8> {
        let mut b = vec![NATPMP_VERSION, RESPONSE_BIT]; // opcode 0 | response bit
        b.extend_from_slice(&0u16.to_be_bytes()); // result success
        b.extend_from_slice(&0u32.to_be_bytes()); // epoch
        b.extend_from_slice(&ip.octets());
        b
    }

    impl UdpFlow for FakeGateway {
        async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
            assert_eq!(
                dst,
                server(),
                "client must address the gateway nat-pmp port"
            );
            self.requests.lock().unwrap().push(data.to_vec());

            // Parse the request enough to echo the right fields.
            let opcode = data[1];
            let reply = match self.behavior.clone() {
                Behavior::Grant(ext) => {
                    let internal = u16::from_be_bytes([data[4], data[5]]);
                    let lifetime = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                    // A delete (lifetime 0) is acknowledged with external 0.
                    let granted = if lifetime == 0 { 0 } else { ext };
                    Some((
                        map_response(opcode, 0, internal, granted, lifetime),
                        server(),
                    ))
                }
                Behavior::Reject(code) => {
                    let internal = u16::from_be_bytes([data[4], data[5]]);
                    let raw = result_raw(code);
                    Some((map_response(opcode, raw, internal, 0, 0), server()))
                }
                Behavior::ExternalIp(ip) => Some((external_address_response(ip), server())),
                Behavior::Silent | Behavior::Closed => None,
                Behavior::WrongSource(ext) => {
                    let internal = u16::from_be_bytes([data[4], data[5]]);
                    let spoof = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), NATPMP_PORT));
                    Some((map_response(opcode, 0, internal, ext, 3600), spoof))
                }
                Behavior::GrantWrongInternal(ext) => {
                    let internal = u16::from_be_bytes([data[4], data[5]]);
                    let lifetime = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                    // Echo a different internal port than requested.
                    Some((
                        map_response(opcode, 0, internal.wrapping_add(1), ext, lifetime),
                        server(),
                    ))
                }
                Behavior::Garbage => {
                    // A non-zero version byte makes the parser reject the frame.
                    Some((vec![0xFF, 0xFF, 0x00, 0x00], server()))
                }
            };
            if let Some((bytes, src)) = reply {
                self.inbox
                    .lock()
                    .unwrap()
                    .push_back((Bytes::from(bytes), src));
            }
            Ok(())
        }

        async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
            loop {
                if let Some(item) = self.inbox.lock().unwrap().pop_front() {
                    return Some(item);
                }
                if matches!(self.behavior, Behavior::Closed) {
                    return None; // the flow has ended
                }
                // No reply scripted: pend so the caller's timeout drives retransmit.
                std::future::pending::<()>().await;
            }
        }
    }

    fn result_raw(code: ResultCode) -> u16 {
        match code {
            ResultCode::Success => 0,
            ResultCode::UnsupportedVersion => 1,
            ResultCode::NotAuthorized => 2,
            ResultCode::NetworkFailure => 3,
            ResultCode::OutOfResources => 4,
            ResultCode::UnsupportedOpcode => 5,
            ResultCode::SuggestedPortUnavailable => 6,
            ResultCode::RateLimited => 7,
            _ => 3,
        }
    }

    fn spec() -> MapSpec {
        MapSpec {
            proto: MapProto::Tcp,
            internal_port: 8080,
            suggested_external_port: 0,
            lifetime_secs: 3600,
        }
    }

    #[tokio::test]
    async fn map_returns_the_granted_external_port() {
        let mut gw = FakeGateway::new(Behavior::Grant(40001));
        let mapping = map(&mut gw, GW, spec()).await.expect("mapping granted");
        assert_eq!(mapping.proto, MapProto::Tcp);
        assert_eq!(mapping.internal_port, 8080);
        assert_eq!(mapping.external_port, 40001);
        assert_eq!(mapping.lifetime_secs, 3600);
    }

    #[tokio::test]
    async fn map_surfaces_a_gateway_rejection() {
        let mut gw = FakeGateway::new(Behavior::Reject(ResultCode::OutOfResources));
        let err = map(&mut gw, GW, spec()).await.unwrap_err();
        assert!(matches!(
            err,
            PortForwardError::Gateway(ResultCode::OutOfResources)
        ));
    }

    #[tokio::test]
    async fn external_address_returns_the_public_ip() {
        let mut gw = FakeGateway::new(Behavior::ExternalIp(Ipv4Addr::new(198, 51, 100, 7)));
        let ip = external_address(&mut gw, GW).await.expect("got address");
        assert_eq!(ip, Ipv4Addr::new(198, 51, 100, 7));
    }

    #[tokio::test(start_paused = true)]
    async fn silent_gateway_times_out_after_retransmissions() {
        let mut gw = FakeGateway::new(Behavior::Silent);
        let requests = Arc::clone(&gw.requests);
        let err = map(&mut gw, GW, spec()).await.unwrap_err();
        assert!(matches!(err, PortForwardError::Timeout));
        // RFC 6886 budget: it retransmitted MAX_ATTEMPTS times before giving up.
        assert_eq!(requests.lock().unwrap().len(), MAX_ATTEMPTS as usize);
    }

    #[tokio::test(start_paused = true)]
    async fn a_spoofed_source_reply_is_ignored() {
        // The gateway replies with a valid frame but from the wrong source; the
        // client must reject it and ultimately time out rather than trust it. The
        // budget assertion proves the spoofed reply was actively ignored (the
        // request kept being retransmitted), not merely never delivered: if the
        // source guard were removed, the forged grant would return Ok instead.
        let mut gw = FakeGateway::new(Behavior::WrongSource(40002));
        let requests = Arc::clone(&gw.requests);
        let err = map(&mut gw, GW, spec()).await.unwrap_err();
        assert!(matches!(err, PortForwardError::Timeout));
        assert_eq!(requests.lock().unwrap().len(), MAX_ATTEMPTS as usize);
    }

    #[tokio::test(start_paused = true)]
    async fn a_malformed_reply_does_not_abort_the_budget() {
        // A garbage frame from the gateway endpoint must be ignored, not abort the
        // exchange; the client retransmits the full budget and then times out.
        let mut gw = FakeGateway::new(Behavior::Garbage);
        let requests = Arc::clone(&gw.requests);
        let err = map(&mut gw, GW, spec()).await.unwrap_err();
        assert!(matches!(err, PortForwardError::Timeout));
        assert_eq!(requests.lock().unwrap().len(), MAX_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn a_grant_for_the_wrong_internal_port_is_rejected() {
        // The gateway must echo the internal port it mapped; a different one means
        // the reply is for another allocation and must not be trusted.
        let mut gw = FakeGateway::new(Behavior::GrantWrongInternal(40004));
        let err = map(&mut gw, GW, spec()).await.unwrap_err();
        assert!(matches!(err, PortForwardError::UnexpectedReply));
    }

    #[tokio::test]
    async fn a_closed_flow_surfaces_a_transport_error() {
        let mut gw = FakeGateway::new(Behavior::Closed);
        let err = map(&mut gw, GW, spec()).await.unwrap_err();
        assert!(matches!(err, PortForwardError::Transport(_)));
    }

    #[test]
    fn refresh_after_is_half_the_lifetime_and_never_zero() {
        assert_eq!(refresh_after(3600), Duration::from_secs(1800));
        assert_eq!(refresh_after(0), Duration::from_secs(1));
        assert_eq!(refresh_after(1), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn run_refresh_renews_then_deletes_on_shutdown() {
        // Lifetime 4s -> renew every 2s. Hold for ~5s of virtual time, then
        // shut down and confirm a delete (lifetime 0) was issued.
        let gw = FakeGateway::new(Behavior::Grant(40003));
        let requests = Arc::clone(&gw.requests);
        let updates = Arc::new(AtomicUsize::new(0));
        let updates_seen = Arc::clone(&updates);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        let spec = MapSpec {
            lifetime_secs: 4,
            ..spec()
        };
        let task = tokio::spawn(async move {
            run_refresh(
                gw,
                GW,
                spec,
                move |m| {
                    assert_eq!(m.external_port, 40003);
                    updates_seen.fetch_add(1, Ordering::SeqCst);
                },
                async move {
                    let _ = rx.await;
                },
            )
            .await
        });

        tokio::time::sleep(Duration::from_secs(5)).await;
        tx.send(()).expect("signal shutdown");
        let result = task.await.expect("task joins");
        assert!(result.is_ok(), "refresh loop ended cleanly");

        // Initial map at t=0 plus renewals at t=2 and t=4: at least 3 grants.
        assert!(
            updates.load(Ordering::SeqCst) >= 3,
            "expected periodic renewals, saw {}",
            updates.load(Ordering::SeqCst)
        );
        // The final request must be a delete: a Map with lifetime 0.
        let reqs = requests.lock().unwrap();
        let last = reqs.last().expect("at least one request");
        let lifetime = u32::from_be_bytes([last[8], last[9], last[10], last[11]]);
        assert_eq!(lifetime, 0, "shutdown issued a delete (lifetime 0)");
    }
}
