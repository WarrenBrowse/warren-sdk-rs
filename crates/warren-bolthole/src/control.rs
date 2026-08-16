//! The gateway's own in-tunnel control plane.
//!
//! The gateway carries whole IP packets, so it has no stack to open a socket
//! on: its NAT-PMP client and its egress probe build their own datagrams and
//! pick their answers out of the downlink. [`GatewayControl`] is the
//! [`UdpOpener`] over that plane, sourced at the address the exit assigned to
//! the epoch, on ports the NAT never hands to a peer flow.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use warren_bolthole_core::{CONTROL_RANGE_END, CONTROL_RANGE_START};
use warren_sdk::net::{NetError, RawUdpDemux, RawUdpFlow, UdpOpener};

/// One epoch's control plane.
///
/// Cloneable because the supervisor keeps one copy for the port forwarder and
/// one for the egress probe; both die with the epoch, because closing it clears
/// the demux and refuses any later flow.
#[derive(Clone)]
pub struct GatewayControl {
    demux: Arc<RawUdpDemux>,
    /// The address the exit assigned: the only source the exit accepts.
    local: Ipv4Addr,
    /// The exit-side gateway, the only host allowed to answer a control flow.
    gateway: Ipv4Addr,
    next_port: Arc<AtomicU32>,
    alive: Arc<AtomicBool>,
}

impl std::fmt::Debug for GatewayControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The assigned address identifies this client at the exit.
        f.debug_struct("GatewayControl")
            .field("alive", &self.alive.load(Ordering::Relaxed))
            .finish()
    }
}

impl GatewayControl {
    /// Builds the control plane of one epoch over its demux.
    #[must_use]
    pub fn new(demux: Arc<RawUdpDemux>, local: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        Self {
            demux,
            local,
            gateway,
            next_port: Arc::new(AtomicU32::new(u32::from(CONTROL_RANGE_START))),
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Ends the epoch's control plane: every open flow reports the epoch dead,
    /// and no new one is handed out.
    pub fn close(&self) {
        self.alive.store(false, Ordering::Relaxed);
        self.demux.close_all();
    }

    /// Whether this control plane still belongs to a live epoch.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// The next source port, cycling through the reserved control range. The
    /// range is held out of the NAT's dynamic pool, so a control flow can never
    /// collide with a peer's.
    fn take_port(&self) -> u16 {
        let span = u32::from(CONTROL_RANGE_END - CONTROL_RANGE_START) + 1;
        let raw = self.next_port.fetch_add(1, Ordering::Relaxed);
        let offset = (raw - u32::from(CONTROL_RANGE_START)) % span;
        CONTROL_RANGE_START + u16::try_from(offset).unwrap_or(0)
    }
}

impl UdpOpener for GatewayControl {
    type Flow = RawUdpFlow;

    async fn open_udp(&self) -> Result<RawUdpFlow, NetError> {
        if !self.is_alive() {
            return Err(NetError::EngineStopped);
        }
        let local = SocketAddr::new(self.local.into(), self.take_port());
        // Pinned to the exit's own address rather than to one of its ports: the
        // same opener serves the NAT-PMP client (5351) and the egress probe
        // (53), and what the pin is about is that no other client of that exit
        // can answer for it.
        Ok(self.demux.register_from_host(local, self.gateway.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use warren_sdk::net::{UdpFlow, build_udp_packet};

    const ASSIGNED: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    fn control() -> (GatewayControl, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let demux = Arc::new(RawUdpDemux::new(tx));
        (GatewayControl::new(demux, ASSIGNED, GATEWAY), rx)
    }

    /// The exit refuses any inner packet whose source is not the address it
    /// assigned, so a control datagram sourced anywhere else is dead on
    /// arrival and invisible from here.
    #[tokio::test]
    async fn a_control_flow_is_sourced_at_the_assigned_address_on_a_reserved_port() {
        let (control, mut uplink) = control();
        let flow = control.open_udp().await.expect("a live epoch opens flows");
        let local = flow.local_addr();
        assert_eq!(local.ip(), ASSIGNED);
        assert!((CONTROL_RANGE_START..=CONTROL_RANGE_END).contains(&local.port()));

        flow.send_to(
            Bytes::from_static(b"map"),
            SocketAddr::new(GATEWAY.into(), 5351),
        )
        .await
        .expect("the uplink takes it");
        let packet = uplink.recv().await.expect("a packet reaches the uplink");
        assert_eq!(&packet[12..16], &ASSIGNED.octets(), "source address");
        assert_eq!(&packet[16..20], &GATEWAY.octets(), "destination address");
    }

    #[tokio::test]
    async fn two_flows_never_share_a_source_port() {
        let (control, _uplink) = control();
        let first = control.open_udp().await.unwrap();
        let second = control.open_udp().await.unwrap();
        assert_ne!(first.local_addr().port(), second.local_addr().port());
    }

    /// The port forwarder and the egress probe both read a closed flow as
    /// "this epoch is over"; a flow opened after the epoch died would instead
    /// wait forever for an answer nobody can send.
    #[tokio::test]
    async fn a_closed_epoch_ends_open_flows_and_refuses_new_ones() {
        let (control, _uplink) = control();
        let mut flow = control.open_udp().await.unwrap();

        control.close();

        assert!(
            flow.recv_from().await.is_none(),
            "an open flow reports the death"
        );
        assert!(matches!(
            control.open_udp().await,
            Err(NetError::EngineStopped)
        ));
    }

    #[tokio::test]
    async fn an_answer_from_the_exit_reaches_the_flow_that_asked() {
        let (control, _uplink) = control();
        let mut flow = control.open_udp().await.unwrap();
        let local = flow.local_addr();
        let answer = build_udp_packet(SocketAddr::new(GATEWAY.into(), 5351), local, b"granted")
            .expect("an answer packet");

        assert!(control.demux.deliver(&answer), "the demux owns the port");
        let (payload, from) = flow.recv_from().await.expect("the answer arrives");
        assert_eq!(payload, Bytes::from_static(b"granted"));
        assert_eq!(from.ip(), GATEWAY);
    }
}
