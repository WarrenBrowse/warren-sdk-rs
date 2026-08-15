//! The UDP-open seam, and its type-erased form.
//!
//! Two datapaths open UDP flows for the same in-tunnel control traffic (the
//! NAT-PMP client and the egress probe): the userspace netstack, which opens
//! them on its own stack, and a raw-IP device, which builds packets itself.
//! [`UdpOpener`] is what they share, so the control-plane code is written once
//! and instantiated on either.
//!
//! [`DynUdpOpener`] is the same capability behind a vtable, so a public handle
//! that hands out port forwards stays non-generic (the FFI layer and the app
//! hold one handle type whatever the datapath under it).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use bytes::Bytes;

use crate::error::NetError;
use crate::proxy::{UdpConnector, UdpFlow};

/// A boxed, `Send` future, the erased form of the seam's `async fn`s.
pub type BoxUdpFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Opens UDP flows that egress at the exit.
///
/// The netstack connector qualifies through the blanket impl below, so the
/// production datapath instantiates this without any wrapper.
pub trait UdpOpener: Send + Sync + 'static {
    /// The flow type this opener produces.
    type Flow: UdpFlow;

    /// Opens one UDP flow (an ephemeral source port on the tunnel side).
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] when the datapath behind it is gone.
    fn open_udp(&self) -> impl Future<Output = Result<Self::Flow, NetError>> + Send;
}

/// Every UDP-capable connector is an opener: the netstack connector qualifies
/// unchanged, so the control-plane code above this seam is the same object on
/// the proxy datapath as on a raw one.
impl<T: UdpConnector> UdpOpener for T {
    type Flow = <T as UdpConnector>::Flow;

    fn open_udp(&self) -> impl Future<Output = Result<Self::Flow, NetError>> + Send {
        UdpConnector::open_udp(self)
    }
}

/// A [`UdpFlow`] behind a vtable, so [`BoxUdpFlow`] can carry any of them.
pub trait DynUdpFlow: Send {
    /// Erased [`UdpFlow::send_to`].
    fn send_to_boxed(&self, data: Bytes, dst: SocketAddr)
    -> BoxUdpFuture<'_, Result<(), NetError>>;

    /// Erased [`UdpFlow::recv_from`].
    fn recv_from_boxed(&mut self) -> BoxUdpFuture<'_, Option<(Bytes, SocketAddr)>>;
}

impl<F: UdpFlow> DynUdpFlow for F {
    fn send_to_boxed(
        &self,
        data: Bytes,
        dst: SocketAddr,
    ) -> BoxUdpFuture<'_, Result<(), NetError>> {
        Box::pin(UdpFlow::send_to(self, data, dst))
    }

    fn recv_from_boxed(&mut self) -> BoxUdpFuture<'_, Option<(Bytes, SocketAddr)>> {
        Box::pin(UdpFlow::recv_from(self))
    }
}

/// A [`UdpFlow`] of unknown concrete type, produced by [`DynUdpOpener`].
pub struct BoxUdpFlow(Box<dyn DynUdpFlow>);

impl BoxUdpFlow {
    /// Erases `flow`.
    #[must_use]
    pub fn new<F: UdpFlow>(flow: F) -> Self {
        Self(Box::new(flow))
    }
}

impl UdpFlow for BoxUdpFlow {
    fn send_to(
        &self,
        data: Bytes,
        dst: SocketAddr,
    ) -> impl Future<Output = Result<(), NetError>> + Send {
        self.0.send_to_boxed(data, dst)
    }

    fn recv_from(&mut self) -> impl Future<Output = Option<(Bytes, SocketAddr)>> + Send {
        self.0.recv_from_boxed()
    }
}

/// A [`UdpOpener`] behind a vtable.
///
/// The generic seam cannot cross a public handle without infecting it with the
/// datapath's type; this can, and a supervised handle stays one type across
/// every datapath.
pub trait DynUdpOpener: Send + Sync {
    /// Erased [`UdpOpener::open_udp`].
    ///
    /// # Errors
    ///
    /// [`NetError::EngineStopped`] when the datapath behind it is gone.
    fn open_udp_boxed(&self) -> BoxUdpFuture<'_, Result<BoxUdpFlow, NetError>>;
}

impl<T: UdpOpener> DynUdpOpener for T {
    fn open_udp_boxed(&self) -> BoxUdpFuture<'_, Result<BoxUdpFlow, NetError>> {
        Box::pin(async move { self.open_udp().await.map(BoxUdpFlow::new) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use tokio::sync::Mutex;
    use tokio::sync::mpsc;

    use crate::proxy::Connector;
    use crate::socks5::Target;

    /// A flow that answers every datagram back to its sender, so a round trip
    /// through the seam is observable.
    struct EchoFlow {
        inbox: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
        replies: mpsc::UnboundedReceiver<(Bytes, SocketAddr)>,
    }

    impl EchoFlow {
        fn new() -> Self {
            let (inbox, replies) = mpsc::unbounded_channel();
            Self { inbox, replies }
        }
    }

    impl UdpFlow for EchoFlow {
        async fn send_to(&self, data: Bytes, dst: SocketAddr) -> Result<(), NetError> {
            self.inbox
                .send((data, dst))
                .map_err(|_| NetError::EngineStopped)
        }

        async fn recv_from(&mut self) -> Option<(Bytes, SocketAddr)> {
            self.replies.recv().await
        }
    }

    /// An opener that hands out [`EchoFlow`]s and counts how many it opened.
    struct EchoOpener(Arc<Mutex<usize>>);

    impl UdpOpener for EchoOpener {
        type Flow = EchoFlow;

        async fn open_udp(&self) -> Result<EchoFlow, NetError> {
            *self.0.lock().await += 1;
            Ok(EchoFlow::new())
        }
    }

    /// A UDP-capable connector, so the blanket impl is exercised on the shape
    /// the netstack connector actually has.
    struct FakeConnector;

    impl Connector for FakeConnector {
        type Stream = tokio::io::DuplexStream;

        async fn connect(&self, _target: Target) -> Result<Self::Stream, NetError> {
            Err(NetError::ConnectFailed)
        }
    }

    impl UdpConnector for FakeConnector {
        type Flow = EchoFlow;

        async fn open_udp(&self) -> Result<EchoFlow, NetError> {
            Ok(EchoFlow::new())
        }

        async fn resolve_host(&self, _host: &str) -> Result<std::net::IpAddr, NetError> {
            Err(NetError::NoDnsRecord)
        }

        fn supports_ipv6(&self) -> bool {
            false
        }
    }

    /// The control-plane shape: written once over the seam, run on any opener.
    async fn round_trip<O: UdpOpener>(opener: &O) -> Option<(Bytes, SocketAddr)> {
        let mut flow = opener
            .open_udp()
            .await
            .expect("the opener hands out a flow");
        let dst: SocketAddr = "10.66.0.1:5351".parse().expect("gateway");
        flow.send_to(Bytes::from_static(b"ping"), dst)
            .await
            .expect("send");
        flow.recv_from().await
    }

    #[tokio::test]
    async fn a_udp_connector_is_an_opener_without_a_wrapper() {
        // The blanket impl is what keeps the netstack connector usable by the
        // control plane after it moved onto the opener seam.
        let got = round_trip(&FakeConnector)
            .await
            .expect("the echo came back");
        assert_eq!(got.0, Bytes::from_static(b"ping"));
        assert_eq!(got.1.port(), 5351, "the datagram kept its destination");
    }

    #[tokio::test]
    async fn an_erased_opener_still_round_trips() {
        // The public handle holds `Arc<dyn DynUdpOpener>`: erasing must not
        // cost the flow's behaviour.
        let opened = Arc::new(Mutex::new(0));
        let erased: Arc<dyn DynUdpOpener> = Arc::new(EchoOpener(Arc::clone(&opened)));
        let mut flow = erased.open_udp_boxed().await.expect("erased open");
        let dst: SocketAddr = "10.66.0.1:53".parse().expect("resolver");
        flow.send_to(Bytes::from_static(b"query"), dst)
            .await
            .expect("send through the erased flow");
        let got = flow.recv_from().await.expect("the echo came back");
        assert_eq!(got.0, Bytes::from_static(b"query"));
        assert_eq!(
            *opened.lock().await,
            1,
            "the erased call reached the opener"
        );
    }
}
