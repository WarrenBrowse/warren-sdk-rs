//! The UDP seam the gateway's peer-facing plane rides.
//!
//! One socket per configured bind: a wildcard socket answers a peer from a
//! source address the routing table picks, which a peer's `Endpoint` may not
//! match. The trait exists so the device is driven end to end in tests without
//! a real socket, including the cases a real socket makes hard to produce (a
//! send that never completes, a peer whose datagram is refused).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

/// A boxed, `Send` future: the seam is held behind a vtable, so a device can
/// carry several sockets of different concrete types.
pub type BoxIoFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One bound UDP socket.
pub trait DatagramSocket: Send + Sync + 'static {
    /// Sends one datagram.
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxIoFuture<'a, io::Result<usize>>;

    /// Awaits the next datagram, returning its length and its source.
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxIoFuture<'a, io::Result<(usize, SocketAddr)>>;

    /// The address this socket is bound to.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports for a socket that is no longer usable.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl DatagramSocket for tokio::net::UdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxIoFuture<'a, io::Result<usize>> {
        Box::pin(tokio::net::UdpSocket::send_to(self, buf, target))
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxIoFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(tokio::net::UdpSocket::recv_from(self, buf))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }
}

/// Binds one UDP socket per address.
///
/// # Errors
///
/// The first bind that fails, named by its address so an operator can tell
/// which entry of the list is at fault.
pub async fn bind_all(addrs: &[SocketAddr]) -> io::Result<Vec<std::sync::Arc<dyn DatagramSocket>>> {
    let mut sockets: Vec<std::sync::Arc<dyn DatagramSocket>> = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let socket = tokio::net::UdpSocket::bind(addr).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("binding the peer listener on {addr}: {e}"),
            )
        })?;
        sockets.push(std::sync::Arc::new(socket));
    }
    Ok(sockets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_bound_socket_round_trips_a_datagram() {
        let sockets = bind_all(&["127.0.0.1:0".parse().unwrap()])
            .await
            .expect("loopback binds");
        let server = &sockets[0];
        let addr = server.local_addr().expect("a bound address");

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        DatagramSocket::send_to(&client, b"hello", addr)
            .await
            .expect("the datagram leaves");

        let mut buf = [0u8; 64];
        let (n, src) = server.recv_from(&mut buf).await.expect("it arrives");
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(src, from, "the source is what the gateway answers to");
    }

    #[tokio::test]
    async fn a_bind_that_fails_names_the_address_at_fault() {
        let first = bind_all(&["127.0.0.1:0".parse().unwrap()]).await.unwrap();
        let taken = first[0].local_addr().unwrap();
        let Err(err) = bind_all(&["127.0.0.1:0".parse().unwrap(), taken]).await else {
            panic!("the second bind is already taken");
        };
        assert!(
            err.to_string().contains(&taken.to_string()),
            "the operator needs to know which entry failed: {err}"
        );
    }
}
