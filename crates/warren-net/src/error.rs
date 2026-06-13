//! Networking error type.

/// Errors from the networking layer.
///
/// Underlying causes are attached via [`std::error::Error::source`], keeping the
/// top-level `Display` free of address or peer detail (no-log discipline).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// The tunnel packet plane failed (send/recv datagram).
    #[error("tunnel error")]
    Tunnel(#[from] warren_transport::TunnelError),
    /// A local I/O error (proxy listener, TUN device).
    #[error("io error")]
    Io(#[source] std::io::Error),
    /// A SOCKS5 protocol error on the proxy inbound.
    #[error("socks5 error")]
    Socks5(#[from] crate::socks5::Socks5Error),
    /// The exit refused the connection (RST during handshake).
    #[error("connection refused by the exit")]
    ConnectionRefused,
    /// The connection handshake did not complete in time.
    #[error("connect timed out")]
    ConnectTimeout,
    /// The userspace stack could not initiate the connection.
    #[error("netstack connect failed")]
    ConnectFailed,
    /// The netstack engine task has stopped (tunnel gone).
    #[error("netstack engine stopped")]
    EngineStopped,
    /// The requested backend or feature is not available on this build/OS.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}
