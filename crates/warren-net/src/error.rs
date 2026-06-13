//! Networking error type.

/// Errors from the networking layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// The tunnel packet plane failed (send/recv datagram).
    #[error("tunnel error: {0}")]
    Tunnel(String),
    /// A local I/O error (proxy listener, TUN device).
    #[error("io error: {0}")]
    Io(String),
    /// A SOCKS5 protocol error on the proxy inbound.
    #[error("socks5 error: {0}")]
    Socks5(#[from] crate::socks5::Socks5Error),
    /// The requested backend or feature is not available on this build/OS.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}
