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
    /// The multihop tunnel packet plane failed (seal/open/send/recv).
    ///
    /// Deliberately `#[source]`, not `#[from]` (unlike `Tunnel`): the multihop
    /// datapath maps this explicitly at its call sites so a stray `?` cannot
    /// silently absorb a multihop error into the wrong variant.
    #[error("multihop tunnel error")]
    Multihop(#[source] warren_transport::MultihopError),
    /// A local I/O error (proxy listener, TUN device).
    #[error("io error")]
    Io(#[source] std::io::Error),
    /// The privileged TUN datapath failed (the device worker stopped, or a frame
    /// could not be framed/deframed).
    #[error("tun datapath error")]
    Tun(#[source] std::io::Error),
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
    /// The resolver answered but carried no record of the requested type (for
    /// example no `AAAA` for a name that only has `A`). Distinct from a timeout
    /// or transport failure so a dual-stack lookup can fall back to `A` on this
    /// alone, not on a slow or unreachable resolver.
    #[error("no DNS record of the requested type")]
    NoDnsRecord,
    /// The requested backend or feature is not available on this build/OS.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

impl NetError {
    /// True when the failure refused ONE packet over a datapath that is still
    /// usable, so a pump drops and counts it instead of ending the epoch.
    ///
    /// The classification belongs to the transport error that carries it (a
    /// datagram refused for its size against a live session, versus a session
    /// that is gone); this only routes to it. Everything else, a closed
    /// session, a stopped engine, a device error, is fatal to the epoch, which
    /// is the asymmetry the netstack writer already applies.
    #[must_use]
    pub fn is_per_packet(&self) -> bool {
        match self {
            Self::Tunnel(e) => e.is_per_packet(),
            Self::Multihop(e) => e.is_per_packet(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_live_session_datagram_refusal_is_per_packet() {
        assert!(
            NetError::Multihop(warren_transport::MultihopError::SendDatagram(
                quinn::SendDatagramError::TooLarge
            ))
            .is_per_packet(),
            "an over-budget datagram is one packet's problem"
        );
        assert!(
            !NetError::Multihop(warren_transport::MultihopError::SendDatagram(
                quinn::SendDatagramError::ConnectionLost(quinn::ConnectionError::LocallyClosed)
            ))
            .is_per_packet(),
            "a lost session must still end the epoch"
        );
        assert!(
            NetError::Tunnel(warren_transport::TunnelError::SendDatagram(
                quinn::SendDatagramError::TooLarge
            ))
            .is_per_packet(),
            "the single-hop plane classifies the same way"
        );
        assert!(
            !NetError::EngineStopped.is_per_packet(),
            "a stopped engine is not a packet-level refusal"
        );
    }
}
