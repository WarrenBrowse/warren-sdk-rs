//! Warren QUIC transport (Phase P5, not yet implemented).
//!
//! Planned surface, ported from warren-core `warren-tunnel` + `warren-tls`:
//! - `ClientTunnel` builder (identity, Warren transport tuning, features, DAITA,
//!   local bind) producing a `ClientSession` after the Setup/SetupAck handshake.
//! - TLS 1.3 with raw public keys (RFC 7250), ALPN `h3`, 0-RTT off; peer exit
//!   pubkey extracted from the QUIC handshake.
//! - RFC 9221 datagram pump over a `PacketSink` abstraction (the seam shared by
//!   the TUN and userspace-netstack backends in [`warren_net`]).
//! - Reconnection backoff (full-jitter) and a supervisor for transparent
//!   reconnects.
//!
//! Pure protocol logic only: no OS coupling. The async runtime seam will be
//! kept narrow so the FFI layer can drive it.

#[cfg(test)]
mod roadmap {
    #[test]
    #[ignore = "P5: implement ClientTunnel handshake + datagram pump over PacketSink"]
    fn placeholder() {}
}
