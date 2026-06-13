//! Warren networking backends (Phase P6, not yet implemented).
//!
//! Two backends sit behind one `PacketSink` seam and share the QUIC core in
//! [`warren_transport`]:
//!
//! 1. `netstack` (default, non-root, feature-complete on Linux, macOS, Windows):
//!    a userspace TCP/IP stack (smoltcp) that terminates application flows and
//!    forwards them as QUIC datagrams, exposed through a local SOCKS5 plus HTTP
//!    CONNECT proxy. No elevated privileges required on any OS.
//! 2. `tun` (optional, privileged): a real TUN device (Linux `/dev/net/tun`,
//!    macOS utun, Windows Wintun) with split-default routing, DNS push and a
//!    killswitch (nft / pf / WFP). Captures all OS traffic transparently.
//!
//! The mode is chosen at runtime (`ConnectMode::Proxy` vs `ConnectMode::Tun`),
//! defaulting to `Proxy`. Per-OS code is `cfg`-gated but pure logic compiles
//! everywhere so it stays unit-testable without privileges.

#[cfg(test)]
mod roadmap {
    #[test]
    #[ignore = "P6: implement non-root netstack proxy backend, then privileged TUN backend"]
    fn placeholder() {}
}
