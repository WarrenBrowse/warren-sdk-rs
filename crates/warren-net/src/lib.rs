//! Warren networking backends.
//!
//! Two datapaths sit behind one packet-plane seam ([`PacketSink`]) and share the
//! QUIC core in `warren-transport`:
//!
//! 1. **Proxy (default, non-root).** A local SOCKS5 listener ([`Socks5Proxy`])
//!    terminates application TCP flows; a userspace netstack ([`netstack`],
//!    smoltcp) synthesizes inner IP packets and drives them through a
//!    [`PacketSink`] over the tunnel. Feature-complete on Linux, macOS and
//!    Windows with no elevated privileges, and validated end to end in-process.
//!    An optional HTTP CONNECT listener ([`HttpConnectProxy`]) is supported, and
//!    domain targets are resolved over the tunnel via the gateway DNS forwarder
//!    ([`dns`]), so lookups never leak to the host resolver.
//! 2. **TUN (optional, privileged).** A real TUN device feeds inner IP packets
//!    straight into a [`PacketSink`], with split-default routing, DNS push and an
//!    OS-enforced [`killswitch`]. Built per OS behind the `tun` feature. Per the
//!    datapath research: a non-root TUN mode is only possible on Linux
//!    (`CAP_NET_ADMIN` or a pre-owned device); macOS and Windows require
//!    privilege, which is exactly why the proxy datapath is the default.
//!
//! What is implemented and tested today: the [`PacketSink`] seam and its QUIC
//! implementation ([`QuicPacketSink`]), the SOCKS5 codec and proxy server, the
//! smoltcp userspace netstack and its tunnel connector ([`TunnelConnector`]),
//! the leak-level model ([`KillSwitchLevel`]), and the proxy datapath config
//! ([`ProxyConfig`]). The per-OS TUN devices, routing/DNS plumbing and OS
//! firewall killswitch are feature-gated work tracked in the roadmap (the TUN
//! datapath config lives in the `warren-tun` crate).

#[cfg(feature = "proxy")]
pub mod dns;
pub mod error;
pub mod killswitch;
pub mod mode;
#[cfg(feature = "proxy")]
pub mod netstack;
#[cfg(feature = "proxy")]
pub mod portforward;
#[cfg(feature = "proxy")]
pub mod proxy;
pub mod sink;
pub mod socks5;
pub mod tun_sink;

#[cfg(feature = "proxy")]
pub use dns::{DnsError, RecordType, encode_query, parse_response};
pub use error::NetError;
pub use killswitch::{KillSwitch, KillSwitchLevel, ProxyOnlyKillSwitch};
pub use mode::ProxyConfig;
#[cfg(feature = "proxy")]
pub use netstack::{
    Ipv6Addressing, NetstackConfig, NetstackListener, NetstackStream, NetstackUdpSocket,
    TunnelConnector, spawn_engine, spawn_over_sink,
};
#[cfg(feature = "proxy")]
pub use portforward::{
    ForwardedPort, MapSpec, PortForwardError, PortMapping, forward_port,
    forward_port_with_suggested, relay_to_local, run_refresh, serve_inbound,
};
#[cfg(feature = "proxy")]
pub use proxy::{Connector, DirectConnector, HttpConnectProxy, Socks5Proxy, UdpConnector, UdpFlow};
pub use sink::{BondedPacketSink, MultihopPacketSink, PacketSink, QuicPacketSink};
pub use tun_sink::{TunBridge, TunPacketSink, forward_bidirectional, tun_channels};
/// The NAT-PMP mapping protocol selector (TCP or UDP), re-exported from the wire
/// codec so callers can name it without depending on `warren-wire` directly.
pub use warren_wire::natpmp::MapProto;
