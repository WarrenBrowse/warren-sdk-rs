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
//! the leak-level model ([`KillSwitchLevel`]), and [`ConnectMode`] selection.
//! The per-OS TUN devices, routing/DNS plumbing and OS firewall killswitch are
//! feature-gated work tracked in the roadmap.

#[cfg(feature = "proxy")]
pub mod dns;
pub mod error;
pub mod killswitch;
pub mod mode;
#[cfg(feature = "proxy")]
pub mod netstack;
#[cfg(feature = "proxy")]
pub mod proxy;
pub mod sink;
pub mod socks5;

#[cfg(feature = "proxy")]
pub use dns::{DnsError, encode_query, parse_response};
pub use error::NetError;
pub use killswitch::{KillSwitch, KillSwitchLevel, ProxyOnlyKillSwitch};
pub use mode::{ConnectMode, ProxyConfig, TunConfig};
#[cfg(feature = "proxy")]
pub use netstack::{
    NetstackStream, NetstackUdpSocket, TunnelConnector, spawn_engine, spawn_over_sink,
};
#[cfg(feature = "proxy")]
pub use proxy::{Connector, DirectConnector, HttpConnectProxy, Socks5Proxy};
pub use sink::{MultihopPacketSink, PacketSink, QuicPacketSink};
