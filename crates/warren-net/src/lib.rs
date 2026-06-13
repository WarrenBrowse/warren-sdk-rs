//! Warren networking backends.
//!
//! Two datapaths sit behind one packet-plane seam ([`PacketSink`]) and share the
//! QUIC core in `warren-transport`:
//!
//! 1. **Proxy (default, non-root).** A local SOCKS5 (and optional HTTP CONNECT)
//!    listener terminates application L4 flows and forwards them over the tunnel.
//!    Feature-complete on Linux, macOS and Windows with no elevated privileges.
//!    The [`socks5`] codec is implemented and tested here. A userspace netstack
//!    then synthesizes inner IP packets from those flows and drives them through
//!    a [`PacketSink`]; that bridge is the next integration step.
//! 2. **TUN (optional, privileged).** A real TUN device feeds inner IP packets
//!    straight into a [`PacketSink`], with split-default routing, DNS push and an
//!    OS-enforced [`killswitch`]. Built per OS behind the `tun` feature. Per the
//!    datapath research: a non-root TUN mode is only possible on Linux
//!    (`CAP_NET_ADMIN` or a pre-owned device); macOS and Windows require
//!    privilege, which is exactly why the proxy datapath is the default.
//!
//! What is implemented and tested today: the [`PacketSink`] seam and its QUIC
//! implementation ([`QuicPacketSink`]), the SOCKS5 wire codec, the leak-level
//! model ([`KillSwitchLevel`]), and the [`ConnectMode`] selection. The per-OS
//! TUN devices, routing/DNS plumbing, OS firewall killswitch, and the
//! smoltcp-based proxy-to-packet bridge are feature-gated work tracked in the
//! roadmap.

pub mod error;
pub mod killswitch;
pub mod mode;
#[cfg(feature = "proxy")]
pub mod proxy;
pub mod sink;
pub mod socks5;

pub use error::NetError;
pub use killswitch::{KillSwitch, KillSwitchLevel, ProxyOnlyKillSwitch};
pub use mode::{ConnectMode, ProxyConfig, TunConfig};
#[cfg(feature = "proxy")]
pub use proxy::{Connector, DirectConnector, Socks5Proxy};
pub use sink::{PacketSink, QuicPacketSink};
