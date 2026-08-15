//! Engine-clean core of the Warren local gateway.
//!
//! The gateway lets a stock WireGuard-protocol client reach the internet
//! through a Warren exit. Two halves live here: the responder that terminates
//! the peers' protocol sessions, and the NAPT that rewrites their packets onto
//! the single address the exit assigned to the tunnel, because the exit refuses
//! any inner packet whose source is not that address.
//!
//! This crate is pure packet logic. It opens no socket, spawns no task and
//! reads no clock: the caller passes the current instant in, and the async
//! shell around it (`warren-burrow`) owns the sockets, the tunnel and the
//! timers. That is what keeps the code portable to the engine later, and what
//! makes every behaviour here testable without a network.

pub mod error;
pub mod icmp;
pub mod ip;
pub mod keys;
pub mod nat;
pub mod peer;
pub mod plan;
pub mod ports;
pub mod scratch;
pub mod stats;

#[cfg(test)]
mod testpkt;

pub use error::{CoreError, PacketError};
pub use icmp::{
    ErrorQuote, build_echo_reply_v4, build_echo_reply_v6, build_unreachable_v4,
    build_unreachable_v6, parse_error_quote, recompute_icmp_checksum, rewrite_error_quote,
};
pub use keys::{GatewayKey, KEY_LEN, KeyError, PeerPublicKey, PresharedKey};
pub use nat::{
    EXIT_ID_LEN, EpochId, ExitId, MapProto, MappingId, Napt, NatConfig, NatDrop, Ownership,
    StaticDnat, Translated,
};
pub use peer::PeerId;
pub use plan::{
    DEFAULT_PEER_SUBNET_V4, DEFAULT_PEER_SUBNET_V6, PeerPlan, PlanError, TUNNEL_GATEWAY_V4,
    TUNNEL_GATEWAY_V6, TUNNEL_POOL_V4, TUNNEL_POOL_V6, complement, is_tunnel_gateway,
    is_tunnel_pool,
};
pub use ports::{
    CONTROL_RANGE_END, CONTROL_RANGE_START, DYNAMIC_POOL_END, DYNAMIC_POOL_START, PortAllocator,
};
pub use scratch::{SCRATCH_LEN, ScratchBuf};
pub use stats::{Counters, Snapshot};

pub use ip::{
    IcmpHeader, IpHeader, Side, checksum_update, is_echo, is_icmp_error, parse_ip, parse_ip_quote,
    read_icmp, read_ports, rewrite_endpoint, tcp_flags,
};
