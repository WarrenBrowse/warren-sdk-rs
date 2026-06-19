//! Safe, always-on TUN seam for the Warren datapath.
//!
//! This crate is the userland-safe half of the TUN backend: it compiles on every
//! target with zero `unsafe` and zero third-party dependencies, so a no-root
//! (proxy) build can depend on it without ever pulling privileged code.
//!
//! - [`frame`]: OS-agnostic TUN packet framing (macOS utun's 4-byte address
//!   family prefix vs the bare-IP framing on Linux/Windows) and IP-version
//!   detection. Pure, fully unit-tested.
//! - [`plan`]: routing and killswitch PLAN computation (which routes and firewall
//!   rules a backend would install). Pure, fully unit-tested. Computing the plan
//!   is separated from applying it so the policy is testable without privilege.
//! - [`gateway`]: default-gateway parsing from the host routing table.
//! - [`device`]: the device seam ([`device::RawTunDevice`] / [`device::TunIo`])
//!   and a framing adapter over any byte stream ([`device::FramedTun`]),
//!   unit-tested over an in-memory mock.
//!
//! The actual per-OS device open (`open_tun`) and the routing/killswitch applier
//! are the privileged half and live in the `warren-tun` crate behind its
//! `experimental-tun` feature.

pub mod device;
pub mod frame;
pub mod gateway;
pub mod plan;

pub use device::{FramedTun, RawTunDevice, TunIo};
pub use frame::{Framing, PacketFamily};
pub use gateway::parse_default_gateway;
pub use plan::{KillswitchPlan, RouteOp, RoutingPlan, TunConfig};
