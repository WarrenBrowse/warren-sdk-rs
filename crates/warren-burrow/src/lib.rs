//! The Warren local gateway: a WireGuard-protocol responder in front of a
//! Warren tunnel.
//!
//! A stock WireGuard-protocol client on the LAN (a phone, a TV, a router, a
//! gluetun container) reaches the internet through a Warren exit without
//! knowing anything about Warren. The gateway terminates those sessions,
//! translates every peer packet onto the single address the exit assigned to
//! the tunnel (the exit refuses any other source), and carries it over the
//! same supervised, self-healing datapath the SDK gives every other client.
//!
//! What runs where: [`warren_burrow_core`] is the packet logic, with no socket
//! and no clock of its own; this crate is the async shell that owns the
//! sockets, the tunnel and the timers.
//!
//! "WireGuard" is a registered trademark of Jason A. Donenfeld. This component
//! implements the WireGuard protocol; it is not affiliated with, endorsed by
//! or a product of the WireGuard project.

pub mod config;
pub mod control;
pub mod device;
pub mod health;
pub mod provision;
pub mod run;
pub mod socket;

pub use config::{GatewayConfigError, GatewayEnv};
pub use control::GatewayControl;
pub use device::{
    GatewayDevice, GatewayEpochSink, GatewayError, GatewayOptions, GatewaySnapshot, GatewayTasks,
};
pub use provision::{ProvisionError, Provisioned};
pub use socket::{DatagramSocket, bind_all};
