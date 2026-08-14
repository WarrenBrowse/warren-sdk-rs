//! Headless Warren proxy daemon.
//!
//! `warren-proxy` wraps [`warren_sdk`]'s supervised failover datapath in a
//! long-running process configured entirely from the environment, so the same
//! binary serves containers, servers, NAS boxes and CI: no root, no TUN
//! device, no capabilities. It exposes a SOCKS5 listener (and optionally HTTP
//! CONNECT), resolves DNS over the tunnel, keeps the tunnel up across drops
//! and exit failures, publishes liveness over a tiny local HTTP endpoint, and
//! forwards a tunnel-side port with gluetun-style up/down command hooks.
//!
//! The binary is a thin `main` over [`run::run`]; everything else is a
//! library so the config, selection, hook and health logic stay unit-tested.

pub mod config;
pub mod health;
pub mod hooks;
pub mod run;
pub mod select;

pub use config::{CircuitKind, Config, ConfigError, ExitFilter, ForwardConfig, ForwardProto};
