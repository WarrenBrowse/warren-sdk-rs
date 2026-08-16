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
//! The binary is a thin `main` over [`run::run`]; the daemon skeleton it
//! shares with the local gateway (env parsing, candidate selection, hooks,
//! health, signals) lives in [`warren_headless`], so the two cannot drift
//! apart on a rule an operator depends on.

pub mod config;
pub mod run;

pub use config::{Config, load};
pub use warren_headless::env::{CircuitKind, ConfigError, ExitFilter};
pub use warren_headless::forward::{ForwardConfig, ForwardProto};
pub use warren_headless::health;
