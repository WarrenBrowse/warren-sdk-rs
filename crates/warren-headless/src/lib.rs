//! The shared skeleton of Warren's headless daemons.
//!
//! `warren-proxy` and `warren-burrow` are the same daemon around two different
//! datapaths: both read their whole configuration from the environment, both
//! resolve exit candidates from the two signed views, both publish liveness on
//! a tiny local HTTP endpoint gated on proven egress, both drive a tunnel-side
//! port forward with `{{PORT}}` command hooks, and both exit 0 on a signal, 1
//! on a startup failure and 2 on a terminal control-plane refusal. Everything
//! in that list lives here, once, so the two binaries cannot drift apart on a
//! rule an operator depends on.
//!
//! What stays in each binary is what genuinely differs: its own knobs, its own
//! datapath, and the routes it adds to the health endpoint.

pub mod account;
pub mod candidates;
pub mod env;
pub mod forward;
pub mod hardening;
pub mod health;
pub mod hooks;
pub mod log;
pub mod select;
pub mod signals;

pub use account::account_line;
pub use candidates::{CandidateError, candidate_circuits};
pub use env::{
    CircuitKind, ConfigError, ExitFilter, healthcheck_target, is_off, parse_addr, parse_circuit,
    parse_connect_timeout, parse_exit_filters, parse_health_listen, parse_optional_addr,
    read_secret,
};
pub use forward::{
    ForwardConfig, ForwardEnv, ForwardProto, HookSink, ShellHooks, Stop, apply_port_change,
    conclude, fatal_line, parse_forward, retire_forward_state, wait_for_stop,
};
pub use hardening::disable_core_dumps;
pub use health::{
    ExtraRoutes, HealthView, RouteReply, probe_healthz, render, serve, track_egress_across_epochs,
};
pub use hooks::{
    HOOK_TIMEOUT, HookOutcome, clear_status_file, run_hook, run_hook_with_timeout, substitute_port,
    write_status_file,
};
pub use log::Log;
pub use select::order_exits;
pub use signals::{ReloadSignal, wait_for_signal};
