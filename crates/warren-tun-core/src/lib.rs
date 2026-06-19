//! Re-export shim: the safe TUN seam now lives in the engine crate
//! `warrenguard-tun-core`. This crate keeps the `warren_tun_core::` path stable
//! for the SDK's userland consumers (warren-net's TUN bridge, warren-tun).
pub use warrenguard_tun_core::*;
