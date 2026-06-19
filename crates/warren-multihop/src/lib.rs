//! Warren multihop HPKE session (client side).
//!
//! This is now a thin re-export of the engine's `warrenguard-multihop`, so a
//! single RFC 9180 HPKE multihop implementation is shared with warren-core: the
//! per-session [`ClientSession`] (seal/open + in-place rekey), the per-epoch
//! [`ReplayWindow`], the proof-of-possession primitives, and the client setup
//! exchange ([`IpAssignment`] / [`SetupError`] + `ClientSession::seal_setup_request`
//! and friends). The golden-vector guard in `tests/pop_vectors.rs` pins the
//! re-exported pop primitives against the shared `vectors/pop.json`.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, ChaCha20Poly1305.
//! Anti-replay (epoch/seq monotonicity) is the caller's responsibility, exactly
//! as in warren-core (the `hpke` crate exposes no seq setter).

pub use warrenguard_multihop::{
    ClientSession, ExitId, ExitSession, IpAssignment, MultihopError, POP_CONTEXT_V2,
    REPLAY_WINDOW_SIZE, ReplayWindow, SetupError, WARREN_HPKE_INFO_V1, parse_exit_x25519_pubkey,
    pop_signing_message, sign_pop, verify_pop,
};
