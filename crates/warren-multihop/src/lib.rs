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

/// Hybrid post-quantum (`/v2` X-Wing: X25519 + ML-KEM-768) multihop seal, when
/// the exit advertises a signed ML-KEM key. Additive and inert until then: the
/// classical `/v1` types above stay the production seal. `negotiate_pq` /
/// `PqAvailability` carry the anti-downgrade decision, the frozen bytes are
/// pinned by `tests/pq_hpke_vectors.rs` against the shared `vectors/`.
#[cfg(feature = "pq-hpke")]
pub use warrenguard_multihop::{
    ExitDescriptorSigned, ExitPkiError, MLKEM768_ENCAPS_KEY_LEN, PqAvailability, PqClientSession,
    PqExitSession, WarrenMultihopFrameV2, XWingRecipientPublicKey, XWingRecipientSecretKey,
    decode_frame_v2, encode_frame_v2, exit_descriptor_signing_payload_pq, negotiate_pq,
    verify_exit_descriptor_pq, xwing_combiner,
};

/// Test-only PQ helpers re-exported so the SDK vector replays reach the same
/// X-Wing reference flow the engine KATs use. Hidden from rendered docs.
#[cfg(feature = "pq-hpke")]
#[doc(hidden)]
pub mod test_support {
    pub use warrenguard_multihop::test_support::{XWingReferenceOutput, xwing_reference_flow};
}
