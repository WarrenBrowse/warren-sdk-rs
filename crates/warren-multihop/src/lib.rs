//! Warren multihop HPKE session (client side).
//!
//! Seals a payload into a [`WarrenMultihopFrame`] for the client -> exit
//! direction and opens the exit's response, RFC 9180 HPKE, byte-compatible with
//! warren-core `warren-multihop`:
//!
//! - Suite: DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, ChaCha20Poly1305.
//! - `setup_sender(Base, exit_x25519, info=`[`WARREN_HPKE_INFO_V1`]`)` once per
//!   session, producing the `encapsulated_key` carried on every frame.
//! - Per packet a unique key is derived via the HPKE exporter
//!   (`ctx.export(info)`, `info = AAD_V1 || epoch_be || seq_be`, the reverse
//!   direction appends `0x02`), then ChaCha20Poly1305 encrypts in place with an
//!   all-zero nonce (safe: the key is unique per `(epoch, seq)` and direction)
//!   and a detached tag. AAD = `AAD_V1 || exit_id || epoch_be || seq_be`.
//!
//! Anti-replay (epoch/seq monotonicity) is the caller's responsibility, exactly
//! as in warren-core (the `hpke` crate exposes no seq setter).

pub mod pop;
pub mod replay;
pub mod setup;

pub use pop::{POP_CONTEXT_V2, pop_signing_message, sign_pop, verify_pop};
pub use replay::{REPLAY_WINDOW_SIZE, ReplayWindow};
pub use setup::{IpAssignment, SetupError};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeS, Serializable, setup_sender};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use warren_wire::WARREN_HPKE_AAD_V1;
use warren_wire::multihop::{EXIT_ID_LEN, WARREN_HPKE_VERSION_V1, WarrenMultihopFrame};

/// HPKE `info` for `setup_sender` (per-session context binding).
pub const WARREN_HPKE_INFO_V1: &[u8] = b"warren/multihop/v1/hpke-info";
/// Reverse-direction (exit -> client) export-info tag byte.
const DIRECTION_TAG_REVERSE: u8 = 0x02;
/// Per-packet symmetric key length.
const PER_PACKET_KEY_LEN: usize = 32;
/// All-zero AEAD nonce (safe: the key is unique per `(epoch, seq)` + direction).
const NONCE_ZERO_12: [u8; 12] = [0u8; 12];

type WarrenAead = HpkeChaCha20Poly1305;
type WarrenKdf = HkdfSha256;
type WarrenKem = X25519HkdfSha256;

/// Errors from the multihop HPKE session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// HPKE setup or exporter failure.
    #[error("hpke error")]
    Hpke,
    /// The frame's epoch is neither the current nor the retained overlap epoch
    /// (a stale reverse frame past the overlap window, or a forward seal asked at
    /// a non-current epoch). `epoch` is a protocol counter, not identity material.
    #[error("unknown epoch {epoch}")]
    UnknownEpoch {
        /// The epoch that has no known sender context.
        epoch: u32,
    },
    /// AEAD seal/open failure (open: tampered ciphertext/AAD/tag or wrong key).
    #[error("aead error")]
    Aead,
    /// A response frame targets a different exit than this session.
    #[error("exit id mismatch on the active session")]
    ExitIdMismatch,
    /// A response frame carries an unsupported wire version.
    #[error("unsupported multihop version")]
    UnsupportedVersion,
    /// A received frame's `seq` was a replay or fell below the active window.
    /// `seq`/`epoch` are protocol counters, not identity material, so they are
    /// safe to surface for diagnostics.
    #[error("anti-replay rejection (epoch {epoch}, seq {seq})")]
    Replay {
        /// Frame epoch.
        epoch: u32,
        /// Frame sequence number.
        seq: u64,
    },
}

/// Fixed AAD length: these are built on every sealed/opened packet, so they are
/// stack arrays (no per-packet heap allocation).
const AAD_LEN: usize = WARREN_HPKE_AAD_V1.len() + EXIT_ID_LEN + 4 + 8;
/// Max export-info length (the reverse direction appends one tag byte).
const EXPORT_INFO_MAX: usize = WARREN_HPKE_AAD_V1.len() + 4 + 8 + 1;

/// `AAD_V1 || exit_id(16) || epoch_be(4) || seq_be(8)`.
fn compose_aad(exit_id: &[u8; EXIT_ID_LEN], epoch: u32, seq: u64) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    let prefix = WARREN_HPKE_AAD_V1.len();
    aad[..prefix].copy_from_slice(WARREN_HPKE_AAD_V1);
    aad[prefix..prefix + EXIT_ID_LEN].copy_from_slice(exit_id);
    aad[prefix + EXIT_ID_LEN..prefix + EXIT_ID_LEN + 4].copy_from_slice(&epoch.to_be_bytes());
    aad[prefix + EXIT_ID_LEN + 4..].copy_from_slice(&seq.to_be_bytes());
    aad
}

/// `AAD_V1 || epoch_be(4) || seq_be(8)` (+ `0x02` for the reverse direction).
/// Returns the fixed buffer and the used length (reverse uses one extra byte).
fn compose_export_info(epoch: u32, seq: u64, reverse: bool) -> ([u8; EXPORT_INFO_MAX], usize) {
    let mut info = [0u8; EXPORT_INFO_MAX];
    let prefix = WARREN_HPKE_AAD_V1.len();
    info[..prefix].copy_from_slice(WARREN_HPKE_AAD_V1);
    info[prefix..prefix + 4].copy_from_slice(&epoch.to_be_bytes());
    info[prefix + 4..prefix + 12].copy_from_slice(&seq.to_be_bytes());
    let mut len = prefix + 12;
    if reverse {
        info[len] = DIRECTION_TAG_REVERSE;
        len += 1;
    }
    (info, len)
}

/// One epoch's HPKE sender context and the encapsulated key that rides its frames.
struct EpochCtx {
    epoch: u32,
    ctx: hpke::aead::AeadCtxS<WarrenAead, WarrenKdf, WarrenKem>,
    encapsulated_key: [u8; 32],
}

/// A client-side HPKE session against one exit. The KEM ECDH runs once in
/// [`ClientSession::new`]; per-frame work is a key export plus an AEAD pass.
///
/// A [`rekey`](ClientSession::rekey) runs a fresh KEM (new encapsulated key) and
/// bumps the epoch, keeping the previous context in an overlap slot so reverse
/// frames still sealed under the old epoch open until
/// [`prune_old_epoch`](ClientSession::prune_old_epoch) is called. Wire-identical to warren-core: rekey introduces no new frame type, it
/// reuses the frame's `epoch` + `encapsulated_key` fields.
pub struct ClientSession {
    exit_x25519: [u8; 32],
    exit_id: [u8; EXIT_ID_LEN],
    current: EpochCtx,
    /// Previous epoch context kept briefly so in-flight old-epoch reverse frames
    /// still open after a rekey (the overlap window). At most one is retained.
    old: Option<EpochCtx>,
}

impl ClientSession {
    /// Sets up a sender session against the exit's long-lived X25519 multihop
    /// key (from the verified directory). `exit_id` is the routing tag.
    ///
    /// # Errors
    ///
    /// [`SessionError::Hpke`] if the key is malformed or `setup_sender` fails.
    pub fn new<R: CryptoRng + RngCore>(
        exit_x25519_pubkey: &[u8; 32],
        exit_id: [u8; EXIT_ID_LEN],
        rng: &mut R,
    ) -> Result<Self, SessionError> {
        let current = Self::derive_epoch(exit_x25519_pubkey, 0, rng)?;
        Ok(Self {
            exit_x25519: *exit_x25519_pubkey,
            exit_id,
            current,
            old: None,
        })
    }

    /// Runs a fresh KEM against the exit key for `epoch`, returning its context.
    fn derive_epoch<R: CryptoRng + RngCore>(
        exit_x25519_pubkey: &[u8; 32],
        epoch: u32,
        rng: &mut R,
    ) -> Result<EpochCtx, SessionError> {
        let pubkey = <WarrenKem as KemTrait>::PublicKey::from_bytes(exit_x25519_pubkey)
            .map_err(|_| SessionError::Hpke)?;
        let (encapped, ctx) = setup_sender::<WarrenAead, WarrenKdf, WarrenKem, R>(
            &OpModeS::Base,
            &pubkey,
            WARREN_HPKE_INFO_V1,
            rng,
        )
        .map_err(|_| SessionError::Hpke)?;
        let mut encapsulated_key = [0u8; 32];
        encapsulated_key.copy_from_slice(&encapped.to_bytes());
        Ok(EpochCtx {
            epoch,
            ctx,
            encapsulated_key,
        })
    }

    /// The 32-byte encapsulated key carried on every frame of the current epoch.
    #[must_use]
    pub fn encapsulated_key(&self) -> [u8; 32] {
        self.current.encapsulated_key
    }

    /// The current epoch (starts at `0`, `+1` per [`rekey`](Self::rekey)).
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.current.epoch
    }

    /// The 16-byte exit identifier this session targets (cleartext routing tag).
    #[must_use]
    pub fn exit_id_bytes(&self) -> [u8; EXIT_ID_LEN] {
        self.exit_id
    }

    /// Rotates the session: a fresh KEM (new encapsulated key), epoch `+1`, with
    /// the previous context retained for the overlap window. Bounds the AEAD
    /// nonce-overflow exposure of a long-lived session (warren-core doctrine).
    ///
    /// # Errors
    ///
    /// [`SessionError::Hpke`] if the fresh `setup_sender` fails.
    pub fn rekey<R: CryptoRng + RngCore>(&mut self, rng: &mut R) -> Result<u32, SessionError> {
        let next_epoch = self.current.epoch.saturating_add(1);
        let next = Self::derive_epoch(&self.exit_x25519, next_epoch, rng)?;
        self.old = Some(std::mem::replace(&mut self.current, next));
        Ok(next_epoch)
    }

    /// Ends the overlap window: drops the previous-epoch context so old-epoch
    /// reverse frames no longer open. Call once the overlap deadline elapses.
    pub fn prune_old_epoch(&mut self) {
        self.old = None;
    }

    /// The sender context that seals/opens frames for `epoch` (current or the
    /// retained old epoch), if known.
    fn ctx_for(&self, epoch: u32) -> Option<&EpochCtx> {
        if epoch == self.current.epoch {
            Some(&self.current)
        } else {
            self.old.as_ref().filter(|o| o.epoch == epoch)
        }
    }

    /// Derives the per-packet key for `(epoch, seq, direction)` from `ctx`.
    ///
    /// Returned in a [`Zeroizing`] so the symmetric key is wiped when the caller
    /// drops it, never lingering on the stack after the AEAD op (secret hygiene,
    /// matches warren-core).
    fn packet_key(
        ctx: &EpochCtx,
        epoch: u32,
        seq: u64,
        reverse: bool,
    ) -> Result<Zeroizing<[u8; 32]>, SessionError> {
        let mut key = Zeroizing::new([0u8; PER_PACKET_KEY_LEN]);
        let (info, n) = compose_export_info(epoch, seq, reverse);
        ctx.ctx
            .export(&info[..n], &mut *key)
            .map_err(|_| SessionError::Hpke)?;
        Ok(key)
    }

    /// Seals `payload` into a frame for the client -> exit direction at the
    /// current epoch. Forward frames are ALWAYS sealed at the current epoch; the
    /// retained old epoch exists only to open reverse overlap frames, so `epoch`
    /// must equal the current epoch (passed by the caller to stamp the frame).
    ///
    /// # Errors
    ///
    /// [`SessionError::UnknownEpoch`] if `epoch` is not the current epoch,
    /// [`SessionError::Hpke`] on exporter failure, [`SessionError::Aead`] if
    /// encryption fails.
    pub fn seal(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, SessionError> {
        if epoch != self.current.epoch {
            return Err(SessionError::UnknownEpoch { epoch });
        }
        let ctx = &self.current;
        let key = Self::packet_key(ctx, epoch, seq, false)?;
        let aad = compose_aad(&self.exit_id, epoch, seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
        let mut buf = payload.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&NONCE_ZERO_12), &aad, &mut buf)
            .map_err(|_| SessionError::Aead)?;
        let mut aead_tag = [0u8; 16];
        aead_tag.copy_from_slice(tag.as_slice());
        Ok(WarrenMultihopFrame {
            version: WARREN_HPKE_VERSION_V1,
            exit_id: self.exit_id,
            epoch,
            seq,
            encapsulated_key: ctx.encapsulated_key,
            aead_tag,
            ciphertext: buf,
        })
    }

    /// Opens an exit -> client response frame sealed against this session. The
    /// frame's `epoch` selects the current or the overlap (old) context.
    ///
    /// # Errors
    ///
    /// [`SessionError::ExitIdMismatch`]/[`SessionError::UnsupportedVersion`] on a
    /// foreign frame, [`SessionError::UnknownEpoch`] if the frame's epoch is past
    /// the overlap window, [`SessionError::Hpke`] on exporter failure, or
    /// [`SessionError::Aead`] if the tag does not verify.
    pub fn open_response(&self, frame: &WarrenMultihopFrame) -> Result<Vec<u8>, SessionError> {
        if frame.version != WARREN_HPKE_VERSION_V1 {
            return Err(SessionError::UnsupportedVersion);
        }
        if frame.exit_id != self.exit_id {
            return Err(SessionError::ExitIdMismatch);
        }
        let ctx = self
            .ctx_for(frame.epoch)
            .ok_or(SessionError::UnknownEpoch { epoch: frame.epoch })?;
        let key = Self::packet_key(ctx, frame.epoch, frame.seq, true)?;
        let aad = compose_aad(&self.exit_id, frame.epoch, frame.seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
        let mut buf = frame.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&NONCE_ZERO_12),
                &aad,
                &mut buf,
                Tag::from_slice(&frame.aead_tag),
            )
            .map_err(|_| SessionError::Aead)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{OpModeR, setup_receiver};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// Recovers the plaintext on the exit side via `setup_receiver` + the same
    /// exporter/AEAD construction, proving the seal is byte-compatible with the
    /// warren-core scheme (forward direction).
    fn exit_open(
        recipient_priv: &<WarrenKem as KemTrait>::PrivateKey,
        frame: &WarrenMultihopFrame,
    ) -> Vec<u8> {
        let encapped =
            <WarrenKem as KemTrait>::EncappedKey::from_bytes(&frame.encapsulated_key).unwrap();
        let ctx = setup_receiver::<WarrenAead, WarrenKdf, WarrenKem>(
            &OpModeR::Base,
            recipient_priv,
            &encapped,
            WARREN_HPKE_INFO_V1,
        )
        .unwrap();
        let mut key = [0u8; PER_PACKET_KEY_LEN];
        let (info, n) = compose_export_info(frame.epoch, frame.seq, false);
        ctx.export(&info[..n], &mut key).unwrap();
        let aad = compose_aad(&frame.exit_id, frame.epoch, frame.seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut buf = frame.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&NONCE_ZERO_12),
                &aad,
                &mut buf,
                Tag::from_slice(&frame.aead_tag),
            )
            .unwrap();
        buf
    }

    /// The exit sealing a REVERSE (exit -> client) frame: `setup_receiver` against
    /// the frame's encapsulated key, reverse export info, then AEAD seal.
    fn exit_seal_reverse(
        recipient_priv: &<WarrenKem as KemTrait>::PrivateKey,
        encapsulated_key: &[u8; 32],
        exit_id: &[u8; EXIT_ID_LEN],
        epoch: u32,
        seq: u64,
        plaintext: &[u8],
    ) -> WarrenMultihopFrame {
        let encapped = <WarrenKem as KemTrait>::EncappedKey::from_bytes(encapsulated_key).unwrap();
        let ctx = setup_receiver::<WarrenAead, WarrenKdf, WarrenKem>(
            &OpModeR::Base,
            recipient_priv,
            &encapped,
            WARREN_HPKE_INFO_V1,
        )
        .unwrap();
        let mut key = [0u8; PER_PACKET_KEY_LEN];
        let (info, n) = compose_export_info(epoch, seq, true);
        ctx.export(&info[..n], &mut key).unwrap();
        let aad = compose_aad(exit_id, epoch, seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&NONCE_ZERO_12), &aad, &mut buf)
            .unwrap();
        let mut aead_tag = [0u8; 16];
        aead_tag.copy_from_slice(tag.as_slice());
        WarrenMultihopFrame {
            version: WARREN_HPKE_VERSION_V1,
            exit_id: *exit_id,
            epoch,
            seq,
            encapsulated_key: *encapsulated_key,
            aead_tag,
            ciphertext: buf,
        }
    }

    #[test]
    fn rekey_rotates_epoch_with_an_overlap_window() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (recipient_priv, recipient_pub) = WarrenKem::gen_keypair(&mut rng);
        let pub_bytes: [u8; 32] = recipient_pub.to_bytes().into();
        let exit_id = [0x07; EXIT_ID_LEN];
        let mut session = ClientSession::new(&pub_bytes, exit_id, &mut rng).unwrap();
        assert_eq!(session.epoch(), 0);
        let e0_key = session.encapsulated_key();

        // A reverse frame sealed by the exit at epoch 0, still in flight at rekey.
        let rev0 = exit_seal_reverse(&recipient_priv, &e0_key, &exit_id, 0, 1, b"old-reply");

        // Rekey: epoch 1 with a fresh KEM key.
        assert_eq!(session.rekey(&mut rng).unwrap(), 1);
        assert_eq!(session.epoch(), 1);
        assert_ne!(session.encapsulated_key(), e0_key, "rekey runs a fresh KEM");

        // Forward seal now rides epoch 1 + the new key; the exit recovers it.
        let fwd1 = session.seal(b"new-data", 1, 0).unwrap();
        assert_eq!(fwd1.epoch, 1);
        assert_eq!(fwd1.encapsulated_key, session.encapsulated_key());
        assert_eq!(exit_open(&recipient_priv, &fwd1), b"new-data");

        // Overlap window: the old-epoch reverse frame still opens.
        assert_eq!(session.open_response(&rev0).unwrap(), b"old-reply");
        // A new-epoch reverse frame opens too.
        let e1_key = session.encapsulated_key();
        let rev1 = exit_seal_reverse(&recipient_priv, &e1_key, &exit_id, 1, 1, b"new-reply");
        assert_eq!(session.open_response(&rev1).unwrap(), b"new-reply");

        // After pruning, old-epoch reverse frames no longer open.
        session.prune_old_epoch();
        assert!(
            session.open_response(&rev0).is_err(),
            "old epoch is dropped after pruning the overlap"
        );
    }

    fn test_session(seed: u64) -> ClientSession {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (_priv, pub_) = WarrenKem::gen_keypair(&mut rng);
        let pub_bytes: [u8; 32] = pub_.to_bytes().into();
        ClientSession::new(&pub_bytes, [0x5a; EXIT_ID_LEN], &mut rng).expect("session")
    }

    #[test]
    fn seal_rejects_a_non_current_epoch() {
        // Forward frames must always seal at the current epoch; asking for the
        // retained old epoch (or any other) is a usage error, not a silent
        // downgrade to a stale context.
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let mut session = test_session(21);
        assert_eq!(session.rekey(&mut rng).unwrap(), 1);
        // Epoch 0 is retained for the reverse overlap but must not seal forward.
        assert!(matches!(
            session.seal(b"stale-forward", 0, 0),
            Err(SessionError::UnknownEpoch { epoch: 0 })
        ));
        // A wholly unknown future epoch is rejected too.
        assert!(matches!(
            session.seal(b"future", 9, 0),
            Err(SessionError::UnknownEpoch { epoch: 9 })
        ));
        // The current epoch still seals.
        assert!(session.seal(b"ok", 1, 0).is_ok());
    }

    #[test]
    fn open_response_rejects_an_epoch_past_the_overlap() {
        let session = test_session(22);
        let mut frame = session.seal(b"x", 0, 0).unwrap();
        // Forge an epoch the session never knew (no current, no overlap).
        frame.epoch = 5;
        assert!(matches!(
            session.open_response(&frame),
            Err(SessionError::UnknownEpoch { epoch: 5 })
        ));
    }

    #[test]
    fn open_response_rejects_wrong_version() {
        let session = test_session(11);
        let mut frame = session.seal(b"x", 0, 0).unwrap();
        frame.version = 0x02;
        assert!(matches!(
            session.open_response(&frame),
            Err(SessionError::UnsupportedVersion)
        ));
    }

    #[test]
    fn open_response_rejects_foreign_exit_id() {
        let session = test_session(12);
        let mut frame = session.seal(b"x", 0, 0).unwrap();
        frame.exit_id = [0xff; EXIT_ID_LEN];
        assert!(matches!(
            session.open_response(&frame),
            Err(SessionError::ExitIdMismatch)
        ));
    }

    #[test]
    fn open_response_rejects_unopenable_frame_as_aead() {
        // A forward-sealed frame carries the right version + exit_id but is keyed
        // for the forward direction, so opening it in the reverse direction must
        // fail the AEAD tag (drives SessionError::Aead through open_response).
        let session = test_session(13);
        let frame = session.seal(b"forward-only", 0, 0).unwrap();
        assert!(matches!(
            session.open_response(&frame),
            Err(SessionError::Aead)
        ));
    }

    #[test]
    fn seal_then_exit_open_roundtrips() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (recipient_priv, recipient_pub) = WarrenKem::gen_keypair(&mut rng);
        let pub_bytes: [u8; 32] = recipient_pub.to_bytes().into();

        let exit_id = [0xa1u8; EXIT_ID_LEN];
        let session = ClientSession::new(&pub_bytes, exit_id, &mut rng).expect("session");

        let payload = b"warren-setup-frame-inner";
        let frame = session.seal(payload, 0, 0).expect("seal");
        assert_eq!(frame.exit_id, exit_id);
        assert_eq!(frame.encapsulated_key, session.encapsulated_key());

        let opened = exit_open(&recipient_priv, &frame);
        assert_eq!(opened, payload);
    }

    #[test]
    fn tampered_aad_fails_to_open() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (recipient_priv, recipient_pub) = WarrenKem::gen_keypair(&mut rng);
        let pub_bytes: [u8; 32] = recipient_pub.to_bytes().into();
        let session = ClientSession::new(&pub_bytes, [0x07; EXIT_ID_LEN], &mut rng).unwrap();

        // Seal at the session's current epoch (0); flip the seq afterward so the
        // AAD/key no longer match and the AEAD tag fails to verify.
        let mut frame = session.seal(b"hello", 0, 9).unwrap();
        frame.seq = 10;
        let encapped =
            <WarrenKem as KemTrait>::EncappedKey::from_bytes(&frame.encapsulated_key).unwrap();
        let ctx = setup_receiver::<WarrenAead, WarrenKdf, WarrenKem>(
            &OpModeR::Base,
            &recipient_priv,
            &encapped,
            WARREN_HPKE_INFO_V1,
        )
        .unwrap();
        let mut key = [0u8; PER_PACKET_KEY_LEN];
        let (info, n) = compose_export_info(frame.epoch, frame.seq, false);
        ctx.export(&info[..n], &mut key).unwrap();
        let aad = compose_aad(&frame.exit_id, frame.epoch, frame.seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut buf = frame.ciphertext.clone();
        assert!(
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&NONCE_ZERO_12),
                    &aad,
                    &mut buf,
                    Tag::from_slice(&frame.aead_tag),
                )
                .is_err()
        );
    }
}
