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

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeS, Serializable, setup_sender};
use rand_core::{CryptoRng, RngCore};

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
    /// AEAD seal/open failure (open: tampered ciphertext/AAD/tag or wrong key).
    #[error("aead error")]
    Aead,
    /// A response frame targets a different exit than this session.
    #[error("exit id mismatch on the active session")]
    ExitIdMismatch,
    /// A response frame carries an unsupported wire version.
    #[error("unsupported multihop version")]
    UnsupportedVersion,
}

/// `AAD_V1 || exit_id(16) || epoch_be(4) || seq_be(8)`.
fn compose_aad(exit_id: &[u8; EXIT_ID_LEN], epoch: u32, seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WARREN_HPKE_AAD_V1.len() + EXIT_ID_LEN + 4 + 8);
    aad.extend_from_slice(WARREN_HPKE_AAD_V1);
    aad.extend_from_slice(exit_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

/// `AAD_V1 || epoch_be(4) || seq_be(8)` (+ `0x02` for the reverse direction).
fn compose_export_info(epoch: u32, seq: u64, reverse: bool) -> Vec<u8> {
    let mut info = Vec::with_capacity(WARREN_HPKE_AAD_V1.len() + 4 + 8 + 1);
    info.extend_from_slice(WARREN_HPKE_AAD_V1);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&seq.to_be_bytes());
    if reverse {
        info.push(DIRECTION_TAG_REVERSE);
    }
    info
}

/// A client-side HPKE session against one exit. The KEM ECDH runs once in
/// [`ClientSession::new`]; per-frame work is a key export plus an AEAD pass.
pub struct ClientSession {
    ctx: hpke::aead::AeadCtxS<WarrenAead, WarrenKdf, WarrenKem>,
    exit_id: [u8; EXIT_ID_LEN],
    encapsulated_key: [u8; 32],
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
        Ok(Self {
            ctx,
            exit_id,
            encapsulated_key,
        })
    }

    /// The 32-byte encapsulated key carried on every frame of this session.
    #[must_use]
    pub fn encapsulated_key(&self) -> [u8; 32] {
        self.encapsulated_key
    }

    /// Derives the per-packet key for `(epoch, seq, direction)`.
    fn packet_key(&self, epoch: u32, seq: u64, reverse: bool) -> Result<[u8; 32], SessionError> {
        let mut key = [0u8; PER_PACKET_KEY_LEN];
        self.ctx
            .export(&compose_export_info(epoch, seq, reverse), &mut key)
            .map_err(|_| SessionError::Hpke)?;
        Ok(key)
    }

    /// Seals `payload` into a frame for the client -> exit direction.
    ///
    /// # Errors
    ///
    /// [`SessionError::Hpke`] on exporter failure, [`SessionError::Aead`] if
    /// encryption fails.
    pub fn seal(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, SessionError> {
        let key = self.packet_key(epoch, seq, false)?;
        let aad = compose_aad(&self.exit_id, epoch, seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
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
            encapsulated_key: self.encapsulated_key,
            aead_tag,
            ciphertext: buf,
        })
    }

    /// Opens an exit -> client response frame sealed against this session.
    ///
    /// # Errors
    ///
    /// [`SessionError::ExitIdMismatch`]/[`SessionError::UnsupportedVersion`] on a
    /// foreign frame, [`SessionError::Hpke`] on exporter failure, or
    /// [`SessionError::Aead`] if the tag does not verify.
    pub fn open_response(&self, frame: &WarrenMultihopFrame) -> Result<Vec<u8>, SessionError> {
        if frame.version != WARREN_HPKE_VERSION_V1 {
            return Err(SessionError::UnsupportedVersion);
        }
        if frame.exit_id != self.exit_id {
            return Err(SessionError::ExitIdMismatch);
        }
        let key = self.packet_key(frame.epoch, frame.seq, true)?;
        let aad = compose_aad(&self.exit_id, frame.epoch, frame.seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
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
        ctx.export(
            &compose_export_info(frame.epoch, frame.seq, false),
            &mut key,
        )
        .unwrap();
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

        let mut frame = session.seal(b"hello", 3, 9).unwrap();
        // Flip the seq: the AAD/key no longer match, so the AEAD tag fails.
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
        ctx.export(
            &compose_export_info(frame.epoch, frame.seq, false),
            &mut key,
        )
        .unwrap();
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
