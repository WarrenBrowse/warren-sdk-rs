//! Deriving an anonymous-token batch from the wallet instead of the CSPRNG.
//!
//! The issuer signs one batch per account, class and epoch, and serves that
//! SAME batch again to whoever sends it bit for bit (warren-core doc 103
//! section 11). A batch drawn from the CSPRNG can be sent by one client only:
//! a second device of the wallet, the browser extension, or a reinstall that
//! lost its store sends another batch and is refused for the rest of the epoch.
//! Deriving the blinding from the wallet seed makes every client of a wallet
//! build the identical batch, so every one of them is served. Blind-RSA
//! signing is deterministic, so a re-served batch creates no credential that
//! did not exist, and the per-epoch cap is untouched.
//!
//! What this costs: whoever holds the wallet seed can compute which tokens the
//! account owns. They hold the account already. The blinding stays
//! unpredictable to the issuer and to the exit, which is where unlinkability
//! lives.
//!
//! The derivation is frozen by `vectors/token_blinding_v1.json` and shared with
//! the TypeScript SDK (`blindingKeyFromSeed`, `deterministicTokenRandom`). The
//! number and order of the draws a slot makes are part of it.

use std::convert::Infallible;

use crypto_bigint::{BoxedUint, Gcd, NonZero};
use hkdf::Hkdf;
use rand010::{TryCryptoRng, TryRng};
use sha2::Sha256;
use warrenguard_token::{ClientState, IssuerPublicKey, TokenChallenge};
use zeroize::Zeroizing;

use crate::tokens::{CredentialClass, TokenClientError};

/// HKDF salt separating this use of the wallet seed from every other one.
/// Frozen: changing it changes every derived batch.
pub const BLINDING_SALT: &[u8] = b"warren/token-blinding/v1";

/// The blinding purpose of the [`CredentialClass::Session`] class. Canonical:
/// every client of a class must use the same label, or two clients of one
/// wallet derive different batches and only one of them is served.
pub const BLINDING_PURPOSE_SESSION: &str = "session/v1";

/// The blinding purpose of the [`CredentialClass::BrowserProxy`] class, the
/// label the browser extension derives with.
pub const BLINDING_PURPOSE_BROWSER_PROXY: &str = "browser-proxy/v1";

/// The token nonce, the first draw of a slot.
const NONCE_DRAW: usize = 32;
/// The RSABSSA-SHA384-PSS salt, the second draw of a slot.
const SALT_DRAW: usize = 48;
/// One HKDF output block of the slot stream.
const BLOCK_LEN: usize = 32;

/// The key a credential class derives its batches from: HKDF-SHA256 of the
/// 32-byte wallet seed (the first 32 bytes of the BIP39 seed, the one the
/// identity derives from) under [`BLINDING_SALT`], with the class purpose as
/// info.
///
/// One-way: holding it does not give back the seed, so a component that only
/// mints credentials never holds the wallet. Zeroized on drop, and its `Debug`
/// names the class only.
pub struct BlindingKey {
    key: Zeroizing<[u8; 32]>,
    class: CredentialClass,
}

impl std::fmt::Debug for BlindingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlindingKey")
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

impl BlindingKey {
    /// The [`CredentialClass::Session`] key of the wallet `seed`.
    #[must_use]
    pub fn session(seed: &[u8; 32]) -> Self {
        Self::derive(seed, CredentialClass::Session, BLINDING_PURPOSE_SESSION)
    }

    /// The [`CredentialClass::BrowserProxy`] key of the wallet `seed`.
    #[must_use]
    pub fn browser_proxy(seed: &[u8; 32]) -> Self {
        Self::derive(
            seed,
            CredentialClass::BrowserProxy,
            BLINDING_PURPOSE_BROWSER_PROXY,
        )
    }

    fn derive(seed: &[u8; 32], class: CredentialClass, purpose: &str) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(BLINDING_SALT), seed)
            .expand(purpose.as_bytes(), key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self { key, class }
    }

    /// The credential class this key mints.
    #[must_use]
    pub fn class(&self) -> CredentialClass {
        self.class
    }

    fn stream(&self, epoch: u64, index: u32) -> SlotStream {
        SlotStream {
            key: Zeroizing::new(*self.key),
            epoch,
            index,
            block: 0,
        }
    }

    /// Blinds slot `index` of `epoch` against `pk` with this key's material,
    /// through the engine's own blinding.
    ///
    /// # Errors
    /// [`TokenClientError::BadDirectoryKey`] if the key's modulus cannot be
    /// read back; [`TokenClientError::BlindingDrawOrder`] if the engine drew
    /// its material in another order than the derivation defines;
    /// [`TokenClientError::Crypto`] if blinding fails.
    pub(crate) fn blind_slot(
        &self,
        pk: &IssuerPublicKey,
        challenge: &TokenChallenge,
        epoch: u64,
        index: u32,
    ) -> Result<(Vec<u8>, ClientState), TokenClientError> {
        let modulus = Modulus::of(pk).ok_or(TokenClientError::BadDirectoryKey { epoch })?;
        let mut rng = SlotRng::new(self.stream(epoch, index), &modulus);
        let blinded = pk.blind_token(&mut rng, challenge)?;
        rng.finish()?;
        Ok(blinded)
    }
}

/// The byte stream of one slot: draw `k` of length `L` concatenates
/// `HKDF-SHA256(key, BLINDING_SALT, epoch_be64 || index_be32 || block_be32)`
/// over consecutive blocks, truncated to `L`. The block counter keeps running
/// across draws, and every draw starts on a fresh block.
struct SlotStream {
    key: Zeroizing<[u8; 32]>,
    epoch: u64,
    index: u32,
    block: u32,
}

impl SlotStream {
    fn draw(&mut self, len: usize) -> Zeroizing<Vec<u8>> {
        let hkdf = Hkdf::<Sha256>::new(Some(BLINDING_SALT), self.key.as_ref());
        let mut out = Zeroizing::new(vec![0u8; len]);
        for chunk in out.chunks_mut(BLOCK_LEN) {
            let mut info = [0u8; 16];
            info[..8].copy_from_slice(&self.epoch.to_be_bytes());
            info[8..12].copy_from_slice(&self.index.to_be_bytes());
            info[12..].copy_from_slice(&self.block.to_be_bytes());
            let mut block = Zeroizing::new([0u8; BLOCK_LEN]);
            hkdf.expand(&info, block.as_mut())
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            chunk.copy_from_slice(&block[..chunk.len()]);
            self.block = self.block.wrapping_add(1);
        }
        out
    }
}

/// The issuer modulus, read back out of the key's SPKI (the engine keeps its
/// own copy private).
struct Modulus {
    n: NonZero<BoxedUint>,
    len: usize,
}

impl Modulus {
    fn of(pk: &IssuerPublicKey) -> Option<Self> {
        use der::asn1::{AnyRef, BitStringRef, UintRef};
        use der::{Decode, Reader, SliceReader};

        let spki = pk.to_spki();
        let mut outer = SliceReader::new(&spki).ok()?;
        let key = outer
            .sequence(|r| {
                AnyRef::decode(r)?;
                BitStringRef::decode(r)
            })
            .ok()?;
        let mut inner = SliceReader::new(key.as_bytes()?).ok()?;
        let n = inner
            .sequence(|r| {
                let n = UintRef::decode(r)?;
                UintRef::decode(r)?;
                Ok::<_, der::Error>(n)
            })
            .ok()?;
        let bytes = n.as_bytes();
        let bits = u32::try_from(bytes.len().checked_mul(8)?).ok()?;
        let n = BoxedUint::from_be_slice(bytes, bits).ok()?;
        Some(Self {
            n: Option::from(NonZero::new(n))?,
            len: bytes.len(),
        })
    }
}

/// The byte source handed to the engine's `blind_token`, shaped so that the
/// engine blinds with exactly the material the derivation defines.
///
/// The engine draws the nonce, then the PSS salt, then samples the blinding
/// factor by rejection (one modulus-wide little-endian draw per attempt, kept
/// when below `n`). The derivation instead takes the first modulus-wide draw
/// reduced mod `n`, redrawn while not a unit above 1. So the third draw answers
/// with that factor in the engine's layout, which the engine accepts on its
/// first attempt. Any other sequence of draws means the engine changed under
/// the derivation, and [`Self::finish`] refuses the batch rather than send one
/// that no other client of the wallet can rebuild.
struct SlotRng<'m> {
    stream: SlotStream,
    modulus: &'m Modulus,
    draws: Vec<usize>,
}

impl<'m> SlotRng<'m> {
    fn new(stream: SlotStream, modulus: &'m Modulus) -> Self {
        Self {
            stream,
            modulus,
            draws: Vec::with_capacity(3),
        }
    }

    /// The factor, little-endian over the modulus width.
    fn blinding_factor(&mut self) -> Zeroizing<Vec<u8>> {
        let bits = self.modulus.n.bits_precision();
        let one = BoxedUint::one_with_precision(bits);
        loop {
            let draw = self.stream.draw(self.modulus.len);
            let x = Zeroizing::new(
                BoxedUint::from_be_slice(&draw, bits)
                    .expect("a modulus-wide draw fits the modulus precision"),
            );
            let r = Zeroizing::new(x.rem_vartime(&self.modulus.n));
            if *r > one && r.gcd(self.modulus.n.as_ref()) == one {
                let le = Zeroizing::new(r.to_le_bytes());
                return Zeroizing::new(le[..self.modulus.len].to_vec());
            }
        }
    }

    fn finish(self) -> Result<(), TokenClientError> {
        if self.draws == [NONCE_DRAW, SALT_DRAW, self.modulus.len] {
            Ok(())
        } else {
            Err(TokenClientError::BlindingDrawOrder)
        }
    }
}

impl TryRng for SlotRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.draws.push(dst.len());
        if self.draws.len() == 3 && dst.len() == self.modulus.len {
            dst.copy_from_slice(&self.blinding_factor());
        } else {
            dst.copy_from_slice(&self.stream.draw(dst.len()));
        }
        Ok(())
    }
}

impl TryCryptoRng for SlotRng<'_> {}

#[cfg(test)]
mod vector_tests {
    //! Replays `vectors/token_blinding_v1.json`, produced by running the
    //! TypeScript reference, so a Rust client and the extension build the
    //! same batch for the same wallet.

    use serde_json::Value;
    use warren_identity::seed_from_mnemonic;

    use super::*;

    fn corpus() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/token_blinding_v1.json"
        );
        let body = std::fs::read_to_string(path).expect("the vectors submodule is checked out");
        serde_json::from_str(&body).expect("token_blinding_v1.json is JSON")
    }

    fn bytes(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().expect("hex string")).expect("valid hex")
    }

    fn seed(v: &Value) -> [u8; 32] {
        bytes(&v["wallet"]["seed_hex"])
            .try_into()
            .expect("a 32-byte seed")
    }

    fn key_for(purpose: &str, seed: &[u8; 32]) -> BlindingKey {
        match purpose {
            BLINDING_PURPOSE_SESSION => BlindingKey::session(seed),
            BLINDING_PURPOSE_BROWSER_PROXY => BlindingKey::browser_proxy(seed),
            other => panic!("unknown blinding purpose {other}"),
        }
    }

    fn issuer_key(v: &Value) -> IssuerPublicKey {
        let pk = IssuerPublicKey::from_spki(&bytes(&v["issuer"]["spki_hex"])).expect("vector key");
        assert_eq!(
            pk.key_id().as_bytes().as_slice(),
            bytes(&v["issuer"]["token_key_id_hex"]).as_slice()
        );
        pk
    }

    #[test]
    fn the_vector_seed_is_the_identity_seed_of_the_vector_mnemonic() {
        let v = corpus();
        let mnemonic = v["wallet"]["mnemonic"].as_str().expect("mnemonic");

        assert_eq!(*seed_from_mnemonic(mnemonic).expect("valid"), seed(&v));
    }

    #[test]
    fn each_class_derives_the_vector_blinding_key() {
        let v = corpus();
        let seed = seed(&v);
        for entry in v["blinding_keys"].as_array().expect("blinding_keys") {
            let purpose = entry["purpose"].as_str().expect("purpose");

            let key = key_for(purpose, &seed);

            assert_eq!(key.key.as_slice(), bytes(&entry["key_hex"]), "{purpose}");
        }
    }

    #[test]
    fn each_slot_draws_the_vector_nonce_salt_and_blinding_draw_in_order() {
        let v = corpus();
        let seed = seed(&v);
        for batch in v["batches"].as_array().expect("batches") {
            let key = key_for(batch["purpose"].as_str().expect("purpose"), &seed);
            let epoch = batch["epoch"].as_u64().expect("epoch");
            for slot in batch["slots"].as_array().expect("slots") {
                let index = u32::try_from(slot["index"].as_u64().expect("index")).expect("u32");
                let mut stream = key.stream(epoch, index);

                assert_eq!(*stream.draw(32), bytes(&slot["nonce_hex"]));
                assert_eq!(*stream.draw(48), bytes(&slot["salt_hex"]));
                assert_eq!(*stream.draw(256), bytes(&slot["blinding_draw_hex"]));
            }
        }
    }

    #[test]
    fn the_engine_receives_the_vector_blinding_factor_as_its_third_draw() {
        let v = corpus();
        let seed = seed(&v);
        let modulus = Modulus::of(&issuer_key(&v)).expect("the vector modulus");
        assert_eq!(
            modulus.n.to_be_bytes().as_ref(),
            bytes(&v["issuer"]["modulus_hex"]).as_slice()
        );
        for batch in v["batches"].as_array().expect("batches") {
            let key = key_for(batch["purpose"].as_str().expect("purpose"), &seed);
            let epoch = batch["epoch"].as_u64().expect("epoch");
            for slot in batch["slots"].as_array().expect("slots") {
                let index = u32::try_from(slot["index"].as_u64().expect("index")).expect("u32");
                let mut rng = SlotRng::new(key.stream(epoch, index), &modulus);
                let (mut nonce, mut salt, mut factor) = ([0u8; 32], [0u8; 48], [0u8; 256]);

                rng.try_fill_bytes(&mut nonce).expect("infallible");
                rng.try_fill_bytes(&mut salt).expect("infallible");
                rng.try_fill_bytes(&mut factor).expect("infallible");

                factor.reverse();
                assert_eq!(factor.as_slice(), bytes(&slot["blinding_factor_hex"]));
                assert_eq!(nonce.as_slice(), bytes(&slot["nonce_hex"]));
                assert_eq!(salt.as_slice(), bytes(&slot["salt_hex"]));
                rng.finish().expect("the defined draw order");
            }
        }
    }

    #[test]
    fn each_slot_blinds_to_the_vector_message_and_finalizes_to_the_vector_token() {
        let v = corpus();
        let seed = seed(&v);
        let pk = issuer_key(&v);
        let issuer = &v["issuer"];
        for batch in v["batches"].as_array().expect("batches") {
            let key = key_for(batch["purpose"].as_str().expect("purpose"), &seed);
            let epoch = batch["epoch"].as_u64().expect("epoch");
            let challenge = TokenChallenge::for_epoch(
                issuer["name"].as_str().expect("name"),
                issuer["context_label"].as_str().expect("label"),
                epoch,
            )
            .expect("challenge");
            assert_eq!(
                challenge.digest().as_slice(),
                bytes(&batch["challenge_digest_hex"])
            );
            for slot in batch["slots"].as_array().expect("slots") {
                let index = u32::try_from(slot["index"].as_u64().expect("index")).expect("u32");

                let (blinded, state) = key
                    .blind_slot(&pk, &challenge, epoch, index)
                    .expect("blind");
                let token = pk
                    .finalize_token(state, &bytes(&slot["blind_signature_hex"]))
                    .expect("finalize");

                assert_eq!(blinded, bytes(&slot["blinded_hex"]), "slot {index}");
                assert_eq!(token.serialize().as_slice(), bytes(&slot["token_hex"]));
            }
        }
    }

    #[test]
    fn a_draw_order_the_derivation_does_not_define_is_refused() {
        let v = corpus();
        let modulus = Modulus::of(&issuer_key(&v)).expect("the vector modulus");
        let key = BlindingKey::session(&seed(&v));
        for order in [&[32, 256][..], &[48, 32, 256], &[32, 48, 256, 256]] {
            let mut rng = SlotRng::new(key.stream(1, 0), &modulus);

            for &len in order {
                rng.try_fill_bytes(&mut vec![0u8; len]).expect("infallible");
            }

            assert!(
                matches!(rng.finish(), Err(TokenClientError::BlindingDrawOrder)),
                "{order:?}"
            );
        }
    }

    #[test]
    fn a_draw_that_is_not_a_unit_above_one_is_redrawn_from_the_running_stream() {
        // Unreachable with a real 2048-bit modulus, so no vector reaches it:
        // a modulus of 6 (units 1 and 5) makes most draws fail the rule.
        let modulus = Modulus {
            n: NonZero::new(BoxedUint::from_be_slice(&[6], 2048).expect("fits")).expect("non-zero"),
            len: 256,
        };
        let key = BlindingKey::session(&[9; 32]);
        let mut reference = key.stream(3, 1);
        reference.draw(NONCE_DRAW);
        reference.draw(SALT_DRAW);
        let mut rejected = 0;
        let expected = loop {
            let draw = reference.draw(256);
            let r = draw
                .iter()
                .fold(0u64, |acc, &b| (acc * 256 + u64::from(b)) % 6);
            if r == 5 {
                break r;
            }
            rejected += 1;
        };
        assert!(rejected > 0, "the stream must exercise at least one redraw");
        let mut rng = SlotRng::new(key.stream(3, 1), &modulus);
        let (mut nonce, mut salt, mut factor) = ([0u8; 32], [0u8; 48], [0u8; 256]);

        rng.try_fill_bytes(&mut nonce).expect("infallible");
        rng.try_fill_bytes(&mut salt).expect("infallible");
        rng.try_fill_bytes(&mut factor).expect("infallible");

        assert_eq!(factor[0], u8::try_from(expected).expect("small"));
        assert!(factor[1..].iter().all(|&b| b == 0));
        rng.finish().expect("one factor draw as the engine sees it");
    }

    #[test]
    fn a_blinding_key_renders_its_class_and_never_its_bytes() {
        let key = BlindingKey::browser_proxy(&[7; 32]);

        let rendered = format!("{key:?}");

        assert!(rendered.contains("BrowserProxy"), "{rendered}");
        assert!(!rendered.contains(&hex::encode(*key.key)), "{rendered}");
        assert!(!rendered.contains(&format!("{:?}", *key.key)), "{rendered}");
    }
}
