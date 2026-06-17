//! BIP39 mnemonic generation and seed derivation.
//!
//! Warren identity is non-custodial: a 12-word BIP39 mnemonic (128 bits of
//! entropy) is the sole secret. The BIP39 passphrase is intentionally empty so
//! the mnemonic alone reproduces the identity. Any future second factor comes
//! from an upper layer (local keyring), never from BIP39.

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize, Zeroizing};

/// Errors from parsing or generating a BIP39 mnemonic.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MnemonicError {
    /// Invalid BIP39 mnemonic (unexpected length, unknown word, bad checksum).
    #[error("invalid BIP39 mnemonic: {0}")]
    Invalid(#[from] bip39::Error),
}

/// Generates a fresh 12-word English BIP39 mnemonic.
///
/// 12 words encode 128 bits of entropy, which is sufficient for a 256-bit
/// symmetric-key scheme and is the Warren standard.
#[must_use]
pub fn generate() -> String {
    Mnemonic::generate(12)
        .expect("BIP39 12-word generation never fails for a valid word count")
        .to_string()
}

/// Converts a BIP39 mnemonic phrase (12 or 24 English words) to the 32-byte
/// seed fed to the HKDF key derivation.
///
/// A BIP39 seed is natively 64 bytes (PBKDF2-SHA512). Warren keeps only the
/// first 32 and feeds them to HKDF-SHA256. This truncation is safe because
/// HKDF re-mixes the input with its salt and info, so no usable entropy is
/// lost beyond 32 bytes in a 256-bit symmetric-key scheme.
///
/// The result is wrapped in [`Zeroizing`] so the 32 secret bytes are wiped at
/// drop, even on an intermediate panic.
///
/// # Errors
///
/// BIP39 parsing error (unknown word, invalid length, bad checksum).
pub fn seed_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<[u8; 32]>, MnemonicError> {
    // Pin English explicitly: `Mnemonic::parse` auto-detects the language from
    // the bip39 crate's enabled features, so enabling another wordlist feature
    // would silently change which words decode and therefore the derived seed
    // (the identity). The frozen contract is English-only.
    let parsed = Mnemonic::parse_in_normalized(Language::English, mnemonic)?;
    let mut full_seed = parsed.to_seed_normalized("");
    let mut seed32 = Zeroizing::new([0u8; 32]);
    seed32.copy_from_slice(&full_seed[..32]);
    full_seed.zeroize();
    Ok(seed32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC_24_ZERO: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn generate_yields_twelve_valid_words() {
        let m = generate();
        assert_eq!(m.split_whitespace().count(), 12);
        seed_from_mnemonic(&m).expect("generated mnemonic must be valid");
    }

    #[test]
    fn two_generated_mnemonics_differ() {
        assert_ne!(generate(), generate());
    }

    #[test]
    fn seed_from_mnemonic_is_deterministic() {
        let s1 = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid mnemonic");
        let s2 = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid mnemonic");
        assert_eq!(s1, s2);
    }

    #[test]
    fn seed_from_mnemonic_is_not_all_zero() {
        let seed = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid mnemonic");
        assert_ne!(*seed, [0u8; 32], "seed must not be all-zero (stub leak?)");
    }

    #[test]
    fn different_mnemonics_produce_different_seeds() {
        let m2 = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        let s1 = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid m1");
        let s2 = seed_from_mnemonic(m2).expect("valid m2");
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn seed_from_mnemonic_pins_the_english_derivation_bytes() {
        // Golden lock on the exact 32-byte seed (BIP39 PBKDF2-SHA512, empty
        // passphrase, first 32 bytes). Any change to the language pin or the
        // derivation would flip these bytes and break every existing identity.
        const EXPECTED: [u8; 32] = [
            0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93,
            0x24, 0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f,
            0xc4, 0x9a, 0xcf, 0x70,
        ];
        let seed = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid mnemonic");
        assert_eq!(*seed, EXPECTED);
    }

    #[test]
    fn seed_from_mnemonic_rejects_invalid() {
        assert!(seed_from_mnemonic("foo bar baz").is_err());
    }

    #[test]
    fn seed_from_mnemonic_rejects_bad_checksum() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(seed_from_mnemonic(bad).is_err());
    }
}
