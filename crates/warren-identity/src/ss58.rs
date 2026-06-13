//! SS58 codec for the Warren wallet identity public key.
//!
//! The Warren user identity is a 32-byte Ed25519 public key. Its canonical
//! string representation, everywhere it is rendered as text (the
//! `X-Warren-PubKey` auth header, JSON bodies, config files, logs, UI, FFI
//! surface), is an SS58 address with Warren's network prefix
//! [`WARREN_SS58_PREFIX`] (`13295`).
//!
//! SS58 is the Substrate/Polkadot address format: it encodes the same 32 raw
//! bytes plus a 2-byte network prefix and a 2-byte Blake2b checksum. Decode an
//! address back to the 32 bytes at the crypto boundary; encode the 32 bytes to
//! an address at the string boundary.
//!
//! # Why prefix 13295
//!
//! Prefix `13295` makes every Warren address start with `wb` (Warren Browse)
//! and run 47 to 49 characters. It is a branding choice and a cheap human
//! sanity check.
//!
//! # Wire compatibility
//!
//! This codec is byte-for-byte identical to `@polkadot/util-crypto`
//! `encodeAddress(pubkey, 13295)` / `decodeAddress`, and to warren-core's
//! `warren-ss58`. The vectors in `vectors/identity.json` pin the exact
//! strings; any divergence here or in a sibling-language SDK fails the shared
//! vector test.
//!
//! # Algorithm
//!
//! ```text
//! prefix_bytes = ss58_prefix_encoding(13295)            // 2 bytes here
//! checksum     = blake2b_512("SS58PRE" || prefix_bytes || pubkey)[..2]
//! address      = base58( prefix_bytes || pubkey || checksum )
//! ```

use blake2::{Blake2b512, Digest};

/// Warren's SS58 network prefix. Chosen so every encoded address starts with
/// the `wb` base58 prefix. Valid SS58 prefixes are 14-bit (`0..=16383`);
/// `13295` sits in the two-byte-encoded range (`64..=16383`).
pub const WARREN_SS58_PREFIX: u16 = 13295;

/// SS58 checksum domain-separation tag, mandated by the spec.
const SS58_CHECKSUM_PREFIX: &[u8] = b"SS58PRE";

/// Raw Ed25519 public-key length (the SS58 payload for an AccountId32).
const PUBKEY_LEN: usize = 32;

/// Checksum length appended after the payload (2 bytes for a 32-byte id).
const CHECKSUM_LEN: usize = 2;

/// Length of the two-byte prefix encoding used for `13295`.
const PREFIX_LEN: usize = 2;

/// Total decoded length: `prefix(2) + pubkey(32) + checksum(2)`.
const DECODED_LEN: usize = PREFIX_LEN + PUBKEY_LEN + CHECKSUM_LEN;

/// Hard cap on accepted textual address length. A 36-byte payload encodes to
/// 47 to 49 base58 chars; 64 leaves slack while keeping the O(n^2) base58
/// decoder away from unauthenticated megabyte inputs (this codec parses the
/// `X-Warren-PubKey` header before any signature check).
const MAX_ADDRESS_LEN: usize = 64;

/// Number of leading characters kept by [`shorten`].
pub const SHORT_HEAD: usize = 6;
/// Number of trailing characters kept by [`shorten`].
pub const SHORT_TAIL: usize = 6;

/// Errors returned when decoding an SS58 string into a Warren pubkey.
///
/// Exhaustive: the SS58 format has exactly these four failure modes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Ss58Error {
    /// The string is not valid base58.
    #[error("not valid base58")]
    BadBase58,
    /// The decoded byte length is not `prefix(2) + pubkey(32) + checksum(2)`.
    #[error("unexpected decoded length (not a 32-byte SS58 account address)")]
    BadLength,
    /// The address encodes a different SS58 network prefix than
    /// [`WARREN_SS58_PREFIX`].
    #[error("wrong SS58 network prefix (not a Warren `wb…` address)")]
    WrongNetwork,
    /// The Blake2b checksum does not match (corrupt or mistyped address).
    #[error("SS58 checksum mismatch (corrupt or mistyped address)")]
    BadChecksum,
}

/// Encodes the two-byte SS58 prefix for a 14-bit network ident in the
/// `64..=16383` range, per the Substrate spec.
fn encode_prefix(prefix: u16) -> [u8; PREFIX_LEN] {
    let ident = prefix & 0b0011_1111_1111_1111;
    let first = ((ident & 0b0000_0000_1111_1100) >> 2) as u8 | 0b0100_0000;
    let second = ((ident >> 8) as u8) | (((ident & 0b0000_0000_0000_0011) << 6) as u8);
    [first, second]
}

/// Computes the 2-byte SS58 checksum over `prefix_bytes || pubkey`.
fn checksum(prefix_bytes: &[u8], pubkey: &[u8; PUBKEY_LEN]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Blake2b512::new();
    hasher.update(SS58_CHECKSUM_PREFIX);
    hasher.update(prefix_bytes);
    hasher.update(pubkey);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

/// Encodes a raw 32-byte Ed25519 public key as a Warren SS58 address (`wb…`).
///
/// Infallible: every 32-byte input maps to a valid address.
#[must_use]
pub fn encode(pubkey: &[u8; PUBKEY_LEN]) -> String {
    let prefix_bytes = encode_prefix(WARREN_SS58_PREFIX);
    let cs = checksum(&prefix_bytes, pubkey);

    let mut buf = [0u8; DECODED_LEN];
    buf[..PREFIX_LEN].copy_from_slice(&prefix_bytes);
    buf[PREFIX_LEN..PREFIX_LEN + PUBKEY_LEN].copy_from_slice(pubkey);
    buf[PREFIX_LEN + PUBKEY_LEN..].copy_from_slice(&cs);

    bs58::encode(buf).into_string()
}

/// Decodes a Warren SS58 address back into the raw 32-byte Ed25519 public key.
///
/// Strictly validates the network prefix ([`WARREN_SS58_PREFIX`]) and the
/// Blake2b checksum, so a corrupt, mistyped, or foreign-network address is
/// rejected rather than silently coerced.
///
/// # Errors
///
/// See [`Ss58Error`].
pub fn decode(address: &str) -> Result<[u8; PUBKEY_LEN], Ss58Error> {
    // Cheap length gate BEFORE the O(n^2) base58 decode: this runs on
    // unauthenticated input (auth header), so an oversized string must never
    // reach the quadratic path.
    if address.len() > MAX_ADDRESS_LEN {
        return Err(Ss58Error::BadLength);
    }

    let data = bs58::decode(address)
        .into_vec()
        .map_err(|_| Ss58Error::BadBase58)?;

    if data.len() != DECODED_LEN {
        return Err(Ss58Error::BadLength);
    }

    let expected_prefix = encode_prefix(WARREN_SS58_PREFIX);
    if data[..PREFIX_LEN] != expected_prefix {
        return Err(Ss58Error::WrongNetwork);
    }

    let pubkey: [u8; PUBKEY_LEN] = data[PREFIX_LEN..PREFIX_LEN + PUBKEY_LEN]
        .try_into()
        .expect("slice length checked above");

    let expected_cs = checksum(&expected_prefix, &pubkey);
    if data[PREFIX_LEN + PUBKEY_LEN..] != expected_cs {
        return Err(Ss58Error::BadChecksum);
    }

    Ok(pubkey)
}

/// Returns `true` if `address` is a well-formed Warren SS58 address (correct
/// prefix and checksum).
#[must_use]
pub fn is_valid(address: &str) -> bool {
    decode(address).is_ok()
}

/// Shortens an address for compact display, Polkadot-style: `wb7kgy…hP9DnB`
/// (first [`SHORT_HEAD`] + `…` + last [`SHORT_TAIL`]).
///
/// Strings too short to shorten are returned unchanged. Presentation only: the
/// full address is what goes on the wire.
#[must_use]
pub fn shorten(address: &str) -> String {
    let len = address.chars().count();
    if len <= SHORT_HEAD + SHORT_TAIL + 1 {
        return address.to_owned();
    }
    let head: String = address.chars().take(SHORT_HEAD).collect();
    let tail: String = address.chars().skip(len - SHORT_TAIL).collect::<String>();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s)
            .expect("test hex")
            .try_into()
            .expect("32 bytes")
    }

    #[test]
    fn every_warren_address_starts_with_wb() {
        for i in 0u8..32 {
            let addr = encode(&[i; 32]);
            assert!(addr.starts_with("wb"), "address must start with wb: {addr}");
        }
    }

    #[test]
    fn roundtrip_is_stable_over_many_keys() {
        for i in 0u8..=255 {
            let pubkey = [i; 32];
            let addr = encode(&pubkey);
            assert_eq!(decode(&addr).expect("roundtrip"), pubkey);
        }
    }

    #[test]
    fn decode_rejects_non_base58() {
        assert_eq!(decode("0OIl not base58"), Err(Ss58Error::BadBase58));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(decode("abc"), Err(Ss58Error::BadLength));
    }

    #[test]
    fn decode_rejects_oversized_input_before_base58() {
        let oversized = "1".repeat(10_000);
        assert_eq!(decode(&oversized), Err(Ss58Error::BadLength));
        let just_over = "1".repeat(MAX_ADDRESS_LEN + 1);
        assert_eq!(decode(&just_over), Err(Ss58Error::BadLength));
    }

    #[test]
    fn decode_rejects_foreign_network_prefix() {
        // The same 32 bytes (0x11..) encoded for SS58 network prefix 1000.
        let foreign_addr = "vjdfteK8ZU3Lg6jotudWVQk1eGD7GEnb46Xv5JdmKpQD2WB1r";
        assert_eq!(decode(foreign_addr), Err(Ss58Error::WrongNetwork));
    }

    #[test]
    fn decode_rejects_corrupt_checksum() {
        let good = encode(&[0x11; 32]);
        let mut chars: Vec<char> = good.chars().collect();
        let idx = chars.len() / 2;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        let corrupt: String = chars.into_iter().collect();
        assert!(decode(&corrupt).is_err());
    }

    #[test]
    fn shorten_keeps_head_and_tail() {
        let addr = "wb7kgy8FF4rx4tamkksPfoymeeeZVXLrnSjbBxCun3XhP9DnB";
        assert_eq!(shorten(addr), "wb7kgy…hP9DnB");
    }

    #[test]
    fn shorten_leaves_short_strings_untouched() {
        assert_eq!(shorten("wb7kgy"), "wb7kgy");
        assert_eq!(shorten("short"), "short");
    }

    #[test]
    fn is_valid_matches_decode() {
        let addr = encode(&[0x42; 32]);
        assert!(is_valid(&addr));
        assert!(!is_valid("definitely not an address"));
    }

    #[test]
    fn known_zero_key_address() {
        // One inline anchor; the full vector set lives in vectors/identity.json.
        assert_eq!(
            encode(&hex32(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            "wb7kgy8FF4rx4tamkksPfoymeeeZVXLrnSjbBxCun3XhP9DnB"
        );
    }
}
