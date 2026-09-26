//! Route admission by anchor, as the session token directory announces it
//! (warren-core doc 107, sections 8.1 and 10.2).
//!
//! The directory's `route_admission` block tells a client which key to seal
//! its route anchor to, how many routes one anchor admits, and which exits
//! admit routes that way. [`RouteAdmission`] is that block once validated:
//! a version this build implements, a KEM key signed by a server key the
//! client pins (doc 107 section 6.5), a usable X25519 point under a
//! non-reserved key id, a non-zero route limit. The engine takes the key as
//! is (`RouteAnchorConfig { kem }`); nothing here carries the anchor secret,
//! which the engine draws and keeps.
//!
//! The document travels over TLS only, and whoever could serve a key of its
//! own would open every anchor and locator sealed to it, linking the device's
//! main session to its routes across exits. So the key is used only under the
//! signature of the API server key, the one the client already pins for the
//! signed relay list and the multi-hop directory; an unsigned or badly signed
//! block reads as no route admission. Every route the block cannot admit
//! falls back to a token route, so validation never fails the directory,
//! whose tokens every main session needs.

use std::collections::BTreeSet;

use warren_contract::dto::{ROUTE_ADMISSION_VERSION, RouteAdmissionInfo, TokenIssuerDirectory};
use warren_contract::route_kem::{self, RouteKemSignatureError};
use warrenguard_multihop::{RouteKemPublicKey, RouteSealError};

/// Why a directory's route admission block cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteAdmissionError {
    /// The block has a version this build does not implement.
    #[error("route admission block version {version} is not supported")]
    UnsupportedVersion {
        /// The version the block announces.
        version: u32,
    },
    /// No pinned server key vouches for the route KEM key (unsigned, badly
    /// signed, expired, or no key pinned).
    #[error("route admission key is not vouched for by a pinned server key")]
    Unauthenticated(#[source] RouteKemSignatureError),
    /// The route KEM key uses the reserved key id, or is not a usable
    /// X25519 point.
    #[error("route admission key is unusable")]
    UnusableKey(#[source] RouteSealError),
    /// The block admits no route per anchor.
    #[error("route admission block admits no route")]
    NoRoutes,
}

/// A validated route admission block: the key route anchors and locators
/// are sealed to, the most routes one anchor holds, and the exits that admit
/// routes by anchor.
#[derive(Clone)]
pub struct RouteAdmission {
    kem: RouteKemPublicKey,
    max_routes_per_anchor: u32,
    exits: BTreeSet<[u8; 16]>,
}

impl RouteAdmission {
    /// The directory's block, validated. `Ok(None)` when the directory
    /// carries none (the server has route admission off, or predates it).
    ///
    /// # Errors
    ///
    /// See [`Self::from_info`].
    pub fn from_directory(
        directory: &TokenIssuerDirectory,
        pinned_server_keys: &[&str],
        now_unix_secs: u64,
    ) -> Result<Option<Self>, RouteAdmissionError> {
        directory
            .route_admission
            .as_ref()
            .map(|info| Self::from_info(info, pinned_server_keys, now_unix_secs))
            .transpose()
    }

    /// Validates one block, its KEM key signed by one of
    /// `pinned_server_keys` (64-char hex Ed25519 keys) and still valid at
    /// `now_unix_secs`.
    ///
    /// # Errors
    ///
    /// [`RouteAdmissionError::UnsupportedVersion`] for a version other than
    /// [`ROUTE_ADMISSION_VERSION`], [`RouteAdmissionError::Unauthenticated`]
    /// for a key no pinned server key vouches for,
    /// [`RouteAdmissionError::UnusableKey`] for a key that cannot seal,
    /// [`RouteAdmissionError::NoRoutes`] for a zero route limit.
    pub fn from_info(
        info: &RouteAdmissionInfo,
        pinned_server_keys: &[&str],
        now_unix_secs: u64,
    ) -> Result<Self, RouteAdmissionError> {
        if info.version != ROUTE_ADMISSION_VERSION {
            return Err(RouteAdmissionError::UnsupportedVersion {
                version: info.version,
            });
        }
        route_kem::verify(info, pinned_server_keys, now_unix_secs)
            .map_err(RouteAdmissionError::Unauthenticated)?;
        if info.max_routes_per_anchor == 0 {
            return Err(RouteAdmissionError::NoRoutes);
        }
        // `PubkeyHex` already holds 64 lowercase hex characters.
        let bytes: [u8; 32] = hex::decode(info.kem_pubkey_hex.as_str())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(RouteAdmissionError::UnusableKey(
                RouteSealError::InvalidPublicKey,
            ))?;
        let kem = RouteKemPublicKey::new(info.kem_key_id, bytes)
            .map_err(RouteAdmissionError::UnusableKey)?;
        Ok(Self {
            kem,
            max_routes_per_anchor: info.max_routes_per_anchor,
            exits: info
                .exit_ids_hex
                .iter()
                .map(|exit| *exit.as_bytes())
                .collect(),
        })
    }

    /// The key the engine seals the anchor and each route locator to.
    #[must_use]
    pub fn kem(&self) -> &RouteKemPublicKey {
        &self.kem
    }

    /// The most route sessions one anchor admits at once.
    #[must_use]
    pub fn max_routes_per_anchor(&self) -> u32 {
        self.max_routes_per_anchor
    }

    /// Whether the exit with this multihop id admits routes by anchor.
    #[must_use]
    pub fn offers_routes(&self, exit_id: &[u8; 16]) -> bool {
        self.exits.contains(exit_id)
    }
}

// Exit ids name the fleet's exits: render counts only.
impl std::fmt::Debug for RouteAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteAdmission")
            .field("kem", &self.kem)
            .field("max_routes_per_anchor", &self.max_routes_per_anchor)
            .field("exits", &self.exits.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use warren_contract::dto::{ExitId, PubkeyHex};
    use warrenguard_multihop::RouteKemSecretKey;

    use super::*;

    const SERVER_SEED: [u8; 32] = [0x71; 32];
    const NOW: u64 = 1_800_000_000;

    fn published_key() -> RouteKemPublicKey {
        RouteKemSecretKey::derive(&SERVER_SEED, 1)
            .expect("key id 1")
            .public_key()
            .clone()
    }

    fn server_pin() -> String {
        hex::encode(
            SigningKey::from_bytes(&SERVER_SEED)
                .verifying_key()
                .as_bytes(),
        )
    }

    /// `info` as the server signs it, after any change a test makes.
    fn signed(mut info: RouteAdmissionInfo) -> RouteAdmissionInfo {
        info.kem_signature = Some(warren_contract::route_kem::sign(
            &info,
            &SigningKey::from_bytes(&SERVER_SEED),
            NOW + 86_400,
        ));
        info
    }

    fn unsigned() -> RouteAdmissionInfo {
        RouteAdmissionInfo {
            version: ROUTE_ADMISSION_VERSION,
            kem_key_id: 1,
            kem_pubkey_hex: PubkeyHex::try_from(hex::encode(published_key().to_bytes()).as_str())
                .expect("64 hex"),
            max_routes_per_anchor: 32,
            exit_ids_hex: vec![ExitId::from_bytes([3; 16]), ExitId::from_bytes([4; 16])],
            kem_signature: None,
        }
    }

    fn info() -> RouteAdmissionInfo {
        signed(unsigned())
    }

    fn check(info: &RouteAdmissionInfo) -> Result<RouteAdmission, RouteAdmissionError> {
        RouteAdmission::from_info(info, &[server_pin().as_str()], NOW)
    }

    #[test]
    fn a_valid_block_carries_the_published_key_limit_and_exits() {
        let admission = check(&info()).expect("valid");

        assert_eq!(admission.kem().to_bytes(), published_key().to_bytes());
        assert_eq!(admission.kem().key_id(), 1);
        assert_eq!(admission.max_routes_per_anchor(), 32);
        assert!(admission.offers_routes(&[3; 16]));
        assert!(admission.offers_routes(&[4; 16]));
        assert!(!admission.offers_routes(&[5; 16]));
    }

    #[test]
    fn an_unsigned_key_is_never_used() {
        assert_eq!(
            check(&unsigned()).err(),
            Some(RouteAdmissionError::Unauthenticated(
                RouteKemSignatureError::Unsigned
            ))
        );
    }

    #[test]
    fn a_key_substituted_under_the_servers_signature_is_refused() {
        let mut forged = info();
        let other = RouteKemSecretKey::derive(&[0x72; 32], 1).expect("key id 1");
        forged.kem_pubkey_hex =
            PubkeyHex::try_from(hex::encode(other.public_key().to_bytes()).as_str())
                .expect("64 hex");

        assert_eq!(
            check(&forged).err(),
            Some(RouteAdmissionError::Unauthenticated(
                RouteKemSignatureError::BadSignature
            ))
        );
    }

    #[test]
    fn a_key_signed_by_an_unpinned_server_is_refused() {
        let other_pin = hex::encode(
            SigningKey::from_bytes(&[0x09; 32])
                .verifying_key()
                .as_bytes(),
        );

        assert_eq!(
            RouteAdmission::from_info(&info(), &[other_pin.as_str()], NOW).err(),
            Some(RouteAdmissionError::Unauthenticated(
                RouteKemSignatureError::BadSignature
            ))
        );
    }

    #[test]
    fn an_expired_signature_is_refused() {
        assert_eq!(
            RouteAdmission::from_info(&info(), &[server_pin().as_str()], NOW + 86_400).err(),
            Some(RouteAdmissionError::Unauthenticated(
                RouteKemSignatureError::Expired
            ))
        );
    }

    #[test]
    fn a_later_block_version_is_not_used() {
        let mut later = unsigned();
        later.version = ROUTE_ADMISSION_VERSION + 1;

        assert_eq!(
            check(&signed(later)).err(),
            Some(RouteAdmissionError::UnsupportedVersion {
                version: ROUTE_ADMISSION_VERSION + 1
            })
        );
    }

    #[test]
    fn a_small_order_point_is_refused() {
        let mut weak = unsigned();
        weak.kem_pubkey_hex = PubkeyHex::try_from("00".repeat(32).as_str()).expect("64 hex");

        assert_eq!(
            check(&signed(weak)).err(),
            Some(RouteAdmissionError::UnusableKey(
                RouteSealError::InvalidPublicKey
            ))
        );
    }

    #[test]
    fn the_reserved_key_id_is_refused() {
        let mut reserved = unsigned();
        reserved.kem_key_id = 0;

        assert_eq!(
            check(&signed(reserved)).err(),
            Some(RouteAdmissionError::UnusableKey(
                RouteSealError::ReservedKeyId
            ))
        );
    }

    #[test]
    fn a_block_admitting_no_route_is_not_used() {
        let mut none = info();
        none.max_routes_per_anchor = 0;

        assert_eq!(check(&none).err(), Some(RouteAdmissionError::NoRoutes));
    }

    #[test]
    fn debug_names_no_exit() {
        let rendered = format!("{:?}", check(&info()).unwrap());

        assert!(
            !rendered.contains("[3, 3") && !rendered.contains("0303"),
            "{rendered}"
        );
        assert!(rendered.contains("exits: 2"), "{rendered}");
    }
}
