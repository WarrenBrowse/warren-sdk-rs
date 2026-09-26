//! Route admission by anchor, as the session token directory announces it
//! (warren-core doc 107, sections 8.1 and 10.2).
//!
//! The directory's `route_admission` block tells a client which key to seal
//! its route anchor to, how many routes one anchor admits, and which exits
//! admit routes that way. [`RouteAdmission`] is that block once validated:
//! a version this build implements, a usable X25519 point under a
//! non-reserved key id, a non-zero route limit. The engine takes the key as
//! is (`RouteAnchorConfig { kem }`); nothing here carries the anchor secret,
//! which the engine draws and keeps.
//!
//! The block is advisory and unsigned beyond TLS: an unreadable one reads as
//! absent, and every route the block cannot admit falls back to a token
//! route. So validation never fails the directory, whose tokens every main
//! session needs.

use std::collections::BTreeSet;

use warren_contract::dto::{ROUTE_ADMISSION_VERSION, RouteAdmissionInfo, TokenIssuerDirectory};
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
    ) -> Result<Option<Self>, RouteAdmissionError> {
        directory
            .route_admission
            .as_ref()
            .map(Self::from_info)
            .transpose()
    }

    /// Validates one block.
    ///
    /// # Errors
    ///
    /// [`RouteAdmissionError::UnsupportedVersion`] for a version other than
    /// [`ROUTE_ADMISSION_VERSION`], [`RouteAdmissionError::UnusableKey`] for a
    /// key that cannot seal, [`RouteAdmissionError::NoRoutes`] for a zero
    /// route limit.
    pub fn from_info(info: &RouteAdmissionInfo) -> Result<Self, RouteAdmissionError> {
        if info.version != ROUTE_ADMISSION_VERSION {
            return Err(RouteAdmissionError::UnsupportedVersion {
                version: info.version,
            });
        }
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
    use warren_contract::dto::{ExitId, PubkeyHex};
    use warrenguard_multihop::RouteKemSecretKey;

    use super::*;

    fn published_key() -> RouteKemPublicKey {
        RouteKemSecretKey::derive(&[0x71; 32], 1)
            .expect("key id 1")
            .public_key()
            .clone()
    }

    fn info() -> RouteAdmissionInfo {
        RouteAdmissionInfo {
            version: ROUTE_ADMISSION_VERSION,
            kem_key_id: 1,
            kem_pubkey_hex: PubkeyHex::try_from(hex::encode(published_key().to_bytes()).as_str())
                .expect("64 hex"),
            max_routes_per_anchor: 32,
            exit_ids_hex: vec![ExitId::from_bytes([3; 16]), ExitId::from_bytes([4; 16])],
        }
    }

    #[test]
    fn a_valid_block_carries_the_published_key_limit_and_exits() {
        let admission = RouteAdmission::from_info(&info()).expect("valid");

        assert_eq!(admission.kem().to_bytes(), published_key().to_bytes());
        assert_eq!(admission.kem().key_id(), 1);
        assert_eq!(admission.max_routes_per_anchor(), 32);
        assert!(admission.offers_routes(&[3; 16]));
        assert!(admission.offers_routes(&[4; 16]));
        assert!(!admission.offers_routes(&[5; 16]));
    }

    #[test]
    fn a_later_block_version_is_not_used() {
        let mut later = info();
        later.version = ROUTE_ADMISSION_VERSION + 1;

        assert_eq!(
            RouteAdmission::from_info(&later).err(),
            Some(RouteAdmissionError::UnsupportedVersion {
                version: ROUTE_ADMISSION_VERSION + 1
            })
        );
    }

    #[test]
    fn a_small_order_point_is_refused() {
        let mut weak = info();
        weak.kem_pubkey_hex = PubkeyHex::try_from("00".repeat(32).as_str()).expect("64 hex");

        assert_eq!(
            RouteAdmission::from_info(&weak).err(),
            Some(RouteAdmissionError::UnusableKey(
                RouteSealError::InvalidPublicKey
            ))
        );
    }

    #[test]
    fn the_reserved_key_id_is_refused() {
        let mut reserved = info();
        reserved.kem_key_id = 0;

        assert_eq!(
            RouteAdmission::from_info(&reserved).err(),
            Some(RouteAdmissionError::UnusableKey(
                RouteSealError::ReservedKeyId
            ))
        );
    }

    #[test]
    fn a_block_admitting_no_route_is_not_used() {
        let mut none = info();
        none.max_routes_per_anchor = 0;

        assert_eq!(
            RouteAdmission::from_info(&none).err(),
            Some(RouteAdmissionError::NoRoutes)
        );
    }

    #[test]
    fn debug_names_no_exit() {
        let rendered = format!("{:?}", RouteAdmission::from_info(&info()).unwrap());

        assert!(!rendered.contains("0303"), "{rendered}");
        assert!(rendered.contains("exits: 2"), "{rendered}");
    }
}
