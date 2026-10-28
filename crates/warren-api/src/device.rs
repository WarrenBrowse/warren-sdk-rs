//! This install's identity in the account's device registry (warren-core doc
//! 115): a random identifier and a generated name.
//!
//! The name is drawn here, from word lists the SDK carries, so every Warren
//! client names its devices the same way whatever language it is written in:
//! the sibling SDKs reach this code over their bridges. Nothing in either
//! value is derived from the wallet or the hardware.

use std::fmt;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::dto::{DEVICE_ID_LEN, DeviceId, DevicePlatform, DeviceRegistration};

/// The first word of a generated device name.
pub const DEVICE_NAME_ADJECTIVES: [&str; 40] = [
    "amber", "bold", "brave", "bright", "calm", "clever", "cosy", "crisp", "curious", "dapper",
    "eager", "fair", "gentle", "glad", "golden", "happy", "honest", "jolly", "keen", "kind",
    "lively", "lucky", "merry", "mighty", "nimble", "noble", "patient", "plucky", "proud", "quick",
    "quiet", "rapid", "shy", "silver", "sleek", "steady", "sunny", "swift", "tidy", "witty",
];

/// The second word of a generated device name.
pub const DEVICE_NAME_ANIMALS: [&str; 40] = [
    "badger", "beaver", "bison", "crane", "deer", "dolphin", "eagle", "falcon", "ferret", "finch",
    "fox", "gecko", "hare", "hedgehog", "heron", "ibis", "jackal", "koala", "lemur", "lynx",
    "marten", "mole", "moose", "newt", "otter", "owl", "panda", "puffin", "rabbit", "raven",
    "robin", "seal", "sparrow", "squirrel", "stoat", "swan", "tapir", "toad", "walrus", "wolf",
];

/// A device name drawn from `rng`: an adjective and an animal, lowercase,
/// separated by one space.
#[must_use]
pub fn device_name_from(rng: &mut impl RngCore) -> String {
    let adjective = DEVICE_NAME_ADJECTIVES[index_below(rng, DEVICE_NAME_ADJECTIVES.len())];
    let animal = DEVICE_NAME_ANIMALS[index_below(rng, DEVICE_NAME_ANIMALS.len())];
    format!("{adjective} {animal}")
}

/// A uniform index below `len` (a few dozen): the modulo bias of a `u32` draw
/// over so short a list is below one in a hundred million.
fn index_below(rng: &mut impl RngCore, len: usize) -> usize {
    rng.next_u32() as usize % len
}

/// This install's identity in the account's device registry: drawn once,
/// kept in the install's state directory, and sent with every registration
/// and issuance.
///
/// `Debug` renders a short prefix of the identifier and no name: both name an
/// install of a wallet, and stay out of every log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// The install's random identifier.
    pub device_id: DeviceId,
    /// The install's name, generated and renamable.
    pub name: String,
}

impl DeviceIdentity {
    /// A new identity: 16 bytes from the operating system's CSPRNG and a name
    /// drawn from the SDK's word lists.
    #[must_use]
    pub fn generate() -> Self {
        let mut id = [0u8; DEVICE_ID_LEN];
        OsRng.fill_bytes(&mut id);
        Self {
            device_id: DeviceId::from_bytes(id),
            name: device_name_from(&mut OsRng),
        }
    }

    /// The registration this identity sends from `platform`, running
    /// `app_version`.
    #[must_use]
    pub fn registration(
        &self,
        platform: DevicePlatform,
        app_version: impl Into<String>,
    ) -> DeviceRegistration {
        DeviceRegistration {
            device_id: self.device_id,
            name: self.name.clone(),
            platform,
            app_version: app_version.into(),
        }
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    #[test]
    fn a_name_is_one_listed_adjective_then_one_listed_animal() {
        let mut rng = StdRng::seed_from_u64(7);

        for _ in 0..200 {
            let name = device_name_from(&mut rng);
            let (adjective, animal) = name.split_once(' ').expect("two words");
            assert!(DEVICE_NAME_ADJECTIVES.contains(&adjective), "{adjective}");
            assert!(DEVICE_NAME_ANIMALS.contains(&animal), "{animal}");
        }
    }

    #[test]
    fn names_reach_every_word_of_both_lists() {
        let mut rng = StdRng::seed_from_u64(11);
        let (mut adjectives, mut animals) = (HashSet::new(), HashSet::new());

        for _ in 0..4000 {
            let name = device_name_from(&mut rng);
            let (adjective, animal) = name.split_once(' ').expect("two words");
            adjectives.insert(adjective.to_owned());
            animals.insert(animal.to_owned());
        }

        assert_eq!(adjectives.len(), DEVICE_NAME_ADJECTIVES.len());
        assert_eq!(animals.len(), DEVICE_NAME_ANIMALS.len());
    }

    #[test]
    fn every_name_fits_the_registry_and_reads_the_same_everywhere() {
        // The registry keeps at most 40 characters; the words are distinct
        // lowercase ASCII so no two pairs spell the same name.
        let words = DEVICE_NAME_ADJECTIVES.iter().chain(&DEVICE_NAME_ANIMALS);
        assert!(
            words
                .clone()
                .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()))
        );
        assert_eq!(
            words.collect::<HashSet<_>>().len(),
            DEVICE_NAME_ADJECTIVES.len() + DEVICE_NAME_ANIMALS.len()
        );
        let longest = DEVICE_NAME_ADJECTIVES
            .iter()
            .map(|w| w.len())
            .max()
            .unwrap()
            + 1
            + DEVICE_NAME_ANIMALS.iter().map(|w| w.len()).max().unwrap();
        assert!(longest <= 40, "{longest}");
    }

    #[test]
    fn two_generated_identities_do_not_share_an_identifier() {
        assert_ne!(
            DeviceIdentity::generate().device_id,
            DeviceIdentity::generate().device_id
        );
    }

    #[test]
    fn a_registration_carries_the_identity_the_platform_and_the_version() {
        let identity = DeviceIdentity {
            device_id: DeviceId::from_bytes([3; DEVICE_ID_LEN]),
            name: "calm heron".to_owned(),
        };

        let registration = identity.registration(DevicePlatform::Ios, "1.4.0");

        assert_eq!(
            registration,
            DeviceRegistration {
                device_id: identity.device_id,
                name: "calm heron".to_owned(),
                platform: DevicePlatform::Ios,
                app_version: "1.4.0".to_owned(),
            }
        );
    }

    #[test]
    fn debug_renders_neither_the_name_nor_the_whole_identifier() {
        let identity = DeviceIdentity {
            device_id: DeviceId::from_bytes([0xAB; DEVICE_ID_LEN]),
            name: "calm heron".to_owned(),
        };

        let rendered = format!("{identity:?}");

        assert!(!rendered.contains("heron"), "{rendered}");
        assert!(
            !rendered.contains(&String::from(identity.device_id)),
            "{rendered}"
        );
    }
}
