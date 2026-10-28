//! File-backed persistence for the anti-rollback floor, the trust-on-first-use
//! server pin, the token rotation and the device identity, so they survive
//! process restarts.
//!
//! The in-memory defaults reset every run, which lets a network attacker replay an
//! older-but-validly-signed list to a freshly launched client. These stores write
//! the trusted state to a small file, closing that window for native and FFI
//! consumers alike.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use warren_api::DeviceIdentity;

use crate::{GenerationStore, ServerKeyStore};

/// A [`GenerationStore`] that persists the highest trusted generation to a file
/// (decimal text). Writes are best-effort (the trait cannot report I/O errors);
/// the in-memory cache always reflects the highest value seen this run.
#[derive(Debug)]
pub struct FileGenerationStore {
    path: PathBuf,
    floor: Mutex<u64>,
}

impl FileGenerationStore {
    /// Opens (or initializes) the store at `path`, reading any persisted floor.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if `path` exists but cannot be read. A missing file is
    /// not an error (the floor starts at `0`).
    pub fn new(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let floor = read_u64(&path)?;
        Ok(Self {
            path,
            floor: Mutex::new(floor),
        })
    }
}

impl GenerationStore for FileGenerationStore {
    fn load_floor(&self) -> u64 {
        *self.floor.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn store_floor(&self, generation: u64) {
        let mut floor = self.floor.lock().unwrap_or_else(|e| e.into_inner());
        if generation > *floor {
            *floor = generation;
            // Best-effort: the trait has no error channel, and the in-memory cache
            // still guards anti-rollback for the rest of this run on a write failure.
            let _ = std::fs::write(&self.path, generation.to_string());
        }
    }
}

/// A [`ServerKeyStore`] that persists the trust-on-first-use server pin (hex text)
/// to a file, so the pin learned on the first fetch survives a restart.
#[derive(Debug)]
pub struct FileServerKeyStore {
    path: PathBuf,
    pin: Mutex<Option<String>>,
}

impl FileServerKeyStore {
    /// Opens (or initializes) the store at `path`, reading any persisted pin.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if `path` exists but cannot be read. A missing file is
    /// not an error (no pin yet).
    pub fn new(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let pin = read_pin(&path)?;
        Ok(Self {
            path,
            pin: Mutex::new(pin),
        })
    }
}

impl ServerKeyStore for FileServerKeyStore {
    fn load_pin(&self) -> Option<String> {
        self.pin.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn store_pin(&self, server_pubkey_hex: &str) {
        let mut pin = self.pin.lock().unwrap_or_else(|e| e.into_inner());
        if pin.is_none() {
            *pin = Some(server_pubkey_hex.to_owned());
            let _ = std::fs::write(&self.path, server_pubkey_hex);
        }
    }
}

/// Reads a persisted `u64` floor, treating a missing file or unparsable content as
/// `0` (a corrupt floor must not crash; anti-rollback simply restarts from zero).
fn read_u64(path: &Path) -> std::io::Result<u64> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s.trim().parse().unwrap_or(0)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// The token rotation kept at `path` for [`crate::WarrenClientBuilder::token_rotation`]:
/// read back, or drawn and kept there on first use.
///
/// An exit gives a client back its inner address and forwarded ports only
/// when it leads with the serial its previous session was admitted on, so a
/// client that draws a new rotation at every start loses both at every
/// restart. A path it cannot write to leaves this process its own draw.
#[must_use]
pub fn kept_token_rotation(path: &Path) -> u64 {
    if let Some(kept) = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
    {
        return kept;
    }
    let drawn: u64 = rand::random();
    let _ = write_whole(path, drawn.to_string().as_bytes());
    drawn
}

/// This install's device identity (warren-core doc 115), kept at `path` for
/// [`crate::WarrenClientBuilder::device`]: read back, or drawn
/// ([`DeviceIdentity::generate`]) and kept there on first use. Keep it next to
/// the token rotation, in the install's own state directory.
///
/// The account's device list names an install by this identity, so one
/// drawn anew at every start would add a device to the list at every start.
/// A path it cannot write to leaves this process its own draw, and an
/// unreadable file is replaced by a new draw.
#[must_use]
pub fn kept_device_identity(path: &Path) -> DeviceIdentity {
    if let Some(kept) = read_device_identity(path) {
        return kept;
    }
    let drawn = DeviceIdentity::generate();
    if let Ok(json) = serde_json::to_vec(&drawn) {
        let _ = write_whole(path, &json);
    }
    drawn
}

/// Keeps `name` as the name of the device identity kept at `path`, once the
/// account renamed the device: the next start registers under it.
///
/// # Errors
///
/// [`std::io::ErrorKind::NotFound`] when no readable identity is kept at
/// `path` (a name is never kept without the identifier it names), or the
/// error of the write.
pub fn keep_device_name(path: &Path, name: &str) -> std::io::Result<()> {
    let mut kept = read_device_identity(path).ok_or(std::io::ErrorKind::NotFound)?;
    name.clone_into(&mut kept.name);
    let json = serde_json::to_vec(&kept).map_err(std::io::Error::other)?;
    write_whole(path, &json)
}

/// Erases the device identity kept at `path`: the device was revoked, or
/// logged out. The next [`kept_device_identity`] draws a new one, which the
/// account lists as a new device.
///
/// # Errors
///
/// The error of the removal; an identity that is not there is already
/// forgotten.
pub fn forget_device_identity(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn read_device_identity(path: &Path) -> Option<DeviceIdentity> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Writes `bytes` to a side file then renames it over `path`, because a torn
/// write would still parse as another value.
fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    std::fs::write(&partial, bytes).and_then(|()| std::fs::rename(&partial, path))
}

/// Reads a persisted pin, treating a missing file as "no pin yet".
fn read_pin(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let s = s.trim().to_owned();
            Ok((!s.is_empty()).then_some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_token_rotation_is_read_back_by_the_next_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token_rotation");

        let drawn = kept_token_rotation(&path);

        assert_eq!(kept_token_rotation(&path), drawn);
    }

    #[test]
    fn an_unreadable_token_rotation_is_drawn_again_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token_rotation");
        std::fs::write(&path, b"not a number").unwrap();

        let drawn = kept_token_rotation(&path);

        assert_eq!(kept_token_rotation(&path), drawn);
    }

    #[test]
    fn a_kept_device_identity_is_read_back_by_the_next_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");

        let drawn = kept_device_identity(&path);

        assert_eq!(kept_device_identity(&path), drawn);
    }

    #[test]
    fn an_unreadable_device_identity_is_drawn_again_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");
        std::fs::write(&path, b"{\"device_id\":\"short\"}").unwrap();

        let drawn = kept_device_identity(&path);

        assert_eq!(kept_device_identity(&path), drawn);
    }

    #[test]
    fn a_kept_name_replaces_the_name_and_keeps_the_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");
        let drawn = kept_device_identity(&path);

        keep_device_name(&path, "calm heron").unwrap();

        let kept = kept_device_identity(&path);
        assert_eq!(kept.device_id, drawn.device_id);
        assert_eq!(kept.name, "calm heron");
    }

    #[test]
    fn a_name_is_never_kept_for_an_identity_that_was_never_drawn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");

        let err = keep_device_name(&path, "calm heron").unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(!path.exists());
    }

    #[test]
    fn a_forgotten_device_identity_is_drawn_anew() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");
        let drawn = kept_device_identity(&path);

        forget_device_identity(&path).unwrap();

        assert!(!path.exists());
        assert_ne!(kept_device_identity(&path).device_id, drawn.device_id);
        forget_device_identity(&dir.path().join("never-drawn"))
            .expect("forgetting nothing is done already");
    }

    #[test]
    fn generation_floor_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gen");

        let store = FileGenerationStore::new(&path).unwrap();
        assert_eq!(store.load_floor(), 0, "missing file starts at zero");
        store.store_floor(7);
        assert_eq!(store.load_floor(), 7);

        // A fresh instance (modelling a restart) reads the persisted floor.
        let reopened = FileGenerationStore::new(&path).unwrap();
        assert_eq!(reopened.load_floor(), 7, "floor survives a restart");
    }

    #[test]
    fn generation_floor_never_decreases() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileGenerationStore::new(dir.path().join("gen")).unwrap();
        store.store_floor(5);
        store.store_floor(3); // a replayed older list must not lower the floor
        assert_eq!(store.load_floor(), 5);
    }

    #[test]
    fn server_pin_persists_and_is_write_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin");

        let store = FileServerKeyStore::new(&path).unwrap();
        assert_eq!(store.load_pin(), None);
        store.store_pin("ab");
        // Trust-on-first-use: a later (attacker-supplied) key must not overwrite.
        store.store_pin("cd");
        assert_eq!(store.load_pin().as_deref(), Some("ab"));

        let reopened = FileServerKeyStore::new(&path).unwrap();
        assert_eq!(reopened.load_pin().as_deref(), Some("ab"));
    }
}
