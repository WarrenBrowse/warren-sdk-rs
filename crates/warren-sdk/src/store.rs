//! File-backed persistence for the anti-rollback floor and the trust-on-first-use
//! server pin, so both survive process restarts.
//!
//! The in-memory defaults reset every run, which lets a network attacker replay an
//! older-but-validly-signed list to a freshly launched client. These stores write
//! the trusted state to a small file, closing that window for native and FFI
//! consumers alike.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
