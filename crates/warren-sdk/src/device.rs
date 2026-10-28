//! The install's device in the account's registry (warren-core doc 115): its
//! registration, and the file its identity is kept in.

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use warren_api::{DeviceId, DeviceRegistration};

/// The device a client registers as, shared by the client and the wallet's
/// port entitlements, which open their batch (and register) later.
pub(crate) struct Device {
    path: PathBuf,
    registration: Mutex<DeviceRegistration>,
}

impl Device {
    pub(crate) fn new(path: PathBuf, registration: DeviceRegistration) -> Self {
        Self {
            path,
            registration: Mutex::new(registration),
        }
    }

    pub(crate) fn id(&self) -> DeviceId {
        self.lock().device_id
    }

    /// The registration as it stands, renames included.
    pub(crate) fn registration(&self) -> DeviceRegistration {
        self.lock().clone()
    }

    /// Takes `name` for the registrations to come, and keeps it in the
    /// identity file so the next start registers under it too.
    pub(crate) fn rename(&self, name: &str) -> std::io::Result<()> {
        name.clone_into(&mut self.lock().name);
        crate::store::keep_device_name(&self.path, name)
    }

    pub(crate) fn forget(&self) -> std::io::Result<()> {
        crate::store::forget_device_identity(&self.path)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DeviceRegistration> {
        self.registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}
