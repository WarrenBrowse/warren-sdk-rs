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

    /// Takes the name the registry answered a registration with, which
    /// carries a rename made from another device of the account, and keeps
    /// it for the next start. A file that cannot keep it is written again at
    /// the next answer.
    pub(crate) fn adopt(&self, name: &str) {
        {
            let mut registration = self.lock();
            if registration.name == name {
                return;
            }
            name.clone_into(&mut registration.name);
        }
        if crate::store::keep_device_name(&self.path, name).is_err() {
            tracing::debug!("the device name could not be kept");
        }
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

/// The key a wallet's credential batch is shared under in this process: one
/// batch per wallet, API and device, since a batch issues as one device.
/// Process memory only; it is never logged.
pub(crate) fn registry_key(wallet_key: String, device: Option<&Device>) -> String {
    match device {
        Some(device) => format!("{wallet_key}\n{}", String::from(device.id())),
        None => wallet_key,
    }
}
