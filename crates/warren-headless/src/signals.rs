//! Process signals.

/// Resolves when the process is asked to stop (SIGTERM, or Ctrl-C anywhere).
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(term) => term,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The reload request a daemon that carries reloadable state listens for.
///
/// Constructing one installs a SIGHUP handler, which by itself changes what
/// SIGHUP does to the process: the default action terminates it. A daemon that
/// has nothing to reload therefore never builds one, and keeps the default.
pub struct ReloadSignal {
    #[cfg(unix)]
    inner: tokio::signal::unix::Signal,
}

impl ReloadSignal {
    /// Starts listening for SIGHUP.
    ///
    /// # Errors
    ///
    /// The handler could not be installed.
    pub fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                inner: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    /// Resolves once per reload request. On a platform with no SIGHUP it never
    /// resolves, so a `select!` arm over it is simply never taken.
    pub async fn recv(&mut self) {
        #[cfg(unix)]
        {
            self.inner.recv().await;
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }
    }
}

impl std::fmt::Debug for ReloadSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReloadSignal")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon arms this before it serves, so a failure to install the
    /// handler has to be visible rather than swallowed into a signal that
    /// silently kills the process later.
    #[tokio::test]
    async fn a_reload_listener_installs() {
        let signal = ReloadSignal::new().expect("SIGHUP is installable on a supported platform");
        assert_eq!(format!("{signal:?}"), "ReloadSignal");
    }

    /// Nothing has asked for a reload, so the arm must stay pending rather
    /// than fire once at startup and reload a configuration nobody changed.
    #[tokio::test]
    async fn a_reload_listener_stays_quiet_until_it_is_signalled() {
        let mut signal = ReloadSignal::new().expect("installable");
        let quiet = tokio::time::timeout(std::time::Duration::from_millis(50), signal.recv()).await;
        assert!(quiet.is_err(), "no signal was raised, so nothing may fire");
    }
}
