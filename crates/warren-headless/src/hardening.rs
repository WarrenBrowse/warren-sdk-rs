//! Process hardening a daemon applies to itself before it holds any secret.

/// Refuses core dumps for this process.
///
/// Both daemons hold the account's recovery phrase and, in the gateway's case,
/// every peer's key material in memory. A core file written by the kernel into
/// a world-readable directory (or shipped to a crash collector) would carry
/// all of it, and no amount of zeroize-on-drop helps against a dump taken while
/// the process is alive. `RLIMIT_CORE` is the portable half; on Linux the
/// dumpable flag also stops a ptrace-based dump by another user and closes the
/// `/proc/<pid>/mem` path that a set-uid-style dumper would take.
///
/// Best effort by design: a sandbox that refuses the call must not stop the
/// daemon from starting, so the outcome is returned rather than enforced, and
/// the caller logs it.
#[must_use]
pub fn disable_core_dumps() -> bool {
    #[cfg(unix)]
    {
        use nix::sys::resource::{Resource, setrlimit};
        #[allow(unused_mut, reason = "the dumpable flag only exists on Linux")]
        let mut ok = setrlimit(Resource::RLIMIT_CORE, 0, 0).is_ok();
        #[cfg(target_os = "linux")]
        {
            ok = nix::sys::prctl::set_dumpable(false).is_ok() && ok;
        }
        ok
    }
    #[cfg(not(unix))]
    {
        // Windows writes a crash dump only where the operator configured one,
        // and the process cannot revoke that from inside.
        false
    }
}

/// Whether this process runs as root.
///
/// A daemon started as a system service keeps its state under a system path,
/// and a daemon started by a user keeps it under that user's own private
/// directory: the two are not interchangeable, and the process is the only
/// thing that knows which one it is.
#[must_use]
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test suite never runs as root on a developer machine or on a CI
    /// runner, and the answer decides where a daemon writes its keys, so a
    /// reading that is merely plausible is not enough.
    #[cfg(unix)]
    #[test]
    fn root_is_read_from_the_effective_uid() {
        assert_eq!(is_root(), nix::unistd::geteuid().is_root());
    }

    /// Asserts the limit the kernel now holds rather than the call's own
    /// return: what matters is that a dump cannot be written afterwards.
    #[cfg(unix)]
    #[test]
    fn a_hardened_process_has_no_core_dump_budget_left() {
        use nix::sys::resource::{Resource, getrlimit};

        assert!(disable_core_dumps(), "the call must succeed on this host");
        let (soft, hard) = getrlimit(Resource::RLIMIT_CORE).expect("the limit is readable");
        assert_eq!(soft, 0, "a core dump would carry the recovery phrase");
        assert_eq!(hard, 0, "and nothing may raise the limit back");
    }
}
