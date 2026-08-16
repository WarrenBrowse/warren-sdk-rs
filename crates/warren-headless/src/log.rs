//! The one-line operator log both daemons write.
//!
//! A headless daemon's stdout is the container log, so every line carries the
//! binary's own name and nothing that identifies the account, a peer or a
//! remote address.

/// The name a daemon prefixes its lines with (`warren-proxy`, `warren-burrow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Log(pub &'static str);

impl Log {
    /// One informational line on stdout.
    pub fn info(self, msg: &str) {
        println!("{}: {msg}", self.0);
    }

    /// One line on stderr, for what an operator has to act on.
    pub fn error(self, msg: &str) {
        eprintln!("{}: {msg}", self.0);
    }
}
