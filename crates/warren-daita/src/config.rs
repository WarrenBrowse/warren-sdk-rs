//! The wire-level DAITA configuration and its errors.

use serde::{Deserialize, Serialize};

/// DAITA v2 negotiated configuration, as it rides the wire.
///
/// On the single-hop path the exit selects one of these and ships it in the
/// handshake `SetupAck`; on the multihop path the client picks its own from the
/// curated [`DaitaPool`](crate::DaitaPool) (the exit pads the reverse direction
/// independently). Either way the machines are carried as the exact base64
/// strings produced by `maybenot::Machine::serialize`, so both peers
/// reconstruct byte-identical defenses.
///
/// The field order is the frozen postcard layout shared with warren-core: a
/// `Vec<String>` then two `f64`s. `deny_unknown_fields` matches the reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaitaConfig {
    /// Serialized maybenot machines, one entry per machine (the string returned
    /// by `Machine::serialize`). An empty vector is semantically "disabled".
    pub machine_specs: Vec<String>,
    /// Hard cap on the fraction of total packets that may be padding, `0.0..=1.0`.
    pub max_padding_frac: f64,
    /// Hard cap on the fraction of total time that may be blocked, `0.0..=1.0`.
    pub max_blocking_frac: f64,
}

impl DaitaConfig {
    /// A config with DAITA disabled (no machines, no caps).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            machine_specs: Vec::new(),
            max_padding_frac: 0.0,
            max_blocking_frac: 0.0,
        }
    }

    /// Builds a config from already-serialized machine specs and the caps.
    #[must_use]
    pub fn from_specs(
        machine_specs: Vec<String>,
        max_padding_frac: f64,
        max_blocking_frac: f64,
    ) -> Self {
        Self {
            machine_specs,
            max_padding_frac,
            max_blocking_frac,
        }
    }

    /// True if the config carries at least one machine spec. An empty config is
    /// a wire-format error on the single-hop path (use an absent `daita_spec`
    /// instead), but a convenient "off" sentinel locally.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.machine_specs.is_empty()
    }

    /// True if both fractional caps are finite and within `[0.0, 1.0]`. A remote
    /// peer can send arbitrary values, so callers must validate before handing
    /// them to maybenot.
    #[must_use]
    pub fn fractions_valid(&self) -> bool {
        (0.0..=1.0).contains(&self.max_padding_frac)
            && (0.0..=1.0).contains(&self.max_blocking_frac)
    }
}

/// Failure building or driving a DAITA defense.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaitaError {
    /// A machine spec string failed to parse via `maybenot::Machine::from_str`.
    /// The cause is rendered as text (the upstream error is not redaction-
    /// sensitive: it describes the malformed encoding, not any identity).
    #[error("invalid DAITA machine spec")]
    InvalidMachine(String),
    /// The fractional caps were not within `[0.0, 1.0]`.
    #[error("invalid DAITA fractions (padding/blocking must be in 0.0..=1.0)")]
    InvalidFraction,
    /// The maybenot framework refused the configuration.
    #[error("DAITA framework rejected the configuration")]
    Framework(String),
}
