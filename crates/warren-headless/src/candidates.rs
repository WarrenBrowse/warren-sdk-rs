//! Exit candidates, from the two signed views to a dial list.

use warren_sdk::Circuit;
use warren_sdk::discovery::VerifiedExit;

use crate::env::{CircuitKind, ExitFilter};
use crate::log::Log;
use crate::select::order_exits;

/// Why no candidate list could be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CandidateError {
    /// The signed relay list could not be fetched or verified.
    #[error("fetching the signed relay list failed")]
    RelayList(#[source] warren_sdk::SdkError),
    /// The multihop directory could not be fetched or verified.
    #[error("fetching the multihop directory failed")]
    Directory(#[source] warren_sdk::SdkError),
    /// Nothing survived the user's filters and the cross-check.
    #[error("no exit matches WARREN_EXITS (or the directory and relay list do not intersect)")]
    NoMatch,
}

/// Fetches both signed views, cross-checks them, applies the user's filters.
///
/// # Errors
///
/// See [`CandidateError`]. A daemon treats every one of them as a startup
/// failure: with no candidate there is nothing to dial and nothing to heal.
pub async fn candidate_circuits(
    client: &warren_sdk::DefaultClient,
    filters: &[ExitFilter],
    circuit: CircuitKind,
    log: Log,
) -> Result<Vec<Circuit>, CandidateError> {
    let selector = client
        .fetch_exits()
        .await
        .map_err(CandidateError::RelayList)?;
    let directory = client
        .fetch_multihop_directory()
        .await
        .map_err(CandidateError::Directory)?;

    // Trust the intersection only: an exit present in the directory but
    // absent from the pinned relay list (or the reverse) is not dialed.
    let cross_checked: Vec<VerifiedExit> = directory
        .into_iter()
        .filter(|e| {
            selector
                .relays()
                .iter()
                .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
        })
        .collect();

    let ordered = order_exits(
        cross_checked,
        filters,
        |e| e.country.clone(),
        |e| e.city.clone(),
    );
    if ordered.is_empty() {
        return Err(CandidateError::NoMatch);
    }
    for e in &ordered {
        log.info(&format!("  candidate: {} / {}", e.country, e.city));
    }
    Ok(ordered
        .into_iter()
        .map(|exit| match circuit {
            CircuitKind::Single => Circuit::SingleHop(exit),
            CircuitKind::Multi => Circuit::MultiHop(exit),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both fetches are network calls the daemon cannot make in a unit test;
    /// what is worth pinning here is that each failure keeps its own line, so
    /// an operator reading the startup error knows which signed view was
    /// missing.
    #[test]
    fn each_startup_refusal_names_what_was_missing() {
        assert_eq!(
            CandidateError::NoMatch.to_string(),
            "no exit matches WARREN_EXITS (or the directory and relay list do not intersect)"
        );
        let relay = CandidateError::RelayList(warren_sdk::SdkError::NoMultihopExit).to_string();
        let directory = CandidateError::Directory(warren_sdk::SdkError::NoMultihopExit).to_string();
        assert_ne!(relay, directory);
        assert!(relay.contains("relay list"), "{relay}");
        assert!(directory.contains("directory"), "{directory}");
    }
}
