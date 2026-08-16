//! The startup account line.

/// The startup account line. The SS58 address is the paying account's
/// identifier and a headless daemon's stdout is the container log (shipped to
/// whatever aggregator the host runs), so only the short prefix the app's UI
/// shows ever reaches it, per the shared no-log rule.
#[must_use]
pub fn account_line(address: &str) -> String {
    let prefix: String = address.chars().take(8).collect();
    format!("account {prefix}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_startup_account_line_carries_only_the_address_prefix() {
        let address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let line = account_line(address);
        assert_eq!(line, "account 5GrwvaEF...");
        assert!(
            !line.contains(address),
            "the full account address must never reach a log: {line}"
        );
    }
}
