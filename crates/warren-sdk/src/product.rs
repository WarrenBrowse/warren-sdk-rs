//! Product/deployment anchors, resolved for the release channel this build
//! targets.
//!
//! Everything that is identical across channels (pinned keys, canonical
//! override env names, the product `User-Agent`) comes straight from the
//! neutral contract crate. The API base is the one anchor that differs, so it
//! is resolved here from the compile-time `WARREN_PRODUCT_ENV` selector
//! (`prod` | `beta`, unset meaning prod). Consumers keep reading
//! `warren_sdk::product::API_URL` and get their channel's host.
//!
//! The runtime override chain (`WARREN_API_URL`, an explicit
//! `WarrenClient::builder().api_base(..)`) still applies on top: this module
//! only supplies the compiled default those chains fall back to.

pub use warren_contract::product::*;

/// Release channel a build targets. Each channel is a fully separate Warren
/// deployment, so a beta client must never reach the prod host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Production deployment, the default for any build with the selector
    /// unset.
    Prod,
    /// Beta deployment, a fully separate stack reached only by an explicit
    /// `WARREN_PRODUCT_ENV=beta` build.
    Beta,
}

impl Channel {
    /// Stable lowercase name, matching the `WARREN_PRODUCT_ENV` spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Channel::Prod => "prod",
            Channel::Beta => "beta",
        }
    }

    /// Base URL of the channel's warren-api deployment (the `/v1` control
    /// plane).
    #[must_use]
    pub const fn api_url(self) -> &'static str {
        match self {
            Channel::Prod => warren_contract::product::API_URL,
            Channel::Beta => "https://api.beta.warrenbrowse.com",
        }
    }
}

const fn parse(name: &str) -> Channel {
    // Byte match because `str` comparison is not const; build.rs already
    // rejected every value outside this set.
    match name.as_bytes() {
        b"beta" => Channel::Beta,
        _ => Channel::Prod,
    }
}

/// The channel this build targets.
pub const CHANNEL: Channel = parse(env!("WARREN_PRODUCT_ENV_RESOLVED"));

/// Stable lowercase name of [`CHANNEL`].
pub const CHANNEL_NAME: &str = CHANNEL.name();

/// Compiled default warren-api base URL for [`CHANNEL`]. Shadows the
/// contract crate's prod-only constant re-exported above.
pub const API_URL: &str = CHANNEL.api_url();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_channel_api_bases() {
        assert_eq!(Channel::Prod.name(), "prod");
        assert_eq!(Channel::Beta.name(), "beta");
        assert_eq!(Channel::Prod.api_url(), "https://api.warrenbrowse.com");
        assert_eq!(Channel::Beta.api_url(), "https://api.beta.warrenbrowse.com");
    }

    #[test]
    fn beta_never_resolves_to_the_prod_host() {
        // api.beta and api.warrenbrowse.com resolve to the same box today, so a
        // wrong binding stays invisible until production splits off.
        assert_ne!(Channel::Beta.api_url(), Channel::Prod.api_url());
    }

    #[test]
    fn compiled_consts_match_the_selected_channel() {
        assert_eq!(CHANNEL_NAME, CHANNEL.name());
        assert_eq!(API_URL, CHANNEL.api_url());
    }

    #[test]
    fn unset_selector_is_prod() {
        assert_eq!(parse(""), Channel::Prod);
        assert_eq!(parse("prod"), Channel::Prod);
        assert_eq!(parse("beta"), Channel::Beta);
    }
}
