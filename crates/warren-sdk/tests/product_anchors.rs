//! Downstream consumers (wclaude, warrend, the FFI bindings) read the product
//! anchors through the SDK facade instead of re-declaring drifting literals.
//! This pins the re-export path, the full per-channel API base table and the
//! anchors shared by every channel, so a silent rotation fails loudly here.

use warren_sdk::product::{self, Channel};

#[test]
fn facade_exposes_the_api_base_of_every_channel() {
    assert_eq!(Channel::Prod.api_url(), "https://api.warrenbrowse.com");
    assert_eq!(Channel::Beta.api_url(), "https://api.beta.warrenbrowse.com");
}

/// The build-time selector reaches the compiled anchor, and an unset selector
/// lands on prod: an ordinary `cargo build`/`cargo test` is a prod build.
#[test]
fn compiled_api_base_follows_the_selected_channel() {
    let expected = match env!("WARREN_PRODUCT_ENV_RESOLVED") {
        "beta" => Channel::Beta,
        _ => Channel::Prod,
    };
    assert_eq!(product::CHANNEL, expected);
    assert_eq!(product::CHANNEL_NAME, expected.name());
    assert_eq!(product::API_URL, expected.api_url());
}

#[test]
fn facade_reexports_the_channel_independent_contract_anchors() {
    assert_eq!(
        product::SERVER_PUBKEY_HEX,
        "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e"
    );
    assert_eq!(product::USER_AGENT, "warren-app");
}
