//! Downstream consumers (wclaude, warrend, the FFI bindings) read the product
//! anchors through the SDK facade instead of re-declaring drifting literals.
//! This pins both the re-export path and the production values, so a silent
//! anchor rotation in the contract crate fails loudly here.

#[test]
fn facade_reexports_the_contract_product_anchors() {
    assert_eq!(warren_sdk::product::API_URL, "https://api.warrenbrowse.com");
    assert_eq!(
        warren_sdk::product::SERVER_PUBKEY_HEX,
        "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e"
    );
}
