//! Validates the `WARREN_PRODUCT_ENV` release-channel selector and forwards it
//! to the crate as a rustc env. Rejecting an unknown value here fails the build
//! instead of silently compiling a prod binary an operator meant to be beta.

fn main() {
    println!("cargo:rerun-if-env-changed=WARREN_PRODUCT_ENV");

    let raw = std::env::var("WARREN_PRODUCT_ENV").unwrap_or_default();
    let resolved = match raw.trim() {
        "" | "prod" => "prod",
        "beta" => "beta",
        other => {
            panic!("WARREN_PRODUCT_ENV must be prod or beta (or unset for prod), got {other:?}")
        }
    };
    println!("cargo:rustc-env=WARREN_PRODUCT_ENV_RESOLVED={resolved}");
}
