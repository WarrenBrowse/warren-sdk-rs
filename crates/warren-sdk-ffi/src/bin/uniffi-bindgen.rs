//! Binding generator entry point.
//!
//! Build the `cdylib`, then generate foreign bindings against it, e.g.:
//!
//! ```text
//! cargo build -p warren-sdk-ffi
//! cargo run -p warren-sdk-ffi --bin uniffi-bindgen -- generate \
//!     --library target/debug/libwarren_sdk_ffi.dylib \
//!     --language kotlin --out-dir target/bindings
//! ```
//!
//! `--language` accepts `kotlin`, `swift`, `python`, or `ruby`.

fn main() {
    uniffi::uniffi_bindgen_main();
}
