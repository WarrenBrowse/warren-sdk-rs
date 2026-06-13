# warren-sdk-rs

Standalone Rust client SDK for the [Warren VPN](https://warrenbrowse.com): a
no-log VPN whose client to exit tunnel is pure QUIC, with a non-custodial Ed25519
identity derived from a BIP39 mnemonic.

This SDK is **standalone**: it does not depend on the warren-core monorepo. It is
a clean-room reimplementation that stays **wire-compatible** with warren-core's
frozen contracts, so it can talk to real exits and the production API. The same
SDK is being reimplemented in TypeScript, Dart, Python, Kotlin, Swift and Java;
this Rust crate is the reference and the source of the shared golden vectors.

See `ARCHITECTURE.md` for the design, `ROADMAP.md` for the plan, and `CLAUDE.md`
for the engineering rules.

## Status

Bootstrap phase. The `warren-identity` layer is implemented and fully tested; the
other layers are scaffolded with their public contracts documented (see the
roadmap). Applications will depend on a single crate, `warren-sdk`.

| Capability | Crate | Status |
|---|---|---|
| Non-custodial identity (BIP39, SS58 `wb…`, request signing) | `warren-identity` | done |
| Wire codecs (handshake, NAT-PMP, multihop) | `warren-wire` | planned (P2) |
| Signed account API client | `warren-api` | planned (P3) |
| Exit discovery and selection | `warren-discovery` | planned (P4) |
| QUIC transport | `warren-transport` | planned (P5) |
| Networking backends (non-root proxy, optional TUN) | `warren-net` | planned (P6) |
| High-level `WarrenClient` facade | `warren-sdk` | planned (P8) |
| FFI bindings (Dart, Kotlin, Swift, Python, Java) | `warren-sdk-ffi` | planned (P9) |

## Identity in a few lines

```rust
use warren_sdk::identity::WarrenIdentity;

// Create a new non-custodial identity (persist the mnemonic securely).
let (identity, mnemonic) = WarrenIdentity::generate();
println!("address: {}", identity.address()); // wb...

// Restore it later from the mnemonic.
let identity = WarrenIdentity::from_mnemonic(&mnemonic)?;

// Sign a Warren API request (the SDK facade supplies the clock and nonce).
let signed = identity.sign_request("GET", "/v1/subscription", b"", timestamp, nonce);
for (name, value) in signed.headers() {
    // attach X-Warren-* headers to your HTTP request
}
```

## Build and test

```bash
cargo build --workspace
cargo test  --workspace
cargo fmt   --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny  check
```

The shared cross-language contracts live in `vectors/`. The
`crates/warren-identity/tests/vectors.rs` test replays them; every other language
SDK must replay the same files.

## License

AGPL-3.0-or-later. See `LICENSE`.
