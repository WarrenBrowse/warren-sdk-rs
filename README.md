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

The cryptographic and protocol core is implemented in strict TDD and validated
end to end in-process (identity to QUIC tunnel to datagram). The per-OS datapath
(proxy/TUN backends) and the FFI binding codegen are scaffolded behind their
seams and tracked as the next phases. Applications depend on a single crate,
`warren-sdk`. See `AUDIT.md` for the post-implementation audit and `ROADMAP.md`
for the remaining work.

| Capability | Crate | Status |
|---|---|---|
| Non-custodial identity (BIP39, SS58 `wb…`, request signing) | `warren-identity` | done, golden vectors |
| Handshake + NAT-PMP wire codecs | `warren-wire` | done, golden vectors |
| Signed account API client (transport-agnostic) | `warren-api` | done; anti-censorship host fallback pending |
| Signed relay list verify (v5) + weighted selector | `warren-discovery` | done, golden vector |
| QUIC transport (RFC 7250 raw-public-key TLS 1.3) | `warren-transport` | done, in-process e2e |
| Datapath seams (`PacketSink`, SOCKS5 codec, kill-switch levels) | `warren-net` | seams done; per-OS proxy/TUN backends pending (P6) |
| High-level `WarrenClient` facade | `warren-sdk` | done, in-process e2e |
| FFI identity surface (uniffi/flutter_rust_bridge-shaped) | `warren-sdk-ffi` | identity surface done; tunnel surface + binding codegen pending (P9) |
| Multihop HPKE frame | `warren-wire` | planned |

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
