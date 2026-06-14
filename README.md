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

The whole client stack is implemented in strict TDD and validated end to end
in-process (identity to QUIC tunnel to datagram to local proxy), and the sealed
multihop tunnel is **live-validated against a production exit**. The **non-root
proxy datapath is feature-complete** on Linux, macOS and Windows: SOCKS5 and HTTP
CONNECT, DNS-over-tunnel (no host-resolver leak), SOCKS5 UDP associate, dual-stack
IPv6, and the port-forwarding primitives. Applications depend on a single crate,
`warren-sdk`. `ROADMAP.md` is the source of truth for fine-grained status; see
`AUDIT.md` for the audit trail.

| Capability | Crate | Status |
|---|---|---|
| Non-custodial identity (BIP39, SS58 `wb…`, request signing) | `warren-identity` | done, golden vectors |
| Wire codecs: handshake, NAT-PMP, multihop HPKE frame, control `/v2`, PoP | `warren-wire` | done, golden vectors |
| Signed account API client (transport-agnostic) incl. anti-censorship host fallback (primary / alternatives / no-SNI) and payments/support/incidents | `warren-api` | done |
| Signed relay list verify (v6) + weighted selector; multihop directory PKI verify | `warren-discovery` | done, golden vectors |
| QUIC transport (RFC 7250 raw-public-key TLS 1.3) + reconnect/backoff supervisor | `warren-transport` | done; validated against a real exit. The sealed multihop tunnel is the path real exits accept |
| Multihop HPKE session (X25519 / HKDF-SHA256 / ChaCha20Poly1305, epoch/seq replay) | `warren-multihop` | done; live-validated |
| Non-root proxy datapath: smoltcp userspace netstack over the tunnel, SOCKS5 + HTTP CONNECT, DNS-over-tunnel (A/AAAA, configurable resolver), UDP associate, dual-stack IPv6, port-forwarding (NAT-PMP client + inbound listen/relay) | `warren-net` | feature-complete, e2e in-process over single-hop and sealed multihop; per-OS privileged TUN backend pending |
| High-level `WarrenClient` facade (`start_proxy` + `start_proxy_multihop` + self-healing `start_proxy_multihop_supervised`, discovery, account API); `ProxyHandle` exposes connection state and one-call `forward_port` | `warren-sdk` | done, in-process e2e |
| FFI surface (uniffi): identity + async client + proxy handle + connection-state events; Python/Kotlin bindings CI-validated | `warren-sdk-ffi` | done |

The full tunnel needs a subscribed wallet (the exit gates the IP assignment on its
allowlist); set `WARREN_MNEMONIC` and run `cargo run -p warren-sdk --example
live_proxy` (or `--example live_exit` to validate the sealed handshake without a
subscription).

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
