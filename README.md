# warren-sdk-rs

Standalone Rust client SDK for the [Warren VPN](https://warrenbrowse.com): a
no-log VPN whose client to exit tunnel is pure QUIC, with a non-custodial Ed25519
identity derived from a BIP39 mnemonic.

This SDK does not depend on the private **warren-core** backend. For the
data-plane primitives (wire frames, identity, multihop HPKE, DAITA, TUN, TLS) it
shares the open-source **WarrenGuard engine** (`warrenguard`, AGPL-3.0, sibling
checkout `../warrenguard`): the `warren-{wire,identity,multihop,daita,tun,tun-core}`
crates are thin re-exports of the matching `warrenguard-*` engine crates, so the
protocol primitives have a single source of truth instead of a duplicate
reimplementation. The wire-facing client-to-server contract (the SS58 address
codec, the X-Warren canonical signing message and header names, and the HTTP
`/v1` DTOs) comes from a second neutral crate, **`warren-contract`**, shared with
warren-core: `warren-identity` re-exports its `ss58` and `auth` modules and
`warren-api` re-exports its `dto`, so this contract cannot drift between the SDK
and the backend. The control-plane (`warren-api`, `-discovery`, `-sdk`) and the
userland transport otherwise stay SDK-local. It stays **wire-compatible** with warren-core's
frozen contracts (same golden vectors), so it can talk to real exits and the
production API. The same SDK is being reimplemented in TypeScript, Dart, Python,
Kotlin, Swift and Java; this Rust crate is the reference and the source of the
shared golden vectors.

See `ARCHITECTURE.md` for the design and `CLAUDE.md` for the engineering rules.

## Status

The whole client stack is implemented in strict TDD and validated end to end
in-process (identity to QUIC tunnel to datagram to local proxy), and the sealed
multihop tunnel is **live-validated against a production exit**. The **non-root
proxy datapath is feature-complete** on Linux, macOS and Windows: SOCKS5 and HTTP
CONNECT, DNS-over-tunnel (no host-resolver leak), SOCKS5 UDP associate, dual-stack
IPv6, and the port-forwarding primitives. Applications depend on a single crate,
`warren-sdk`.

| Capability | Crate | Status |
|---|---|---|
| Non-custodial identity (BIP39, SS58 `wb…`, request signing) | `warren-identity` | done, golden vectors |
| Wire codecs: handshake, NAT-PMP, multihop HPKE frame, control `/v2`, PoP | `warren-wire` | done, golden vectors |
| Signed account API client (transport-agnostic) incl. anti-censorship host fallback (primary / alternatives / no-SNI) and payments/support/incidents | `warren-api` | done |
| Signed relay list verify (v10) + weighted selector; multihop directory PKI verify | `warren-discovery` | done, golden vectors |
| QUIC transport (RFC 7250 raw-public-key TLS 1.3) + reconnect/backoff supervisor | `warren-transport` | done; validated against a real exit. The sealed multihop tunnel is the path real exits accept |
| Multihop HPKE session (X25519 / HKDF-SHA256 / ChaCha20Poly1305, epoch/seq replay) | `warren-multihop` | done; live-validated |
| Non-root proxy datapath: smoltcp userspace netstack over the tunnel, SOCKS5 + HTTP CONNECT, DNS-over-tunnel (A/AAAA, configurable resolver), UDP associate, dual-stack IPv6, port-forwarding (NAT-PMP client + inbound listen/relay) | `warren-net` | feature-complete, e2e in-process over single-hop and sealed multihop; per-OS privileged TUN backend pending |
| High-level `WarrenClient` facade over a `Circuit` (single- or multi-hop): one-shot `start_proxy` + self-healing `start_proxy_supervised`, with exit failover, discovery, account API; `ProxyHandle` exposes connection state and one-call `forward_port` | `warren-sdk` | done, in-process e2e |
| FFI surface (uniffi): identity + async client + proxy handle + connection-state events + `forward_port` + self-healing supervised proxy; Python/Kotlin bindings CI-validated | `warren-sdk-ffi` | done |

### Live validation against production

Set `WARREN_MNEMONIC` to a subscribed account and run any of the `warren-sdk`
examples below (`cargo run -p warren-sdk --example <name>`). They validate the
SDK against the production API and real exits:

| Example | Proves |
|---|---|
| `live_exit` | signed v10 exit list + multihop directory verify and cross-check; sealed handshake reaches the exit policy gate (no subscription needed) |
| `live_proxy` | full multihop tunnel: real `IpAssign` + egress through the sealed tunnel |
| `live_reconnect` | app-driven reconnect: independent sessions each rebuild from a fresh `IpAssign` and egress |
| `live_supervised` | self-healing supervised proxy: stable address, reaches `Connected`, egresses |
| `live_failover` | exit failover routes around a broken exit (broken candidate first) to a working one |
| `live_forward_port` | NAT-PMP port forward end to end: the exit grants a mapping and an external dial-in to the public port round-trips through the tunnel |
| `live_ipv6` | surveys every exit's `IpAssign` for a v6 address and, if granted, proves IPv6 egress |

## Identity in a few lines

```rust
use warren_sdk::identity::WarrenIdentity;

// Create a new non-custodial identity (persist the mnemonic securely).
let (identity, mnemonic) = WarrenIdentity::generate();
println!("address: {}", identity.address()); // wb...

// Restore it later from the mnemonic.
let identity = WarrenIdentity::from_mnemonic(&mnemonic)?;

// Sign a Warren API request. The SDK facade supplies the clock and a random
// nonce; here they are shown explicitly.
let timestamp = 1_700_000_000;
let nonce = [0u8; 16];
let signed = identity.sign_request("GET", "/v1/subscription", b"", timestamp, nonce);
for (name, value) in signed.headers() {
    // attach X-Warren-* headers to your HTTP request
}
```

## Minimum supported Rust version

MSRV is **1.89** (edition 2024), pinned in `rust-toolchain.toml`. Newer
toolchains work; older ones are not supported.

## Feature flags

Applications depend only on `warren-sdk`:

| Crate | Feature | Default | Effect |
|---|---|---|---|
| `warren-sdk` | `reqwest-transport` | on | Bundles the reqwest HTTP transport so `WarrenClient::builder().build()` works out of the box. Disable it (`default-features = false`) to bring your own `HttpTransport` and build via `build_with_transport`. |
| `warren-api` | `reqwest-transport` | on | Backs the above; the same opt-out applies. |
| `warren-discovery` | `test-helpers` | off | Exposes server-side signing helpers for tests in other crates. Never enable in production; it is wired only as a dev-dependency. |

## Release channel (build-time)

`WARREN_PRODUCT_ENV` picks the channel a build targets, `prod` (the default when
unset) or `beta`, and `warren_sdk::product::API_URL` resolves to that channel's
API base (`https://api.warrenbrowse.com` or `https://api.beta.warrenbrowse.com`).
Any other value fails the build, and the runtime overrides (`WARREN_API_URL`,
`WarrenClient::builder().api_base(..)`) still win over the compiled default.

```bash
cargo build                             # prod
WARREN_PRODUCT_ENV=beta cargo build     # beta
```

## Build and test

The golden vectors live in `vectors/`, which is a **git submodule** of the
shared [`warren-vectors`](https://github.com/WarrenBrowse/warren-vectors)
repository (a single source of truth reused by every sibling SDK, no
duplication). Clone with submodules, or initialize them after cloning:

```bash
git clone --recurse-submodules git@github.com:WarrenBrowse/warren-sdk-rs.git
# or, in an existing checkout:
git submodule update --init
```

```bash
cargo build --workspace
cargo test  --workspace      # the test binaries read vectors/ at runtime
cargo fmt   --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny  check
```

The `crates/warren-identity/tests/vectors.rs` test (and the per-crate
`tests/vectors.rs` files) replay the shared vectors; every other language SDK
replays the same files. CI fetches the private submodule using a `VECTORS_TOKEN`
secret (a PAT with read access to this repo and `warren-vectors`); set it as an
org or repo secret for the `test` and `coverage` jobs.

## License

AGPL-3.0-or-later. See `LICENSE`.
