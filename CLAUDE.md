# warren-sdk-rs: Project Rules for Claude Code

Standalone Rust client SDK for the Warren VPN. This repo is the reference
implementation of the Warren client protocol; the same SDK is reimplemented in
TypeScript, Dart, Python, Kotlin, Swift and Java. Read `ARCHITECTURE.md` for the
layering.

> Shared Warren rules (single source of truth: WarrenBrowse/warren-workspace).
> They resolve when this repo is checked out inside the workspace (mani sync);
> cloned standalone, the imports just warn harmlessly.
@../shared/rules/00-conventions.md
@../shared/rules/10-tdd.md
@../shared/rules/20-errors-secrets.md
@../shared/rules/30-git-commits.md
@../shared/rules/40-wire-vectors.md

## Prime directive: engine-backed, no backend dependency, wire-compatible

1. **No dependency on the private backend (`warren-core`).** This SDK never
   imports a `warren-core` crate; `../warren-core` is read-only reference
   material only. The data-plane primitives (wire frames, identity, multihop
   HPKE, DAITA, TUN, TLS) come from the **shared open-source engine**
   `warrenguard` (AGPL-3.0, sibling checkout `../warrenguard`): the SDK's
   `warren-{wire,identity,multihop,daita,tun,tun-core}` crates are thin
   re-exports of the matching `warrenguard-*` engine crates, so there is a
   single source of truth for the protocol primitives rather than a duplicate
   reimplementation. The SDK keeps its own control-plane (`warren-api`,
   `-discovery`, `-sdk`, `-sdk-ffi`) and userland transport (`warren-transport`,
   `-net`), which are intentionally SDK-specific (non-root userland datapath).
   The wire-facing client-to-server contract has a second neutral home,
   `warren-contract` (sibling git-dep patched to the local checkout, pinned by `.warren-contract-version`,
   depends only on `warrenguard-wire`): it owns the SS58 address codec, the
   X-Warren canonical signing message plus header names, and the HTTP `/v1`
   DTOs. `warren-identity` re-exports its `ss58` and `auth` modules (as
   `ss58` and `signing`) and `warren-api` re-exports its `dto`; `warren-core`
   depends on the same crate, so this contract cannot drift between the SDK and
   the backend either.
2. **Wire compatibility is non-negotiable** (see the shared wire-vectors rule).
   Identity derivation, SS58, request signing, the handshake frames, the signed
   relay list, NAT-PMP and the multihop frame must match warren-core
   byte-for-byte, otherwise the SDK cannot talk to real exits or the production
   API.
3. **Portability in concept.** Keep each layer mappable to the other languages:
   no clever Rust-only constructs in the public surface, narrow async seams, and
   plain serializable types at boundaries (the FFI layer depends on this).

## Testing specifics (in addition to the shared TDD rule)

- Async tests use `#[tokio::test]`; networking regression tests use
  `flavor = "multi_thread"`.
- Local fake-device tests are necessary but not sufficient for tunnel features:
  the real behavior is validated against a real exit before claiming it works.

## Code style and lints

- Edition 2024, MSRV 1.89 (pinned in `rust-toolchain.toml`).
- `unsafe_code = "forbid"` workspace-wide. Zero exceptions.
- Native `async fn in trait`; no `async-trait` macro unless a `dyn` async trait
  is genuinely required.
- Before any commit, all four gates must be green:
  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  cargo deny check
  ```
- Coverage target: 80% line coverage on library code
  (`cargo llvm-cov --workspace --summary-only`).

## Crate layout

One crate per layer under `crates/` (see `ARCHITECTURE.md`). The public surface
lives in `src/lib.rs` (re-exports plus crate docs); modules are split by concern.
Applications depend only on `warren-sdk`, which re-exports the layers.
