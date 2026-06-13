# warren-sdk-rs: Project Rules for Claude Code

Standalone Rust client SDK for the Warren VPN. This repo is the reference
implementation of the Warren client protocol; the same SDK is reimplemented in
TypeScript, Dart, Python, Kotlin, Swift and Java. Read `ARCHITECTURE.md` for the
layering and `ROADMAP.md` for the phase plan.

## Prime directive: standalone and wire-compatible

1. **No dependency on warren-core.** This SDK never imports a warren-core crate.
   It is a clean-room reimplementation. warren-core is read-only reference
   material at `../warren-core` (source of truth for the frozen contracts).
2. **Wire compatibility is non-negotiable.** Identity derivation, SS58, request
   signing, the handshake frames, the signed relay list, NAT-PMP and the
   multihop frame must match warren-core byte-for-byte, otherwise the SDK cannot
   talk to real exits or the production API.
3. **Golden vectors are the contract.** Every frozen format is pinned by a file
   under `vectors/`. These vectors are shared across all sibling-language SDKs.
   Changing a vector means changing the wire format, which requires bumping the
   schema version (for example `identity/v2`). Never edit a vector to make a test
   pass; fix the code.
4. **Portability in concept.** Keep each layer mappable to the other languages:
   no clever Rust-only constructs in the public surface, narrow async seams, and
   plain serializable types at boundaries (the FFI layer depends on this).

## TDD is mandatory

Red, green, refactor. For every functional change:

1. Write the test first. It must fail for the right reason before any production
   code exists.
2. Make it pass with the minimal change.
3. Refactor with the test green.

Rules:

- Every public function has a direct test. Every documented error variant
  (`# Errors`) is triggered by at least one test.
- No hollow tests (`assert!(true)`, `assert_eq!(x, x)`). A test must be able to
  fail by breaking the production code.
- Frozen wire formats get a vector test that pins the exact bytes/string.
- Async tests use `#[tokio::test]`; networking regression tests use
  `flavor = "multi_thread"`.
- Local fake-device tests are necessary but not sufficient for tunnel features:
  the real behavior is validated against a real exit before claiming it works.

## Error handling

- Libraries use `thiserror`; binaries use `anyhow`. Never a stringly-typed error.
- Public error enums are `#[non_exhaustive]`.
- Attach the underlying error via `#[source]`; never string-wrap it.
- No-log discipline: never put a pubkey, address, IP, nonce or other identity
  material in an error message or log in clear. Redact to a short prefix if a
  value is genuinely needed for debugging.

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

## Language policy: English only in code

All code comments, doc comments, identifiers, commit messages and PR
descriptions are in **English**. Rationale: keep the codebase aligned with the
sibling-language SDKs and accessible to all contributors. Exceptions:
`.planning/` artifacts and assistant chat output to the user may be in French.

## Typography: never use the em-dash

The em-dash `—` (U+2014) and en-dash `–` (U+2013) are banned everywhere you
author text (code, comments, docs, commit messages). Use a comma, a colon, a
period, a hyphen for ranges, or restructure the sentence. When you edit a file
that still contains a stray dash, fix it as part of your change.

## Comment content: why, not what

A comment explains the non-obvious why: an invariant, a subtle reason for an
unusual choice, or a warning that stops a future agent from reintroducing a
known bug. No step narration, no tombstones of old behavior, no restating the
next line. Be parsimonious; when in doubt, leave it out.

## Crate layout

One crate per layer under `crates/` (see `ARCHITECTURE.md`). The public surface
lives in `src/lib.rs` (re-exports plus crate docs); modules are split by concern.
Applications depend only on `warren-sdk`, which re-exports the layers.

## Secrets and zeroization

Buffers holding secret material (seeds, signing keys) are zeroized on drop
(`zeroize`). Never derive `Debug` on a type holding a secret; implement it
manually to render only the public handle (for example the SS58 address).
