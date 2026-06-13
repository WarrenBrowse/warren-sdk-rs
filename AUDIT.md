# Audit report (post-implementation)

Comprehensive audit of `warren-sdk-rs` after the P1 to P9 implementation, across
security, Rust architecture/clean-code, and performance/userland. Conducted by
three independent reviewers reading the full source and cross-checking the
frozen contracts against warren-core. This document records every finding, its
status (FIXED in this pass, or DEFERRED with rationale), and the follow-up list.

The cryptographic core was found solid: identity derivation, SS58, request
signing, the TLS 1.3 raw-public-key verifier, and signed-relay-list verification
are faithful ports of warren-core's frozen contracts (verified line by line).
No `unsafe`, no secret logging, no panics on attacker-controlled input.

## Security

| Sev | Finding | Status |
|---|---|---|
| HIGH | Facade dropped anti-rollback (`generation`) and anti-freeze (`expires_at`) enforcement on the live-fetch path: a replayed stale-but-valid signed exit list was accepted. | FIXED. `WarrenClient::fetch_exits` now rejects expired lists (`SdkError::StaleRelayList`) and enforces a monotonic generation floor (`SdkError::RolledBackRelayList`). Locked by `tests/discovery_enforcement.rs` (fresh accepted, expired rejected, rollback rejected). |
| MED | rustls `logging` feature could surface the SNI (which encodes the exit pubkey) into an embedder's `log` sink. | FIXED. Dropped `logging` from the rustls features (`Cargo.toml`). |
| MED | TOFU reachable by default with no warning or first-use persistence (effectively trust-on-every-use when no pin is set). | PARTIAL. `server_pubkey_pin` doc now states production MUST pin and spells out the risk. True first-use persistence is DEFERRED (needs a storage hook). |
| LOW | Facade examples steer callers to `ExitSelector::select` (deterministic first match, ignores weight and zero-weight relays). | DEFERRED. `select_with_rng`/`select_for_attempt` already implement weighted selection; the facade should default to them. Tracked. |
| INFO | Confirmed good: unsafe-free, secrets zeroized, no secret in `Debug`, verifier/signing faithful to warren-core, DoS gates (SS58 length cap, `MAX_SETUP_FRAME_BYTES`, trailing-byte rejection, `deny_unknown_fields`), strict cargo-deny. | n/a |

## Performance / userland

| # | Finding | Status |
|---|---|---|
| P1 | Per-packet `to_vec()` copy on receive (quinn already returns `Bytes`). | FIXED. `ClientSession::read_datagram` returns `bytes::Bytes`; `PacketSink::recv_packet` returns `Bytes`. Zero-copy receive. |
| P2 | Per-packet `to_vec()` then `Bytes::from` on send. | FIXED. `ClientSession::send_datagram` takes `impl Into<Bytes>`; `QuicPacketSink` passes `Bytes::copy_from_slice` (single unavoidable copy from `&[u8]`). |
| P3 | No QUIC `TransportConfig`: datagram buffers, idle timeout, keepalive, initial MTU all at quinn defaults (64 KiB datagram buffers overflow under burst; no idle timeout = zombie connections). | FIXED. `warren_transport_config()` sets 8 MiB recv / 4 MiB send datagram buffers, 180s idle, 20s keepalive, 1280 initial MTU (matching warren-core constants). |
| P4 | `max_payload()` ignored the exit's `assigned_max_mtu` and floored at 1200. | FIXED. Returns `min(path_mtu, assigned_max_mtu)`, falling back to the policy MTU before the first PMTU probe. |
| P10 | quinn `initial_mtu` not set, costing a PMTU probe RTT. | FIXED (via P3): `initial_mtu = 1280` (IPv6 minimum, safe on every path). |
| P5 | `PacketSink` has no batch API; GSO/GRO (quinn-udp) underused. macOS needs `fast-apple-datapath`. | DEFERRED to the P6 datapath bridge. Add `send_batch`/`recv_batch` and enable `fast-apple-datapath` on macOS. |
| P6 | New `quinn::Endpoint` + TLS config per `connect_tunnel`; should be shared for reconnects/multiconn. | DEFERRED. Hoist a shared endpoint into `WarrenClient` when the supervisor/multiconn lands. |
| P7 | Error variants allocate `String` on the error path. | PARTIAL (overlaps the clean-code error finding below). Datagram fast path no longer stringifies on the happy path; typed error sources DEFERRED. |
| P8 | `PacketSink::send_packet` is `async` but wraps a sync `send_datagram` (no real backpressure). | DEFERRED. Add backpressure (semaphore or `send_datagram_wait`) with the bridge. |
| P9 | smoltcp TUN-mode netstack ceiling (no SACK, poll model). | DEFERRED (TUN mode, not built yet). Drive smoltcp on a dedicated thread; pin a maintained `netstack-smoltcp` fork. |

## Rust architecture / clean code

| Pri | Finding | Status |
|---|---|---|
| P1 | `spawn_fake_exit` triplicated across three test files; `async` keyword unused on those helpers. | DEFERRED. Extract a shared `warren-transport` test helper. (Low risk, cosmetic.) |
| P1 | Five quinn error types stringified in `TunnelError`; `TransportError::Io(String)`, `NetError::*(String)` lose the source. | DEFERRED. Convert to `#[source]`-carrying variants. Justified follow-up; touches several call sites. |
| P1 | Golden vectors are minimal (1 BIP39, 1 canonical-message, 1 signature). | DEFERRED. Enrich `vectors/` for stronger cross-language confidence. |
| P1 | No test for `parse_response(ExternalAddress)` in NAT-PMP. | FIXED. Added `parse_external_address_response`. |
| P2 | `ResultCode` (NAT-PMP) not `#[non_exhaustive]`. | FIXED. |
| P2 | API endpoints `register/check/open_session/close_session/delete_account` untested; `BadClock` untestable without an injectable clock. | DEFERRED. Add per-endpoint mock tests; consider an injectable clock. |
| P2 | `ClientError::Deserialize` covers three distinct failure modes. | DEFERRED. Split into precise variants. |
| P2 | `cast_possible_truncation` (ss58 prefix, SOCKS5 domain length) lacks a justifying comment. | DEFERRED. Add range-proof comments / bounded `#[allow]`. |
| P3 | `WarrenClient<T>` generic surfaces into app code; consider a `DefaultClient` alias. | DEFERRED. |
| P3 | `WarrenClientBuilder::build` panics on missing identity (bad across FFI). | DEFERRED. Return `Result` when the FFI tunnel surface lands. |
| P3 | `doc_markdown` / `missing_panics_doc` pedantic nits. | DEFERRED (cosmetic; not in the default lint set). |
| Good | Clean layering, no cycles, consistent thiserror + `#[non_exhaustive]`, no `todo!`/`unimplemented!`, no em-dashes, all public items documented, FFI surface generic-free. | n/a |

## What was fixed in this pass

- Security HIGH-1 (anti-freeze + anti-rollback enforcement) with regression tests.
- Security: removed the SNI-leaking rustls `logging` feature; hardened the pin doc.
- Performance: zero-copy `Bytes` datagram plane (send and receive), full QUIC
  transport tuning (datagram buffers, idle, keepalive, initial MTU 1280), and a
  correct `max_payload` that honors both path and policy MTU.
- Coverage: NAT-PMP `ExternalAddress` parse test; `ResultCode` made
  `#[non_exhaustive]`.

All gates remain green after the fixes: `cargo test --workspace`, `cargo fmt
--all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo deny check`.

The DEFERRED items are tracked in `ROADMAP.md` under "Audit follow-ups". They are
either contained refactors (typed error sources, shared test helper, richer
vectors, per-endpoint tests) or work that belongs to the not-yet-built datapath
bridge (batch I/O, shared endpoint, backpressure, smoltcp threading).
