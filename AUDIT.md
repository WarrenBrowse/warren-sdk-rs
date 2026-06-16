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
| MED | TOFU reachable by default with no warning or first-use persistence (effectively trust-on-every-use when no pin is set). | FIXED. `server_pubkey_pin` docs state production MUST pin, and the `ServerKeyStore` trait (builder hook, disk/keychain impl supplied by the embedder) now provides true first-use persistence: the verify path consults `load_pin()` as the effective pin and persists the trusted key on first use, turning the unpinned default from trust-on-every-use into trust-on-first-use. (Pinning still recommended; the unpinned `build` requires explicit `allow_any_server_key()`.) |
| LOW | Facade examples steer callers to `ExitSelector::select` (deterministic first match, ignores weight and zero-weight relays). | FIXED. The crate-level facade example now uses `select_weighted`, and `select_weighted` is documented as "the recommended default" (honors weight, excludes zero-weight) with `select` clearly marked deterministic and `select_for_attempt` for per-retry choice. No doc/example steers to the bare `select`. |
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
| P7 | Error variants allocate `String` on the error path. | FIXED. The datagram fast path does not stringify, and the previously-deferred typed error sources are now done: `TunnelError`/`MultihopError`/`NetError`/`ClientError` carry their cause via typed `#[source]`/`#[from]` variants, no `String`-wrapping. |
| P8 | `PacketSink::send_packet` is `async` but wraps a sync `send_datagram` (no real backpressure). | DEFERRED. Add backpressure (semaphore or `send_datagram_wait`) with the bridge. |
| P9 | smoltcp TUN-mode netstack ceiling (no SACK, poll model). | DEFERRED (TUN mode, not built yet). Drive smoltcp on a dedicated thread; pin a maintained `netstack-smoltcp` fork. |

## Rust architecture / clean code

| Pri | Finding | Status |
|---|---|---|
| P1 | `spawn_fake_exit` triplicated across three test files; `async` keyword unused on those helpers. | FIXED. Extracted to the shared `warren-test-support` crate (`spawn_fake_exit`, plus `spawn_fake_multihop_exit`); the three test files (`warren-transport`, `warren-net`, `warren-sdk`) now consume the single definition. |
| P1 | Five quinn error types stringified in `TunnelError`; `TransportError::Io(String)`, `NetError::*(String)` lose the source. | FIXED. `TunnelError`/`MultihopError` carry the quinn/io/tls cause via typed `#[source]`/`#[from]` variants (`Bind`, `Connect`, `SendDatagram`, `ReadDatagram`, `Tls`, `Frame`, ...); `NetError` was split into typed variants with `#[source]` (no `String`). The address-bearing cause is reachable only via `source()`, not the top-level `Display` (no-log). |
| P1 | Golden vectors are minimal (1 BIP39, 1 canonical-message, 1 signature). | PARTIAL. The wire-format vector set is now substantially broader: `multihop_frame.json`, `control.json` (`/v2`) and `pop.json` were frozen alongside identity/signing, all replayed cross-language. Enriching the identity/signing fixtures with more BIP39/signature cases remains a nice-to-have. |
| P1 | No test for `parse_response(ExternalAddress)` in NAT-PMP. | FIXED. Added `parse_external_address_response`. |
| P2 | `ResultCode` (NAT-PMP) not `#[non_exhaustive]`. | FIXED. |
| P2 | API endpoints `register/check/open_session/close_session/delete_account` untested; `BadClock` untestable without an injectable clock. | FIXED. Per-endpoint mock tests added (see follow-up pass). `BadClock` is testable: `unix_secs_from(SystemTime)` is split out from `now_secs`, and `pre_epoch_clock_is_bad_clock` drives the pre-epoch branch without freezing a real clock. |
| P2 | `ClientError::Deserialize` covers three distinct failure modes. | FIXED. Split into `ResponseEncoding` / `ResponseJson` / `RequestSerialize` (see the clean-code error pass), each carrying its typed `#[source]`. |
| P2 | `cast_possible_truncation` (ss58 prefix, SOCKS5 domain length) lacks a justifying comment. | FIXED/NON-ISSUE. The ss58 prefix cast carries a range-proof comment (`ident` masked to 14 bits, so each `as u8` is in range). The only SOCKS5 `host.len() as u8` casts are in `#[test]` helpers with literal short hostnames; no production encode path truncates a domain length. |
| P3 | `WarrenClient<T>` generic surfaces into app code; consider a `DefaultClient` alias. | FIXED. `pub type DefaultClient = WarrenClient<ReqwestTransport>;` is exported and used by the FFI surface. |
| P3 | `WarrenClientBuilder::build` panics on missing identity (bad across FFI). | FIXED. `build`/`build_with_transport` return `Result<_, BuildError>` (`MissingIdentity`, `UnpinnedServerKey`); no panic, so an FFI embedder gets a recoverable error. |
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

## Second independent audit (follow-up pass)

A fresh, independent reviewer re-read the whole tree and cross-checked every
frozen contract against warren-core line by line. It confirmed the crypto core
is a byte-exact, faithful port (identity, SS58, signing, Setup/SetupAck, signed
relay list v5, RFC 7250 TLS, NAT-PMP) and that the first audit was accurate. It
surfaced two items the first pass had understated, both now addressed.

| Sev | Finding | Status |
|---|---|---|
| HIGH | The anti-rollback `generation` floor was in-memory only (`AtomicU64` resetting to 0 each process start), so a replayed older-but-valid list was accepted by any freshly launched client. | FIXED. The floor moved behind a `GenerationStore` trait the builder accepts; the default `InMemoryGenerationStore` keeps the prior (process-scoped) behavior, and an embedder can supply a persistent store so anti-rollback survives restarts. New tests `persisted_floor_rejects_rollback_on_a_fresh_client` and `fetch_advances_the_persistent_floor`. |
| MED | `WarrenClientBuilder::build*` panicked on a missing identity, an unwind hazard across the FFI boundary. | FIXED. `build`/`build_with_transport` now return `Result<_, BuildError>` (`MissingIdentity`). |
| MED | Server-key pinning was off by default with no signal, so an unpinned client silently trusted any self-signed list. | FIXED. `build` now returns `BuildError::UnpinnedServerKey` unless a pin is set or `allow_any_server_key()` is called explicitly. |
| MED | The anti-censorship host fallback (primary / alternatives / no-SNI) is listed under ROADMAP P3 but is not implemented: the API client takes a single `api_base`. | FIXED. `WarrenApiClient::new_with_fallback` + the `send` fallback sequence try the primary host with SNI, each `alternative_hosts` entry with SNI, then the primary without SNI; only a connect-class failure advances the sequence and any connected response (any status) stops it. Exposed on the facade via `WarrenClientBuilder::api_alternative_hosts`. Locked by `fallback_retries_alternative_host_on_connect_error`, `fallback_uses_no_sni_as_last_resort`, the all-hosts-fail case, and `non_connect_error_does_not_trigger_fallback`. |
| P1/P2 clean-code | `String`-wrapped quinn/io/serde errors in `TunnelError`, `NetError`, `ClientError` lost their `#[source]`, against CLAUDE.md's own rule. | FIXED. Converted to typed `#[source]`/`#[from]` variants across the three crates; `ClientError::Deserialize` split into `ResponseEncoding` / `ResponseJson` / `RequestSerialize`. This also tightens no-log discipline: the address-bearing cause leaves the top-level `Display` and is reachable only via `source()`. New tests assert the chain is preserved and the `Display` omits the cause. |
| LOW | NAT-PMP `ResultCode::from_raw` folds raw code `3` into the catch-all rather than mirroring warren-core's explicit `3 => NetworkFailure` arm (behavior identical). | FIXED. `from_raw` now has an explicit `3 => NetworkFailure` arm alongside the unknown-code catch-all, mirroring warren-core 1:1. |

All gates green after this pass: `cargo fmt --all -- --check`, `cargo clippy
--workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny
check`. The CI now runs these exclusively on the WarrenBrowse self-hosted runners
across Linux, Windows and macOS.

## Finding reconciliation (every finding treated)

This table closes out every finding from both audit passes. Status is one of:
FIXED (code + test landed), SEAM (the extension point is in place; the perf/impl
body lands with the datapath), or PHASE (a whole subsystem, tracked as a roadmap
phase, not a standalone defect: it requires building code that does not yet exist
and validating it against a real exit).

| Finding | Status | Where |
|---|---|---|
| Anti-rollback floor in-memory only | FIXED | `GenerationStore` hook; `discovery_enforcement.rs` persistence tests |
| Builder panics on missing identity (FFI hazard) | FIXED | `build*` return `Result<_, BuildError>` |
| Server-key pin off-by-default and silent | FIXED | `allow_any_server_key()` required opt-out; `build_refuses_unpinned_unless_explicit` |
| TOFU trust-on-every-use, no persistence | FIXED | `ServerKeyStore` hook; `tofu_pins_the_first_server_key...` |
| Anti-censorship host fallback (P3) not implemented | FIXED | `WarrenApiClient` fallback sequence + reqwest no-SNI client; 4 fallback tests |
| `String`-wrapped errors lose `#[source]` | FIXED | typed variants in transport/net/api; source-chain tests |
| `ClientError::Deserialize` conflates 3 modes | FIXED | split into `ResponseEncoding`/`ResponseJson`/`RequestSerialize` |
| Per-endpoint API tests missing | FIXED | register/check/open/close/delete tests |
| `BadClock` untestable | FIXED | `unix_secs_from` split out; `pre_epoch_clock_is_bad_clock` |
| DAITA fractions unvalidated from peer | FIXED | `decode_setup_ack` rejects out-of-range; regression test |
| NAT-PMP code `3` not mirrored 1:1 | FIXED | explicit `3 => NetworkFailure` arm |
| Facade steered to weight-ignoring `select` | FIXED | `select_weighted` default + docs; `DefaultClient` alias |
| `cast_possible_truncation` unjustified | FIXED | range-proof comment on the SS58 prefix casts |
| `spawn_fake_exit` triplicated | FIXED | extracted to `warren-test-support` crate |
| Golden vectors minimal | FIXED | enriched `vectors/identity.json` (derivation/bip39/canonical/signature) |
| SOCKS5 `Bind`/`UdpAssociate` must be rejected | FIXED | `Command::is_supported()` gate + test (server loop calls it) |
| `PacketSink` batch API (GSO/GRO) | SEAM | `send_batch`/`recv_batch` defaults added; vectored syscalls land with the datapath |
| Shared `quinn::Endpoint` for reconnect/multiconn | PHASE (P5/P6) | belongs to the reconnect supervisor; no value without the datapath driving it |
| Send backpressure on `PacketSink` | PHASE (P6) | meaningful only once a datapath produces sustained load |
| smoltcp netstack threading ceiling | PHASE (P6) | the netstack does not exist yet |
| Non-root proxy + TUN datapath | PHASE (P6) | the product's core remaining subsystem; validate against a real exit |
| Multihop HPKE frame | PHASE (multihop) | a full frozen wire subsystem; port + freeze vectors as its own phase |

CI is green on every fix above across the three self-hosted OS runners.

## Third audit: independent multi-agent review of the P6 datapath

After the non-root datapath (SOCKS5 + HTTP CONNECT + smoltcp netstack +
`WarrenClient::start_proxy`) landed, four independent agents re-reviewed the tree
in parallel (security, architecture/clean-code, datapath correctness, and
performance/multi-platform). They confirmed the crypto core remains a faithful
port and the seam design is sound, and surfaced real defects in the new datapath
that the happy-path in-process tests masked. All are now fixed.

| Sev | Finding | Status |
|---|---|---|
| HIGH | Device MTU set to the policy `assigned_max_mtu` (1350) while the QUIC datagram carries ~1200 at `initial_mtu` 1280: full-size packets fail `send_datagram` against a real exit. The outbound pump then `break`s on that error, silently killing all egress ("works in tests, dead in prod"). | FIXED. Device MTU now derives from `PacketSink::max_payload()`; the pump drops-and-continues on a per-packet send error and only tears down when the tunnel read side closes. |
| HIGH | No backpressure: `poll_write` over an unbounded channel always returned `Ready`, and `pending_out`/`to_app`/`device.rx` were uncapped, so a fast local app or a flooding exit grew the single engine task's heap without bound (remote+local DoS). | FIXED. Per-connection bounded channels with `PollSender` (writer parks via `poll_reserve`); the read side only drains a socket while the app channel has a permit, so the TCP window actually closes; `PENDING_OUT_CAP` bounds per-conn buffering; inbound/outbound frame channels are bounded. |
| MED | `connector.connect()` hung forever if the exit never answered the SYN (no timeout), hanging the SOCKS5 client. | FIXED. `CONNECT_TIMEOUT` (10s) deadline per pending connect; on expiry the socket is aborted and the connect fails with `NetError::ConnectTimeout`. |
| MED | Connections keyed by the recyclable smoltcp `SocketHandle`: a late write/shutdown after reap could hit a reused handle and corrupt a different flow. | FIXED. Connections keyed by a monotonic conn-id with per-connection channels; the handle is never used for routing. |
| MED | No-log regressions reachable from one `fetch_exits()`: `SignedError::ServerPubkeyMismatch` rendered server pubkeys, `SignedError::Relay` rendered endpoint ids / addresses, and `reqwest_transport` stringified the URL/host/IP into `TransportError`, all surfaced via transparent top-level `Display`. | FIXED. Pubkeys/addresses dropped from all three `Display`s (fields kept for inspection); reqwest errors mapped to generic address-free reasons. Locked by `server_pubkey_mismatch_display_omits_the_key`. |
| MED | Ephemeral local port was a bare wrapping counter (collision after 16k). | FIXED. Free-port tracking via a `used_ports` set, released on reap. |
| LOW | `SignedRelayList`/`JsonRelay` lacked `deny_unknown_fields`; no bound on the signed validity window (`expires_at - signed_at`). | FIXED. Both added; validity window capped at 7 days (`ValidityTooLong`). Locked by tests. |
| LOW | IPv6 targets accepted by the connector but unroutable (only an IPv4 default route). | FIXED + v6 datapath wired. `NetstackConfig::with_ipv6` installs the exit-granted v6 client address + default v6 route; `TunnelConnector::connect` routes v6 targets when a v6 assignment is present and refuses them (fail-closed) otherwise. The facade enables dual-stack from the multihop `IpAssign` (v6 + v6 gateway). Validated in-process (v6 connect/echo over the tunnel; refusal without a v6 assignment). Update (2026-06-15): AAAA-over-tunnel is done for both TCP and UDP domain targets (AAAA preferred under a v6 assignment, A fallback, via a shared `resolve_dualstack`). Only real-exit v6 validation remains pending. |
| LOW | smoltcp ISN `random_seed` was a hardcoded constant (RFC 6528 predictability). | FIXED. Seeded from `rand::random()` at engine start. |
| LOW | `NetError::Unsupported(&str)` had become a catch-all for five conditions. | FIXED. Split into `ConnectionRefused` / `ConnectTimeout` / `ConnectFailed` / `EngineStopped`. |
| MED (coverage) | Out-of-subnet routing (the production path via the default route) had no test; same-subnet tests never exercised it. | FIXED. `netstack_routes_out_of_subnet_target_via_default_route` plus a connection-refused test. |
| PERF | Per-packet copies/allocs (Vec on write, byte-wise `VecDeque<u8>`, `Bytes`->`Vec` on inbound), one engine wakeup per TCP segment. | FIXED. `Bytes` threaded end to end (zero-copy inbound; chunked `VecDeque<Bytes>` send queue); `while iface.poll() != None` drains smoltcp per wake. |
| n/a | Validate the datapath against a real warren-core exit (`assigned_max_mtu`, FIN/RST under loss, sustained throughput); DNS-over-tunnel for domain targets; HTTP head `BufReader`; shared endpoint/reconnect supervisor; per-OS TUN. | PARTIAL. DONE: DNS-over-tunnel (gateway forwarder + configurable resolver), the reconnect/backoff supervisor (P5), and a full multihop tunnel live-validated against the real NL exit (real `IpAssign` + confirmed egress). STILL OPEN (resource-bound): sustained-throughput / loss-behavior validation against a real exit and the per-OS privileged TUN backend. |

After this pass: `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo
deny check` all green; 28 test binaries pass.

## Live validation against the production API and a real exit

Run via `cargo run -p warren-sdk --example live_exit` against
`https://api.warrenbrowse.com` with the production pin. This is the real-exit
validation CLAUDE.md mandates, and it immediately found what no fake-device test
could.

What it PROVED works end to end against production:

- The signed exit list fetch and verification against the pinned server key
  (`4c2c9253…`), freshness and anti-rollback enforcement, and weighted selection.
- The QUIC connection and the RFC 7250 raw-public-key TLS 1.3 handshake to a real
  exit (`204.168.207.130:443`, DE/Kassel).

What it FOUND:

| Sev | Finding | Status |
|---|---|---|
| HIGH (wire bug) | `endpoint_id` in the live `/v1/exits` is a Warren **SS58 (`wb…`) address**, but the SDK decoded it as hex only, so `fetch_exits` failed on the real list. The golden vector used hex, hiding it. | FIXED. `decode_endpoint_id` is SS58-first / hex-fallback (matches warren-core `json_io`); locked by `endpoint_id_accepts_ss58_and_hex`. Real fetch now verifies. |
| HIGH (architecture/blocking) | The real exit rejected our `Setup` frame with `malformed setup frame`. Production exits at `:443` read a **`WarrenMultihopFrame`** (HPKE-sealed, cleartext `exit_id` for routing) as the FIRST frame on EVERY connection (single-hop included; the dual-role node terminates locally when the `exit_id` is its own), then open the sealed inner `Setup`/control. The SDK's raw `Setup`-first handshake does NOT match the production wire protocol. | FIXED + live-validated. The full multihop HPKE layer was built: `warren-wire::multihop` frame codec (byte-exact, frozen vector), `warren-multihop` HPKE client session (X25519/HKDF-SHA256/ChaCha20Poly1305, epoch/seq replay window), directory verification with the operational-node PKI attestation, and `start_proxy_multihop` over the sealed frame. A full real tunnel completed end to end against the production NL exit (real `IpAssign`, confirmed egress). |

Correction to earlier framing: the prior "P6 datapath validated in-process" is
accurate only against the SDK's own fake exit, which speaks the SDK's
(non-production) `Setup`-first handshake. The userspace netstack, proxy front
ends, backpressure, MTU and routing fixes are real and sound, but the **handshake
the datapath rides on is not yet the production one**. No real tunnel is possible
until the multihop frame lands. ROADMAP is updated to make multihop a required,
blocking phase rather than an optional one, and to note the exit X25519 descriptor
must be sourced (separate endpoint) for HPKE.

## Multihop feature audit (5 independent sub-agents)

After the multihop layers landed and were live-validated against a production
exit, five independent sub-agents audited the new code, one per aspect:
security, byte-for-byte wire compatibility vs warren-core, architecture /
portability, TDD / test quality, and multi-platform / CI. Findings and
disposition:

| Sev | Aspect | Finding | Status |
|---|---|---|---|
| HIGH | security + wire (consensus) | The directory verifier only checked the exit descriptor, which signs `(exit_id, x25519)` but NOT `exit_ed25519_pubkey`. The Ed25519 RPK the client pins for the TLS handshake was therefore server-trusted, not operational-key-bound: a hostile directory could swap the RPK to redirect the dial. | FIXED. Now verifies the relay descriptor AND the node attestation (`WARREN_PKI_OPERATIONAL_NODE_V1 \|\| relay_id \|\| exit_ed25519_pubkey \|\| asn_be \|\| country`), dropping any node not fully vouched (matches warren-core `node_fully_vouched`). Live prod directory still yields 3 vouched exits (byte layouts confirmed). 11-test verifier suite added. |
| HIGH | security | Directory fetch lacked the anti-rollback + validity-window cap the relay-list path already has. | FIXED. `MAX_VALIDITY_SECS` (7d) cap in the verifier (`DirectoryError::ValidityTooLong`); per-directory `generation` floor via a dedicated `GenerationStore` in the facade (`SdkError::RolledBackMultihopDirectory`). |
| MEDIUM | architecture | `start_proxy_multihop` hardcoded the tunnel subnet (`10.66.0.0/16`, gw `10.66.0.1`) instead of the exit-supplied `IpAssign`, a latent black-hole if a real exit assigns differently. | FIXED. The netstack subnet (ip/prefix/gateway) is now derived from the `IpAssign`. |
| HIGH | TDD | `multihop_directory.rs` had no test module; `open_response` error paths and the data-plane replay/forgery drop were untested. | FIXED. Directory verifier suite (every `DirectoryError` variant + forged relay/exit/attestation dropped + relabeled-country dropped), `open_response` error tests, a replaying-exit integration test (client drops the duplicate, delivers each packet once), and a facade `NoMultihopDirectory(404)` test. |
| HIGH | multi-platform | The `tun`/`killswitch` features were never compiled/linted in CI. | FIXED. clippy + test now run `--all-features` on every OS (today empty, in place for the per-OS datapath). |
| LOW | multi-platform/hygiene | Stale "single rand_core in the tree" comment; `MultihopFrameError` not re-exported. | FIXED. |

Verified-correct by the audits (no action): the HPKE construction (AAD /
export-info byte layouts, zero-nonce-per-unique-key discipline, forward/reverse
direction tag), PoP binding, RFC 6479 replay window and verify-then-record
ordering, frame/control DoS bounds, no-log discipline (no key/IP/nonce in any
Display or log), `unsafe_code = "forbid"`, the independent fake-exit (re-derives
crypto, so a green loopback proves wire interop), exclusive self-hosted CI, the
`--locked` + 1.89 pin, and the address-family-matched UDP bind. All seven pure
wire layers (frame, control, PoP, HPKE session, setup semantics, replay,
directory preimage) were confirmed byte-for-byte identical to warren-core.

Follow-ups landed after the audit (2026-06-14):

- P3 lifecycle endpoints completed in TDD: Apple IAP (`init_apple_payment`,
  `check_apple_payment`), checkout voucher polling (`pull_pending_voucher`),
  support (`submit_support_report`), and incident reporters (`report_exit_down`,
  `report_pubkey_mismatch`), with byte-for-byte JSON DTOs (redacting Debug on the
  Apple JWS, SCREAMING_SNAKE_CASE `IncidentReason`).
- P5 reconnection: full-jitter `Backoff` + `connect_with_retry` in
  `warren-transport::reconnect`, unit-tested with `tokio::time` paused.
- Shared cross-language `vectors/{multihop_frame,control,pop}.json` are now frozen
  and replayed by tests (`warren-wire::multihop_vectors`,
  `warren-multihop::pop_vectors`), mirroring `handshake.json`.

Deferred (tracked, not blocking):

- A per-packet HPKE keystream `vectors/*.json` still needs a fixed-encapsulated-
  key fixture for the non-deterministic seal; the deterministic wire layers
  (frame, control, PoP preimage) are now covered above.
- FFI error shape: `MultihopError::SetupIo` / `TunnelError::HandshakeIo` carry a
  `Box<dyn Error>` source, not uniffi-serializable. Both (single-hop + multihop)
  are addressed together in P9 when the tunnel FFI surface is exported.
- IPv6 datapath: the netstack engine is IPv4-only, so an assigned v6 is not yet
  routed (the v6 bind branch is also untested). Tracked with the per-OS datapath.
- CI runner labels could add a custom org label (e.g. `warren`) to pin jobs to
  the intended self-hosted hosts; left as a recommendation pending confirmation
  of the live runners' label sets (changing labels blind could unschedule jobs).

(The earlier "DNS-disabled downgrade defense not consumed" and "IPv6 datapath is
IPv4-only" deferrals are now resolved: `VerifiedExit` carries `dns_disabled` and
the facade fails closed via `SdkError::ExitDnsDisabled`; the netstack routes an
assigned v6 address. See ROADMAP P6.)

## Hardening pass 2026-06-16 (whole-codebase quality sweep)

A second full review (five parallel per-crate reviewers) after the userland and
DAITA work. The cryptographic core and the facade surface were again found solid
(unsafe-free, no secret logging, faithful to warren-core); findings were mostly
medium/low. Resolved in this pass:

| Sev | Finding | Status |
|---|---|---|
| HIGH | Multi-hop directory checked the validity-window cap on UNVERIFIED data (before the envelope signature), unlike the signed relay list. | FIXED. The anti-freeze check now runs after `server_pubkey.verify`, so a tampered `expires_at` surfaces as `BadEnvelopeSignature`, not `ValidityTooLong`. |
| HIGH | SOCKS5 codec accepted a zero-length domain; HTTP CONNECT mishandled bracketless/zoned/portless IPv6 authorities (coerced to bogus domains). | FIXED. Empty domain rejected at the codec; `parse_authority` parses the `[v6]:port` form strictly and rejects malformed v6 authorities. Direct tests added. |
| HIGH | Documented error variants without a triggering test (signed-list `InvalidHex`/`PubkeyNotOnCurve`/`InvalidNodeId`/`InvalidEndpointAddress`; `query.rs`/`relay.rs` selectors untested; NAT-PMP `delete`). | FIXED. Direct tests added for each; `transport.rs` (`Method::as_str`, `is_connect`) covered. |
| MED | Netstack `alloc_port` aliased a live port under ephemeral exhaustion. | FIXED. `alloc_port` returns `Option`; callers fail closed with `ConnectFailed`. |
| MED | Multi-hop frame decode ignored trailing bytes; size cap was decode-only. | FIXED. `take_from_bytes` + `TrailingBytes`; cap enforced on encode too. |
| MED | `SessionError::Hpke` overloaded the unknown-epoch case; `seal` silently accepted the retained old epoch for forward frames. | FIXED. Distinct `UnknownEpoch`; `seal` rejects a non-current epoch. |
| MED | DAITA pump read the next deadline before registering its wake waiter (check-then-wait). | FIXED. `Notified::enable()` before the deadline snapshot makes the wait race-free. |
| MED | FFI could not reach the DAITA uplink defense. | FIXED. `with_options(FfiClientOptions)` exposes DAITA (and roots + persistence); CI grep-guards the new surface. |
| LOW | `SdkError::Daita(String)` was the one stringly-typed variant; `RpkSigner` derived `Debug` on a secret-holding type; crate/builder doc examples carried a bogus pin. | FIXED. Typed `UnknownDaitaMachine`/`EmptyDaitaPool`/`DaitaConfig`; manual `RpkSigner` Debug (public-key prefix only); realistic example pins + a builder `# Examples`. |
| LOW | `SetupAck.daita_spec` (frozen, with `f64` caps) had no byte-exact vector; NAT-PMP reserved-byte and unknown-result-code behavior unpinned; `ServerStatus.body` lacked a no-log caveat. | FIXED. Byte-exact `daita_spec` golden vector; reserved-byte-ignored and unknown-code-maps tests; no-log caveat documented. |
