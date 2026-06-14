# Roadmap

Each phase is a vertical slice delivered in strict TDD (red, green, refactor) and
pinned by golden vectors where a wire format is involved. warren-core
(`../warren-core`) is the read-only source of truth for every frozen contract.

## P1: Bootstrap (done)

- Workspace, tooling (fmt, clippy, deny, CI), docs, crate skeletons.
- `warren-identity` fully implemented and tested: BIP39 to Ed25519 (frozen HKDF),
  SS58 `wb…`, canonical request signing with `X-Warren-*` headers.
- Shared golden vectors in `vectors/identity.json`, replayed by tests.

## P2: warren-wire

- Port the Setup/SetupAck handshake codec (postcard, protocol version 4, device
  id, feature bitmask), NAT-PMP (RFC 6886 plus Warren rate-limit trailer), and
  the multihop HPKE frame (frame v1).
- Extract postcard golden vectors from warren-core via a small reference step and
  freeze them under `vectors/`.

## P3: warren-api (done)

- `WarrenApiClient` over an abstracted async HTTP backend, attaching the signed
  headers from `warren-identity`.
- Endpoints implemented and tested: register, subscription, check, exits,
  multihop directory, session open/close, account delete, checkout/voucher
  polling (`pull_pending_voucher`), Apple in-app payments
  (`init_apple_payment`/`check_apple_payment`), and the support/incident
  reporters (`submit_support_report`, `report_exit_down`,
  `report_pubkey_mismatch`). All request/response DTOs are byte-for-byte
  JSON-compatible with warren-core (`IncidentReason` is SCREAMING_SNAKE_CASE,
  the Apple JWS has a redacting `Debug`).
- Google Play payment init/acknowledge is intentionally NOT in the Rust client:
  warren-core exposes it only as a server handler, so the mobile binding drives
  Play Billing natively. Notices and referral are server-only too.
- Anti-censorship host fallback (primary, alternatives, no-SNI). Signed calls
  reuse it; unsigned calls (exits, directory, voucher polling) ride it as well.

## P4: warren-discovery

- Verify the signed relay list (v5): canonical JSON, Ed25519 against the pinned
  server pubkey, generation anti-rollback, expiry anti-freeze.
- Weighted relay selector with geography, IP availability and deterministic
  per-attempt failover. Golden vectors for the signed list.

## P5: warren-transport (done)

- QUIC handshake with rustls raw public keys (RFC 7250), ALPN `h3`, 0-RTT off.
- `ClientTunnel` builder to `ClientSession`, RFC 9221 datagram pump over the
  `PacketSink` seam.
- Full-jitter reconnection backoff (`Backoff`, AWS pattern), a retrying connector
  (`connect_with_retry`), and a state-emitting supervisor (`connect_with_state` +
  `ConnectionState::{Connecting, Connected, Reconnecting, Failed}`) in
  `warren-transport::reconnect`, generic over the connect closure so both the
  retry policy and the exact state-transition sequence are unit-tested with
  `tokio::time` paused (no real sleeps, no network). `ConnectionState` is the
  portable basis for the P9 FFI event stream.

## P6: warren-net

- Non-root `netstack` backend first: userspace TCP/IP (smoltcp) plus a local
  SOCKS5 and HTTP CONNECT proxy, feature-complete on Linux, macOS and Windows.
- Then the privileged `tun` backend: real TUN per OS, split-default routing, DNS
  push, killswitch (nft / pf / WFP).

## P7: port forwarding

- NAT-PMP client and refresh loop, wired into both backends (in proxy mode a
  forwarded port maps to a local listener).

## P8: warren-sdk facade

- `WarrenClient` orchestrating identity, API, discovery, connect and mode
  selection, with a lifecycle event stream. End-to-end tests against a real exit
  and the production API.

## P9: warren-sdk-ffi (uniffi scaffolding done)

- Done and tested: the pure, deterministic identity surface (`generate_identity`,
  `identity_from_mnemonic`, `address_from_mnemonic`, `ss58_encode`/`ss58_decode`,
  `sign_request`) is exported via uniffi (`#[uniffi::export]`,
  `#[derive(uniffi::Record)]`/`uniffi::Error)]`, `setup_scaffolding!()`) with
  owned, generic-free types and a serializable `FfiError`. The crate builds a
  `cdylib`; `src/bin/uniffi-bindgen.rs` generates Swift/Kotlin/Python/Ruby
  bindings, and a CI job (`bindings`) builds the cdylib and regenerates Python +
  Kotlin so any export regression fails the build.
- FFI boundary exception: `warren-sdk-ffi` is the ONLY crate that downgrades
  `unsafe_code` from `forbid` to `deny` (uniffi generates the C-ABI scaffolding;
  we hand-write zero unsafe). Documented at the crate-level `#![allow]`.
- Async surface in progress: a `WarrenFfiClient` uniffi Object (built from
  mnemonic + api_base + pin) over `#[uniffi::export(async_runtime = "tokio")]`
  exposes a sync `address()` plus async `subscription_expiry()`,
  `is_tunnel_active()` (signed `/v1/check`), and `fetch_multihop_exits()`
  (verified directory -> `FfiExit` records). The generated Python binding renders
  the class with `async def`s, proving the async bridge end to end; each error
  path is unit-tested against an unroutable host. `ClientError`/`SdkError` map to
  `FfiError::{ServerStatus, Client}` with the server-status body dropped (no-log).
- Proxy lifecycle done: `WarrenFfiClient::start_proxy(exit_id_hex, socks5_listen)`
  starts the non-root SOCKS5 proxy over a multihop tunnel and returns a
  `WarrenFfiProxy` Object (`socks5_address()`, `http_address()`, idempotent
  `shutdown()`; dropping it tears the tunnel down via `ProxyHandle::drop`). Both
  argument-validation error paths fail fast before any network and are unit-tested;
  the happy path is covered by the facade e2e tests (it needs a real exit, not
  injectable through the concrete reqwest transport at the FFI layer).
- Connection event stream done: `start_proxy` takes an optional
  `ConnectionObserver` (uniffi callback interface) and, via `connect_with_state`,
  retries the dial with full-jitter backoff while reporting each
  `FfiConnectionState` (`Connecting` / `Reconnecting` / `Connected` / `Failed`).
  Tested with a recording observer (the callback interface is a plain Rust trait).
- Remaining: the first Dart/Flutter integration (and Kotlin/Swift/Python/Java),
  consuming the generated bindings. Every binding replays the same `vectors/`.

## Audit follow-ups (see AUDIT.md)

All discrete audit findings are resolved; see the reconciliation table in
`AUDIT.md`. The fixes landed: persistable anti-rollback (`GenerationStore`),
non-panicking `Result` builder, mandatory pin / `allow_any_server_key` opt-out,
trust-on-first-use (`ServerKeyStore`), anti-censorship host fallback, typed
error sources, split `ClientError`, per-endpoint API tests, testable `BadClock`,
DAITA fraction validation, the explicit NAT-PMP `3` arm, `select_weighted` +
`DefaultClient`, justified SS58 casts, the shared `warren-test-support` crate,
enriched golden vectors, the SOCKS5 `Command::is_supported` gate, and the
`PacketSink` batch-I/O seam.

What remains are not defects but whole subsystems, tracked as phases below
because each requires building code that does not exist yet and validating it
against a real exit (a shared `quinn::Endpoint`/reconnect supervisor, send
backpressure, and the smoltcp netstack all belong to that datapath work):

- P6 datapath:
  - Done (validated in-process): non-root SOCKS5 proxy + userspace smoltcp
    netstack over the tunnel (SOCKS5 + HTTP CONNECT), wired through `WarrenClient::start_proxy`; e2e from
    a SOCKS5 client through a real QUIC tunnel to a netstack-terminating exit.
  - DNS-over-tunnel: done. `Target::Domain` is resolved by a smoltcp UDP socket
    in the netstack engine querying the gateway forwarder (`10.66.0.1:53`) with
    the pinned `warren-net::dns` codec, so lookups never hit the host resolver.
    Validated end to end in-process (a DNS+echo "exit" answers the query, then
    the domain CONNECT echoes).
  - UDP associate: egress primitive done. The netstack engine binds a UDP flow
    (`TunnelConnector::open_udp` -> `NetstackUdpSocket`) that sends/receives
    datagrams to arbitrary targets through the tunnel (lossy, source-tagged),
    validated in-process against a UDP echo exit. Pending: the SOCKS5 UDP
    ASSOCIATE server loop (relay socket + per-datagram header) on top of it.
  - Pending: validation against a real Warren exit (mandatory before production);
    a configurable fallback resolver for `dns_disabled` exits;
    privileged per-OS TUN/routing/DNS/killswitch; GSO/GRO batch syscalls behind
    the `PacketSink` batch seam and `fast-apple-datapath` on macOS.
- Multihop HPKE frame (REQUIRED, blocking, discovered via live-exit validation):
  production exits read a `WarrenMultihopFrame` (HPKE-sealed; cleartext `exit_id`)
  as the first frame on EVERY connection, single-hop included, then open the
  sealed inner `Setup`. The current `Setup`-first handshake is rejected by real
  exits (`malformed setup frame`). Slices (all unblocked; the live directory and
  all keys/contexts are identified, no account needed):
  1. DONE: `WarrenMultihopFrame` wire codec, byte-exact + frozen vector
     (`warren-wire::multihop`), with the v1 version/AAD/PKI constants.
  2. DONE: directory verification (`warren-discovery::multihop_directory`):
     server-pin -> envelope sig -> operational cert -> exit descriptor v2/v1,
     byte-exact canonical preimage. VALIDATED against a captured real production
     directory (envelope + all exit sigs verify; yields trusted x25519 keys).
  3. DONE: client HPKE session (`warren-multihop` crate): `hpke =0.13.0` +
     `chacha20poly1305 =0.10.1` + `rand_core 0.9`. `setup_sender(Base, exit_x25519,
     info="warren/multihop/v1/hpke-info")`; per-packet `key = ctx.export(AAD_V1||
     epoch_be||seq_be[||0x02 reverse])`; ChaCha20Poly1305 detached, zero nonce;
     `aad = AAD_V1||exit_id||epoch_be||seq_be`. `seal`/`open_response` with a
     crypto round-trip test (exit-side `setup_receiver` recovers; tampered AAD
     rejected). Cross-language vectors for the deterministic wire layers (frame,
     control `/v2`, PoP preimage) are frozen under `vectors/`; a per-packet HPKE
     keystream vector needs deterministic KEM seeding and stays a nice-to-have.
  4. DONE: datapath integration. The first sealed frame's INNER payload is a
     control message, not a bare `Setup`: ported the `IpRequest`/`IpAssign`
     control codec (`warren-wire::control`, byte-exact `/v2` vectors), the PoP
     (`warren-multihop::pop`), the setup exchange (`warren-multihop::setup`:
     `seal_setup_request`/`open_setup_reply` -> `IpAssignment`), the RFC 6479
     reverse anti-replay window (`warren-multihop::replay`), the multihop QUIC
     tunnel (`warren-transport::multihop`: sealed setup over a bidi stream +
     per-packet sealed datagrams, forward seq from 1), the `MultihopPacketSink`
     (`warren-net`, with a pinned frame MTU overhead bound), and the facade
     (`fetch_multihop_directory`/`connect_multihop`/`start_proxy_multihop`).
     In-process e2e: SOCKS5 -> netstack -> sealed multihop tunnel -> exit echo.
  5. PARTIALLY DONE (live-validated). `cargo run -p warren-sdk --example
     live_exit` against production: the signed exit list + signed multihop
     directory verify under the pinned key, and a real production exit
     (NL/Amsterdam) OPENS our sealed `IpRequest` and returns a sealed `Rejected`
     that the client OPENS and decodes. This proves the multihop frame/HPKE/
     control wire layers byte-for-byte against a real exit; no more "malformed
     setup frame". The remaining step is a full tunnel with a SUBSCRIBED wallet
     (the exit gates the `IpAssign` on its allowlist + the `/v1/session/open`
     device cap): set `WARREN_MNEMONIC` to complete routing.
  6. DONE (live-validated, 2026-06-13). A full real tunnel with a subscribed
     wallet: real `IpAssign` (10.66.0.3/24 from the NL/Amsterdam exit) and
     confirmed egress (a TCP handshake to a public host completes through the
     sealed tunnel via `cargo run -p warren-sdk --example live_proxy`). Frame,
     control `/v2` and PoP cross-language vectors are frozen under `vectors/`.

## Cross-cutting

- Keep the public surface FFI-friendly from P2 onward (no exported generics,
  serializable errors, narrow async seams).
- Keep coverage at or above 80% on library code.
- License: AGPL-3.0-or-later (confirmed).
