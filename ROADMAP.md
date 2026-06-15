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

- Verify the signed relay list (v6): canonical JSON, Ed25519 against the pinned
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

- Client + refresh loop: DONE. `warren-net::portforward` is the RFC 6886 client
  over the backend-agnostic `UdpFlow` seam (so it runs over the netstack today
  and a TUN backend later): `exchange` with exponential-backoff retransmission
  and gateway-source validation (anti-spoof), `map`/`external_address`/`delete`,
  and `run_refresh` (renew at half the granted lifetime, best-effort delete on
  shutdown). The wire codec was already in `warren-wire::natpmp`. Validated
  in-process against a scripted gateway (grant, rejection, timeout, spoofed
  source, periodic renewal + teardown).
- Inbound bridge: DONE (primitives). The netstack now listens and accepts
  (`TunnelConnector::listen` -> `NetstackListener::accept`, an accept-backlog pool
  mirroring the outbound connect path), and `warren-net::serve_inbound` /
  `relay_to_local` relay each accepted inbound connection to a local listener
  (the app's server). Validated in-process (an exit dials in, the netstack
  accepts, and the connection round-trips to a local echo listener).
- One-call convenience: DONE. `warren-net::forward_port` composes
  `listen` + NAT-PMP `map` + background renewal + `serve_inbound` into a single
  call returning a `ForwardedPort` (the gateway-allocated `external_port`, with
  graceful `shutdown` that asks the exit to delete the mapping). The facade
  surfaces it as `ProxyHandle::forward_port(proto, internal_port, local_target)`,
  using the datapath's own connector and exit gateway. Validated in-process
  against a NAT-PMP-gateway exit simulator that grants a mapping and then dials
  back into the forwarded port, round-tripping to a local server.
- Real-exit validation: DONE, end to end. `cargo run -p warren-sdk --example
  live_forward_port` opens a real multihop proxy to the NL/Amsterdam prod exit,
  the exit GRANTS a TCP mapping (allocated external port), and then the SAME host
  dials the exit's public `ip:external_port` directly (as an external internet
  peer, a distinct network path from the in-process tunnel client): the exit
  forwards that connection through the sealed tunnel to the client's internal
  port, `serve_inbound` relays it to the local server, and the payload
  round-trips. Map exchange, inbound forwarding, relay and teardown are all
  confirmed against production infrastructure.

## P8: warren-sdk facade

- DONE: `WarrenClient` orchestrating identity, API (via `client.api()`),
  discovery (single-hop + multihop), and the non-root datapaths (`start_proxy`,
  `start_proxy_multihop`). `ProxyHandle` exposes the listener address(es) and the
  tunnel connection state (`TunnelState::{Connected, Disconnected}` via `state()`
  / `watch_state()`), so an app reacts to a dropped tunnel. In-process e2e tested.
- DONE: one-call port forwarding on the datapath handle
  (`ProxyHandle::forward_port`, see P7).
- Reconnect: DONE, both modes.
  - App-driven (live-validated): each `start_proxy_multihop` rebuilds the whole
    datapath from a freshly fetched `IpAssign` (a new session may carry a
    different tunnel address/gateway/MTU), so observing `ProxyHandle::state` and
    re-calling on `Disconnected` reconnects correctly. `cargo run -p warren-sdk
    --example live_reconnect` proves two independent sessions each rebuild from a
    fresh assignment and egress against a production exit.
  - Automatic in-facade supervisor: `start_proxy_multihop_supervised` binds the
    SOCKS5/HTTP listeners once and keeps the tunnel up across drops, rebuilding
    the netstack from a fresh `IpAssign` on each reconnect while the app-facing
    proxy address stays stable. `SupervisedProxyHandle` reports
    `ConnectionState::{Connecting, Connected, Reconnecting}`; reconnect is
    immediate after a drop with capped exponential backoff between failed
    attempts. The `warren-net` proxies grew borrowed-listener `serve_*_until`
    variants so one bound port survives rebuilds. Unit-tested in-process with a
    fake sink whose read side closes on demand (asserts auto-reconnect + the
    listener stays live on the same address across the rebuild).
- The supervisor happy path is live-validated: `cargo run -p warren-sdk --example
  live_supervised` starts `start_proxy_multihop_supervised` against the prod exit,
  reaches `Connected` on the state watch, and egresses through the stable address.
- Pending: real-exit validation of the automatic supervisor's drop-triggered
  reconnect specifically (forcing a mid-session tunnel drop on a production exit is
  not reliably reproducible from the dev sandbox; the rebuild-from-fresh-`IpAssign`
  path it reuses is already live-validated), and broader end-to-end tests against
  a real exit and the production API.

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
- Port forwarding done: `WarrenFfiProxy::forward_port(protocol, internal_port,
  local_target)` (with `FfiMapProto`) returns a `WarrenFfiForwardedPort` Object
  (`external_port()`, async `shutdown()`). The selector mapping and the argument
  validation are unit-tested; the live path is covered by the warren-net e2e (it
  needs a NAT-PMP-gateway exit, not injectable at the FFI layer).
- Supervised proxy done: `WarrenFfiClient::start_proxy_supervised` returns a
  self-healing `WarrenFfiSupervisedProxy` (`socks5_address()`, `http_address()`,
  `state()`, idempotent `shutdown()`) that keeps the tunnel up across drops behind
  a stable address, forwarding `ConnectionState` to the observer. Argument-
  validation paths are unit-tested; the supervisor core is covered by the facade
  unit tests. All new exports are CI grep-guarded in the generated bindings.
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
  - UDP associate: DONE. The netstack engine binds a UDP flow
    (`TunnelConnector::open_udp` -> `NetstackUdpSocket`, lossy/source-tagged), and
    `Socks5Proxy::serve_with_udp` runs the full `UDP ASSOCIATE` relay (loopback
    relay socket, SOCKS5 UDP header parse/encode, name resolution over the tunnel,
    association tied to the TCP control connection). Wired into the facade proxy.
    Validated in-process: egress primitive against a UDP echo exit, and the relay
    end to end via a SOCKS5 UDP client through the proxy.
  - Configurable resolver: DONE. `NetstackConfig` carries a `dns_server` (defaults
    to the gateway forwarder), overridable via `ProxyConfig::dns_server` for
    `dns_disabled` exits; the override still egresses over the tunnel, so lookups
    never leak to the host resolver. Validated in-process (an exit answering DNS
    only at a non-gateway in-tunnel address resolves and connects).
  - Dual-stack IPv6: DONE (datapath). `NetstackConfig::with_ipv6` installs the
    exit-granted v6 client address + default v6 route; the connector routes v6
    targets when v6 was assigned and refuses them otherwise (fail-closed). The
    facade enables it from the multihop `IpAssign` (v6 + v6 gateway, with a
    bounded prefix); single-hop stays v4-only (its SetupAck carries no v6
    gateway/prefix). Domain targets resolve over the tunnel with AAAA preferred
    and A fallback when v6 is assigned (the `warren-net::dns` codec now does both
    `A` and `AAAA`). Literal v6 UDP targets egress through the SOCKS5 UDP
    associate when v6 is assigned (`UdpConnector::supports_ipv6`). Validated
    in-process (literal v6 connect/echo, off-subnet v6 default route, AAAA
    resolve+v6 connect, A fallback, v6 UDP flow, AAAA-preferred resolution for
    UDP *domain* targets). UDP domain targets now share the TCP dual-stack policy
    (AAAA preferred under a v6 assignment, else A) via a shared `resolve_dualstack`
    helper. Pending: real-exit v6 validation.
  - Pending: validation against a real Warren exit (mandatory before production);
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
  6. DONE (live-validated, 2026-06-13; re-validated against prod v6 2026-06-15).
     A full real tunnel with a subscribed wallet: real `IpAssign` (from the
     NL/Amsterdam exit) and confirmed egress (a TCP handshake to a public host
     completes through the sealed tunnel via `cargo run -p warren-sdk --example
     live_proxy`). Frame, control `/v2` and PoP cross-language vectors are frozen
     under `vectors/`. The signed relay list is now v6 (node/endpoint model): the
     SDK fetches and verifies the live prod v6 list under the pinned server key,
     the multihop directory cross-checks against it, and end-to-end egress is
     confirmed on prod v6.

## Cross-cutting

- Keep the public surface FFI-friendly from P2 onward (no exported generics,
  serializable errors, narrow async seams).
- Keep coverage at or above 80% on library code.
- License: AGPL-3.0-or-later (confirmed).
