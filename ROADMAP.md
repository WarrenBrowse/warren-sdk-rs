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

## P3: warren-api

- `WarrenApiClient` over an abstracted async HTTP backend, attaching the signed
  headers from `warren-identity`.
- Endpoints: register, subscription, check, exits, session open/close, account
  delete, checkout/voucher polling, mobile payments, incident and support
  reports.
- Anti-censorship host fallback (primary, alternatives, no-SNI).

## P4: warren-discovery

- Verify the signed relay list (v5): canonical JSON, Ed25519 against the pinned
  server pubkey, generation anti-rollback, expiry anti-freeze.
- Weighted relay selector with geography, IP availability and deterministic
  per-attempt failover. Golden vectors for the signed list.

## P5: warren-transport

- QUIC handshake with rustls raw public keys (RFC 7250), ALPN `h3`, 0-RTT off.
- `ClientTunnel` builder to `ClientSession`, RFC 9221 datagram pump over the
  `PacketSink` seam, full-jitter reconnection backoff and a reconnect supervisor.

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

## P9: warren-sdk-ffi

- uniffi scaffolding and the first Dart/Flutter binding, then Kotlin, Swift,
  Python and Java. Every binding replays the same `vectors/`.

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
  - Pending: validation against a real Warren exit (mandatory before production);
    DNS-over-tunnel for domain targets; UDP associate;
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
  3. HPKE session (spec extracted, turnkey): deps `hpke = "=0.13.0"` (features
     `alloc`,`x25519`), `chacha20poly1305 = "=0.10.1"`, `rand_core 0.9` +
     `rand_chacha 0.9` (hpke 0.13 needs the rand_core 0.9 trait surface; NOT
     `hpke-rs`). Suite `X25519HkdfSha256`/`HkdfSha256`/`ChaCha20Poly1305`.
     `setup_sender(OpModeS::Base, exit_x25519, info=b"warren/multihop/v1/hpke-info")`
     once -> `(encapsulated_key, ctx)`. Per packet: `key32 = ctx.export(info)`,
     forward `info = b"warren/multihop/v1/aad"(22)||epoch_be(4)||seq_be(8)`
     (reverse appends `0x02`); then
     `ChaCha20Poly1305::new(key32).encrypt_in_place_detached(nonce=[0;12], aad, payload)`,
     `aad = b"warren/multihop/v1/aad"||exit_id(16)||epoch_be(4)||seq_be(8)` ->
     `WarrenMultihopFrame`. Zero nonce safe (key unique per `(epoch,seq)`).
     Generate cross-language HPKE vectors from warren-core to pin it.
  4. Datapath: ride per-packet sealed `WarrenMultihopFrame`s on the datagram
     plane; replace the current raw-`Setup` handshake in `warren-transport`.
  5. Live-validate a real single-hop tunnel against an exit; freeze shared
     vectors. Until then the in-process datapath tests use a non-production
     fake handshake.

## Cross-cutting

- Keep the public surface FFI-friendly from P2 onward (no exported generics,
  serializable errors, narrow async seams).
- Keep coverage at or above 80% on library code.
- License: AGPL-3.0-or-later (confirmed).
