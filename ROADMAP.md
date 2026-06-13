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

- P6 datapath: non-root proxy (smoltcp + SOCKS5/HTTP CONNECT) then privileged
  per-OS TUN/routing/DNS/killswitch, with GSO/GRO batch syscalls behind the
  `PacketSink` batch seam and `fast-apple-datapath` on macOS.
- Multihop: port and freeze the HPKE frame (its own wire phase).

## Cross-cutting

- Keep the public surface FFI-friendly from P2 onward (no exported generics,
  serializable errors, narrow async seams).
- Keep coverage at or above 80% on library code.
- License: AGPL-3.0-or-later (confirmed).
