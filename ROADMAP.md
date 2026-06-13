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

Done in the audit passes:

- Typed error sources: `TunnelError`, `NetError`, `ClientError` now carry
  `#[source]`/`#[from]` causes instead of `String` (`ClientError::Deserialize`
  split into `ResponseEncoding` / `ResponseJson` / `RequestSerialize`).
- Facade: `build` returns `Result` (no panic); server-key pinning is required
  unless `allow_any_server_key()` is set; anti-rollback floor is persistable via
  the `GenerationStore` trait.

Still tracked:

- Anti-censorship host fallback (P3): the API client takes a single `api_base`;
  the primary / alternatives / no-SNI fallback chain is not implemented yet.
- Datapath bridge perf: `PacketSink::send_batch`/`recv_batch` (GSO/GRO),
  `fast-apple-datapath` on macOS, a shared `quinn::Endpoint` in `WarrenClient`,
  and send backpressure.
- Test depth: per-endpoint `warren-api` mock tests, injectable clock for
  `BadClock`, richer golden vectors, a shared `spawn_fake_exit` test helper.
- Facade: default to weighted exit selection; consider a `DefaultClient` alias.
- Discovery: trust-on-first-use persistence of the server pubkey (same storage
  hook as the persisted generation floor).
- NAT-PMP: mirror warren-core's explicit `3 => NetworkFailure` arm (cosmetic).

## Cross-cutting

- Keep the public surface FFI-friendly from P2 onward (no exported generics,
  serializable errors, narrow async seams).
- Keep coverage at or above 80% on library code.
- License: AGPL-3.0-or-later (confirmed).
