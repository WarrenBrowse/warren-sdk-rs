# Architecture

`warren-sdk-rs` is a standalone client SDK for the Warren VPN. It does not depend
on the warren-core monorepo: it is a clean-room reimplementation that stays
wire-compatible with warren-core's frozen contracts, so it can talk to real
exits and the production API. The same architecture is meant to be reproduced in
TypeScript, Dart, Python, Kotlin, Swift and Java, so every layer is kept
portable in concept and pinned by shared golden vectors under `vectors/`.

## Layers

```
                 +---------------------------------------------+
   facade        | warren-sdk : WarrenClient (orchestration,   |
                 | lifecycle, events, FFI-friendly surface)    |
                 +------+-----------+-----------+--------------+
   net                 |           |           |
            +----------+---+  +-----+------+  +-+------------+
            | warren-net   |  | warren-    |  | (port-forward|
            | tun +        |  | transport  |  |  lives in    |
            | netstack     |  | (quinn)    |  |  warren-net  |
            | proxy, perOS |  |            |  |  P7)         |
            +------+-------+  +-----+------+  +-+------------+
   core            |               |           |
        +----------+----+  +--------+----+  +---+----------+  +-----------+
        | warren-       |  | warren-api  |  | warren-wire  |  | warren-   |
        | discovery     |  | (http signed)| | (pure codecs)|  | identity  |
        | (signed list  |  |             |  |              |  | (+ ss58)  |
        |  + selector)  |  |             |  |              |  |           |
        +---------------+  +-------------+  +--------------+  +-----------+
```

## Crates

| Crate | Layer | Role | Status |
|---|---|---|---|
| `warren-identity` | core | BIP39 mnemonic to Ed25519, SS58 `wb…` address, canonical API request signing | done |
| `warren-wire` | core | Pure codecs: Setup/SetupAck handshake, NAT-PMP, multihop HPKE frame, control `/v2`, PoP | done |
| `warren-api` | core | Signed HTTP client for the `/v1/*` account API (incl. payments, support, incidents) with anti-censorship host fallback; transport-agnostic core + optional reqwest | done |
| `warren-discovery` | core | Verify the signed relay list (v6) + weighted selection; verify the multihop directory PKI chain | done |
| `warren-multihop` | core | Client HPKE session (X25519 / HKDF-SHA256 / ChaCha20Poly1305), sealed `IpRequest`/`IpAssign`, epoch/seq replay window | done |
| `warren-transport` | net | QUIC handshake (quinn + rustls raw public keys), single-hop + multihop `ClientSession` datagram plane, reconnect/backoff supervisor | done |
| `warren-net` | net | `PacketSink` seam + QUIC plane + smoltcp userspace netstack (TCP/UDP, dual-stack IPv6) + SOCKS5/HTTP CONNECT proxy + DNS-over-tunnel + NAT-PMP port-forwarding (client + inbound listen/relay) + killswitch levels; per-OS privileged TUN backend feature-gated (todo) | done (proxy); TUN todo |
| `warren-sdk` | facade | `WarrenClient` composing identity/api/discovery/multihop/transport/net | done |
| `warren-sdk-ffi` | facade | uniffi surface: identity + async client + proxy handle + connection-state events; Python/Kotlin bindings CI-validated | done |

Every "done" crate is implemented in TDD with unit tests, golden vectors where a
wire format is involved, and in-process end-to-end tests for the datapath. The
remaining "todo" is the part that needs real privilege (the per-OS TUN backend
with its OS firewall killswitch); per CLAUDE.md, the datapath must also be
validated against a real exit before it is relied on in production.

Applications depend only on `warren-sdk`.

## Networking: feature-complete on every OS, non-root by default

A classic VPN needs root for a TUN device plus routing, DNS and a killswitch.
Warren SDK keeps a non-root, feature-complete mode on Linux, macOS and Windows by
offering two backends behind one `PacketSink` seam:

1. **`netstack` (default, non-root).** A userspace TCP/IP stack (smoltcp)
   terminates application flows and forwards them as QUIC datagrams to the exit,
   exposed through a local SOCKS5 plus HTTP CONNECT proxy. No elevated privileges
   on any OS. This is the mode every sibling-language SDK targets first.
2. **`tun` (optional, privileged).** A real TUN device (Linux `/dev/net/tun`,
   macOS utun, Windows Wintun) with split-default routing, DNS push and a
   killswitch (nft / pf / WFP). Captures all OS traffic transparently.

The mode is selected at runtime (`ConnectMode::Proxy` vs `ConnectMode::Tun`),
defaulting to `Proxy`. Both backends share the QUIC core in `warren-transport`.

## Frozen wire contracts (ported from warren-core)

These are reproduced exactly and pinned by `vectors/`. A change is a wire-format
break and requires a schema version bump.

| Domain | Contract |
|---|---|
| Identity | BIP39 (12 words) -> seed (64 bytes, empty passphrase) -> first 32 bytes -> HKDF-SHA256 (salt `warren/identity/v1`, info `vpn-node-key`) -> Ed25519 |
| Address | SS58 prefix 13295 (`wb…`), Blake2b-512 checksum, base58 |
| API auth | canonical `METHOD\npath\ntimestamp\nnonce_hex\nsha256_hex(body)`, Ed25519 signature, headers `X-Warren-PubKey` (SS58), `X-Warren-Sig`, `X-Warren-Timestamp`, `X-Warren-Nonce` |
| Handshake | Setup/SetupAck (postcard), protocol version 4, 16-byte device id, feature bitmask |
| Discovery | Signed relay list (v6), canonical JSON, Ed25519 over a pinned server pubkey, generation anti-rollback, expiry anti-freeze |
| TLS | Raw public keys (RFC 7250), ALPN `h3`, TLS 1.3 only, 0-RTT off |
| NAT-PMP | RFC 6886 plus Warren rate-limit extensions |
| Multihop | HPKE (X25519 + HKDF-SHA256 + ChaCha20Poly1305), frame v1 (postcard) |
| Network constants | tunnel 10.66.0.0/16, gateway 10.66.0.1, initial MTU 1280, idle 180s, keepalive 20s |

## FFI boundary

The public API is kept FFI-friendly so a single `uniffi` definition generates the
Dart, Kotlin, Swift, Python and Java bindings: no generics in exported
signatures, `#[non_exhaustive]` serializable error enums, owned plain types
across the boundary, and connection-state events delivered through a callback
interface. The `warren-sdk-ffi` crate exposes the identity helpers, an async
`WarrenFfiClient` (address, voucher, subscription, exits, proxy start), and a
`WarrenFfiProxy` handle; the Python and Kotlin bindings are generated and
grep-checked in CI. It is the one crate that relaxes `unsafe_code` from `forbid`
to `deny` for uniffi's generated scaffolding (documented in the crate).
