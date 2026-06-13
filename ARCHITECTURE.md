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
| `warren-identity` | core | BIP39 mnemonic to Ed25519, SS58 `wb…` address, canonical API request signing | implemented |
| `warren-wire` | core | Pure codecs: Setup/SetupAck handshake, NAT-PMP, multihop HPKE frame | P2 |
| `warren-api` | core | Signed HTTP client for the `/v1/*` account API, host fallback | P3 |
| `warren-discovery` | core | Verify the signed relay list, select an exit | P4 |
| `warren-transport` | net | QUIC handshake (quinn + rustls raw public keys), datagram pump, backoff | P5 |
| `warren-net` | net | `PacketSink` seam, non-root netstack proxy backend and privileged TUN backend | P6 |
| `warren-sdk` | facade | The single crate apps depend on; re-exports the layers and the `WarrenClient` facade | partial |
| `warren-sdk-ffi` | facade | FFI surface (uniffi) for Dart/Kotlin/Swift/Python/Java bindings | P9 |

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
| Discovery | Signed relay list (v5), canonical JSON, Ed25519 over a pinned server pubkey, generation anti-rollback, expiry anti-freeze |
| TLS | Raw public keys (RFC 7250), ALPN `h3`, TLS 1.3 only, 0-RTT off |
| NAT-PMP | RFC 6886 plus Warren rate-limit extensions |
| Multihop | HPKE (X25519 + HKDF-SHA256 + ChaCha20Poly1305), frame v1 (postcard) |
| Network constants | tunnel 10.66.0.0/16, gateway 10.66.0.1, initial MTU 1280, idle 180s, keepalive 20s |

## FFI boundary (designed now, implemented in P9)

The public API is kept FFI-friendly so a single `uniffi` definition can generate
the Dart, Kotlin, Swift, Python and Java bindings: no generics in exported
signatures, `#[non_exhaustive]` serializable error enums, owned plain types
across the boundary, and lifecycle events delivered as a stream.
