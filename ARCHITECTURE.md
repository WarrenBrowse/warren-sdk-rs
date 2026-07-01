# Architecture

`warren-sdk-rs` is the client SDK for the Warren VPN. It does not depend on the
private `warren-core` backend; instead it shares the open-source **WarrenGuard
engine** (`warrenguard`, AGPL-3.0, sibling checkout `../warrenguard`) for the
data-plane primitives: the `warren-{wire,identity,multihop,daita,tun,tun-core}`
crates are thin re-exports of the matching `warrenguard-*` engine crates, so the
protocol primitives have a single source of truth rather than a duplicate
reimplementation. The wire-facing client-to-server contract has a second neutral
home, the **`warren-contract`** crate (sibling path-dep, depends only on
`warrenguard-wire`): it owns the SS58 address codec, the X-Warren canonical
signing message and header names, and the HTTP `/v1` DTOs, with golden tests for
all three. `warren-identity` re-exports its `ss58` and `auth` modules and
`warren-api` re-exports its `dto`; warren-core depends on the same crate, so the
contract cannot drift between the SDK and the backend. The SDK keeps its own
control-plane and userland transport on top. It stays wire-compatible with
warren-core's frozen contracts (same golden vectors under `vectors/`, shared with
the engine), so it can talk to real exits and the production API. The same architecture is meant to be reproduced in
TypeScript, Dart, Python, Kotlin, Swift and Java, so every layer is kept
portable in concept.

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
| `warren-wire` | core | Re-exports the engine's (`warrenguard-wire`) canonical codecs: Setup/SetupAck handshake, NAT-PMP, multihop HPKE frame, control `/v2`, PoP | done |
| `warren-api` | core | Signed HTTP client for the `/v1/*` account API (incl. payments, support, incidents) with anti-censorship host fallback; transport-agnostic core + optional reqwest | done |
| `warren-discovery` | core | Verify the signed relay list (v7) + weighted selection; verify the multihop directory PKI chain | done |
| `warren-multihop` | core | Client HPKE session (X25519 / HKDF-SHA256 / ChaCha20Poly1305), sealed `IpRequest`/`IpAssign`, epoch/seq replay window | done |
| `warren-daita` | core | DAITA uplink traffic-analysis defense: curated machine pool, scheduler state, padding/cover-traffic config | done |
| `warren-transport` | net | QUIC handshake (quinn + rustls raw public keys), single-hop + multihop `ClientSession` datagram plane, reconnect/backoff supervisor | done |
| `warren-net` | net | `PacketSink` seam + QUIC plane + smoltcp userspace netstack (TCP/UDP, dual-stack IPv6) + SOCKS5/HTTP CONNECT proxy + DNS-over-tunnel + NAT-PMP port-forwarding (client + inbound listen/relay) + killswitch levels; per-OS privileged TUN backend feature-gated (todo) | done (proxy); TUN todo |
| `warren-tun` | net | OS TUN datapath behind `experimental-tun`: device seam + framing, route/killswitch plan and apply, physical-gateway discovery (macOS), fail-safe revert | experimental |
| `warren-sdk` | facade | `WarrenClient` composing identity/api/discovery/multihop/transport/net | done |
| `warren-sdk-ffi` | facade | uniffi surface: identity + async client + proxy handle + connection-state events; Python/Kotlin bindings CI-validated | done |
| `warren-test-support` | test | Shared fake-exit harness (`spawn_fake_exit`, `spawn_fake_multihop_exit`) for cross-crate networking tests; dev-only, never a production dependency | done |

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
| Handshake | Setup/SetupAck (postcard), protocol version 5, 16-byte device id, feature bitmask, in-band client auth (client signs the TLS channel binding in `Setup`; no mutual-TLS client certificate) |
| Discovery | Signed relay list (v7), canonical JSON, Ed25519 over a pinned server pubkey, generation anti-rollback, expiry anti-freeze |
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

## Decision record: how sibling-language SDKs consume this core

The phrase "the same SDK is reimplemented in TypeScript, Dart, Python, Kotlin,
Swift and Java" must not be read as "reimplement the tunnel in six languages."
The defensible boundary is **control plane vs datapath**, and it dictates what is
reimplemented per language versus what is reused from this Rust core.

**Control plane** (low frequency, deterministic, fully pinned by `vectors/`):
identity (BIP39 -> Ed25519, SS58), request signing, the signed HTTP account API,
signed-relay-list verification, exit selection, subscription and voucher flows,
and event/state orchestration. This layer is a candidate for a pure per-language
reimplementation, because it is exactly what the golden vectors freeze and it
carries no line-rate or OS-privilege concern.

**Datapath** (line rate, per-packet crypto, OS privilege): QUIC (including
DATAGRAM frames, RFC 9221), the TLS 1.3 raw-public-key handshake (RFC 7250),
HPKE multihop sealing, per-packet AEAD, the smoltcp userspace netstack, and the
per-OS TUN device with its firewall killswitch. This layer is **always reused as
native code**, never reimplemented per language. Three facts force this:

1. There is no production-grade pure-language QUIC + TLS-1.3-RPK + userspace
   TCP/IP stack in Dart/TS/Python/etc.; reimplementing quinn/rustls/smoltcp per
   language multiplies the wire-compat surface far beyond Warren's own frames.
2. Per-packet AEAD in a GC'd language caps throughput well below the Rust core,
   so serious implementations bind a native crypto library anyway.
3. On mobile the datapath must run inside a native network-extension process
   (iOS `NEPacketTunnelProvider`, Android `VpnService`); the UI/control layer
   talks to it over a platform channel. A "full Dart" tunnel is therefore
   structurally impossible on the platforms that matter most.

This is the universal industry pattern: a single native datapath core (Mullvad
and Cloudflare WARP in Rust, Tailscale in Go) wrapped by thin per-platform
layers. This repository is that core for Warren.

## QUIC handshake obfuscation: on by default, parity with warren-core/app

This SDK builds its QUIC datapath on the **`warren-quinn` fork** (the published
`WarrenBrowse/warren-quinn` git-dep, pinned by tag, consumed as
`quinn = { package = "warren-quinn" }`; the package is renamed but the lib name
stays `quinn`, so `use quinn` is unchanged). It is the same QUIC backend that
`warren-core` and `warrenguard` use, so the SDK is fork-aligned, not on upstream
quinn.

Obfuscation is **on by default**. `warren_transport_config()` in
`warren-transport` sets the fork's two Initial-fragmentation knobs alongside the
buffers, keep-alive, MTU and idle timeout:

- `initial_datagram_min_size(INITIAL_MTU)` pads the obfuscated client Initial so
  the first datagram is full-MTU sized.
- `initial_crypto_first_fragment_size(Some(64))` splits the ClientHello across
  several Initial packets so a DPI box cannot read the obfuscation SNI (which
  encodes the exit pubkey) out of a single packet.

Consequence, stated plainly:

- A client built on this SDK presents the **same QUIC Initial fingerprint** as
  `warren-app` (the Mullvad fork, which goes through `warren-core` and the same
  fork). The encoded-pubkey SNI is split across packets exactly as in the app,
  so a censor doing QUIC DPI sees the obfuscated handshake, not a distinct one.
- The steady-state traffic-analysis defense (DAITA cover traffic) is also present
  in this SDK (`daita_driver`), and the golden vectors freeze the **frame** wire
  format (Setup/SetupAck, multihop HPKE, NAT-PMP), so "wire-compatible" holds at
  both the protocol layer and the QUIC-Initial obfuscation layer.
- Every consumer inherits the obfuscated default: the desktop system-VPN daemon
  (`warrend`), the Dart/Flutter proxy mode (`warren_sdk_frb`), and the Node
  native binding (`warren_napi`) all pin this crate and therefore the fork.

The connect path still takes a caller-supplied transport config:
`WarrenClient::transport_config` (and the `with_transport_config` builders on
`ClientTunnel` / `MultihopClientTunnel`) accept an `Arc<TransportConfig>` that
overrides the default, so a deployment can tune or disable obfuscation as a
per-deployment threat-model decision. The fork is a git-dep, so the SDK builds
`--all-features` clean for embedders with no vendored tree or local setup.

**Recommended target for the Dart/Flutter SDK: hybrid.** It lives in the sibling
repository `warren-sdk-dart` and reuses this engine; it is not implemented here.

- Datapath: this Rust core via `flutter_rust_bridge` in-process (proxy mode), and
  via a privileged out-of-process component for the system-VPN mode (a desktop
  daemon or a mobile network extension embedding this engine). See
  `warren-sdk-dart/ARCHITECTURE.md` and its decision records for the full design.
- Control plane: reused over the same FFI rather than reimplemented in Dart,
  since the crypto is already vector-locked here and need not be re-audited in a
  seventh language. The tunnel is reused either way.

This engine keeps its `uniffi` surface (`warren-sdk-ffi`) for the non-Flutter
consumers (Python, Kotlin, Swift). Flutter uses `flutter_rust_bridge` instead, so
no hand-written Dart binding lives in this repository.
