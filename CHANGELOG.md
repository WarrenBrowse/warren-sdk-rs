# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it leaves
the pre-release `0.0.x` line.

## [Unreleased]

### Added

- ADR-0006 idle cover traffic ("B2-lite"), opt-in via `with_idle_cover(true)` on
  `ClientTunnel` and `MultihopClientTunnel` (off by default). When enabled the
  keep-alive PING is disabled and a caller-spawned `IdleCoverDriver` emits a
  jittered (10-20s), size-varied cover datagram while the tunnel is idle, reusing
  the existing `0xFF` DAITA discriminator (no wire change). This replaces the
  fixed keep-alive beacon, which is a passive traffic-analysis tell that no
  browser produces, while still refreshing the NAT mapping and resetting the idle
  timeout. Real-exit validation against a live exit is still required before
  enabling it by default. New public surface: `IdleCover`, `IdleCoverDriver`,
  `IdleCoverDriverHandle`, `CoverSink`.

## [0.0.11] - 2026-06-24

### Changed

- Adopted WarrenGuard protocol v5 in-band client authentication. The client now
  declares its Ed25519 identity in `Setup` and proves possession by signing the
  connection's TLS channel binding (`sign_client_auth`), so the exit no longer
  issues a mutual-TLS `CertificateRequest`. Dropping the client certificate
  removes an active-probing tell while keeping the per-connection binding that
  makes a captured `Setup` useless on any other connection. The pinned engine
  (rev in `.warrenguard-version`) is bumped to `6e4f40c`, and the v5 golden
  vectors are pinned under `vectors/`.

## [0.0.10] - 2026-06-22

### Added

- `WarrenClient::transport_config` (and `with_transport_config` on `ClientTunnel`
  and `MultihopClientTunnel`) inject a caller-supplied transport config,
  re-exported as `warren_transport::TransportConfig`. The default still builds the
  SDK's upstream-quinn settings; a privileged system-VPN build patched to the
  WarrenGuard quinn fork passes the engine's obfuscated QUIC-Initial config
  (`warrenguard_transport_core::warren_transport_config_client`) here to match
  warren-app's anti-DPI handshake. The SDK names no fork-only quinn API, so it
  keeps building on upstream quinn for embedders. See ARCHITECTURE.md "QUIC
  handshake obfuscation".

### Changed

- The WarrenGuard engine crates are now sourced as pinned git dependencies
  (rev in `.warrenguard-version`) instead of bare `../warrenguard` path deps, so
  the SDK is self-resolving as a git dependency for downstream consumers (the
  desktop daemon `warrend`, the Dart `flutter_rust_bridge` binding, the TS napi
  binding) that have no sibling engine checkout. Local dev and CI keep building
  against the sibling `../warrenguard` via a `[patch]` in the workspace manifest.
  This fixes consumption of the SDK by git tag, which the engine extraction had
  broken after v0.0.8.

### Removed

- The hand-written Dart binding under `bindings/dart/` is removed. The Dart and
  Flutter SDK now lives in the sibling repository `warren-sdk-dart` and reuses
  this engine through `flutter_rust_bridge`, so no Dart code remains here. The
  `uniffi` surface (`warren-sdk-ffi`) is unchanged and still serves the
  non-Flutter consumers (Python, Kotlin, Swift).

### Security

- The signed multi-hop directory now verifies the server envelope signature
  BEFORE applying the validity-window (anti-freeze) cap, matching the signed
  relay list, so every anti-freeze decision is made on authenticated fields (a
  tampered `expires_at` can no longer mask a `BadEnvelopeSignature`).
- The SOCKS5 codec rejects a zero-length domain, and the HTTP `CONNECT` authority
  parser rejects malformed IPv6 authorities (unbracketed, zoned, or portless)
  instead of coercing them into a bogus domain name.
- The userspace netstack fails closed on ephemeral-port exhaustion (>16k live
  flows) rather than aliasing two flows onto one port.
- The multi-hop dispatch frame decoder rejects trailing bytes (parity with the
  setup/control codecs), and the size cap is enforced symmetrically on encode.

### Hardening and quality

- `warren_multihop::SessionError` gained a distinct `UnknownEpoch` variant
  (previously folded into `Hpke`), and `ClientSession::seal` now rejects a
  non-current epoch (forward frames only ever seal at the current epoch; the
  retained old epoch is reverse-overlap only).
- The DAITA pump (`DaitaDriver::run`) arms its wake waiter before snapshotting
  the next deadline (`Notified::enable`), making the timer wait race-free against
  concurrent datapath events.
- `SdkError::Daita(String)` was modeled into the typed
  `UnknownDaitaMachine` / `EmptyDaitaPool` / `DaitaConfig` variants.
- The TLS `RpkSigner` now renders only a public-key prefix in `Debug` (manual,
  never derived on a secret-holding type).
- A byte-exact golden vector for a populated `SetupAck.daita_spec` (pinning the
  IEEE-754 `f64` encoding) was added under `vectors/handshake.json`.

### FFI

- `WarrenFfiClient::with_options(.., FfiClientOptions)` exposes the DAITA uplink
  defense (and root pins + persistence) to foreign bindings via a future-proof
  options record, so mobile consumers can enable traffic-analysis defense. The
  generated bindings are CI grep-guarded for the new surface.
- All `start_proxy*` methods take an optional `FfiProxyOptions` (HTTP CONNECT
  listen address, in-tunnel DNS override), so foreign bindings reach the per-proxy
  `ProxyConfig.http` / `dns_server` knobs the Rust facade already had.

### Privileged TUN backend (P6, experimental, NOT real-exit validated)

- New `warren-tun` crate: the foundation for the optional privileged TUN backend.
  Ships only the device-and-root-free, unit-tested parts: OS-agnostic TUN framing
  (`frame`), the routing/killswitch PLAN computation (`plan`: split-default
  capture preserving the carrier route to the exit, an nftables killswitch with a
  v6 leak block), and the `TunIo` device seam + `FramedTun` adapter (`device`).
  The Linux device open (`/dev/net/tun` + `TUNSETIFF`) is behind the
  `experimental-tun` feature with hand-audited `unsafe` and `SAFETY` docs; the
  crate's manifest downgrades `unsafe_code` to `deny` and admits unsafe only under
  that feature (mirroring the `warren-sdk-ffi` boundary exception). The default
  build pulls no new dependency and is unsafe-free.
- The privileged applier landed (feature-gated): `RoutingPlan::to_ip_commands`
  (`ip route replace` argv) and `KillswitchPlan::nft_apply_argv`/`nft_teardown_argv`
  (both unit-tested for the exact argv), executed by `warren_tun::apply`; plus
  the macOS `utun` device open and `gateway::parse_default_gateway` (parses `ip
  route show default`, unit-tested).
- `warren_net::tun_sink` wires the TUN device into the async `PacketSink`:
  `tun_channels` returns a channel-backed `TunPacketSink` plus a `TunBridge`
  worker (`pump_inbound_once`/`pump_outbound_once`), unit-tested end to end over
  an in-memory mock device. `warren-net` stays `unsafe_code = forbid`.
- The real-fd async duplex datapath driver landed (`warren_net::tun_sink::
  TunBridge::run`, Unix, feature-gated): tokio `AsyncFd` + `O_NONBLOCK` multiplexes
  read/write over the full-duplex fd and calls the tested `pump_*_once`.
  Compile-checked on Linux + macOS.
- Windows Wintun device open landed (`warren_tun::device` Windows path, raw
  `LoadLibraryW`/`GetProcAddress` + Wintun adapter/session ring I/O, no
  third-party deps), cross-compile-checked on the Windows target. So all three
  per-OS device backends now compile on their targets.
- Still to do (per CLAUDE.md, not possible from the dev sandbox): end-to-end
  validation of the privileged datapath against a real exit with root + a device.

### Single-hop DAITA

- The negotiated single-hop `SetupAck.daita_spec` is no longer discarded:
  `warren_transport::ClientSession` exposes `negotiated_daita()` and
  `build_daita_state()` (wire spec -> runnable maybenot state) plus the
  `send_cover_traffic()` `0xFF`-dummy primitive.

- The multihop directory root-key pin is now enforced. `WarrenClientBuilder`
  gained `multihop_root_pubkey_pin`, and when at least one root is pinned the
  directory's operational certificate must be signed by a pinned root (the
  facade previously always passed an empty root set, leaving the chain on
  trust-on-first-use terms).
- Strict parsing (`deny_unknown_fields`) on the multihop directory wire structs,
  matching the signed relay list.
- Starting a proxy against an exit that runs no DNS forwarder now fails fast with
  `SdkError::ExitDnsDisabled` unless an override resolver is configured, instead
  of leaving every name lookup silently unresolvable.

### Changed

- `WarrenApiClient::get_multihop_directory` renamed to `fetch_multihop_directory`
  (drops the non-idiomatic `get_` prefix).
- `SignedError::Node(String)` split into the typed variants `InvalidNodeId`,
  `UnrecognizedRole`, `InvalidEndpointAddress`, and `EndpointFamilyMismatch`.
- The supervised proxy now backs off with full jitter (avoiding synchronized
  reconnect waves) via the new `warren_transport::JitterBackoff`.

### Added (userland features)

- DNS result cache in the netstack engine: repeat connects to a host reuse a
  TTL-bounded cached answer instead of re-querying over the tunnel.
- Auto outbound-IP detection: `warren_transport::local_ip_for_endpoint`, tunnel
  `with_auto_local_ip()`, and facade `WarrenClientBuilder::auto_local_ip()` pin the
  QUIC endpoint to the default-route source IP (multi-NIC determinism).
- Session metrics: `MultihopMetricsSnapshot` (bytes/packets/cover-traffic/epoch/
  uptime) on the session, the sink, and `ProxyHandle::metrics()`.
- DAITA cover-traffic primitive: `MultihopSession::send_cover_traffic` emits the
  frozen `0xFF` dummy frame (dropped by the exit) for client-side traffic shaping.
- Multipath connection bonding: `warren_net::BondedPacketSink` plus facade
  `connect_multihop_bonded` / `start_proxy_multihop_bonded` (stripe send, merge
  recv across N same-identity sessions the exit coheres to one sticky IP).
- DAITA traffic-analysis defense, end to end. New clean-room `warren-daita` crate
  (maybenot 2.2.2): the wire `DaitaConfig`, the curated five-machine pool
  (`netflow`/`tamaraw`/`front`/`interspace_server`/`scrambler_server`), and the
  `DaitaState` driver (event -> action -> per-machine timer). `DaitaDriver` pumps
  the scheduled uplink cover traffic over a multihop session, wired into the facade
  opt-in via `WarrenClientBuilder::daita()` / `daita_machine(name)` (auto-spawned in
  `connect_multihop`). Validated live against the real DAITA-active exit.
- Rekey / epoch rotation, end to end: `warren_multihop::ClientSession::rekey`
  (fresh KEM, epoch+1, overlap window) plus the live transport driver
  `MultihopSession::rekey` / `prune_old_epoch` (an `RwLock<ClientSession>` so the
  datapath keeps sealing under `&self`, forward-seq reset per epoch, a per-epoch
  reverse anti-replay map) and `RekeyPolicy` (the 8-hour doctrine). Rekey reuses
  the frame's `epoch` + `encapsulated_key` (no new wire format; the exit re-derives
  its receiver context implicitly).

### Testing

- Real-exit wire-compat validation against the genuine `warren-core` exit run
  locally (gated `real_exit_tests` in `warren-transport`), not just the in-repo
  fake exit:
  - Echo mode (`WARREN_EXIT_BIN`, no root): the sealed-frame datapath and the full
    rekey rotation (epoch switch, overlap window, per-epoch datapath).
  - Full termination mode (`WARREN_EXIT_ADDR`, rooted `--use-tun` exit): the real
    `IpAssign` handshake (a 10.66.0.0/16 IP is assigned), the sticky-IP multipath
    coherence (same identity -> same IP, distinct identity -> distinct IP), a
    DAITA-active exit accepting the client's `0xFF` cover traffic, and the
    `DaitaDriver` emitting maybenot-scheduled padding the exit accepts.

### Performance

- A release profile (thin LTO, `codegen-units = 1`) enables cross-crate inlining
  across the packet datapath's trait seams.
- Per-packet HPKE associated data and export info are built on the stack instead
  of allocating, and the tunnel frame queue is shallower to shed latency.

### Internal

- The signed-list/directory minting helpers are gated behind a `test-helpers`
  feature so they never enter the production-compiled surface.
- `warren-sdk`'s monolithic `lib.rs` was split into `error`, `client`, `proxy`,
  and `supervisor` modules.

## [0.0.1]

- Initial standalone, wire-compatible client SDK: non-custodial identity,
  signed account API, exit discovery (signed relay list + multihop directory),
  QUIC transport, sealed HPKE multihop tunnel, the non-root proxy datapath
  (SOCKS5/HTTP CONNECT, DNS-over-tunnel, IPv6, NAT-PMP port forwarding), and the
  uniffi FFI surface.
