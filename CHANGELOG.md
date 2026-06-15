# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it leaves
the pre-release `0.0.x` line.

## [Unreleased]

### Security

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
