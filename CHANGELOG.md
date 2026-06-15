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
- Rekey crypto core: `warren_multihop::ClientSession::rekey` (fresh KEM, epoch+1,
  overlap window) + `prune_old_epoch` + epoch-aware seal/open. The transport-level
  driver (per-epoch replay windows, `RekeyPolicy` timer) remains, pending a real
  exit to validate against.

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
