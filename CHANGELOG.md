# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it leaves
the pre-release `0.0.x` line.

## [Unreleased]

### Added

- `TokenManager::session_stack(now)` hands one session every token of the
  current epoch, without consuming any, starting at a rotation drawn once per
  manager and leaving out the serials this process's live sessions hold.
  `TokenManager::claim(token)` records such a hold as a `SerialLease`, cloned
  by bonded legs and released with the last of them. Every client of a wallet
  holds the same batch, so the rotation spreads them over its serials, and a
  session the exit refuses on one serial walks on to the next.
- Session and browser-proxy token batches are derived from the wallet instead
  of the CSPRNG, byte for byte as the TypeScript SDK does
  (`vectors/token_blinding_v1.json`). The issuer serves an account's epoch
  batch again to whoever sends it bit for bit, so a second device of the
  wallet, the browser extension and a reinstall that lost its store are all
  served the credentials the account holds instead of `already_issued`.
  Those clients then hold the SAME session tokens and pop them in the same
  order, and an exit leases a serial to one session at a time, so two
  concurrent devices contend for serials until each device draws from its own
  index (warren-core `PROD-READINESS.md` section 7).
  `BlindingKey::session(seed)` / `BlindingKey::browser_proxy(seed)` derive the
  class key from the 32-byte wallet seed (purposes `session/v1` and
  `browser-proxy/v1`, `BLINDING_*` constants). Breaking:
  `TokenManager::new(client, key)` takes the key and mints its class
  (`TokenManager::for_class` is gone), `TokenManager::refresh(now)` takes no
  RNG and replaces `refresh_auto`, `mint_tokens(client, directory, epochs,
  key)` takes the key, and `mint_tokens_for` is replaced by
  `mint_port_entitlements`, the one class still drawn from the CSPRNG.
  `TokenClientError::BlindingDrawOrder` refuses a batch the engine blinded in
  another order than the derivation defines.
- The SDK's own port forwards present the wallet's port entitlement envelope
  (warren-core doc 105), so an exit that refuses a credential-less NAT-PMP Map
  request (engine `requires_credential`, result code 2) keeps granting them.
  `warren_net` gains the credential seam, built on the engine's trailer codec
  (`append_credential_trailer`, re-exported from `warren_wire::natpmp`) rather
  than a copy of it: `CredentialProvider` (the engine client's contract, asked
  once per refresh cycle), `map_with_credential`, and `map_cycle`, which maps
  one or two legs under ONE credential, the second leg on the first leg's
  port, and releases a granted leg when a later one is refused.
  `forward_port_with_suggested`, `forward_port_raw` and `run_refresh` take an
  `Option<CredentialProvider>` (breaking); `forward_port` presents none.
  `PortForwardError::Credential` (a credential the trailer cannot carry,
  nothing sent) and `PortForwardError::is_not_authorized` are new.
  `warren-sdk` opens one `PortEntitlementManager` per wallet and API at the
  wallet's first slot claim (a client that never forwards mints and keeps
  nothing) and keeps it for the life of the process, as warren-app does,
  since a reopened batch would be answered `already_issued` for the whole
  prefetch window. It refreshes every ten minutes while a rule holds a slot
  and stops once none does, and gives every forwarding rule the lowest free
  slot for its whole life (across reconnects for a supervised rule), freed
  with it: `ProxyHandle`, `ProxyForwarder`, `PacketForwarder` and both
  supervised handles all present it. A code-2 refusal surfaces as
  `SdkError::PortForwardRefused { entitlement_presented }`, or as
  `SdkError::Api(ClientError::Banned { .. })` when the issuer has answered
  that the wallet is banned; a supervised rule publishes
  `PortFollowOutcome::NotAuthorized { entitlement_presented }` or
  `PortFollowOutcome::Banned { reason_code, lapses_at_unix_secs }` and keeps
  retrying. Across uniffi: `FfiError::PortForwardRefused` and
  `FfiError::Banned { reason: FfiBanReason, lapses_at_unix_secs }` (the latter
  for any API call answered with a ban). `warren-proxy` and `warren-bolthole`
  log a refused forward once per refusal (`warren_headless::RefusalWatch`,
  `log_refusals`). `WarrenClientBuilder::build_with_transport` now requires
  `T: 'static`.
- A banned wallet gets a typed refusal from issuance (warren-core doc 105):
  `ClientError::Banned { reason_code: BanReasonCode, lapses_at_unix_secs }`
  from `issue_tokens` / `issue_tokens_for` when the issuer answers 403
  `{"error":"banned"}`, for session tokens and port entitlements alike, so an
  app can show the suspension without dialing an exit. Any other status, a 403
  with another body included, keeps its `ServerStatus` mapping.
  `TokenManager::refresh` and `PortEntitlementManager::refresh_auto` return the
  ban (wrapped in `TokenClientError::Api`) instead of swallowing it as a
  per-epoch failure, and stop the pass there with that epoch unsettled, so a
  lifted ban mints at the next tick. The attribution failures below
  (`BadAttributionKey`, `AttributionTag*`) are returned the same way, so a
  broken issuer shows up at refresh instead of as a batch that never fills.
  `BanReasonCode` and `IssuanceRefusal` are re-exported from `warren_api`.
- `WarrenApiClient::account_standing()`: the wallet-signed
  `GET /v1/account/standing`, returning the contract's
  `AccountStandingResponse` (live port-forward abuse strikes with day,
  category, exit country, port and case reference; the threshold and window;
  the ban in force with its lapse date). Meant to be polled on the token
  refresh timer. `AccountStandingResponse`, `AccountStrike`, `AccountBan` and
  `AbuseCategory` are re-exported from `warren_api`.

- Network changes now MIGRATE the live QUIC session instead of always redialing
  it. The supervised proxy datapath arms the engine migration watchdog
  (`warrenguard_transport::migration_watchdog`, re-exported as
  `warren_transport::migration_watchdog`) for each connected epoch: on a moved
  default path it rebinds the session onto a fresh wildcard socket, probes the
  tunnel with DAITA padding, and keeps the epoch when the relay revalidates the
  path (about one RTT, no re-handshake, with the connection-ID rotation quinn
  performs on a local-address change). The redial is now the FALLBACK: when the
  migration does not take within the engine's probe window, the watchdog ends
  the epoch exactly as a network change did before, so nothing regresses when a
  path cannot be migrated. A session riding the TLS-over-TCP carrier is never
  rebound (it has no UDP socket to swap) and redials straight away.
  New session surface: `MultihopSession::rebind_wildcard()`, `local_addr()`,
  `is_over_carrier()`, `force_close_for_reconnect()`, `send_daita_padding()`,
  plus the re-exported `RebindPolicy` / `RebindError`, and
  `PacketSink::multihop_session()` so a supervisor can reach the QUIC path
  behind a datapath.

- The experimental privileged TUN datapath (`start_tun_multihop`) gets the same
  watchdog, which it had no equivalent of at all: a network change used to leave
  it on a 4-tuple that no longer existed until quinn's idle timeout noticed.
  It now migrates the session, with the per-OS escape the datapath already
  installs (the Linux fwmark bypass reapplied to the fresh socket, the macOS
  `<exit>/32` host route reinstalled ahead of the rebind and pinned to the
  gateway resolved at dial time, before the split capture makes `route get
  default` name the tunnel). Having no supervisor to redial it, its fallback
  stops at closing the session, so the caller rebuilds the datapath exactly as
  it already does on any tunnel loss.

- Live datapath observability reachable from the SUPERVISED datapath, which is
  the one every real app holds. `ProxyHandle::metrics` already existed but only
  on the unsupervised handle, so any app needing reconnection could not read the
  counters the engine was already keeping. New:
  `SupervisedProxyHandle::metrics()` and `metrics_reader()` (a cheap cloneable
  `MetricsReader` for a background task, following reconnects), plus
  `MultihopSession::path_quality()` / `carrier()`.
  `MultihopMetricsSnapshot` gains `path: Option<PathQuality>` carrying the outer
  `Carrier` (native QUIC vs the TLS-over-TCP fallback, recorded at the dial
  race), smoothed RTT, the settled PMTU and max inner payload, and quinn's own
  `black_holes`, `lost_packets`, `congestion_events` and PLPMTUD probe counts.
  These are the variables datapath incidents turn on, and none was observable
  from a client before.
  The probe observes WITHOUT owning: quinn closes a connection when its last
  handle drops, so a strong reference in an observability path would extend the
  datapath's lifetime. It holds a weak reference and reports `None` once the
  epoch ends. No change to the shared `warrenguard` engine was needed: the
  carrier race is generic over the connection type, so each leg tags its own
  value and the winner carries the tag.

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

### Changed

- A port-forwarding slot now presents the entitlement ENVELOPE, not a bare
  token (warren-core doc 105): `PortEntitlementManager::credential_for_slot`
  returns the 500-byte `EntitlementEnvelope` encoding (version, token, and the
  attribution tag the issuer minted beside it), which every exit now requires
  on a NAT-PMP Map request. Minting a port-entitlement batch checks each tag
  the way the exit will: one tag per blind signature
  (`TokenClientError::AttributionTagCount`), minted for the batch's epoch
  (`AttributionTagEpoch`), signed under the directory's
  `attribution_verifying_key_hex` (`AttributionTagInvalid`). A directory with
  no usable key fails with `BadAttributionKey` before anything is blinded, so
  the once-per-epoch issuance is not spent on credentials no exit accepts.
  `MintedEpoch` gains `attribution_tags`. A `TokenManager` of the
  port-entitlement class no longer vends, exports or restores bare
  entitlements; the batch stays RAM-only. `AttributionTag` and
  `EntitlementEnvelope` are re-exported from `warren_api`, and
  `vectors/pf_attribution.json` is replayed through the SDK's store and mint
  checks.
- The userspace proxy datapath's inner TCP is now congestion-controlled. smoltcp
  moves from 0.12 to 0.14, the first release whose congestion window actually
  bounds the data in flight (smoltcp #1154 to #1157, #1155), and every inner
  socket is CUBIC explicitly (`socket-tcp-cubic`). Before this every connection
  through the proxy sent as fast as the peer's window allowed, up to a megabyte
  at once into a datagram queue that keeps about 128 KiB on a narrow link, and
  re-sent the whole window at every hole: a member's 1 Mbit/s uplink was offered
  419 MB in 105 minutes with 10 % of the wire packets lost and the PMTU pinned
  at the floor (workspace incident 2026-09-13). On a lossy loopback the same
  256 KiB upload now costs 190 payload packets instead of 468 or never finishing
  (`a_lossy_uplink_does_not_multiply_the_payload_the_client_emits`).
- Minimum supported Rust is 1.91 (smoltcp 0.14's floor); the toolchain pin and
  CI move with it. The wire contracts are pinned by `Cargo.lock`, not by the
  toolchain, so the golden vectors are unaffected.
- `ClientError::AllHostsBlocked` no longer calls itself "possible censorship":
  a host with no network fails the same way, in the same time, and did so 1,752
  times across the wclaude fleet in three days. The message now names both
  causes; a caller that knows whether the host has a route decides.

### Added

- `PathQuality` reports `sent_packets` (QUIC packets that reached the wire),
  `dg_dropped_aqm` and `dg_dropped_overflow` (outgoing datagrams the send queue
  itself discarded). `packets_sent` counts what the inner stack offered the
  queue, retransmissions included, and on a saturated uplink that alone could
  not separate a lossy path from a dropping queue.
- `scripts/bench/proxy-upload-shaped.sh` and the `bench_proxy` example: the
  proxy datapath uploading through a real exit over a shaped uplink (netem
  bufferbloat, cake) inside a privileged container on the local VM, the shape of
  one Claude Code turn on a member's narrow line.

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
