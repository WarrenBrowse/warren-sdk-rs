# warren-bolthole

warren-bolthole implements the WireGuard protocol so that stock WireGuard clients
can use Warren. "WireGuard" is a registered trademark of Jason A. Donenfeld;
this project is not affiliated with or endorsed by the WireGuard project.

**Warren's QUIC transport and its obfuscation begin AT this gateway.** The hop
between a stock client and the gateway is ordinary WireGuard, recognisable to
anyone inspecting the traffic. On a home network or a NAS that hop is local,
which is the point; a gateway reachable across the internet gives up Warren's
censorship resistance for that leg. Do not publish the gateway's UDP port to
the internet.

Three things to know before handing anyone a client configuration:

1. **One Warren session, shared.** Every peer of one gateway rides one
   authenticated session: one address assigned at the exit, one abuse identity,
   one device slot on the account, one port-forwarding quota, one failover (a
   peer that congests the uplink can get the tunnel rebuilt, and every peer's
   public address changes with it), shared NAT state and bandwidth, and no
   per-peer accounting. Peer isolation (on by default) keeps peers from
   reaching each other; it does not isolate their share of the session. A
   client configuration is a bearer credential for the operator's subscription
   on that network.
2. **The obfuscation boundary is the gateway** (above).
3. **The kill switch is the peer's own setting.** The gateway is fail-closed by
   construction: it never writes a peer's packet anywhere except into the
   tunnel, and while no epoch has proven it egresses it emits nothing toward a
   peer but a stateless cookie reply. What it cannot do is stop a peer's
   operating system from routing around an interface that was torn down. Use
   the client's own setting where it has one: "block untunneled traffic" on
   Windows, "block connections without VPN" on Android, gluetun's own firewall,
   your router's equivalent.

A peer with a full-tunnel configuration loses access to its own LAN (printer,
NAS, casting) unless its configuration was generated with an excluded prefix
(`--lan-exclude`), and an excluded LAN is not protected.

## Which Warren component to run

| you have | use |
|---|---|
| a host that can hold `NET_ADMIN` and `/dev/net/tun` | the `warren-vpn` container |
| a restricted namespace, CI, per-application egress | `warren-proxy` |
| a device that cannot run Warren at all (a TV, a router, a console, a phone without the app), or a gluetun stack you will not replace | `warren-bolthole` |

Deployment shapes (a gateway for LAN devices, a gluetun stack) and the import
path for each kind of device live in `docs/bolthole/` at the root of this
repository. What follows is the contract those examples are built on.

## Commands

```
warren-bolthole [run]                      serve (the default; first run provisions)
warren-bolthole init [OPTIONS]             generate the gateway and its peers
warren-bolthole add-peer LABEL [OPTIONS]   add one peer and write its files
warren-bolthole remove-peer LABEL          revoke one peer
warren-bolthole show LABEL [--qr]          print a peer's client configuration
warren-bolthole reload                     apply the configuration file to the running daemon
warren-bolthole reset-peer LABEL           rebuild one peer's session (a device whose clock jumped)
warren-bolthole healthcheck                probe the running daemon's /healthz
warren-bolthole --version                  print the build this binary came from
```

Options for `init` and `add-peer`: `--peers N`, `--label NAME`,
`--lan-exclude CIDR`, `--no-v6`, `--force`.

The first `run` on an empty state directory generates the gateway key and
`WARREN_BOLTHOLE_PEERS` peers, writes their files and says how to retrieve one. A
state directory that holds something else is refused rather than written into.
The files under `clients/` ARE the credentials: each carries a peer's private
key and preshared key, and they are kept nowhere else.

## Environment

Shared with the other headless daemons:

| variable | default | meaning |
|---|---|---|
| `WARREN_MNEMONIC` / `WARREN_MNEMONIC_FILE` | required by `run` | the account recovery phrase; the file variant wins and is what containers should use. The subcommands that only write files need no account |
| `WARREN_EXITS` | all exits | priority list of `cc` or `cc/city` (e.g. `de, se/stockholm`); failover tries them in order |
| `WARREN_CIRCUIT` | `single` | `single` (direct to exit) or `multi` (entry relay then exit) |
| `WARREN_DNS_SERVER` | `10.66.0.1` | the resolver written into client configurations. Any other value also keeps `dns_disabled` exits in the rotation; `off` writes no `DNS` line |
| `WARREN_CONNECT_TIMEOUT` | `90` | seconds allowed for the first `Connected`, and the budget the first egress proof is retried within |
| `WARREN_HEALTH_LISTEN` | `127.0.0.1:9998` | liveness endpoint (the proxy's own default is 9999, so both run on one host); `off`, `none` or empty disables it, and `warren-bolthole healthcheck` then exits 0, which reports the container healthy for as long as it exists |
| `WARREN_API_URL` | channel default | control-plane override |
| `WARREN_SERVER_PUBKEY_HEX` | compiled pin | relay-list signing key override |
| `WARREN_PORT_FORWARD_INTERNAL_PORT` | off | enables NAT-PMP forwarding of a tunnel-side port; refused inside `61000-61999`, which this gateway keeps for its own in-tunnel control plane |
| `WARREN_PORT_FORWARD_PROTOCOL` | `tcp` | `tcp` or `udp` |
| `WARREN_PORT_FORWARD_TARGET` | required with a forward | the peer socket inbound traffic is delivered to; it must be an address inside the peer subnet, because delivery is by cryptokey routing and this gateway relays nothing itself |
| `WARREN_PORT_FORWARD_UP_COMMAND` / `_DOWN_COMMAND` / `_STATUS_FILE` | | as in `warren-proxy`: `{{PORT}}` substituted, the recovery phrase stripped from the hook child's environment |

The gateway's own:

| variable | default | meaning |
|---|---|---|
| `WARREN_BOLTHOLE_LISTEN` | `127.0.0.1:51820` | comma-separated UDP binds, one socket per entry |
| `WARREN_BOLTHOLE_LAN` | `0` | must be `1` to bind anything but loopback. The refusal states who can then reach the gateway, and where the obfuscation boundary is |
| `WARREN_BOLTHOLE_ENDPOINT` | detected on a LAN gateway, `127.0.0.1:<port>` otherwise | the `Endpoint` written into client configurations. Detection uses the primary address of the default-route interface (a connected UDP socket, no packet sent) and refuses a loopback result on a LAN gateway |
| `WARREN_BOLTHOLE_PEERS` | `1` | how many peers a first run generates |
| `WARREN_BOLTHOLE_STATE_DIR` | `/var/lib/warren-bolthole` as root, else `$XDG_STATE_HOME/warren-bolthole`, `~/Library/Application Support/warren-bolthole` or `%LOCALAPPDATA%\warren-bolthole` | where the configuration, the client files and the admin token live; created `0700`, every file `0600` |
| `WARREN_BOLTHOLE_CONF` | `<state>/bolthole.conf` | the gateway-side configuration; refused unless it is mode 0600 on unix |
| `WARREN_BOLTHOLE_PEER_SUBNET` | `10.67.0.0/24` | the peers' addresses; refused if it overlaps the tunnel pool `10.66.0.0/16` |
| `WARREN_BOLTHOLE_PEER_SUBNET_V6` | `fd77:6172:7265::/64` | the same for IPv6 |
| `WARREN_BOLTHOLE_IPV6` | `1` | ask the exit for an IPv6 assignment. IPv6 is opportunistic: it follows the exit and the path budget, and is withdrawn with a fast unreachable under the IPv6 minimum MTU rather than black-holed |
| `WARREN_BOLTHOLE_CLIENT_MTU` | `1280` | the `MTU` line written into client configurations; refused outside 1280 to 1420 |
| `WARREN_BOLTHOLE_PEER_ISOLATION` | `1` | drop peer-to-peer traffic |
| `WARREN_BOLTHOLE_HANDSHAKE_RATE` | `200` | threshold of the shared cookie limiter |
| `WARREN_BOLTHOLE_HEALTH_PEERS` | `1` | `0` removes the `/peers` route on a shared host |
| `WARREN_BOLTHOLE_FWMARK` (Linux) / `WARREN_BOLTHOLE_BIND_IF` (macOS, Windows) | unset | carrier-socket bypass, the supported recipe for a peer on the gateway host itself |
| `WARREN_BOLTHOLE_NAT_UDP_TIMEOUT`, `_UDP_INITIAL_TIMEOUT`, `_TCP_TIMEOUT`, `_TCP_SYN_TIMEOUT`, `_TCP_CLOSING_TIMEOUT`, `_ICMP_TIMEOUT` | RFC-derived | NAT expiry, in seconds |
| `WARREN_BOLTHOLE_NAT_PER_PEER_MAPPINGS`, `_PER_PEER_IDENTIFIERS` | | per-peer caps, so one peer cannot exhaust the shared table |

Key material is never on argv, never in the environment and never logged: the
gateway private key, the peer public keys and the preshared keys live in
`bolthole.conf` alone, and the startup line carries an 8-character key prefix.

## Health and admin

- `/healthz`: 200 only when the tunnel is `Connected` AND egress is proven for
  the epoch running now. A reconnect clears the proof until a fresh probe
  passes, and the gate closes with it.
- `/state`, `/port`: the supervised state, and the granted public port.
- `/status`: JSON, the epoch, the gate, the live inner budget and the
  recommended client MTU, IPv6 availability, peer counts, NAT mappings and
  every drop counter. No key, no address. Two counters are easy to misread:
  `spoofed_source` is a peer sourcing an address another peer owns, while the
  MLD reports and router solicitations any peer's own link-local address emits
  at interface bring-up are refused by the same rule under
  `link_local_source`, so a `spoofed_source` that moves is worth reading.
- `/peers`: per-peer labels and counters (`WARREN_BOLTHOLE_HEALTH_PEERS=0`
  removes it). Never a peer's remote address.
- `POST /admin/reload`, `POST /admin/reset-peer/<label>`: served only when the
  health listener is on a loopback address, behind
  `Authorization: Bearer <token>` where the token is `<state>/admin.token`,
  written 0600 and regenerated at every start. `warren-bolthole reload` and
  `warren-bolthole reset-peer LABEL` are the callers; `add-peer` and
  `remove-peer` reload the running daemon themselves. On unix `SIGHUP` also
  reloads, and it is the only way when the health listener is off.

Sessions do not survive a restart of the gateway. A peer that was connected
keeps its own session and its packets arrive under an index the new process
does not know, counted as `unknown_index` and answered with nothing, which is
what the protocol requires. Each peer rebuilds its session on its own timers,
needing no reconfiguration and no restart, but it looks dead until they fire
and traffic to it is lost in the meantime. Measured against the live network:
17 seconds for a peer that has data to send, which is its liveness rule (a 10
second keepalive timeout plus a 5 second rekey timeout), and 79 seconds for an
idle peer emitting only its 25 second persistent keepalive, bounded by the
protocol's 120 second rekey interval.

`reload` adds new peers, removes deleted ones with their sessions, endpoints
and NAT mappings (the revocation path for a lost device), rebuilds the peers
whose key material or allowed IPs changed, and leaves every other session
untouched. `reset-peer` rebuilds one peer's session and clears its handshake
timestamp guard, which is the escape for a device whose clock jumped.

Exit codes: `0` clean signal shutdown, `1` configuration or startup failure,
`2` a terminal control-plane refusal. Restart on `1`, stop on `2`.
