# warren-proxy

Headless Warren proxy daemon: the SDK's supervised failover datapath as one
long-running binary, configured entirely from the environment. No root, no
TUN device, no capabilities: the tunnel terminates in an in-process userspace
netstack behind a SOCKS5 listener (plus optional HTTP CONNECT), DNS resolves
over the tunnel, and the process keeps itself connected across drops and exit
failures.

Use it where the full desktop daemon is too heavy or too privileged:
containers, servers, NAS boxes, CI. The unprivileged container image
(`ghcr.io/warrenbrowse/warren-proxy`) is this binary and nothing else; the
privileged full-VPN image (`ghcr.io/warrenbrowse/warren-vpn`, kill switch,
netns ownership) is the sibling for the gluetun-style `network_mode:
"service:..."` pattern.

## Commands

```
warren-proxy                 serve (the default)
warren-proxy healthcheck     probe the running daemon's /healthz
warren-proxy --version       print the build this binary came from
```

An argument that is not one of these is refused: every other knob is an
environment variable, so a flag the daemon does not know would otherwise be
ignored while the operator believed it applied.

## Environment

| variable | default | meaning |
|---|---|---|
| `WARREN_MNEMONIC` / `WARREN_MNEMONIC_FILE` | required | the account recovery phrase; the file variant wins and is what containers should use |
| `WARREN_SOCKS_LISTEN` | `127.0.0.1:1080` | SOCKS5 listener. The listeners are unauthenticated: bind non-loopback only inside an isolated netns/container |
| `WARREN_HTTP_LISTEN` | off | HTTP CONNECT listener |
| `WARREN_HEALTH_LISTEN` | `127.0.0.1:9999` | liveness endpoint: `/healthz` (200 only when Connected AND egress verified for the CURRENT epoch: a reconnect clears the proof until a fresh probe passes), `/state`, `/port`; `off`, `none` or empty disables it, and `warren-proxy healthcheck` then exits 0, which also makes the image's `HEALTHCHECK` a no-op: the runtime can no longer tell a wedged daemon from a healthy one |
| `WARREN_EXITS` | all exits | priority list of `cc` or `cc/city` (e.g. `de, se/stockholm`); failover tries them in order |
| `WARREN_CIRCUIT` | `single` | `single` (direct to exit) or `multi` (entry relay then exit) |
| `WARREN_DNS_SERVER` | exit forwarder | IPv4 resolver queried over the tunnel (needed for `dns_disabled` exits) |
| `WARREN_CONNECT_TIMEOUT` | `90` | seconds allowed for first Connected + verified egress |
| `WARREN_API_URL` | channel default | control-plane override (e.g. the beta host on a prod-built binary) |
| `WARREN_SERVER_PUBKEY_HEX` | compiled pin | relay-list signing key override (bench/rotation) |
| `WARREN_PORT_FORWARD_INTERNAL_PORT` | off | enables NAT-PMP forwarding of a tunnel-side port |
| `WARREN_PORT_FORWARD_PROTOCOL` | `tcp` | `tcp` or `udp`, one transport per daemon: TCP and UDP are two independent mappings, reachable on two public ports of which only one could be announced, and holding two of the exit's per-client forward slots |
| `WARREN_PORT_FORWARD_TARGET` | `127.0.0.1:<internal>` | local socket inbound connections are relayed to |
| `WARREN_PORT_FORWARD_UP_COMMAND` | | run via the platform shell on every grant, `{{PORT}}` substituted (the gluetun up-command shape). The recovery phrase and its file path are removed from the hook child's own environment, so a hook that dumps `env` cannot leak them; a hook that outlives its 30 s budget is killed, on unix with everything it spawned (it runs in its own process group), on Windows the shell alone, so its grandchildren survive |
| `WARREN_PORT_FORWARD_DOWN_COMMAND` | | run when the port is replaced, when the grant is lost, and at shutdown |
| `WARREN_PORT_FORWARD_STATUS_FILE` | | the granted public port, one decimal line, atomically rewritten; removed when the mapping goes away and on every daemon exit. The image ships `/run/warren` writable by the runtime user: put the file there and share that directory with the container that reads it |

Port forwarding runs on the exit's default per-client quota: this daemon
presents no entitlement credential, so the account's fleet-wide slot count is
not what bounds it. The engine implements the atomic TCP+UDP pair (one public
port, one credential); the SDK forward path this daemon uses does not carry it
yet, which is why `both` is refused. The down command runs and the status file
is removed on every exit, a signal and a terminal refusal alike. The NAT-PMP
mapping is released at the exit rather than left to lapse with its lease, and
the release is bounded: the daemon logs which of the three outcomes it got (the
mapping was deleted, no live mapping was left to delete, or the delete did not
answer inside its budget), and on the last two the exit keeps the public port
until the lease lapses.

Exit codes: `0` clean signal shutdown, `1` configuration or startup failure,
`2` a terminal control-plane refusal, printed with its cause (unauthorized
account, device cap, suspension, opaque policy refusal). There is no code for
"every candidate exit failed": a transient failure never stops the supervisor,
which keeps rotating exits and retrying, so `2` always means a refusal that no
restart and no other exit resolves. Restart on `1`, stop on `2`.

## Nested-VPN caveats (validated 2026-08-15)

- Running inside another VPN (including the Warren desktop app's own tunnel)
  squeezes the path: set `WARREN_TUNNEL_INITIAL_MTU=1200` (the engine knob) or
  the QUIC handshake black-holes and connects fall back slowly, if at all.
- Never constrain `WARREN_EXITS` to the SAME exit the outer tunnel uses: the
  dial hairpins out of that exit back into itself and stalls in `Connecting`.
  Leave the list free (failover rotates to a working exit) or pick another
  country.

## Live validation record

2026-08-15, macOS arm64 against the beta network: supervised failover rotated
past a broken/hairpinned candidate to `Connected`; SOCKS5 and HTTP CONNECT
egress verified (exit IP observed on both, distinct from the host path);
`/healthz` gating on verified egress; NAT-PMP grant observed (public port
49587), status file + up-command fired, inbound reachability proven end to
end (HTTP fetch from outside through `exit:49587` to a local server on the
forward target), down-command fired on SIGTERM.
