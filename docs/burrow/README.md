# Deploying warren-burrow

warren-burrow implements the WireGuard protocol so that stock WireGuard clients
can use Warren. "WireGuard" is a registered trademark of Jason A. Donenfeld;
this project is not affiliated with or endorsed by the WireGuard project.

One gateway runs on a machine that can run Warren, holds one authenticated
Warren session, and carries the traffic of the devices that cannot: a TV, a
router, a console behind that router, a phone without the app, or a gluetun
stack you would rather not replace. Each of those devices runs its own stock
WireGuard client and points it at the gateway.

The env contract, the commands and the health surface are in
[`crates/warren-burrow/README.md`](../../crates/warren-burrow/README.md). This
directory carries the deployment shapes and the per-device import paths.

| file | what it is |
|---|---|
| [`docker-compose.peer.yml`](docker-compose.peer.yml) | one gateway on a LAN host, for devices on that LAN |
| [`docker-compose.gluetun.yml`](docker-compose.gluetun.yml) | a stock gluetun and an application behind it, all on one host |
| [`clients.md`](clients.md) | importing a configuration on a router, an Apple TV, a phone, Windows, a NAS |
| [`test-examples.sh`](test-examples.sh) | the structural checks the two compose files have to keep passing |

## Which Warren component to run

| you have | use | why |
|---|---|---|
| a host that can hold `NET_ADMIN` and `/dev/net/tun` (docker, a NAS, Kubernetes) | the `warren-vpn` container | one crypto layer, one NAT, a kill switch tied to the death of the namespace, native-sidecar ordering under Kubernetes |
| a restricted namespace, CI, per-application egress, no capability to give | `warren-proxy` | SOCKS5 and HTTP CONNECT, unprivileged, one process |
| a device that cannot run Warren at all, or a gluetun stack you will not replace | `warren-burrow` | a stock WireGuard client on the device, one gateway on the LAN, one Warren session for all of them |

The gateway is the answer when the device is the constraint. When the host can
run Warren itself, the two other components carry less machinery and give a
stronger kill switch.

## Three things to know before handing anyone a configuration

**One Warren session, shared.** Every peer of one gateway rides one
authenticated session: one address assigned at the exit, one abuse identity,
one device slot on the account, one port-forwarding quota, one failover (a peer
that congests the uplink can get the tunnel rebuilt, and every peer's public
address changes with it), shared NAT state and bandwidth, and no per-peer
accounting. Peer isolation, on by default, keeps peers from reaching each
other; it does not isolate their share of the session. A client configuration
is a bearer credential for the operator's subscription on that network.

**The obfuscation boundary is the gateway.** Warren's QUIC transport and its
obfuscation begin AT the gateway. The hop between a stock client and the
gateway is ordinary WireGuard, recognisable to anyone inspecting the traffic.
On a home network or a NAS that hop is local, which is the point. A gateway
reachable across the internet gives up Warren's censorship resistance for that
leg, which is why neither example publishes the gateway's UDP port and why the
daemon refuses a non-loopback bind until `WARREN_BURROW_LAN=1` says otherwise.

**The kill switch is the peer's own setting.** The gateway is fail-closed by
construction: it never writes a peer's packet anywhere except into the tunnel,
and while no epoch has proven it egresses it emits nothing toward a peer but a
stateless cookie reply. What it cannot do is stop a peer's operating system
from routing around an interface that was torn down. Use the client's own
setting where it has one; [`clients.md`](clients.md) names it per platform.

## A gateway for LAN devices

`docker-compose.peer.yml`. The gateway binds the host's LAN address, and the
devices import a configuration whose `Endpoint` is that address.

```sh
cd docs/burrow
umask 077
printf '%s\n' 'the twelve words of the account' > warren-mnemonic.txt
export WARREN_LAN_IP=192.168.1.10          # this host's LAN address
docker compose -f docker-compose.peer.yml up -d
```

The first run generates the gateway key and `WARREN_BURROW_PEERS`
configurations, named `peer2`, `peer3` and so on. Retrieve one:

```sh
docker compose -f docker-compose.peer.yml exec warren-burrow warren-burrow show peer2
docker compose -f docker-compose.peer.yml exec warren-burrow warren-burrow show peer2 --qr
```

The text form is what a router or a desktop imports as a file; the QR is what a
phone scans. Both carry that peer's private key and preshared key, so treat the
output as the credential it is: a trusted screen, and no chat, no mail, no
shared drive. [`clients.md`](clients.md) takes it from there, per device.

Adding a device later needs no restart:

```sh
docker compose -f docker-compose.peer.yml exec warren-burrow warren-burrow add-peer livingroom-tv
docker compose -f docker-compose.peer.yml exec warren-burrow warren-burrow remove-peer livingroom-tv
```

`add-peer` and `remove-peer` reload the running daemon themselves, and a
removed peer loses its session, its endpoint and its NAT mappings on the spot,
which is the revocation path for a device that walked out of the building.

## The gluetun stack

`docker-compose.gluetun.yml`. gluetun is unmodified `qmcgaw/gluetun:v3.41.3`
with `VPN_SERVICE_PROVIDER=custom` and `VPN_TYPE=wireguard`, and every
`WIREGUARD_*` key it needs comes from a file the gateway generated.

```sh
cd docs/burrow
umask 077
printf '%s\n' 'the twelve words of the account' > warren-mnemonic.txt

# Generate the gateway and one peer named glue, before anything starts.
docker compose -f docker-compose.gluetun.yml run --rm warren-burrow init --label glue

# Take the generated env snippet out of the state volume, once.
docker compose -f docker-compose.gluetun.yml run --rm --entrypoint cat \
  warren-burrow /var/lib/warren-burrow/clients/glue.gluetun.env > glue.gluetun.env

docker compose -f docker-compose.gluetun.yml up -d
```

`glue.gluetun.env` carries that peer's private key and preshared key: 0600, and
never in version control. Do not hand-edit it; regenerate the peer instead. The
endpoint stays in the compose file, because it is a property of the network
rather than of the peer.

Verify the whole path, from the host:

```sh
curl -s https://api.ipify.org; echo                                  # this host's own address
curl -s --proxy http://127.0.0.1:8888 https://api.ipify.org; echo    # through gluetun, through the exit
```

Two different addresses is the proof. The second one is the exit's.

`app` joins gluetun's network namespace, so it has no interface and no route
of its own and gluetun's firewall applies to it. Restarting gluetun replaces
that namespace, and `app` keeps a handle on a destroyed one: no connectivity,
no error, until `app` is restarted too.

## Operating

`/healthz` answers 200 only when the tunnel is connected AND egress is proven
for the epoch running now, which is what the compose healthcheck reads and what
gluetun waits for. `/status` carries the epoch, the gate, the live inner budget
and the recommended client MTU, the NAT mappings and every drop counter, with no
key and no address in it. `/peers` carries per-peer labels and counters.

```sh
docker compose -f docker-compose.peer.yml exec warren-burrow \
  curl -s http://127.0.0.1:9998/status
```

Restarting the gateway costs its peers a reconnection: their sessions do not
survive it, and each peer rebuilds on its own timers, needing no
reconfiguration. Measured against the live network: about 15 seconds for a peer
with traffic to send, and as long as a rekey interval (two minutes) for an idle
peer whose keepalives are all it emits. A peer looks dead until its timer
fires, and its traffic is lost in the meantime.

The daemon exits 0 on a clean signal, 1 on a configuration or startup failure,
and 2 on a terminal control-plane refusal (an expired subscription, a rejected
account). `restart: unless-stopped` is right for 1 and wrong for 2, and docker
marks an unhealthy container without restarting it, so a gateway that stays
unhealthy needs a watchdog or an eye.

## What has been exercised

Against a real Warren exit, from a Mac with colima: the gateway itself, a stock
`wg-quick` peer in both userspace (wireguard-go) and kernel mode, and
unmodified `qmcgaw/gluetun:v3.41.3` fed the generated snippet verbatim, all
egressing at the exit; DNS through the tunnel; ICMP through the NAT; a 1 GB
transfer; a spoofed inner source dropped and counted; the gate closing on
tunnel loss and emitting nothing to peers until it healed; a NAT-PMP port
forward reachable from a neutral vantage.

The per-platform import paths in [`clients.md`](clients.md) come from each
platform's documented behaviour. No GUI client (tvOS, iOS, Android, the Windows
app, a router UI) was run against a gateway, so treat those sections as the
shape to expect rather than as a measured result.
