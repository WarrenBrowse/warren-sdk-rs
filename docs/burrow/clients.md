# Importing a configuration on a device

Every device below runs a stock WireGuard client and points it at a gateway.
Nothing on the device is Warren software, and nothing about it is
Warren-specific: the configuration is an ordinary WireGuard configuration.

The import paths below come from each platform's documented behaviour. The
gateway itself was validated live against a real exit with `wg-quick` in
userspace and kernel mode and with unmodified gluetun; no GUI client was run
against it, so treat a platform section as the shape to expect.

## What you are handing over

```
[Interface]
PrivateKey = <this peer's private key>
Address = 10.67.0.2/32, fd77:6172:7265::2/128
DNS = 10.66.0.1
MTU = 1280

[Peer]
PublicKey = <the gateway's public key>
PresharedKey = <this peer's preshared key>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.168.1.10:51820
PersistentKeepalive = 25
```

The file IS the credential: whoever holds it joins the gateway and rides the
operator's Warren session. Move it on a trusted path, and revoke a device that
leaves with `warren-burrow remove-peer <label>`, which drops its session and
its NAT mappings immediately.

Four lines decide whether the import works:

- **`Endpoint`** must be an address the device can reach. It is what
  `WARREN_BURROW_ENDPOINT` was set to when the peer was generated, so a peer
  generated on a gateway that later moved needs a new configuration.
- **`AllowedIPs = 0.0.0.0/0, ::/0`** is a full tunnel: the device loses its own
  LAN (printer, NAS, casting) while connected. Generating the peer with
  `--lan-exclude 192.168.1.0/24` writes the complement of that prefix instead,
  and the excluded prefix is then not protected.
- **`MTU = 1280`** is what the gateway recommends by default
  (`WARREN_BURROW_CLIENT_MTU`); `/status` reports the live inner budget and the
  MTU that fits it. A client that ignores the line and probes for itself is
  what `PersistentKeepalive` and the gateway's ICMP handling are there for, and
  the fix for a stalled large transfer is to lower this value.
- **`DNS = 10.66.0.1`** is the exit's resolver, on the far side of the tunnel.
  A client that has no DNS setting (a router, mostly) keeps its own resolver,
  which then answers outside the tunnel.

Retrieve one, on the host that runs the gateway:

```sh
warren-burrow show peer2          # the text a file import wants
warren-burrow show peer2 --qr     # the same thing as a QR, for a camera
```

In a container, put `docker compose exec warren-burrow` in front of it.

## A router (OpenWrt, GL.iNet, Keenetic)

The router becomes one peer and masquerades its LAN behind that tunnel, so
every device behind it egresses at the exit without knowing anything about
Warren. This is the only way a console, a smart appliance or a guest device
gets there.

1. Copy the configuration text to the router: LuCI's *Network / Interfaces /
   Add interface / WireGuard VPN* takes a pasted configuration or an uploaded
   file; GL.iNet's UI has *VPN / WireGuard Client / Add a New WireGuard
   Configuration / Manual*; Keenetic imports a `.conf` under *Other
   connections / VPN connections / WireGuard*.
2. Keep `MTU = 1280`. Router firmware often defaults to 1420, and the symptom
   is the classic one: pings and small pages work, large downloads and TLS
   handshakes stall.
3. Set the firewall zone so the LAN is allowed out through the WireGuard
   interface with masquerading on, and make the tunnel the default route only
   for the clients you intend (OpenWrt: a policy route, or the default route in
   the peer's `AllowedIPs`).
4. Give the router its own resolver decision. A router that keeps forwarding to
   the ISP resolver leaks every lookup outside the tunnel; point it at
   `10.66.0.1`, or at a resolver reachable through the tunnel.

Two costs come with this shape. The gateway is a LAN host, so every packet
crosses the LAN twice and hairpins through the router, which is what a
router-shaped deployment pays. And a router has no kill switch of its own: if
the tunnel stops, the router's default route is what decides whether its LAN
falls back to the plain internet, so set that route deliberately.

## Apple TV (tvOS 17 and later)

The official WireGuard app exists on tvOS and imports a configuration file;
there is no camera, so the QR form is useless here. Put the `.conf` where the
Files app can reach it (iCloud Drive), and import it from the app on the TV.

The TV has no LAN exclusion worth keeping, so the full-tunnel default is
usually right. AirPlay from a phone on the same LAN keeps working, because the
phone reaches the TV over the LAN and the TV's own egress is what moved.

## A phone (iOS, Android)

The official WireGuard app on both platforms scans a QR: `warren-burrow show
<label> --qr` prints one in the terminal. Show it on a trusted screen; it
carries the peer's private key and preshared key.

- **Android**: the kill switch is the system's, under *Settings / Network /
  VPN*, "Always-on VPN" plus "Block connections without VPN". The WireGuard app
  supports both.
- **iOS**: the app has "On-Demand", which reconnects the tunnel rather than
  blocking traffic while it is down. There is no equivalent of "block
  untunneled traffic".

A phone that leaves the LAN loses the gateway with it: `Endpoint` is a LAN
address, and nothing answers it from outside. That is the intended shape, since
publishing the gateway to the internet gives up the property the gateway exists
to keep. A phone that needs Warren everywhere wants the Warren app.

## Windows

The official WireGuard for Windows app imports the file through *Add Tunnel*,
and its "Block untunneled traffic (kill-switch)" checkbox is the one to use.

That checkbox exists only for a tunnel whose `AllowedIPs` is `0.0.0.0/0` (and
`::/0`), which is the default here. A configuration generated with
`--lan-exclude` carries the complement of the excluded prefix instead, so the
kill switch is unavailable on it: pick one or the other, deliberately.

## A NAS (Synology, QNAP, TrueNAS, unRAID)

A NAS is usually the machine that runs the gateway rather than a peer of one:
it is up all the time, it is on the LAN, and it has docker.
[`docker-compose.peer.yml`](docker-compose.peer.yml) is that deployment, and
[`docker-compose.gluetun.yml`](docker-compose.gluetun.yml) is the same host
also carrying an application behind gluetun.

If the NAS is instead a peer of a gateway elsewhere on the LAN, import the
configuration into its own WireGuard package (Synology's `SynoCLI`/wg package,
QNAP's QVPN, TrueNAS's native WireGuard) or into a WireGuard container. Do not
point a same-host client at a gateway running on that same host: a client that
installs a default route into its interface captures the gateway's own outgoing
datagrams and loops the tunnel into itself. The supported same-host recipe is
`WARREN_BURROW_FWMARK=<n>` on Linux with the peer's `FwMark = <n>` and an
`ip rule add fwmark <n> lookup main` installed once by root, or
`WARREN_BURROW_BIND_IF` on macOS and Windows.

## When something does not work

| symptom | what it usually is |
|---|---|
| no handshake at all | the device cannot reach `Endpoint`: wrong address, a firewall on the gateway host, or the gateway bound to loopback because `WARREN_BURROW_LAN` is unset |
| a handshake, then nothing | the gateway's gate is closed: `/healthz` is not 200 because no epoch has proven egress yet. It emits nothing to peers until it heals |
| small requests fine, large transfers stall | MTU. Keep the `MTU` line the gateway wrote, or lower it |
| the device works, its LAN does not | the full-tunnel default. Regenerate the peer with `--lan-exclude <your LAN>`, and accept that the excluded prefix is unprotected |
| DNS resolves outside the tunnel | the client ignored or lost the `DNS` line (routers, mostly). Point the device's resolver at `10.66.0.1` |
| a device that was fine is refused after a clock jump | its handshake timestamps went backwards. `warren-burrow reset-peer <label>` clears that guard for one peer |
| every peer goes quiet after a gateway restart | sessions do not survive a restart. A peer with traffic to send rebuilds in about 15 seconds, an idle one within a rekey interval (two minutes) |
