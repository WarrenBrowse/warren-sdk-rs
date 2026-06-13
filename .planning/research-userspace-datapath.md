# Recherche: datapath userspace non-root multi-OS (P6)

Synthèse de la recherche approfondie (2025-2026) qui guide `warren-net`.

## Décisions clés

1. **Deux backends derrière une même couture (`Inbound` seam, modele leaf/sing-box).**
   - **Mode non-root (defaut): proxy local SOCKS5 + HTTP CONNECT.** Un serveur
     local termine les flux L4 de l'app et reinjecte les payloads dans le tunnel
     QUIC. **Insight majeur: ce mode n'a PAS besoin de netstack** (le serveur
     SOCKS/HTTP fournit deja des flux L4 termines). smoltcp ne sert qu'au TUN.
   - **Mode privilegie (optionnel): TUN.** Device TUN alimente par un netstack
     userspace (smoltcp) qui reconstruit les flux L4 a partir des paquets IP.
2. **Donnees = QUIC DATAGRAMs (RFC 9221); un stream QUIC pour le controle/auth.**
   Modele MASQUE (RFC 9298 CONNECT-UDP, RFC 9484 CONNECT-IP). Evite le TCP-over-TCP.
3. **Crates retenues:** `quinn` 0.11, `fast-socks5` 1.0 (CONNECT + UDP ASSOCIATE),
   HTTP CONNECT a la main via `hyper`/`hyper-util` (`upgrade::on` +
   `copy_bidirectional`), `tun-rs` 2.8 (TUN tous OS + GSO/GRO Linux),
   `smoltcp` 0.13 via un fork maintenu de `netstack-smoltcp` (mode TUN),
   killswitch: `nftables`/`rustables` (Linux), `pfctl-rs` (macOS), `windows-wfp` (Windows).

## Realite du non-root par OS

| OS | TUN create exige | TUN non-root ? | Mode proxy non-root ? |
|---|---|---|---|
| Linux | CAP_NET_ADMIN | OUI (setcap ou device pre-cree) | OUI |
| macOS | root OU entitlement Network Extension | NON | OUI |
| Windows | Administrateur | NON | OUI |

Garantie SDK: **un mode non-root feature-complete existe partout via le backend
proxy.** Un mode TUN non-root n'existe que sur Linux.

## Killswitch / anti-fuite

- **Mode proxy (non-root):** pas de killswitch OS reel sans privilege. Fuites par
  defaut: apps non configurees, composants qui bypassent le proxy, DNS systeme,
  IPv6, WebRTC/STUN, fenetre pre-tunnel. Mitigations best-effort: listener ouvert
  seulement quand le tunnel est up (fail-closed par app), **DNS distant force**
  (`socks5h` ou resolveur local sur QUIC) pour tuer les fuites DNS, rejet sur echec
  upstream. Documenter les fuites residuelles honnetement.
- **Mode TUN (privilegie):** vrai killswitch default-drop atomique (nftables/pf/WFP),
  applique avant la montee du tunnel (modele Mullvad/WireGuard). IPv6 + DNS inclus.
- Exposer un `KillSwitchLevel` (OsEnforced | BestEffortProxy) jusqu'a l'UI/FFI.

## Architecture warren-net (cible)

```
tunnel/   (PUR, testable sans privilege) quic.rs datagram.rs control.rs mtu.rs
inbound/  socks5.rs http_connect.rs  tun/{device.rs, netstack.rs} [cfg tun]
outbound/ router.rs  (partage par tous les inbounds -> tunnel QUIC)
dns/      resolveur distant sur le tunnel (no-leak)
killswitch/ linux.rs macos.rs windows.rs proxy_only.rs  [cfg killswitch]
platform/ linux.rs macos.rs windows.rs  (routing + DNS)  [cfg per-OS]
```

Traits cles: `Inbound::accept() -> Flow` (Tcp/Udp + Target Ip|Domain),
`Outbound::dispatch(Flow)`, `PacketSink` (mode TUN: send/recv inner packet +
max_payload suivant quinn max_datagram_size/PMTU), `KillSwitch::engage/disengage`
+ `guarantees() -> KillSwitchLevel`.

## FFI / portabilite

- **Coeur Rust-only (via FFI):** QUIC (quinn), TLS/crypto, framing datagram,
  netstack (smoltcp), TUN I/O, firewall/routing OS. Reimplementer QUIC+netstack
  par langage est infaisable.
- **Reimplementable par langage (couche fine):** API connect/disconnect/status,
  config, stockage credentials, etat UI, logs. Surface FFI minuscule.
- **Toolchain:** `uniffi` (Swift/Kotlin/Python), `flutter_rust_bridge` 2.x (Dart,
  PAS le generateur Dart de uniffi), `napi-rs` ou wasm (TS). TS WASM ne peut pas
  faire TUN/UDP brut/firewall.

## Points de vigilance

- `netstack-smoltcp` repo d'origine archive: epingler un fork maintenu.
- smoltcp: pas d'async natif (boucle poll), pas de SACK -> plafond debit moindre
  sous perte/RTT. Batching GSO/GRO + sendmmsg cote quinn des le depart.
- `tokio-socks` (client-only) advisory RUSTSEC-2024-0334: non concerne si fast-socks5.
