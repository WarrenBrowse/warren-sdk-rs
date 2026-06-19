#!/usr/bin/env bash
#
# cargo-test-nofw - wrapper qui désactive temporairement l'Application
# Firewall macOS pendant un cargo test/run/bench, pour éviter les popups
# récurrents à chaque nouveau hash de binaire compilé par cargo.
#
# Désactive les 3 modes du Application Firewall macOS :
#   - --setglobalstate     : firewall actif/inactif global
#   - --setblockall        : "block all incoming" mode strict
#   - --setstealthmode     : ne répond pas aux pings
# Tous les 3 sont restaurés dans leur état initial via `trap` à la fin,
# y compris en cas de Ctrl-C, panic, ou de kill du wrapper.
#
# Usage :
#   ./scripts/dev/cargo-test-nofw.sh test --workspace
#   ./scripts/dev/cargo-test-nofw.sh test -p warren-tunnel --test bench --release -- --ignored
#   ./scripts/dev/cargo-test-nofw.sh run -p warren-exit -- --use-tun ...
#
# Hint : `alias nofw='./scripts/dev/cargo-test-nofw.sh'` dans ton ~/.zshrc.
#
# Sur Linux, transparent passthrough vers cargo.

set -euo pipefail

# ---------------------------------------------------------------------------
# Linux / non-macOS : passthrough.
# ---------------------------------------------------------------------------
if [[ "$(uname)" != "Darwin" ]]; then
    exec cargo "$@"
fi

FW_BIN=/usr/libexec/ApplicationFirewall/socketfilterfw

# ---------------------------------------------------------------------------
# Vérifier que sudo peut appeler `socketfilterfw` sans password.
#
# Idéalement, le user a configuré `/etc/sudoers.d/warren-firewall` avec
# NOPASSWD pour socketfilterfw uniquement (cf. scripts/README.md). Dans
# ce cas, `sudo -n socketfilterfw --getglobalstate` passe immédiatement.
#
# `sudo -v` (validation générique des creds) demande un password même
# avec un NOPASSWD scopé - donc on l'évite et on teste directement la
# commande visée.
# ---------------------------------------------------------------------------
if ! sudo -n "$FW_BIN" --getglobalstate >/dev/null 2>&1; then
    echo "==> sudo password required for socketfilterfw" >&2
    echo "==> Configure NOPASSWD pour éviter ce prompt (cf. scripts/README.md)" >&2
    sudo -v
fi

# ---------------------------------------------------------------------------
# Capturer l'état initial des 3 modes du firewall.
# Sortie typique :
#   "Firewall is enabled. (State = 1)"
#   "Firewall has block all state set to disabled."
#   "Stealth mode disabled"
# ---------------------------------------------------------------------------
state_was() {
    local query="$1"
    local pattern="$2"
    sudo "$FW_BIN" "$query" 2>/dev/null | grep -qiE "$pattern"
}

GLOBAL_WAS_ON=0
state_was --getglobalstate 'enabled' && GLOBAL_WAS_ON=1

BLOCKALL_WAS_ON=0
state_was --getblockall 'set to enabled' && BLOCKALL_WAS_ON=1

STEALTH_WAS_ON=0
state_was --getstealthmode '^stealth mode enabled' && STEALTH_WAS_ON=1

# ---------------------------------------------------------------------------
# Restauration via trap. Toujours best-effort : on log mais on ne fail pas
# si une commande de restauration échoue (l'utilisateur peut toujours la
# relancer manuellement).
# ---------------------------------------------------------------------------
restore_firewall() {
    local exit_code=$?
    if [[ "$GLOBAL_WAS_ON" == "1" ]]; then
        echo "==> Restoring firewall global state (was: enabled)" >&2
        sudo "$FW_BIN" --setglobalstate on >/dev/null 2>&1 || true
    fi
    if [[ "$BLOCKALL_WAS_ON" == "1" ]]; then
        echo "==> Restoring firewall block-all (was: enabled)" >&2
        sudo "$FW_BIN" --setblockall on >/dev/null 2>&1 || true
    fi
    if [[ "$STEALTH_WAS_ON" == "1" ]]; then
        echo "==> Restoring firewall stealth mode (was: enabled)" >&2
        sudo "$FW_BIN" --setstealthmode on >/dev/null 2>&1 || true
    fi

    # **M3.J round 9 - kill orphan test binaries.** Les helpers
    # `accept_one_handshake_for_test` peuvent stuck (avant le fix timeout
    # 30 s) si le client ne se connecte jamais. Sous `cargo test --workspace`,
    # plusieurs ExitListener acceptent en parallèle sur des ports random
    # → contention localhost UDP/TCP → certains binaires test boucle à
    # ~90 % CPU des heures durant. Découvert en M3.J : 3 process
    # regressions_m3e à ~90 % CPU pendant 9 h. On nettoie best-effort si
    # ce wrapper est tué (Ctrl-C, timeout, kill du shell parent) sans que
    # cargo ait reap ses enfants.
    local orphans
    orphans=$(pgrep -f "$REPO_ROOT/target/(debug|release|profiling)/deps/(regressions_|multi_conn|pump-|e2e_|exit_|coverage_)" 2>/dev/null || true)
    if [[ -n "$orphans" ]]; then
        echo "==> Killing orphan test binaries: $(echo "$orphans" | tr '\n' ' ')" >&2
        kill -9 $orphans 2>/dev/null || true
    fi

    exit $exit_code
}
trap restore_firewall EXIT INT TERM

# Capture le repo root pour le nettoyage des orphans (au cas où le cwd
# change pendant l'exécution ou le wrapper est lancé depuis un sous-dir).
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Désactiver les 3 modes pendant l'exécution.
# ---------------------------------------------------------------------------
if [[ "$GLOBAL_WAS_ON" == "1" ]]; then
    echo "==> Disabling firewall global state" >&2
    sudo "$FW_BIN" --setglobalstate off >/dev/null
fi
if [[ "$BLOCKALL_WAS_ON" == "1" ]]; then
    echo "==> Disabling firewall block-all" >&2
    sudo "$FW_BIN" --setblockall off >/dev/null
fi
if [[ "$STEALTH_WAS_ON" == "1" ]]; then
    echo "==> Disabling firewall stealth mode" >&2
    sudo "$FW_BIN" --setstealthmode off >/dev/null
fi

# ---------------------------------------------------------------------------
# Lance cargo avec les args passés. `exec` n'est *pas* utilisé ici parce
# qu'on a besoin du `trap` pour restaurer le firewall après.
# ---------------------------------------------------------------------------
cargo "$@"
