#!/usr/bin/env bash
#
# cargo-test-nofw - wrapper that temporarily disables the macOS Application
# Firewall around a cargo test/run/bench, to avoid the recurring popups on
# every new binary hash compiled by cargo.
#
# It disables the 3 modes of the macOS Application Firewall:
#   - --setglobalstate     : global firewall on/off
#   - --setblockall        : strict "block all incoming" mode
#   - --setstealthmode     : do not reply to pings
# All 3 are restored to their initial state via `trap` on exit, including on
# Ctrl-C, panic, or a kill of the wrapper.
#
# Usage:
#   ./scripts/dev/cargo-test-nofw.sh test --workspace
#   ./scripts/dev/cargo-test-nofw.sh test -p warren-transport --test loopback --release -- --ignored
#   ./scripts/dev/cargo-test-nofw.sh run -p warren-sdk --example ...
#
# Hint: `alias nofw='./scripts/dev/cargo-test-nofw.sh'` in your ~/.zshrc.
#
# On Linux, transparent passthrough to cargo.

set -euo pipefail

# ---------------------------------------------------------------------------
# Linux / non-macOS: passthrough.
# ---------------------------------------------------------------------------
if [[ "$(uname)" != "Darwin" ]]; then
    exec cargo "$@"
fi

FW_BIN=/usr/libexec/ApplicationFirewall/socketfilterfw

# ---------------------------------------------------------------------------
# Check that sudo can call `socketfilterfw` without a password.
#
# Configure `/etc/sudoers.d/warren-firewall` with a NOPASSWD entry scoped to
# socketfilterfw only, so `sudo -n socketfilterfw --getglobalstate` passes
# immediately without a prompt.
#
# `sudo -v` (generic credential validation) prompts for a password even with a
# scoped NOPASSWD entry, so we avoid it and test the target command directly.
# ---------------------------------------------------------------------------
if ! sudo -n "$FW_BIN" --getglobalstate >/dev/null 2>&1; then
    echo "==> sudo password required for socketfilterfw" >&2
    echo "==> Configure a NOPASSWD sudoers entry for socketfilterfw to avoid this prompt" >&2
    sudo -v
fi

# Repo root, captured before the trap so orphan cleanup resolves it even if the
# cwd changes during the run or the wrapper is launched from a sub-directory.
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Capture the initial state of the 3 firewall modes.
# Typical output:
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
# Restore via trap. Always best-effort: log but do not fail if a restore
# command fails (the user can always re-run it manually).
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

    # Kill orphan test binaries. Networking tests spin up userland listeners
    # (loopback, multihop, proxy, netstack sinks) that can keep spinning at high
    # CPU if the wrapper is killed (Ctrl-C, timeout, parent-shell kill) before
    # cargo reaps its children. Scope strictly to this repo's compiled test
    # binaries so we never touch unrelated processes.
    local orphans
    orphans=$(pgrep -f "$REPO_ROOT/target/(debug|release|profiling)/deps/" 2>/dev/null || true)
    if [[ -n "$orphans" ]]; then
        echo "==> Killing orphan test binaries: $(echo "$orphans" | tr '\n' ' ')" >&2
        kill -9 $orphans 2>/dev/null || true
    fi

    exit $exit_code
}
trap restore_firewall EXIT INT TERM

# ---------------------------------------------------------------------------
# Disable the 3 modes for the duration of the run.
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
# Run cargo with the passed args. `exec` is not used here because we need the
# `trap` to restore the firewall afterwards.
# ---------------------------------------------------------------------------
cargo "$@"
