#!/usr/bin/env bash
#
# Anti-refragmentation gate for warren-sdk-rs.
#
# Turns the manual doc-94 single-home audit
# (warren-core/docs/94-DEDUP-AUDIT-2026-07-16.md, the catalog) into an automated
# tripwire so a responsibility that was single-homed cannot silently regrow a
# second home in this repo. It is the runnable form of doc 47 section 5 invariant
# 6 ("un seul foyer") at file granularity, complementing the crate-level
# warren-core `single_home.rs` / `engine_direction.rs` conformance tests.
#
# Design goals: cheap (grep + one offline `cargo metadata --no-deps`), offline,
# and low-false-positive. Each rule bans a resurrected TWIN DEFINITION while
# allowing re-exports and calls of the single home, excludes test code, cites its
# doc-94 item on failure, and honors an inline `anti-refrag:allow` escape hatch.
#
# Prove a rule bites by reintroducing its twin (a fresh `fn resolve_fallback_policy`,
# a `src/idle_cover.rs`), running this, and watching it fail; then remove it.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

VIOLATIONS=0

report() {
  # $1 doc-94 ref, $2 message, $3 evidence
  VIOLATIONS=$((VIOLATIONS + 1))
  printf '\n[anti-refrag] VIOLATION (%s): %s\n' "$1" "$2"
  printf '%s\n' "$3" | sed 's/^/    /'
}

# Fail if <file> exists: a source module that was deleted when its responsibility
# moved to its single home must not reappear.
forbid_file() {
  doc="$1"; msg="$2"; file="$3"
  if [ -e "$REPO_ROOT/$file" ]; then
    report "$doc" "$msg" "$file exists (must stay deleted)"
  fi
}

# Fail if <regex> matches production Rust (definition-level bans; re-exports and
# calls do not match a `fn NAME` / module regex). Test code and the escape hatch
# are excluded.
forbid_rs() {
  doc="$1"; msg="$2"; regex="$3"; shift 3
  out="$(grep -REn --include='*.rs' \
        --exclude-dir=target --exclude-dir=tests \
        --exclude='tests.rs' --exclude='*_test.rs' \
        "$regex" "$@" 2>/dev/null | grep -v 'anti-refrag:allow' || true)"
  [ -n "$out" ] && report "$doc" "$msg" "$out"
}

# Fail if <regex> is ABSENT from <paths>: a positive anchor for a delegation that
# a hand-rolled twin would replace.
require_rs() {
  doc="$1"; msg="$2"; regex="$3"; shift 3
  if ! grep -REq --include='*.rs' --exclude-dir=target "$regex" "$@" 2>/dev/null; then
    report "$doc" "$msg" "expected delegation \`$regex\` not found in: $*"
  fi
}

# Dependency direction via cargo metadata (doc 47 section 5 invariant 1): no
# dependency of this workspace may resolve into a forbidden repo (path dep) or a
# forbidden source (git dep). `--no-deps` is offline; we grep the JSON, so no
# JSON tooling is required. Skips (fail-open) if cargo is unavailable.
forbid_dep_direction() {
  doc="$1"; forbidden="$2"
  command -v cargo >/dev/null 2>&1 || { printf '[anti-refrag] cargo absent, skipping dep-direction\n'; return 0; }
  meta="$(cargo metadata --no-deps --format-version 1 2>/dev/null)" || {
    printf '[anti-refrag] cargo metadata failed, skipping dep-direction\n'; return 0; }
  hits="$(printf '%s' "$meta" | grep -oE '"(path|source)":[[:space:]]*"[^"]*"' \
          | grep -E "$forbidden" || true)"
  [ -n "$hits" ] && report "$doc" \
    "dependency direction: the SDK must not depend up into the backend/app (doc 47 s5.1)" \
    "$hits"
}

printf '[anti-refrag] warren-sdk-rs: scanning for regrown single-home twins...\n'

# ---- Rules (each cites its doc-94 item) --------------------------------------

# A3: the SDK idle-cover twin was deleted; the single home is
# `warrenguard-pump::idle_cover`, re-exported by warren-transport.
forbid_file "doc94 A3" \
  "SDK idle-cover twin resurrected (home: warrenguard-pump::idle_cover)" \
  "crates/warren-transport/src/idle_cover.rs"

# A2: the userland client transport profile is single-homed in
# warrenguard-transport-core; the SDK must delegate, never re-declare it.
require_rs "doc94 A2" \
  "SDK client transport profile must delegate to the engine, not re-declare it" \
  "warrenguard_transport_core::warren_transport_config_client" \
  "crates/warren-transport/src/client.rs"

# A9: TCP-fallback policy + UDP-vs-TCP race are single-homed in
# warrenguard-tcp-fallback; the SDK re-exports/calls `resolve_fallback_policy`,
# it must not define its own.
forbid_rs "doc94 A9" \
  "SDK re-defines resolve_fallback_policy (home: warrenguard-tcp-fallback)" \
  'fn[[:space:]]+resolve_fallback_policy' \
  "crates"

# Task 79: the client entry-RTT store (EWMA cache + endpoint keying) is
# single-homed in warren-discovery-core next to the path-aware selector; the
# SDK re-exports it (`warren_discovery::RttCache`) and must never re-declare
# its own store.
forbid_rs "doc49 t79" \
  "SDK re-defines the client RTT store (home: warren-discovery-core::RttCache)" \
  'struct[[:space:]]+RttCache' \
  "crates"

# The epoch identity (ExitId, EpochId, EXIT_ID_LEN) has two definitions on
# purpose: warren-net is async and warren-burrow-core opens no socket, so the
# gateway core cannot depend on it. What must not happen is the two drifting,
# because the gateway device implements warren-net's per-epoch trait with
# warren-burrow-core's type and the conversion between them is by field. Pin the
# one thing whose divergence would be silent.
for epoch_home in "crates/warren-net/src/device.rs" "crates/warren-burrow-core/src/nat.rs"; do
  require_rs "design L/M" \
    "the epoch identifier length must stay identical in both homes" \
    'pub const EXIT_ID_LEN: usize = 16;' \
    "$epoch_home"
  require_rs "design L/M" \
    "both epoch homes must keep the same ExitId shape (UNKNOWN, from_bytes, as_bytes)" \
    'pub const fn from_bytes\(bytes: \[u8; EXIT_ID_LEN\]\) -> Self' \
    "$epoch_home"
done

# boringtun's `HalfHandshake`, `Packet` and `TunnResult` derive Debug, and what
# they render is a peer's static public key or a decrypted packet. No-log
# discipline forbids either reaching a log, so no production line of a file that
# holds one of those values may format anything with `{:?}`: the rule is on the
# file rather than on the type, because a grep cannot tell what a binding holds.
# Inline `#[cfg(test)]` modules are cut off first (a test panic that renders a
# TunnResult reaches no log), and `anti-refrag:allow` remains the escape hatch.
forbid_debug_where_boringtun_lives() {
  doc="$1"
  for file in $(grep -rl 'boringtun' crates/warren-burrow-core/src crates/warren-burrow/src 2>/dev/null); do
    cut="$(grep -n '#\[cfg(test)\]' "$file" | head -1 | cut -d: -f1)"
    [ -n "$cut" ] || cut=999999
    out="$(head -n "$((cut - 1))" "$file" \
          | grep -nE '\{[A-Za-z_.]*:#?\?\}' \
          | grep -v 'anti-refrag:allow' || true)"
    [ -n "$out" ] && report "$doc" \
      "Debug formatting in $file, which holds boringtun values (a key or a decrypted packet)" \
      "$out"
  done
}

forbid_debug_where_boringtun_lives "design E"

# Dependency direction: the client SDK never depends on the private backend
# (warren-core) or the app (warren-app / mullvad-*). warrenguard + warren-contract
# siblings are allowed.
forbid_dep_direction "doc94 s48" 'warren-core|warren-app|/mullvad-|[/+]mullvad-'

# -----------------------------------------------------------------------------

if [ "$VIOLATIONS" -gt 0 ]; then
  printf '\n[anti-refrag] FAILED: %d single-home violation(s). Extend the single home, do not re-home here.\n' "$VIOLATIONS"
  exit 1
fi
printf '[anti-refrag] OK: no regrown twins.\n'
