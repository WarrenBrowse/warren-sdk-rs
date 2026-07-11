#!/usr/bin/env bash
# CI gate: fail if a shipped binary embeds a builder-home absolute path.
#
# A privacy binary must not leak where it was built (Mullvad "absolute paths that
# leak into binaries" flag). Pair with reproducible-build.sh, which remaps those
# paths out; this gate proves the remap actually took. Greps each given artifact
# for the builder's $HOME and $CARGO_HOME prefixes.
#
# Usage: scripts/dev/check-no-abspath.sh <binary> [<binary>...]
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <binary> [<binary>...]" >&2
  exit 2
fi

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
# Match the machine-specific roots that must never survive into an artifact.
needles=("$HOME/" "$cargo_home/")

status=0
for bin in "$@"; do
  if [[ ! -f "$bin" ]]; then
    echo "MISSING: $bin" >&2
    status=1
    continue
  fi
  for needle in "${needles[@]}"; do
    if strings -a "$bin" | grep -qF "$needle"; then
      echo "LEAK: $bin contains absolute path prefix '$needle'" >&2
      status=1
    fi
  done
  [[ $status -eq 0 ]] && echo "OK: $bin (no builder-home path)"
done

exit $status
