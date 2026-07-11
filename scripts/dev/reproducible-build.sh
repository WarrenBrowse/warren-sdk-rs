#!/usr/bin/env bash
# Reproducible, path-leak-free release build for the Warren SDK.
#
# Strips absolute build paths (the builder's $HOME, $CARGO_HOME registry cache,
# and the absolute workspace path) out of panic strings and debug info via the
# STABLE `--remap-path-prefix` rustc flag, and pins SOURCE_DATE_EPOCH so the
# build is bit-reproducible. This is the stable-toolchain stand-in for
# `profile.trim-paths = "all"`, which is NOT yet stabilized on the pinned
# rust-toolchain (1.89); switch to the profile key once the pin reaches 1.90.
#
# Usage: scripts/dev/reproducible-build.sh [extra cargo build args...]
#   e.g. scripts/dev/reproducible-build.sh -p warren-sdk-ffi
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# Remap, most specific first. `to` targets are stable placeholders so two
# machines with different homes/checkout paths produce identical output.
remap=(
  "--remap-path-prefix=${cargo_home}=/cargo"
  "--remap-path-prefix=${repo_root}=/warren-sdk-rs"
  "--remap-path-prefix=${HOME}=/home"
)

# Deterministic timestamp: honour an externally pinned value, else the last
# commit time, so buildinfo's SOURCE_DATE_EPOCH path is fed a stable input.
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$repo_root" log -1 --pretty=%ct)"
fi
export SOURCE_DATE_EPOCH

RUSTFLAGS="${RUSTFLAGS:-} ${remap[*]}" \
  cargo build --release --locked "$@"
