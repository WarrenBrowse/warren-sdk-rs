#!/usr/bin/env bash
# Generates the Dart bindings for warren-sdk-ffi from the built cdylib.
#
# Prerequisites: a Dart SDK and uniffi-bindgen-dart (install with
#   cargo install uniffi-bindgen-dart
# whose version supports the `uniffi` crate in crates/warren-sdk-ffi/Cargo.toml).
#
# KNOWN GENERATOR DEFECTS (tested with 0.1.3 against uniffi 0.31, see README):
# this script applies post-process patches for the static codegen bugs. As of
# 0.1.3 the bindings still CRASH at the FFI boundary (ABI-incompatible RustBuffer
# marshaling), so the patches make the package analyze cleanly but a working
# binding needs a fixed generator (or flutter_rust_bridge). The patches are
# idempotent and harmless once upstream fixes land.
#
# This script is the single source of truth for HOW the binding is produced; it
# is intentionally explicit so the result is reproducible.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$(cd "$(dirname "$0")/.." && pwd)/lib/src/generated"
GEN="$OUT/warren_sdk_ffi.dart"
mkdir -p "$OUT"

# 1. Build the release cdylib (per-OS artifact name differs).
( cd "$ROOT" && cargo build -p warren-sdk-ffi --release )

case "$(uname -s)" in
  Linux)  LIB="$ROOT/target/release/libwarren_sdk_ffi.so" ;;
  Darwin) LIB="$ROOT/target/release/libwarren_sdk_ffi.dylib" ;;
  *)      LIB="$ROOT/target/release/warren_sdk_ffi.dll" ;;
esac

# 2. Generate the Dart bindings. `--crate warren_sdk_ffi` fixes the double-prefixed
#    `ffi_*` symbol family (defect 3a).
uniffi-bindgen-dart generate --crate warren_sdk_ffi --out-dir "$OUT" "$LIB"

# 3. Post-process the remaining known codegen defects (no-ops once fixed upstream):
#    - defect 2:  is_tunnel_active returns int where Future<bool> is expected.
#    - defect 3b: the function symbol family carries a bogus `ffibuffer_` infix.
python3 - "$GEN" <<'PY'
import sys, re
p = sys.argv[1]; s = open(p).read()
s = re.sub(r"(IsTunnelActiveFfiBufferRustFutureComplete\(futureHandle, outStatusPtr\);.*?)return resultValue;",
           r"\1return resultValue != 0;", s, count=1, flags=re.S)
s = s.replace("uniffi_ffibuffer_warren_sdk_ffi", "uniffi_warren_sdk_ffi")
open(p, "w").write(s)
PY

echo "Generated Dart bindings into $OUT (with known-defect patches applied)."
echo "Bundle $LIB with the app and load it via lib/warren_sdk.dart."
