#!/usr/bin/env bash
# Generates the Dart bindings for warren-sdk-ffi from the built cdylib.
#
# Prerequisites (NOT runnable from the SDK dev sandbox; needs a Dart/Flutter
# toolchain): a Dart SDK, and uniffi-bindgen-dart
# (https://github.com/NiallBunting/uniffi-rs-dart or the actively maintained
# fork; pin the exact version that matches the uniffi crate in warren-sdk-ffi).
#
# This script is the single source of truth for HOW the binding is produced; it
# is intentionally explicit so the result is reproducible and the generated code
# never drifts from the Rust surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$(cd "$(dirname "$0")/.." && pwd)/lib/src/generated"
mkdir -p "$OUT"

# 1. Build the release cdylib (per-OS artifact name differs).
( cd "$ROOT" && cargo build -p warren-sdk-ffi --release )

case "$(uname -s)" in
  Linux)  LIB="$ROOT/target/release/libwarren_sdk_ffi.so" ;;
  Darwin) LIB="$ROOT/target/release/libwarren_sdk_ffi.dylib" ;;
  *)      LIB="$ROOT/target/release/warren_sdk_ffi.dll" ;;
esac

# 2. Generate the Dart bindings from the library metadata.
uniffi-bindgen-dart generate --library "$LIB" --out-dir "$OUT"

echo "Generated Dart bindings into $OUT"
echo "Bundle $LIB with the app and load it via lib/warren_sdk.dart."
