# warren_sdk (Dart/Flutter binding)

The Dart/Flutter binding for the Warren VPN client SDK. It wraps the
uniffi-generated bindings over the `warren-sdk-ffi` cdylib, so a Dart/Flutter app
reaches the same client surface as the Rust facade (identity, account API, exit
discovery, the sealed multihop proxy datapath, port forwarding, the supervised
self-healing proxy, and the DAITA uplink defense).

## Status

SCAFFOLD. This package lays down the structure, the generation script, and the
golden-vector replay obligation. The generated bindings and the native library
are produced by `tool/generate.sh`; they are not checked in. Building and
validating the binding requires a Dart/Flutter toolchain and a device, so it is
completed and exercised outside the SDK's headless dev sandbox. Nothing here may
be claimed to work end to end until it has run against a real exit on a device.

## How it is generated

```sh
# From this directory, with a Dart SDK and uniffi-bindgen-dart installed:
./tool/generate.sh
```

That script builds the release cdylib (`cargo build -p warren-sdk-ffi --release`)
and runs `uniffi-bindgen-dart` against it, writing the Dart surface into
`lib/src/generated/`. `lib/warren_sdk.dart` re-exports it and centralizes loading
the native library. Pin the `uniffi-bindgen-dart` version to the one matching the
`uniffi` crate version in `crates/warren-sdk-ffi/Cargo.toml`; a mismatch produces
ABI-incompatible glue.

## Bundling the native library

Ship the per-OS artifact next to the app so the dynamic loader finds it:

| Platform | Artifact | Location |
|---|---|---|
| Android | `libwarren_sdk_ffi.so` | `android/app/src/main/jniLibs/<abi>/` |
| iOS / macOS | `libwarren_sdk_ffi.dylib` | embedded Frameworks (code-signed) |
| Linux | `libwarren_sdk_ffi.so` | bundled lib dir / `LD_LIBRARY_PATH` |
| Windows | `warren_sdk_ffi.dll` | next to the executable |

Build the cdylib for each target triple you ship (`cargo build -p
warren-sdk-ffi --release --target <triple>`).

## API surface

The generated classes mirror `crates/warren-sdk-ffi/src/lib.rs` one-to-one
(async methods become Dart `Future`s):

- `WarrenFfiClient`: `new`, `withMultihopRoots`, `withPersistence`, and
  `withOptions(FfiClientOptions { multihopRootPubkeyPins, stateDir, daita,
  daitaMachine })`.
- account / discovery: `subscriptionExpiry`, `redeemVoucher`,
  `fetchMultihopExits`.
- datapath: `startProxy`, `startProxySupervised`,
  `startProxySupervisedFailover`, each taking an optional
  `FfiProxyOptions { httpListen, dnsServer }`; returning `WarrenFfiProxy` /
  `WarrenFfiSupervisedProxy`, with `forwardPort` -> `WarrenFfiForwardedPort`.
- pure identity: `generateIdentity`, `identityFromMnemonic`,
  `addressFromMnemonic`, `ss58Encode` / `ss58Decode`, `signRequest`.

## Wire-compatibility obligation

Like every sibling-language SDK, this binding MUST replay the repo's shared
golden vectors (`vectors/`) so the wire formats stay byte-identical across
languages. `test/vectors_test.dart` is the Dart side of that contract; enable it
once the bindings are generated.
