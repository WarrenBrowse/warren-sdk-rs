# warren_sdk (Dart/Flutter binding)

The Dart/Flutter binding for the Warren VPN client SDK. It wraps the
uniffi-generated bindings over the `warren-sdk-ffi` cdylib, so a Dart/Flutter app
reaches the same client surface as the Rust facade (identity, account API, exit
discovery, the sealed multihop proxy datapath, port forwarding, the supervised
self-healing proxy, and the DAITA uplink defense).

## Status

PARTIAL, with the pure surface WORKING and validated.

- The entire DETERMINISTIC, server-free surface is bound by a small hand-written
  FFI (`lib/src/identity.dart`) and is PROVEN against the real cdylib by
  `dart test` (`test/vectors_test.dart`, all green): `ss58Encode`/`ss58Decode`/
  `addressFromMnemonic` (replaying `vectors/identity.json` byte-for-byte),
  `generateIdentity` (a record return), and `signRequest` (a multi-argument
  `Result<FfiSignedHeaders>`). This exercises the full uniffi-0.31 String/record/
  u64/Result marshaling ABI by hand, so the cross-language wire-compat contract is
  satisfied on the Dart side for every deterministic call.
- The async + object ABI is ALSO proven by hand: `WarrenFfiClientFfi.create`
  (the uniffi object constructor), `subscriptionExpiry()` (an async method driven
  through the RustFuture poll/complete/free protocol with a `NativeCallable`
  continuation), and `startProxy()` (an async OBJECT-returning method with
  `Option<RustBuffer>` arguments). `dart test` validates each via the error path
  (an unroutable host, no live server), exactly like the Rust FFI tests. So EVERY
  uniffi-0.31 ABI shape works from Dart: String, record, multi-arg `Result`,
  object, async future, and async object-returning method with optional args.
- The ONE shape not bound is the `ConnectionObserver` CALLBACK INTERFACE (the
  optional `observer` of `start_proxy*`). This is a FUNDAMENTAL Dart/uniffi
  limitation, not missing effort: a uniffi callback method is invoked
  SYNCHRONOUSLY from a Rust thread (here a tokio worker during the async dial) and
  must set its out-status before returning, but Dart's FFI cannot service a
  synchronous callback from a non-isolate thread (only `NativeCallable.listener`,
  which is asynchronous, works cross-thread). This is exactly why
  `uniffi-bindgen-dart` itself SKIPS `start_proxy*` ("unsupported signature"). The
  observer-less `startProxy` above is bound and tested; reporting connection-state
  events to Dart needs a different mechanism (poll a state-watch method, or
  `flutter_rust_bridge`'s stream model) rather than a uniffi callback interface.
- Server happy paths (`subscriptionExpiry` value, `fetchMultihopExits`,
  `redeemVoucher` success) need a live API/exit to exercise, which the headless
  dev sandbox lacks; the error paths above already prove the binding mechanics.

The native library is built by `cargo build -p warren-sdk-ffi --release`. The
hand-written layer needs only a Dart SDK (no Flutter); the full surface needs a
correct generator (or `flutter_rust_bridge`) plus a device for end-to-end
validation against a real exit.

## How it is generated

```sh
# From this directory, with a Dart SDK and uniffi-bindgen-dart installed:
./tool/generate.sh
```

That script builds the release cdylib (`cargo build -p warren-sdk-ffi --release`)
and runs `uniffi-bindgen-dart` against it, writing the Dart surface into
`lib/src/generated/`. `lib/warren_sdk.dart` re-exports it and centralizes loading
the native library.

### Generator status (empirically tested 2026-06-16)

`warren-sdk-ffi` uses **uniffi 0.31**, and `uniffi-bindgen-dart` 0.1.3 builds
against `uniffi_bindgen ^0.31`, so the versions match and it DOES generate.
However, running it against the built cdylib surfaced a chain of generator
defects that make 0.1.3 unusable for this surface as-is:

1. It skips the three `start_proxy*` methods ("unsupported signature": the async +
   `ConnectionObserver` callback-interface form). The proxy lifecycle is then
   unreachable from Dart.
2. `is_tunnel_active` is generated with an `int` return where `Future<bool>` is
   expected (one analyzer error).
3. Two symbol-namespace defects: the `ffi_*` family is double-prefixed
   (`ffi_uniffi_warren_sdk_ffi_*`, fixed by passing `--crate warren_sdk_ffi`), and
   the function family carries a bogus `ffibuffer_` infix
   (`uniffi_ffibuffer_warren_sdk_ffi_fn_func_*` vs the real
   `uniffi_warren_sdk_ffi_fn_func_*`).
4. After patching 1-3, the package analyzes clean (`No issues found!`) but the
   FIRST native call CRASHES inside the Rust function
   (`uniffi_warren_sdk_ffi_fn_func_ss58_encode+0x84`): the argument marshaling
   (`RustBuffer` lowering) is ABI-incompatible.

So 0.1.3 cannot produce a working binding for warren-sdk-ffi today. The scaffold,
the generation script, and `test/vectors_test.dart` (a real golden-vector replay
over the cdylib) are correct and ready; they pass once a generator emits
ABI-correct glue. Two ways forward, both needing a Dart toolchain to finish:

1. A fixed/newer uniffi-0.31-compatible Dart generator (re-run `tool/generate.sh`,
   which applies the documented patches for the known codegen bugs), or
2. Switch this binding to `flutter_rust_bridge` (its own codegen, no dependence on
   the uniffi metadata ABI).

Do NOT commit the bindings 0.1.3 produces: they analyze but crash at the FFI
boundary.

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
