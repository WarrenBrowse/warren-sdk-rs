/// Warren SDK, Dart/Flutter binding.
///
/// This is the public entrypoint of the binding. The actual API is generated
/// from the Rust `warren-sdk-ffi` surface by `tool/generate.sh` (uniffi) into
/// `lib/src/generated/`; this file re-exports it and centralizes loading the
/// native library, so an app imports only `package:warren_sdk/warren_sdk.dart`.
///
/// STATUS: scaffold. The generated bindings are produced by the tool above and
/// are NOT checked in. Building and validating the binding needs a Dart/Flutter
/// toolchain, so it is completed and exercised outside the SDK dev sandbox.
///
/// Like every sibling-language SDK, this binding MUST replay the shared golden
/// vectors in the repo's `vectors/` directory (identity/SS58/signing, the
/// multihop frame, the control `/v2` messages, the handshake including the
/// `daita_spec` `f64` caps) to prove byte-for-byte wire compatibility. See
/// `test/` for the harness stub.
library warren_sdk;

// Once generated, the binding re-exports the uniffi surface, for example:
//   export 'src/generated/warren_sdk_ffi.dart';
//
// The generated code loads the native library by name; bundle the per-OS
// artifact (libwarren_sdk_ffi.so / .dylib / .dll) with the app. On Flutter,
// place it under the platform runner's library path (jniLibs on Android, the
// Frameworks/embedded dylib on iOS/macOS) so the dynamic loader finds it.
//
// The exported async surface mirrors the Rust facade (see
// `crates/warren-sdk-ffi/src/lib.rs`):
//   - WarrenFfiClient: new / withMultihopRoots / withPersistence / withOptions
//     (FfiClientOptions { multihopRootPubkeyPins, stateDir, daita, daitaMachine })
//   - subscriptionExpiry, redeemVoucher, fetchMultihopExits
//   - startProxy / startProxySupervised / startProxySupervisedFailover, each
//     taking an optional FfiProxyOptions { httpListen, dnsServer }
//   - WarrenFfiProxy / WarrenFfiSupervisedProxy / WarrenFfiForwardedPort
//   - the pure identity helpers: generateIdentity, identityFromMnemonic,
//     addressFromMnemonic, ss58Encode / ss58Decode, signRequest
