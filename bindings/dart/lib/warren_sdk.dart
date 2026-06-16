/// Warren SDK, Dart/Flutter binding.
///
/// The public entrypoint. The API is generated from the Rust `warren-sdk-ffi`
/// surface by `tool/generate.sh` (uniffi-bindgen-dart) into `lib/src/generated/`
/// (not checked in); this file re-exports it, so an app imports only
/// `package:warren_sdk/warren_sdk.dart`.
///
/// The generated code loads the native library by name; bundle the per-OS
/// artifact (libwarren_sdk_ffi.so / .dylib / .dll) with the app (jniLibs on
/// Android, the embedded Frameworks dylib on iOS/macOS) so the dynamic loader
/// finds it.
///
/// KNOWN GENERATOR LIMITATION: uniffi-bindgen-dart 0.1.3 skips the three
/// `start_proxy*` methods (their async + `ConnectionObserver` callback-interface
/// signature is unsupported by that generator), so the proxy LIFECYCLE is not
/// yet reachable from Dart. Everything else generates: client construction
/// (including `withOptions` / DAITA), the account/discovery calls, and the pure
/// identity helpers. Resolve by tracking the generator upstream or adding an
/// observer-free proxy-start method for the Dart surface.
///
/// Like every sibling-language SDK, this binding MUST replay the shared golden
/// vectors in the repo's `vectors/` directory to prove byte-for-byte wire
/// compatibility. See `test/` for the harness.
library warren_sdk;

export 'src/generated/warren_sdk_ffi.dart';
