/// Warren SDK, Dart/Flutter binding.
///
/// Two layers:
///
///  - `src/identity.dart` (exported below): a small, WORKING hand-written FFI for
///    the pure identity surface (ss58 encode/decode, address-from-mnemonic),
///    validated by the golden-vector test in `test/`. It exists because the
///    current `uniffi-bindgen-dart` (0.1.3) output crashes at the FFI boundary
///    (see README.md), so the pure surface is bound by hand until a correct
///    generator (or `flutter_rust_bridge`) is in place.
///  - the full async surface (client construction, the account/discovery calls,
///    the proxy lifecycle, DAITA, port forwarding) comes from the GENERATED
///    bindings produced by `tool/generate.sh` into `src/generated/`; that file is
///    re-exported here once it is generated with a correct generator.
///
/// Bundle the per-OS native artifact (libwarren_sdk_ffi.so / .dylib / .dll) with
/// the app so the dynamic loader finds it.
library warren_sdk;

export 'src/identity.dart';

// Once a correct generator emits `src/generated/warren_sdk_ffi.dart`, add:
//   export 'src/generated/warren_sdk_ffi.dart';
