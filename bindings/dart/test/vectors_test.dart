// Golden-vector replay for the Dart binding, run against the real cdylib.
//
// Every sibling-language SDK replays the SAME `vectors/` files so the wire
// formats stay byte-identical across languages (mirrors the Rust
// `warren-identity` vector tests). This exercises the pure identity surface
// (no server needed) through the generated FFI bindings over the native library.
//
// Run from this directory, after `tool/generate.sh` and with the cdylib built:
//   dart pub get && dart test
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:warren_sdk/warren_sdk.dart';

Map<String, dynamic> _loadVectors() {
  // The repo root is three levels up from bindings/dart/test.
  final path = '${Directory.current.path}/../../vectors/identity.json';
  return jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
}

void main() {
  // Load the native library built by `cargo build -p warren-sdk-ffi --release`.
  final ext = Platform.isMacOS
      ? 'dylib'
      : Platform.isWindows
          ? 'dll'
          : 'so';
  final prefix = Platform.isWindows ? '' : 'lib';
  final libPath =
      '${Directory.current.path}/../../target/release/${prefix}warren_sdk_ffi.$ext';
  configureDefaultBindings(libraryPath: libPath);

  final vectors = _loadVectors();

  test('SS58 encode vectors replay byte-for-byte', () {
    final cases = (vectors['ss58'] as Map)['vectors'] as List;
    expect(cases, isNotEmpty);
    for (final pair in cases) {
      final pubkeyHex = (pair as List)[0] as String;
      final expected = pair[1] as String;
      expect(ss58Encode(pubkeyHex), equals(expected),
          reason: 'ss58Encode($pubkeyHex)');
    }
  });

  test('SS58 decode round-trips back to the pubkey hex', () {
    final cases = (vectors['ss58'] as Map)['vectors'] as List;
    for (final pair in cases) {
      final pubkeyHex = (pair as List)[0] as String;
      final address = pair[1] as String;
      expect(ss58Decode(address), equalsIgnoringCase(pubkeyHex),
          reason: 'ss58Decode($address)');
    }
  });

  test('BIP39 mnemonic derives the frozen address', () {
    final cases = (vectors['bip39'] as Map)['vectors'] as List;
    expect(cases, isNotEmpty);
    for (final v in cases) {
      final m = v as Map;
      final mnemonic = m['mnemonic'] as String;
      final expected = m['address'] as String;
      expect(addressFromMnemonic(mnemonic), equals(expected),
          reason: 'addressFromMnemonic(<mnemonic>)');
    }
  });
}
