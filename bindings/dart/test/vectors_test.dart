// Golden-vector replay harness for the Dart binding.
//
// STATUS: scaffold. Enable once `tool/generate.sh` has produced the bindings.
// Every sibling-language SDK replays the SAME `vectors/` files so the wire
// formats stay byte-identical across languages; this is the Dart side of that
// contract (mirrors `crates/warren-identity` vector tests).
//
// The intended assertions (uncomment after generation, importing the generated
// surface from `package:warren_sdk/warren_sdk.dart`):
//
//   import 'dart:convert';
//   import 'dart:io';
//   import 'package:test/test.dart';
//   import 'package:warren_sdk/warren_sdk.dart';
//
//   void main() {
//     test('identity vectors replay byte-for-byte', () {
//       final raw = File('../../vectors/identity.json').readAsStringSync();
//       final vectors = jsonDecode(raw) as Map<String, dynamic>;
//       for (final v in vectors['cases'] as List) {
//         final addr = addressFromMnemonic(v['mnemonic'] as String);
//         expect(addr, equals(v['address']));
//       }
//     });
//   }
//
// Until generation runs, this file documents the obligation without a failing
// import, so `dart test` over the scaffold is a no-op rather than a false green.
void main() {}
