// Golden-vector replay for the Dart binding, run against the real cdylib.
//
// Every sibling-language SDK replays the SAME `vectors/` files so the wire
// formats stay byte-identical across languages (mirrors the Rust
// `warren-identity` vector tests). This exercises the pure identity surface
// (no server needed) through the hand-written FFI in `lib/src/identity.dart`
// over the native library (the generated bindings currently crash, see README).
//
// Run from this directory, after `cargo build -p warren-sdk-ffi --release`:
//   dart pub get && dart test
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:warren_sdk/src/identity.dart';

Map<String, dynamic> _loadVectors() {
  final path = '${Directory.current.path}/../../vectors/identity.json';
  return jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
}

void main() {
  final ffi = openWarrenIdentityFfi();
  final vectors = _loadVectors();

  test('SS58 encode vectors replay byte-for-byte', () {
    final cases = (vectors['ss58'] as Map)['vectors'] as List;
    expect(cases, isNotEmpty);
    for (final pair in cases) {
      final pubkeyHex = (pair as List)[0] as String;
      final expected = pair[1] as String;
      expect(ffi.ss58Encode(pubkeyHex), equals(expected),
          reason: 'ss58Encode($pubkeyHex)');
    }
  });

  test('SS58 decode round-trips back to the pubkey hex', () {
    final cases = (vectors['ss58'] as Map)['vectors'] as List;
    for (final pair in cases) {
      final pubkeyHex = (pair as List)[0] as String;
      final address = pair[1] as String;
      expect(ffi.ss58Decode(address), equalsIgnoringCase(pubkeyHex),
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
      expect(ffi.addressFromMnemonic(mnemonic), equals(expected),
          reason: 'addressFromMnemonic(<mnemonic>)');
    }
  });

  test('generateIdentity returns a self-consistent record', () {
    // Record lift over the FFI: the returned mnemonic must re-derive the same
    // address, and the pubkey must SS58-encode to it.
    final id = ffi.generateIdentity();
    expect(id.mnemonic.split(' ').length, equals(12));
    expect(id.address, startsWith('wb'));
    expect(ffi.addressFromMnemonic(id.mnemonic), equals(id.address));
    expect(ffi.ss58Encode(id.publicKeyHex), equals(id.address));
  });

  test('signRequest round-trips a deterministic record', () {
    // A multi-argument call returning a Result<record>: the signer's pubkey must
    // equal the mnemonic's address, the clock + nonce echo, and the signature is
    // a 128-hex Ed25519 signature. (The frozen signature vector keys on a raw
    // seed, which the mnemonic-based FFI cannot take, so we pin shape + identity.)
    final bip = (vectors['bip39'] as Map)['vectors'] as List;
    final mnemonic = (bip.first as Map)['mnemonic'] as String;
    final address = (bip.first as Map)['address'] as String;
    const nonce = '09090909090909090909090909090909';
    final h = ffi.signRequest(
      mnemonic: mnemonic,
      method: 'POST',
      path: '/v1/register',
      body: '{"voucher":"abc"}',
      timestamp: 1700000000,
      nonceHex: nonce,
    );
    expect(h.pubkeySs58, equals(address));
    expect(h.timestamp, equals(1700000000));
    expect(h.nonceHex, equals(nonce));
    expect(h.signatureHex, matches(RegExp(r'^[0-9a-f]{128}$')));
  });

  test('async client method drives the RustFuture to an error on a dead host',
      () async {
    // Exercises the uniffi object + async ABI end to end (constructor, an async
    // method, the RustFuture poll/complete/free bridge). Port 1 on loopback
    // refuses fast, so the future completes with an error without a live server
    // (mirrors the Rust FFI test). Proves the async path works, not just the
    // deterministic one.
    final client = WarrenFfiClientFfi.create(
      ffi,
      mnemonic: (((vectors['bip39'] as Map)['vectors'] as List).first
          as Map)['mnemonic'] as String,
      apiBase: 'https://127.0.0.1:1',
      serverPubkeyPin: 'ab' * 32,
    );
    try {
      await expectLater(client.subscriptionExpiry(), throwsA(isA<Object>()));
    } finally {
      client.close();
    }
  });

  test('async start_proxy (observer-less) errors on a dead host', () async {
    // The full async object-returning method with Option args: start_proxy with
    // a valid-format exit id + a bindable socks5 address but an unroutable API
    // base. The directory fetch fails, so the RustFuture completes with an error
    // (object-returning future via complete_u64). Validates the async object
    // method + Option<RustBuffer> argument lowering without a live exit.
    final client = WarrenFfiClientFfi.create(
      ffi,
      mnemonic: (((vectors['bip39'] as Map)['vectors'] as List).first
          as Map)['mnemonic'] as String,
      apiBase: 'https://127.0.0.1:1',
      serverPubkeyPin: 'ab' * 32,
    );
    try {
      await expectLater(
        client.startProxy(exitIdHex: 'ab' * 16, socks5Listen: '127.0.0.1:0'),
        throwsA(isA<Object>()),
      );
    } finally {
      client.close();
    }
  });

  test('async start_proxy_supervised errors on a dead host', () async {
    // The supervised proxy is the host of the pollable state() (the state-watch
    // alternative to the Dart-incompatible ConnectionObserver). It fetches the
    // multihop directory before returning, so against an unroutable API it errors
    // (no handle is produced). This validates the async object-method binding;
    // exercising state()/socks5Address needs a reachable API to instantiate the
    // proxy (the state() enum binding is present and correct, but the handle is
    // unreachable without a live exit, like every server-dependent happy path).
    final client = WarrenFfiClientFfi.create(
      ffi,
      mnemonic: (((vectors['bip39'] as Map)['vectors'] as List).first
          as Map)['mnemonic'] as String,
      apiBase: 'https://127.0.0.1:1',
      serverPubkeyPin: 'ab' * 32,
    );
    try {
      await expectLater(
        client.startProxySupervised(
            exitIdHex: 'ab' * 16, socks5Listen: '127.0.0.1:0'),
        throwsA(isA<Object>()),
      );
    } finally {
      client.close();
    }
  });

  // Server-dependent HAPPY PATH: runs only when pointed at a reachable exit via
  // env (a subscribed account), otherwise skipped so the offline suite stays
  // green. This is the one-command validation of a value-returning async call:
  //   WARREN_LIVE_MNEMONIC="..." WARREN_LIVE_API="https://api.warrenbrowse.com" \
  //     dart test
  final liveMnemonic = Platform.environment['WARREN_LIVE_MNEMONIC'];
  final liveApi = Platform.environment['WARREN_LIVE_API'];
  const livePin =
      '4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e';
  test(
    'live subscriptionExpiry returns a value (server happy path)',
    () async {
      final client = WarrenFfiClientFfi.create(
        ffi,
        mnemonic: liveMnemonic!,
        apiBase: liveApi!,
        serverPubkeyPin: Platform.environment['WARREN_LIVE_PIN'] ?? livePin,
      );
      try {
        final expiry = await client.subscriptionExpiry();
        expect(expiry, greaterThan(0),
            reason: 'a subscribed account has a future expiry');
      } finally {
        client.close();
      }
    },
    skip: (liveMnemonic == null || liveApi == null)
        ? 'set WARREN_LIVE_MNEMONIC + WARREN_LIVE_API to run against a live exit'
        : false,
  );
}
