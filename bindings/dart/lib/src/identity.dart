// Hand-written FFI for the pure identity surface of warren-sdk-ffi.
//
// The uniffi-bindgen-dart 0.1.3 output crashes at the FFI boundary (see
// ../../README.md), so until a correct generator lands, this small,
// dependency-light binding exposes the pure, server-free functions that the
// golden-vector tests need (ss58 encode/decode, address-from-mnemonic). It
// implements exactly the uniffi 0.31 C ABI for `String -> String` calls:
// a RustBuffer holding raw UTF-8 (no length prefix), passed/returned by value,
// with a RustCallStatus out-parameter.
//
// This is intentionally narrow. The full surface (client, proxy, etc.) belongs
// to the generated bindings once the generator is fixed.
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// uniffi `RustBuffer { u64 capacity; u64 len; u8* data }`.
final class _RustBuffer extends ffi.Struct {
  @ffi.Uint64()
  external int capacity;
  @ffi.Uint64()
  external int len;
  external ffi.Pointer<ffi.Uint8> data;
}

/// uniffi `ForeignBytes { i32 len; u8* data }`.
final class _ForeignBytes extends ffi.Struct {
  @ffi.Int32()
  external int len;
  external ffi.Pointer<ffi.Uint8> data;
}

/// uniffi `RustCallStatus { i8 code; RustBuffer error_buf }`.
final class _RustCallStatus extends ffi.Struct {
  @ffi.Int8()
  external int code;
  external _RustBuffer errorBuf;
}

typedef _StringFnC = _RustBuffer Function(
    _RustBuffer, ffi.Pointer<_RustCallStatus>);
typedef _StringFnDart = _RustBuffer Function(
    _RustBuffer, ffi.Pointer<_RustCallStatus>);

typedef _FromBytesC = _RustBuffer Function(
    _ForeignBytes, ffi.Pointer<_RustCallStatus>);
typedef _FromBytesDart = _RustBuffer Function(
    _ForeignBytes, ffi.Pointer<_RustCallStatus>);

typedef _FreeC = ffi.Void Function(_RustBuffer, ffi.Pointer<_RustCallStatus>);
typedef _FreeDart = void Function(_RustBuffer, ffi.Pointer<_RustCallStatus>);

typedef _NoArgFnC = _RustBuffer Function(ffi.Pointer<_RustCallStatus>);
typedef _NoArgFnDart = _RustBuffer Function(ffi.Pointer<_RustCallStatus>);

// sign_request(mnemonic, method, path, body, timestamp:u64, nonce) -> RustBuffer
typedef _SignFnC = _RustBuffer Function(_RustBuffer, _RustBuffer, _RustBuffer,
    _RustBuffer, ffi.Uint64, _RustBuffer, ffi.Pointer<_RustCallStatus>);
typedef _SignFnDart = _RustBuffer Function(_RustBuffer, _RustBuffer, _RustBuffer,
    _RustBuffer, int, _RustBuffer, ffi.Pointer<_RustCallStatus>);

/// A generated identity (uniffi record `FfiIdentity`).
class FfiIdentity {
  FfiIdentity(this.mnemonic, this.address, this.publicKeyHex);
  final String mnemonic;
  final String address;
  final String publicKeyHex;
}

/// The four signed `X-Warren-*` header values (uniffi record `FfiSignedHeaders`).
class FfiSignedHeaders {
  FfiSignedHeaders(
      this.pubkeySs58, this.signatureHex, this.timestamp, this.nonceHex);
  final String pubkeySs58;
  final String signatureHex;
  final int timestamp;
  final String nonceHex;
}

/// The pure identity functions of warren-sdk-ffi, over the native library.
class WarrenIdentityFfi {
  WarrenIdentityFfi(ffi.DynamicLibrary lib)
      : _fromBytes = lib.lookupFunction<_FromBytesC, _FromBytesDart>(
            'ffi_warren_sdk_ffi_rustbuffer_from_bytes'),
        _free = lib.lookupFunction<_FreeC, _FreeDart>(
            'ffi_warren_sdk_ffi_rustbuffer_free'),
        _ss58Encode = lib.lookupFunction<_StringFnC, _StringFnDart>(
            'uniffi_warren_sdk_ffi_fn_func_ss58_encode'),
        _ss58Decode = lib.lookupFunction<_StringFnC, _StringFnDart>(
            'uniffi_warren_sdk_ffi_fn_func_ss58_decode'),
        _addressFromMnemonic = lib.lookupFunction<_StringFnC, _StringFnDart>(
            'uniffi_warren_sdk_ffi_fn_func_address_from_mnemonic'),
        _generateIdentity = lib.lookupFunction<_NoArgFnC, _NoArgFnDart>(
            'uniffi_warren_sdk_ffi_fn_func_generate_identity'),
        _signRequest = lib.lookupFunction<_SignFnC, _SignFnDart>(
            'uniffi_warren_sdk_ffi_fn_func_sign_request');

  /// Opens the library from `path` (the built cdylib).
  factory WarrenIdentityFfi.open(String path) =>
      WarrenIdentityFfi(ffi.DynamicLibrary.open(path));

  final _FromBytesDart _fromBytes;
  final _FreeDart _free;
  final _StringFnDart _ss58Encode;
  final _StringFnDart _ss58Decode;
  final _StringFnDart _addressFromMnemonic;
  final _NoArgFnDart _generateIdentity;
  final _SignFnDart _signRequest;

  /// SS58 `wb…` address for a 64-hex pubkey.
  String ss58Encode(String pubkeyHex) => _callString(_ss58Encode, pubkeyHex);

  /// 64-hex pubkey for an SS58 `wb…` address.
  String ss58Decode(String address) => _callString(_ss58Decode, address);

  /// SS58 `wb…` address derived from a BIP39 mnemonic.
  String addressFromMnemonic(String mnemonic) =>
      _callString(_addressFromMnemonic, mnemonic);

  /// Generates a fresh identity (uniffi record return; no arguments).
  FfiIdentity generateIdentity() {
    final status = calloc<_RustCallStatus>();
    try {
      final result = _generateIdentity(status);
      _check(status, 'generate_identity');
      final r = _RecordReader(result);
      final id = FfiIdentity(r.readString(), r.readString(), r.readString());
      _free(result, status);
      _check(status, 'rustbuffer_free');
      return id;
    } finally {
      calloc.free(status);
    }
  }

  /// Signs a request, returning the four `X-Warren-*` header values (a uniffi
  /// `Result<FfiSignedHeaders, FfiError>`).
  FfiSignedHeaders signRequest({
    required String mnemonic,
    required String method,
    required String path,
    required String body,
    required int timestamp,
    required String nonceHex,
  }) {
    final status = calloc<_RustCallStatus>();
    final lowered = <_Lowered>[];
    try {
      _RustBuffer lower(String s) {
        final l = _lower(s, status);
        _check(status, 'rustbuffer_from_bytes');
        lowered.add(l);
        return l.buffer;
      }

      final result = _signRequest(lower(mnemonic), lower(method), lower(path),
          lower(body), timestamp, lower(nonceHex), status);
      _check(status, 'sign_request');
      final r = _RecordReader(result);
      final headers = FfiSignedHeaders(
          r.readString(), r.readString(), r.readU64(), r.readString());
      _free(result, status);
      _check(status, 'rustbuffer_free');
      return headers;
    } finally {
      for (final l in lowered) {
        malloc.free(l.dataPtr);
        calloc.free(l.foreignBytes);
      }
      calloc.free(status);
    }
  }

  /// Lowers `input` to a RustBuffer, calls `fn`, lifts the returned RustBuffer
  /// back to a Dart string, freeing native buffers and checking the status.
  String _callString(_StringFnDart fn, String input) {
    final bytes = utf8.encode(input);
    final dataPtr = malloc<ffi.Uint8>(bytes.isEmpty ? 1 : bytes.length);
    final status = calloc<_RustCallStatus>();
    try {
      dataPtr.asTypedList(bytes.length).setAll(0, bytes);
      final fb = calloc<_ForeignBytes>();
      fb.ref.len = bytes.length;
      fb.ref.data = dataPtr;
      final arg = _fromBytes(fb.ref, status);
      calloc.free(fb);
      _check(status, 'rustbuffer_from_bytes');

      final result = fn(arg, status);
      // `arg` ownership transferred to the callee on a successful uniffi call.
      _check(status, 'call');

      final out = _liftString(result);
      _free(result, status);
      _check(status, 'rustbuffer_free');
      return out;
    } finally {
      malloc.free(dataPtr);
      calloc.free(status);
    }
  }

  /// Lowers `s` to a RustBuffer (raw UTF-8). The caller frees the returned
  /// source pointers after the FFI call (the RustBuffer ownership transfers to
  /// the callee).
  _Lowered _lower(String s, ffi.Pointer<_RustCallStatus> status) {
    final bytes = utf8.encode(s);
    final dataPtr = malloc<ffi.Uint8>(bytes.isEmpty ? 1 : bytes.length);
    if (bytes.isNotEmpty) {
      dataPtr.asTypedList(bytes.length).setAll(0, bytes);
    }
    final fb = calloc<_ForeignBytes>();
    fb.ref.len = bytes.length;
    fb.ref.data = dataPtr;
    final buffer = _fromBytes(fb.ref, status);
    return _Lowered(buffer, dataPtr, fb);
  }

  String _liftString(_RustBuffer buf) {
    if (buf.len == 0 || buf.data == ffi.nullptr) {
      return '';
    }
    final view = buf.data.asTypedList(buf.len);
    // Copy out before the buffer is freed.
    return utf8.decode(Uint8List.fromList(view));
  }

  void _check(ffi.Pointer<_RustCallStatus> status, String where) {
    final code = status.ref.code;
    if (code != 0) {
      // Free any error buffer to avoid a leak, then surface a clear error.
      final err = status.ref.errorBuf;
      if (err.data != ffi.nullptr) {
        _free(err, status);
      }
      throw StateError('warren-sdk-ffi $where failed (status code $code)');
    }
  }
}

/// A lowered string argument plus the native source pointers to free afterwards.
class _Lowered {
  _Lowered(this.buffer, this.dataPtr, this.foreignBytes);
  final _RustBuffer buffer;
  final ffi.Pointer<ffi.Uint8> dataPtr;
  final ffi.Pointer<_ForeignBytes> foreignBytes;
}

/// Reads uniffi-lowered record fields from a RustBuffer: a String is an i32
/// big-endian length prefix followed by UTF-8 bytes; a u64 is 8 big-endian bytes.
class _RecordReader {
  _RecordReader(_RustBuffer buf)
      : _bytes = (buf.len == 0 || buf.data == ffi.nullptr)
            ? Uint8List(0)
            : Uint8List.fromList(buf.data.asTypedList(buf.len));
  final Uint8List _bytes;
  int _off = 0;

  String readString() {
    final len = _readI32();
    final s = utf8.decode(_bytes.sublist(_off, _off + len));
    _off += len;
    return s;
  }

  int _readI32() {
    final v =
        ByteData.sublistView(_bytes, _off, _off + 4).getInt32(0, Endian.big);
    _off += 4;
    return v;
  }

  int readU64() {
    final v =
        ByteData.sublistView(_bytes, _off, _off + 8).getUint64(0, Endian.big);
    _off += 8;
    return v;
  }
}

/// Opens the cdylib from the conventional release path relative to the repo root.
WarrenIdentityFfi openWarrenIdentityFfi({String? libraryPath}) {
  if (libraryPath != null) {
    return WarrenIdentityFfi.open(libraryPath);
  }
  final ext = Platform.isMacOS
      ? 'dylib'
      : Platform.isWindows
          ? 'dll'
          : 'so';
  final prefix = Platform.isWindows ? '' : 'lib';
  return WarrenIdentityFfi.open(
      '${Directory.current.path}/../../target/release/${prefix}warren_sdk_ffi.$ext');
}
