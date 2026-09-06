//// The master key for a Shadowsocks endpoint.
////
//// ### The key does not come back out
////
//// There is no function here that returns the master key. The only thing a
//// `Key` will hand over is a session subkey for a given salt, which is what the
//// codec needs and is useless to anyone without that salt. Key material
//// therefore has no route into a log line, an error message, or a caller that
//// had no business holding it.
////
//// That also means the method and the key length cannot disagree. A `Key`
//// carries its own method, so there is no call anywhere that could pair a
//// 16 byte key with AES-256.
////
//// ### One caveat worth knowing
////
//// Gleam's `echo` and `string.inspect` reach inside opaque types. Use
//// `redacted` when a key has to appear in output; it renders the same text for
//// every key of a given method, so it cannot be used to tell two apart.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/result
import ssocks/internal/kdf
import ssocks/method.{type Method}

/// A master key, bound to the method it belongs to.
pub opaque type Key {
  Key(method: Method, master: BitArray)
}

/// Why some bytes could not be a key.
pub type KeyError {
  /// The method fixes the key length, and this was not it. Both numbers are
  /// named so the reader is not left counting bytes.
  WrongKeyLength(expected: Int, actual: Int)
  MalformedBase64(text: String)
}

/// Derive a key from a password, the way the deployed protocol does.
///
/// This is OpenSSL's EVP_BytesToKey over MD5, chosen by Shadowsocks long ago
/// and kept here for interoperability rather than for its merits. It is fast to
/// brute force. Prefer `from_bytes` with a random key wherever both ends are
/// yours to configure.
pub fn from_password(chosen_method: Method, password: String) -> Key {
  Key(
    chosen_method,
    kdf.evp_bytes_to_key(password, method.key_size(chosen_method)),
  )
}

/// Use raw key bytes, which must be exactly the method's key length.
pub fn from_bytes(
  chosen_method: Method,
  candidate: BitArray,
) -> Result(Key, KeyError) {
  let expected = method.key_size(chosen_method)
  case bit_array.byte_size(candidate) {
    actual if actual == expected -> Ok(Key(chosen_method, candidate))
    actual -> Error(WrongKeyLength(expected:, actual:))
  }
}

/// Use base64 encoded key bytes.
///
/// Standard and URL-safe alphabets are both accepted, with or without padding,
/// because a key copied out of an `ss://` URL arrives URL-safe and a key from a
/// config file usually does not.
pub fn from_base64(
  chosen_method: Method,
  encoded: String,
) -> Result(Key, KeyError) {
  use decoded <- result.try(
    decode_either_alphabet(encoded)
    |> result.replace_error(MalformedBase64(encoded)),
  )
  from_bytes(chosen_method, decoded)
}

fn decode_either_alphabet(encoded: String) -> Result(BitArray, Nil) {
  case bit_array.base64_decode(encoded) {
    Ok(decoded) -> Ok(decoded)
    Error(_) -> bit_array.base64_url_decode(encoded)
  }
}

/// The method this key belongs to.
pub fn method(key: Key) -> Method {
  key.method
}

/// Derive the session subkey for one salt.
///
/// This is the only thing that leaves a `Key`, and it is specific to the salt
/// it was asked for, so holding one tells you nothing about the key or about
/// any other session.
pub fn derive_subkey(key: Key, salt: BitArray) -> BitArray {
  kdf.session_subkey(key.master, salt, method.key_size(key.method))
}

/// How to render a key where a key must be rendered.
///
/// Names the method, because that is diagnostic, and nothing else, because
/// nothing else is safe. Two keys of the same method render identically on
/// purpose: a rendering that varied with the key would be a distinguisher, and
/// a distinguisher in a log file is a slow leak.
pub fn redacted(key: Key) -> String {
  "Key("
  <> method.to_string(key.method)
  <> ", <redacted "
  <> int.to_string(method.key_size(key.method))
  <> " bytes>)"
}
