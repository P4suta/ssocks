//// The AEAD methods this library implements, and the sizes the wire format is
//// built out of.
////
//// Method names reach a program from places nobody controls: an `ss://` URL
//// pasted out of a provider dashboard, a config file written years ago, a
//// colleague's message. So parsing one is as much about explaining a refusal as
//// it is about recognising a match. `from_string` distinguishes a deprecated
//// stream cipher from a Shadowsocks 2022 method from a typo, and `explain`
//// turns any of those into a sentence worth showing a person.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/string

/// An AEAD method from SIP004.
///
/// These three are the whole set this library implements. Stream ciphers are
/// deliberately absent: they are unauthenticated, which means an attacker on
/// the path can alter traffic without detection.
pub type Method {
  Aes128Gcm
  Aes256Gcm
  ChaCha20Poly1305
}

/// Why a method name was refused.
///
/// The distinction matters. Telling someone their working-but-deprecated cipher
/// is "unknown" sends them hunting for a typo that is not there.
pub type UnsupportedMethod {
  /// A pre-SIP004 stream cipher. Real, once widely deployed, and deliberately
  /// not implemented here because it provides no authentication.
  StreamCipherMethod(name: String)
  /// A Shadowsocks 2022 method. Not implemented yet; it needs BLAKE3.
  Aead2022Method(name: String)
  /// A genuine AEAD method that this library happens not to implement.
  UnimplementedAeadMethod(name: String)
  /// Not a Shadowsocks method at all.
  UnknownMethod(name: String)
}

/// Every implemented method uses a 12 byte nonce.
pub const nonce_size = 12

/// Every implemented method produces a 16 byte authentication tag.
pub const tag_size = 16

/// The largest payload one TCP chunk may carry.
///
/// The length field is two bytes with its top two bits required to be zero, so
/// a chunk holds at most 16383 bytes of plaintext.
pub const max_payload_size = 0x3fff

/// The master key length in bytes.
pub fn key_size(method: Method) -> Int {
  case method {
    Aes128Gcm -> 16
    Aes256Gcm -> 32
    ChaCha20Poly1305 -> 32
  }
}

/// The per-session salt length in bytes.
///
/// This equals `key_size` for all three implemented methods. It is a separate
/// function because they are separate concepts, and the 2022 edition breaks the
/// coincidence.
pub fn salt_size(method: Method) -> Int {
  case method {
    Aes128Gcm -> 16
    Aes256Gcm -> 32
    ChaCha20Poly1305 -> 32
  }
}

/// The name this method carries in an `ss://` URL or a config file.
///
/// Note that Shadowsocks spells the ChaCha20 method `chacha20-ietf-poly1305`
/// while cryptography libraries call the same construction `chacha20-poly1305`.
/// This function emits the protocol spelling; the cipher spelling belongs to
/// the AEAD layer and never escapes it.
pub fn to_string(method: Method) -> String {
  case method {
    Aes128Gcm -> "aes-128-gcm"
    Aes256Gcm -> "aes-256-gcm"
    ChaCha20Poly1305 -> "chacha20-ietf-poly1305"
  }
}

/// Recognise a method name, or explain why it cannot be used.
///
/// Matching ignores surrounding whitespace and letter case. A refusal echoes
/// the name exactly as it was supplied, because that is the spelling the reader
/// will search their configuration for.
pub fn from_string(name: String) -> Result(Method, UnsupportedMethod) {
  case normalise(name) {
    "aes-128-gcm" -> Ok(Aes128Gcm)
    "aes-256-gcm" -> Ok(Aes256Gcm)
    "chacha20-ietf-poly1305" -> Ok(ChaCha20Poly1305)
    normalised -> Error(classify(normalised, name))
  }
}

fn normalise(name: String) -> String {
  name |> string.trim |> string.lowercase
}

fn classify(normalised: String, original: String) -> UnsupportedMethod {
  case is_stream_cipher(normalised), is_2022(normalised) {
    True, _ -> StreamCipherMethod(original)
    _, True -> Aead2022Method(original)
    False, False ->
      case is_unimplemented_aead(normalised) {
        True -> UnimplementedAeadMethod(original)
        False -> UnknownMethod(original)
      }
  }
}

fn is_stream_cipher(name: String) -> Bool {
  case name {
    "aes-128-cfb"
    | "aes-192-cfb"
    | "aes-256-cfb"
    | "aes-128-cfb1"
    | "aes-192-cfb1"
    | "aes-256-cfb1"
    | "aes-128-cfb8"
    | "aes-192-cfb8"
    | "aes-256-cfb8"
    | "aes-128-cfb128"
    | "aes-192-cfb128"
    | "aes-256-cfb128"
    | "aes-128-ofb"
    | "aes-192-ofb"
    | "aes-256-ofb"
    | "aes-128-ctr"
    | "aes-192-ctr"
    | "aes-256-ctr"
    | "camellia-128-cfb"
    | "camellia-192-cfb"
    | "camellia-256-cfb"
    | "bf-cfb"
    | "cast5-cfb"
    | "des-cfb"
    | "idea-cfb"
    | "rc2-cfb"
    | "seed-cfb"
    | "rc4"
    | "rc4-md5"
    | "chacha20"
    | "chacha20-ietf"
    | "xchacha20"
    | "salsa20"
    | "plain"
    | "none" -> True
    _ -> False
  }
}

fn is_2022(name: String) -> Bool {
  string.starts_with(name, "2022-blake3-")
}

fn is_unimplemented_aead(name: String) -> Bool {
  case name {
    // A real AEAD method, just not one of the three implemented here.
    "aes-192-gcm" | "xchacha20-ietf-poly1305" -> True
    // Without the "ietf" marker this historically meant the 64-bit nonce
    // construction, which is not wire compatible with what Shadowsocks uses.
    // Guessing which one was meant would produce a client that silently cannot
    // talk to its server.
    "chacha20-poly1305" -> True
    _ -> False
  }
}

/// Turn a refusal into a sentence worth showing a person.
///
/// Every explanation names the offending text and at least one method that
/// would work, because a rejection that does not say what to use instead only
/// moves the search somewhere else.
pub fn explain(reason: UnsupportedMethod) -> String {
  case reason {
    StreamCipherMethod(name) ->
      quoted(name)
      <> " is a Shadowsocks stream cipher. Stream ciphers carry no "
      <> "authentication, so anyone on the network path can alter traffic "
      <> "undetected, and they are what active probing has historically used to "
      <> "identify servers. ssocks implements AEAD methods only. "
      <> suggestion
    Aead2022Method(name) ->
      quoted(name)
      <> " is a Shadowsocks 2022 (SIP022) method. Those derive session keys "
      <> "with BLAKE3, which the Erlang crypto application does not provide, so "
      <> "ssocks does not implement them yet. "
      <> suggestion
    UnimplementedAeadMethod(name) ->
      quoted(name)
      <> " is an AEAD method that ssocks does not implement. "
      <> suggestion
    UnknownMethod(name) ->
      quoted(name) <> " is not a recognised Shadowsocks method. " <> suggestion
  }
}

const suggestion = "Use aes-256-gcm, aes-128-gcm or chacha20-ietf-poly1305."

fn quoted(name: String) -> String {
  "\"" <> name <> "\""
}
