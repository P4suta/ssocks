//// The master key, and the fact that it does not come back out.
////
//// `Key` has no accessor for its bytes. The only thing it will hand over is a
//// derived session subkey, which is useless without the salt it was derived
//// for. That is what keeps key material out of logs, out of error messages and
//// out of the reach of a caller who did not need it.
////
//// The tests below reach into `ssocks/internal/kdf` to recompute what the
//// master key must be. That is a test looking behind the curtain on purpose, so
//// it can assert the curtain is closed.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/string
import ssocks/internal/hex
import ssocks/internal/kdf
import ssocks/key
import ssocks/method
import vector.{bytes}

const every_method = [
  method.Aes128Gcm,
  method.Aes256Gcm,
  method.ChaCha20Poly1305,
]

// --- building from a password ------------------------------------------------

pub fn a_password_derives_a_key_of_the_method_s_length_test() {
  use chosen <- list.each(every_method)
  let derived = key.from_password(chosen, "hunter2")
  assert key.method(derived) == chosen
  // The length is not observable directly, so it is checked through the one
  // derivation the key will perform.
  assert bit_array.byte_size(key.derive_subkey(derived, salt_for(chosen)))
    == method.key_size(chosen)
}

pub fn the_password_derivation_is_evp_bytes_to_key_test() {
  // Anchored to the same algorithm the rest of the ecosystem uses, so a key
  // built here matches one built by any other client from the same password.
  use chosen <- list.each(every_method)
  let salt = salt_for(chosen)
  assert key.derive_subkey(key.from_password(chosen, "hunter2"), salt)
    == kdf.session_subkey(
      kdf.evp_bytes_to_key("hunter2", method.key_size(chosen)),
      salt,
      method.key_size(chosen),
    )
}

pub fn different_passwords_derive_different_keys_test() {
  let salt = salt_for(method.Aes256Gcm)
  assert key.derive_subkey(key.from_password(method.Aes256Gcm, "one"), salt)
    != key.derive_subkey(key.from_password(method.Aes256Gcm, "two"), salt)
}

pub fn an_empty_password_is_allowed_but_derives_a_real_key_test() {
  // Refusing it would be a policy decision the protocol does not make, and a
  // caller with an empty password has a configuration problem, not a crash.
  let derived = key.from_password(method.Aes256Gcm, "")
  assert bit_array.byte_size(key.derive_subkey(
      derived,
      salt_for(method.Aes256Gcm),
    ))
    == 32
}

// --- building from raw bytes --------------------------------------------------

pub fn raw_bytes_of_the_right_length_are_accepted_test() {
  use chosen <- list.each(every_method)
  let size = method.key_size(chosen)
  let assert Ok(built) = key.from_bytes(chosen, filler(size))
  assert key.method(built) == chosen
}

pub fn raw_bytes_of_the_wrong_length_are_refused_with_both_numbers_test() {
  // Saying only "wrong length" leaves the reader counting bytes by hand.
  assert key.from_bytes(method.Aes256Gcm, filler(16))
    == Error(key.WrongKeyLength(expected: 32, actual: 16))
  assert key.from_bytes(method.Aes128Gcm, filler(32))
    == Error(key.WrongKeyLength(expected: 16, actual: 32))
  assert key.from_bytes(method.Aes256Gcm, <<>>)
    == Error(key.WrongKeyLength(expected: 32, actual: 0))
}

pub fn a_key_that_is_one_byte_short_is_refused_test() {
  // The near miss matters more than the obvious one: a truncated paste is a
  // real thing that happens.
  assert key.from_bytes(method.Aes256Gcm, filler(31))
    == Error(key.WrongKeyLength(expected: 32, actual: 31))
}

// --- building from base64 ------------------------------------------------------

pub fn standard_base64_is_accepted_test() {
  // 32 bytes of 0x41 encodes as this. Shadowsocks 2022 distributes keys this
  // way and people paste them into AEAD configs too.
  let assert Ok(built) =
    key.from_base64(
      method.Aes256Gcm,
      "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
    )
  assert key.method(built) == method.Aes256Gcm
}

pub fn url_safe_base64_is_accepted_test() {
  // ss:// URLs carry URL-safe base64, so a key copied out of one arrives with
  // - and _ in place of + and /.
  // Chosen so the two alphabets actually disagree: these bytes encode to
  // characters that are + and / in standard base64 and - and _ in URL-safe.
  let raw =
    bytes(
      "fbfe03f8ffff0102030405060708090a
       0b0c0d0e0f101112131415161718191a",
    )
  assert bit_array.byte_size(raw) == 32
  let standard = bit_array.base64_encode(raw, True)
  let url_safe = bit_array.base64_url_encode(raw, True)
  assert standard != url_safe

  let assert Ok(from_url) = key.from_base64(method.Aes256Gcm, url_safe)
  let assert Ok(from_standard) = key.from_base64(method.Aes256Gcm, standard)
  assert from_url == from_standard
}

pub fn unpadded_base64_is_accepted_test() {
  let raw = filler(32)
  let assert Ok(built) =
    key.from_base64(method.Aes256Gcm, bit_array.base64_encode(raw, False))
  let assert Ok(expected) = key.from_bytes(method.Aes256Gcm, raw)
  assert built == expected
}

pub fn text_that_is_not_base64_is_refused_test() {
  assert key.from_base64(method.Aes256Gcm, "not base64!!")
    == Error(key.MalformedBase64("not base64!!"))
}

pub fn base64_that_decodes_to_the_wrong_length_is_refused_test() {
  // Decodes fine, but is not a key for this method. The error names the length
  // problem rather than blaming the encoding.
  let encoded = bit_array.base64_encode(filler(16), True)
  assert key.from_base64(method.Aes256Gcm, encoded)
    == Error(key.WrongKeyLength(expected: 32, actual: 16))
}

// --- derivation ---------------------------------------------------------------

pub fn a_subkey_depends_on_the_salt_test() {
  let built = key.from_password(method.Aes256Gcm, "hunter2")
  assert key.derive_subkey(built, filler(32))
    != key.derive_subkey(built, other_filler(32))
}

pub fn a_subkey_is_reproducible_test() {
  // Both ends of a connection derive the same subkey from the same salt, so
  // this has to be a pure function of its inputs and nothing else.
  let built = key.from_password(method.Aes256Gcm, "hunter2")
  assert key.derive_subkey(built, filler(32))
    == key.derive_subkey(built, filler(32))
}

pub fn a_subkey_matches_the_length_of_the_method_test() {
  use chosen <- list.each(every_method)
  assert bit_array.byte_size(key.derive_subkey(
      key.from_password(chosen, "hunter2"),
      salt_for(chosen),
    ))
    == method.key_size(chosen)
}

// --- the master key stays inside ------------------------------------------------

pub fn a_redacted_key_names_the_method_and_hides_the_bytes_test() {
  let password = "correct horse battery staple"
  let built = key.from_password(method.Aes256Gcm, password)
  let master = kdf.evp_bytes_to_key(password, 32)

  let shown = key.redacted(built)
  assert string.contains(shown, "aes-256-gcm")
  assert string.contains(shown, "redacted")

  // The thing that must never appear.
  assert !string.contains(shown, hex.encode(master))
  assert !string.contains(shown, password)
}

pub fn a_redacted_key_is_the_same_for_two_different_keys_of_one_method_test() {
  // If the rendering varied with the key it would be a distinguisher, and a
  // distinguisher printed into logs is a slow leak.
  assert key.redacted(key.from_password(method.Aes256Gcm, "one"))
    == key.redacted(key.from_password(method.Aes256Gcm, "two"))
}

pub fn two_keys_built_the_same_way_are_equal_test() {
  assert key.from_password(method.Aes256Gcm, "hunter2")
    == key.from_password(method.Aes256Gcm, "hunter2")
}

pub fn the_same_bytes_under_different_methods_are_not_the_same_key_test() {
  let assert Ok(one) = key.from_bytes(method.Aes256Gcm, filler(32))
  let assert Ok(other) = key.from_bytes(method.ChaCha20Poly1305, filler(32))
  assert one != other
}

// --- helpers -------------------------------------------------------------------

fn salt_for(chosen: method.Method) -> BitArray {
  filler(method.salt_size(chosen))
}

fn filler(size: Int) -> BitArray {
  <<0x41:8>> |> list.repeat(size) |> bit_array.concat
}

fn other_filler(size: Int) -> BitArray {
  <<0x42:8>> |> list.repeat(size) |> bit_array.concat
}
