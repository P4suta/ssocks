//// Method names arrive from strangers: an `ss://` URL pasted out of a provider
//// dashboard, or a config file written years ago. Parsing them is therefore as
//// much about explaining a refusal as it is about recognising a match, and the
//// refusal is what most of these tests pin down.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/list
import gleam/string
import ssocks/method

pub fn the_three_implemented_methods_parse_test() {
  assert method.from_string("aes-128-gcm") == Ok(method.Aes128Gcm)
  assert method.from_string("aes-256-gcm") == Ok(method.Aes256Gcm)
  assert method.from_string("chacha20-ietf-poly1305")
    == Ok(method.ChaCha20Poly1305)
}

pub fn method_names_round_trip_through_text_test() {
  // to_string emits the protocol spelling, which is what an ss:// URL carries.
  // A round trip failure here would produce URLs no other client can read.
  let each = [method.Aes128Gcm, method.Aes256Gcm, method.ChaCha20Poly1305]
  let round_tripped =
    each
    |> list.map(method.to_string)
    |> list.map(method.from_string)
  assert round_tripped
    == [
      Ok(method.Aes128Gcm),
      Ok(method.Aes256Gcm),
      Ok(method.ChaCha20Poly1305),
    ]
}

pub fn the_chacha_protocol_name_carries_the_ietf_marker_test() {
  // Shadowsocks spells this method "chacha20-ietf-poly1305" while the crypto
  // libraries underneath call the same construction "chacha20-poly1305". The
  // two names must not be confused, so the protocol spelling is asserted here
  // and the cipher spelling is asserted in the AEAD tests.
  assert method.to_string(method.ChaCha20Poly1305) == "chacha20-ietf-poly1305"
}

pub fn method_names_are_matched_case_insensitively_test() {
  assert method.from_string("AES-256-GCM") == Ok(method.Aes256Gcm)
  assert method.from_string("ChaCha20-IETF-Poly1305")
    == Ok(method.ChaCha20Poly1305)
}

pub fn surrounding_whitespace_in_a_method_name_is_ignored_test() {
  assert method.from_string("  aes-256-gcm  ") == Ok(method.Aes256Gcm)
}

// --- refusals, each with its own explanation --------------------------------

pub fn stream_ciphers_are_refused_as_deprecated_rather_than_unknown_test() {
  // These exist and once worked. Telling a user their cipher is "unknown" when
  // it is really "unauthenticated, and deliberately not implemented" sends them
  // hunting for a typo that is not there.
  assert method.from_string("aes-256-cfb")
    == Error(method.StreamCipherMethod("aes-256-cfb"))
  assert method.from_string("chacha20")
    == Error(method.StreamCipherMethod("chacha20"))
  assert method.from_string("chacha20-ietf")
    == Error(method.StreamCipherMethod("chacha20-ietf"))
  assert method.from_string("rc4-md5")
    == Error(method.StreamCipherMethod("rc4-md5"))
  assert method.from_string("salsa20")
    == Error(method.StreamCipherMethod("salsa20"))
}

pub fn shadowsocks_2022_methods_are_refused_as_not_yet_implemented_test() {
  assert method.from_string("2022-blake3-aes-256-gcm")
    == Error(method.Aead2022Method("2022-blake3-aes-256-gcm"))
  assert method.from_string("2022-blake3-chacha20-poly1305")
    == Error(method.Aead2022Method("2022-blake3-chacha20-poly1305"))
}

pub fn aead_methods_outside_the_implemented_three_say_so_test() {
  assert method.from_string("aes-192-gcm")
    == Error(method.UnimplementedAeadMethod("aes-192-gcm"))
  assert method.from_string("xchacha20-ietf-poly1305")
    == Error(method.UnimplementedAeadMethod("xchacha20-ietf-poly1305"))
}

pub fn anything_else_is_reported_as_unknown_with_the_text_that_was_given_test() {
  assert method.from_string("") == Error(method.UnknownMethod(""))
  assert method.from_string("aes-256") == Error(method.UnknownMethod("aes-256"))
  assert method.from_string("nonsense")
    == Error(method.UnknownMethod("nonsense"))
}

pub fn a_refusal_preserves_the_text_exactly_as_it_was_supplied_test() {
  // The echoed name is what a user greps their config for, so it must be their
  // spelling, not a normalised one.
  assert method.from_string("  AES-256-CFB  ")
    == Error(method.StreamCipherMethod("  AES-256-CFB  "))
}

pub fn every_refusal_explains_itself_in_a_sentence_test() {
  let explained = method.explain(method.StreamCipherMethod("aes-256-cfb"))
  assert explained != ""
  assert string_contains(explained, "aes-256-cfb")

  let explained =
    method.explain(method.Aead2022Method("2022-blake3-aes-256-gcm"))
  assert string_contains(explained, "2022-blake3-aes-256-gcm")

  let explained = method.explain(method.UnknownMethod("nonsense"))
  assert string_contains(explained, "nonsense")

  let explained = method.explain(method.UnimplementedAeadMethod("aes-192-gcm"))
  assert string_contains(explained, "aes-192-gcm")
}

pub fn every_refusal_names_the_methods_that_would_work_test() {
  // A rejection that does not say what to use instead just moves the search.
  let all = [
    method.StreamCipherMethod("aes-256-cfb"),
    method.Aead2022Method("2022-blake3-aes-256-gcm"),
    method.UnimplementedAeadMethod("aes-192-gcm"),
    method.UnknownMethod("nonsense"),
  ]
  let each_mentions_a_working_method =
    all
    |> list.map(method.explain)
    |> list.all(fn(text) { string_contains(text, "aes-256-gcm") })
  assert each_mentions_a_working_method
}

// --- sizes, which the whole wire format is built out of ---------------------

pub fn key_sizes_match_the_sip004_table_test() {
  assert method.key_size(method.Aes128Gcm) == 16
  assert method.key_size(method.Aes256Gcm) == 32
  assert method.key_size(method.ChaCha20Poly1305) == 32
}

pub fn salt_sizes_match_the_sip004_table_test() {
  // Salt size equals key size for all three implemented methods. It is a
  // separate function anyway, because they are separate concepts and the 2022
  // edition breaks the coincidence.
  assert method.salt_size(method.Aes128Gcm) == 16
  assert method.salt_size(method.Aes256Gcm) == 32
  assert method.salt_size(method.ChaCha20Poly1305) == 32
}

pub fn every_method_uses_a_twelve_byte_nonce_and_a_sixteen_byte_tag_test() {
  assert method.nonce_size == 12
  assert method.tag_size == 16
}

pub fn the_payload_length_field_caps_a_chunk_at_16383_bytes_test() {
  // Two bytes wide, with the top two bits required to be zero.
  assert method.max_payload_size == 0x3fff
  assert method.max_payload_size == 16_383
}

fn string_contains(haystack: String, needle: String) -> Bool {
  string.contains(haystack, needle)
}

pub fn the_non_ietf_chacha_spelling_is_refused_rather_than_guessed_test() {
  // Without the "ietf" marker this name historically meant the 64-bit nonce
  // construction, which is not wire compatible with what Shadowsocks uses.
  // Guessing which one a config meant would produce a client that silently
  // cannot talk to its server, so it is refused instead.
  assert method.from_string("chacha20-poly1305")
    == Error(method.UnimplementedAeadMethod("chacha20-poly1305"))
}
