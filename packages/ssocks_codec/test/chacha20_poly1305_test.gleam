//// The AEAD_CHACHA20_POLY1305 construction from RFC 8439 section 2.8.
////
//// Two things here are easy to get wrong in a way that still round-trips
//// against itself and fails against every other implementation: the zero
//// padding that aligns the associated data and the ciphertext to 16 bytes, and
//// the two little-endian lengths appended at the end. Both are exercised by the
//// published vector, whose associated data is 12 bytes and whose plaintext is
//// 114, so neither is already aligned.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import ssocks/cipher/chacha20_poly1305 as aead
import vector.{bytes}

const key = "808182838485868788898a8b8c8d8e8f
             909192939495969798999a9b9c9d9e9f"

// --- 2.6.2: deriving the one-time Poly1305 key ------------------------------

pub fn rfc8439_one_time_key_generation_matches_the_published_vector_test() {
  // Block zero of the ChaCha20 keystream, first 32 bytes. Block one onwards is
  // what encrypts the payload, which is why the counter starts at one there.
  assert aead.one_time_key(bytes(key), bytes("000000000001020304050607"))
    == bytes(
      "8ad5a08b905f81cc815040274ab29471
       a833b637e3fd0da508dbb8e2fdd1a646",
    )
}

pub fn a_one_time_key_is_thirty_two_bytes_test() {
  assert bit_array.byte_size(aead.one_time_key(
      bytes(key),
      bytes("070000004041424344454647"),
    ))
    == 32
}

// --- 2.8.2: the full construction -------------------------------------------

const nonce = "070000004041424344454647"

const aad = "50515253c0c1c2c3c4c5c6c7"

const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

const expected_ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2
                             a4aded51296e08fea9e2b5a736ee62d6
                             3dbea45e8ca9671282fafb69da92728b
                             1a71de0a9e060b2905d6a5b67ecd3b36
                             92ddbd7f2d778b8c9803aee328091b58
                             fab324e4fad675945585808b4831d7bc
                             3ff4def08e4b7a9de576d26586cec64b
                             6116"

const expected_tag = "1ae10b594f09e26a7e902ecbd0600691"

pub fn rfc8439_sealing_matches_the_published_ciphertext_and_tag_test() {
  assert bit_array.byte_size(bytes(aad)) == 12
  assert bit_array.byte_size(<<plaintext:utf8>>) == 114

  assert aead.seal(bytes(key), bytes(nonce), bytes(aad), <<plaintext:utf8>>)
    == #(bytes(expected_ciphertext), bytes(expected_tag))
}

pub fn rfc8439_opening_recovers_the_plaintext_test() {
  assert aead.open(
      bytes(key),
      bytes(nonce),
      bytes(aad),
      bytes(expected_ciphertext),
      bytes(expected_tag),
    )
    == Ok(<<plaintext:utf8>>)
}

// --- every way of getting it wrong must fail --------------------------------

pub fn opening_with_a_altered_tag_fails_test() {
  assert aead.open(
      bytes(key),
      bytes(nonce),
      bytes(aad),
      bytes(expected_ciphertext),
      bytes("1ae10b594f09e26a7e902ecbd0600690"),
    )
    == Error(Nil)
}

pub fn opening_with_an_altered_ciphertext_fails_test() {
  let assert <<first:8, rest:bits>> = bytes(expected_ciphertext)
  let tampered = <<{ first + 1 }:8, rest:bits>>
  assert aead.open(
      bytes(key),
      bytes(nonce),
      bytes(aad),
      tampered,
      bytes(expected_tag),
    )
    == Error(Nil)
}

pub fn opening_with_altered_associated_data_fails_test() {
  // The associated data is not encrypted, only authenticated. If it were left
  // out of the tag computation this would still succeed, which is the whole
  // point of the check.
  assert aead.open(
      bytes(key),
      bytes(nonce),
      bytes("50515253c0c1c2c3c4c5c6c8"),
      bytes(expected_ciphertext),
      bytes(expected_tag),
    )
    == Error(Nil)
}

pub fn opening_with_the_wrong_key_or_nonce_fails_test() {
  assert aead.open(
      bytes(
        "808182838485868788898a8b8c8d8e8f
         909192939495969798999a9b9c9d9ea0",
      ),
      bytes(nonce),
      bytes(aad),
      bytes(expected_ciphertext),
      bytes(expected_tag),
    )
    == Error(Nil)

  assert aead.open(
      bytes(key),
      bytes("070000004041424344454648"),
      bytes(aad),
      bytes(expected_ciphertext),
      bytes(expected_tag),
    )
    == Error(Nil)
}

pub fn opening_a_truncated_tag_fails_rather_than_crashing_test() {
  // A short tag is attacker supplied input. It must be refused, and refusing
  // must not be a crash: a server that dies on a malformed frame is a denial of
  // service waiting to happen.
  assert aead.open(
      bytes(key),
      bytes(nonce),
      bytes(aad),
      bytes(expected_ciphertext),
      bytes("1ae10b594f09e26a"),
    )
    == Error(Nil)

  assert aead.open(
      bytes(key),
      bytes(nonce),
      bytes(aad),
      bytes(expected_ciphertext),
      <<>>,
    )
    == Error(Nil)
}

// --- the padding boundaries -------------------------------------------------

pub fn sealing_and_opening_round_trips_at_every_padding_boundary_test() {
  // 0, 15, 16 and 17 bytes on both the associated data and the plaintext cover
  // "no padding needed", "one byte short", "exactly aligned" and "one byte
  // over" on each of the two padded regions.
  let sizes = [0, 15, 16, 17]
  use associated_size <- each(sizes)
  use plaintext_size <- each(sizes)

  let associated = filler(0xab, associated_size)
  let message = filler(0xcd, plaintext_size)

  let #(ciphertext, tag) =
    aead.seal(bytes(key), bytes(nonce), associated, message)
  assert bit_array.byte_size(ciphertext) == plaintext_size
  assert bit_array.byte_size(tag) == 16
  assert aead.open(bytes(key), bytes(nonce), associated, ciphertext, tag)
    == Ok(message)
}

pub fn sealing_nothing_still_produces_a_tag_test() {
  let #(ciphertext, tag) = aead.seal(bytes(key), bytes(nonce), <<>>, <<>>)
  assert ciphertext == <<>>
  assert bit_array.byte_size(tag) == 16
  assert aead.open(bytes(key), bytes(nonce), <<>>, <<>>, tag) == Ok(<<>>)
}

pub fn a_message_spanning_several_keystream_blocks_round_trips_test() {
  let message = <<0:size(8000)>>
  let #(ciphertext, tag) = aead.seal(bytes(key), bytes(nonce), <<>>, message)
  assert bit_array.byte_size(ciphertext) == 1000
  assert aead.open(bytes(key), bytes(nonce), <<>>, ciphertext, tag)
    == Ok(message)
}

fn each(items: List(a), run: fn(a) -> Nil) -> Nil {
  case items {
    [] -> Nil
    [first, ..rest] -> {
      run(first)
      each(rest, run)
    }
  }
}

fn filler(byte: Int, size: Int) -> BitArray {
  <<byte:8>> |> list.repeat(size) |> bit_array.concat
}
