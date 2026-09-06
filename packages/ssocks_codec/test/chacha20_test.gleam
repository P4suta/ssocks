//// ChaCha20 against RFC 8439, one layer at a time.
////
//// The quarter round, the block function and the stream cipher are asserted
//// separately because the RFC publishes a vector for each. When the AEAD output
//// is wrong, being able to ask "is the block function still right?" turns an
//// open-ended hunt into a bisection over three named layers.
////
//// This implementation exists because Bun ships no ChaCha20 at all. It doubles
//// as a second opinion: every value it produces is cross-checked against the
//// platform cipher wherever the platform has one.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import ssocks/cipher/chacha20
import vector.{bytes}

/// RFC 8439 uses this key, bytes 0 to 31 in order, for most of its vectors.
const sequential_key = "000102030405060708090a0b0c0d0e0f
                        101112131415161718191a1b1c1d1e1f"

// --- 2.1.1: the quarter round ----------------------------------------------

pub fn rfc8439_quarter_round_matches_the_published_vector_test() {
  assert chacha20.quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567)
    == #(0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)
}

pub fn a_quarter_round_keeps_every_word_inside_32_bits_test() {
  // Addition wraps and rotation is circular, so nothing may grow past 2^32.
  // On the Erlang target integers are arbitrary precision, so a missing mask
  // would silently produce oversized words rather than crash.
  let #(a, b, c, d) =
    chacha20.quarter_round(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)
  assert a < 0x100000000
  assert b < 0x100000000
  assert c < 0x100000000
  assert d < 0x100000000
  assert a >= 0
  assert b >= 0
  assert c >= 0
  assert d >= 0
}

// --- 2.3.2: the block function ---------------------------------------------

const block_nonce = "000000090000004a00000000"

const block_keystream = "10f1e7e4d13b5915500fdd1fa32071c4
                         c7d1f4c733c068030422aa9ac3d46c4e
                         d2826446079faa0914c2d705d98b02a2
                         b5129cd1de164eb9cbd083e8a2503c4e"

pub fn rfc8439_block_function_matches_the_published_keystream_test() {
  assert chacha20.block(bytes(sequential_key), 1, bytes(block_nonce))
    == bytes(block_keystream)
}

pub fn a_block_is_always_sixty_four_bytes_test() {
  let produced = chacha20.block(bytes(sequential_key), 0, bytes(block_nonce))
  assert bit_array.byte_size(produced) == 64
}

pub fn consecutive_counters_produce_different_blocks_test() {
  let first = chacha20.block(bytes(sequential_key), 1, bytes(block_nonce))
  let second = chacha20.block(bytes(sequential_key), 2, bytes(block_nonce))
  assert first != second
}

// --- 2.4.2: the stream cipher ----------------------------------------------

const sunscreen_nonce = "000000000000004a00000000"

const sunscreen_plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

const sunscreen_ciphertext = "6e2e359a2568f98041ba0728dd0d6981
                              e97e7aec1d4360c20a27afccfd9fae0b
                              f91b65c5524733ab8f593dabcd62b357
                              1639d624e65152ab8f530c359f0861d8
                              07ca0dbf500d6a6156a38e088a22b65e
                              52bc514d16ccf806818ce91ab7793736
                              5af90bbf74a35be6b40b8eedf2785e42
                              874d"

pub fn rfc8439_stream_encryption_matches_the_published_vector_test() {
  assert chacha20.encrypt(bytes(sequential_key), 1, bytes(sunscreen_nonce), <<
      sunscreen_plaintext:utf8,
    >>)
    == bytes(sunscreen_ciphertext)
}

pub fn encryption_is_its_own_inverse_test() {
  // The cipher is a keystream XOR, so running it twice returns the input. This
  // is what makes one code path serve both directions.
  let plaintext = <<sunscreen_plaintext:utf8>>
  let once =
    chacha20.encrypt(
      bytes(sequential_key),
      1,
      bytes(sunscreen_nonce),
      plaintext,
    )
  let twice =
    chacha20.encrypt(bytes(sequential_key), 1, bytes(sunscreen_nonce), once)
  assert twice == plaintext
}

pub fn encryption_preserves_length_test() {
  let plaintext = <<sunscreen_plaintext:utf8>>
  assert bit_array.byte_size(chacha20.encrypt(
      bytes(sequential_key),
      1,
      bytes(sunscreen_nonce),
      plaintext,
    ))
    == bit_array.byte_size(plaintext)
}

pub fn encrypting_nothing_yields_nothing_test() {
  assert chacha20.encrypt(
      bytes(sequential_key),
      1,
      bytes(sunscreen_nonce),
      <<>>,
    )
    == <<>>
}

// --- counter handling across block boundaries -------------------------------

pub fn the_keystream_is_the_concatenation_of_successive_blocks_test() {
  // 128 bytes spans exactly two blocks. If the counter failed to advance, the
  // second half would repeat the first, which is the catastrophic failure mode
  // for a stream cipher and must be pinned down explicitly.
  let key = bytes(sequential_key)
  let nonce = bytes(block_nonce)
  let expected =
    bit_array.concat([
      chacha20.block(key, 7, nonce),
      chacha20.block(key, 8, nonce),
    ])
  let produced = chacha20.encrypt(key, 7, nonce, <<0:size(1024)>>)
  assert produced == expected
}

pub fn the_two_halves_of_a_long_keystream_differ_test() {
  let produced =
    chacha20.encrypt(bytes(sequential_key), 1, bytes(block_nonce), <<
      0:size(1024),
    >>)
  let assert <<first:bytes-size(64), second:bytes-size(64)>> = produced
  assert first != second
}

pub fn a_partial_final_block_is_truncated_not_padded_test() {
  // 65 bytes uses all of block one and a single byte of block two.
  let key = bytes(sequential_key)
  let nonce = bytes(block_nonce)
  let produced = chacha20.encrypt(key, 1, nonce, <<0:size(520)>>)
  assert bit_array.byte_size(produced) == 65

  let assert <<whole:bytes-size(64), tail:bytes-size(1)>> = produced
  assert whole == chacha20.block(key, 1, nonce)
  let assert <<expected_tail:bytes-size(1), _:bits>> =
    chacha20.block(key, 2, nonce)
  assert tail == expected_tail
}

pub fn a_single_byte_message_uses_only_the_first_keystream_byte_test() {
  let key = bytes(sequential_key)
  let nonce = bytes(block_nonce)
  let assert <<first_keystream_byte:8, _:bits>> = chacha20.block(key, 1, nonce)
  let assert <<produced:8>> = chacha20.encrypt(key, 1, nonce, <<0xff>>)
  assert produced == int.bitwise_exclusive_or(0xff, first_keystream_byte)
}
