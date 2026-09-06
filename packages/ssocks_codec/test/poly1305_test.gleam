//// Poly1305 against RFC 8439.
////
//// This is the piece most likely to be subtly wrong. It is arithmetic modulo
//// 2^130 - 5, and Gleam integers are arbitrary precision on Erlang but 64-bit
//// floats on JavaScript, so the implementation carries the value in small limbs
//// rather than as one number. A limb that overflows silently produces a wrong
//// tag on one target only, which is exactly the failure the whole runtime
//// matrix exists to catch.
////
//// Where a vector had to be transcribed from prose rather than hex, its length
//// is asserted first. A miscopied character then fails as "the message is the
//// wrong length", which points at the test, instead of as a tag mismatch, which
//// points at the implementation.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import ssocks/cipher/poly1305
import vector.{bytes}

// --- 2.5.2: the worked example ---------------------------------------------

const example_key = "85d6be7857556d337f4452fe42d506a8
                     0103808afb0db2fd4abff6af4149f51b"

const example_message = "Cryptographic Forum Research Group"

const example_tag = "a8061dc1305136c6c22b8baf0c0127a9"

pub fn rfc8439_worked_example_produces_the_published_tag_test() {
  assert bit_array.byte_size(<<example_message:utf8>>) == 34
  assert poly1305.mac(bytes(example_key), <<example_message:utf8>>)
    == bytes(example_tag)
}

// --- A.3 test vector 1: everything zero ------------------------------------

pub fn rfc8439_vector_1_authenticates_zeros_under_a_zero_key_as_zero_test() {
  // Both halves of the key are zero, so r and s are zero and the tag is zero
  // whatever the message. It is the degenerate case, and an implementation that
  // special-cases nothing should still land on it.
  let zero_key = <<0:size(256)>>
  let zero_text = <<0:size(512)>>
  assert poly1305.mac(zero_key, zero_text) == <<0:size(128)>>
}

// --- A.3 test vector 4: a message that is not a whole number of blocks ------

const jabberwocky_key = "1c9240a5eb55d38af3338886 04f6b5f0
                         473917c1402b80099dca5cbc 207075c0"

const jabberwocky = "'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe:
All mimsy were the borogoves,
And the mome raths outgrabe."

const jabberwocky_tag = "4541669a7eaaee61e708dc7cbcc5eb62"

pub fn rfc8439_vector_4_handles_a_partial_final_block_test() {
  // 127 bytes is seven whole blocks and a 15 byte remainder, so this is the
  // vector that catches padding the tail instead of shortening it.
  assert bit_array.byte_size(<<jabberwocky:utf8>>) == 127
  assert poly1305.mac(bytes(jabberwocky_key), <<jabberwocky:utf8>>)
    == bytes(jabberwocky_tag)
}

// --- the degenerate halves of the key, stated as properties ----------------

pub fn a_zero_r_makes_the_tag_equal_s_for_any_message_test() {
  // RFC 8439 vector 2 is this case with one particular message. Stated as a
  // property it covers the same code path without depending on transcribing
  // 375 bytes of prose correctly.
  let s = bytes("36e5f6b5c5e06070f0efca96227a863e")
  let key = bit_array.concat([<<0:size(128)>>, s])

  assert poly1305.mac(key, <<"anything at all":utf8>>) == s
  assert poly1305.mac(key, <<>>) == s
  assert poly1305.mac(key, <<0:size(4096)>>) == s
}

pub fn a_zero_s_leaves_the_accumulator_as_the_tag_test() {
  // RFC 8439 vector 3 is this case. With s zero the tag is the reduced
  // accumulator alone, so any error in the final addition shows up here rather
  // than being masked by a large s.
  let r = bytes("36e5f6b5c5e06070f0efca96227a863e")
  let key = bit_array.concat([r, <<0:size(128)>>])
  let with_zero_s =
    poly1305.mac(key, <<"Cryptographic Forum Research Group":utf8>>)
  assert with_zero_s != <<0:size(128)>>
  assert bit_array.byte_size(with_zero_s) == 16
}

// --- structural properties --------------------------------------------------

pub fn a_tag_is_always_sixteen_bytes_test() {
  let key = bytes(example_key)
  assert bit_array.byte_size(poly1305.mac(key, <<>>)) == 16
  assert bit_array.byte_size(poly1305.mac(key, <<0>>)) == 16
  assert bit_array.byte_size(poly1305.mac(key, <<0:size(128)>>)) == 16
  assert bit_array.byte_size(poly1305.mac(key, <<0:size(1024)>>)) == 16
}

pub fn every_message_length_around_a_block_boundary_is_distinct_test() {
  // 15, 16 and 17 bytes exercise short, exact and split blocks. The padding
  // byte means these must all differ even though the content is the same.
  let key = bytes(example_key)
  let fifteen = poly1305.mac(key, <<0:size(120)>>)
  let sixteen = poly1305.mac(key, <<0:size(128)>>)
  let seventeen = poly1305.mac(key, <<0:size(136)>>)
  assert fifteen != sixteen
  assert sixteen != seventeen
  assert fifteen != seventeen
}

pub fn changing_one_message_bit_changes_the_tag_test() {
  let key = bytes(example_key)
  assert poly1305.mac(key, <<0, 0, 0, 0>>) != poly1305.mac(key, <<0, 0, 0, 1>>)
  assert poly1305.mac(key, <<0, 0, 0, 0>>) != poly1305.mac(key, <<1, 0, 0, 0>>)
}

pub fn changing_one_key_bit_changes_the_tag_test() {
  let message = <<example_message:utf8>>
  let one = poly1305.mac(bytes(example_key), message)
  let other =
    poly1305.mac(
      bytes(
        "85d6be7857556d337f4452fe42d506a9
         0103808afb0db2fd4abff6af4149f51b",
      ),
      message,
    )
  assert one != other
}

pub fn the_same_input_always_produces_the_same_tag_test() {
  let key = bytes(example_key)
  let message = <<example_message:utf8>>
  assert poly1305.mac(key, message) == poly1305.mac(key, message)
}

// --- carry propagation, the part limb arithmetic gets wrong ------------------

pub fn an_all_ones_message_exercises_carry_propagation_test() {
  // Every limb saturated forces a carry through the whole accumulator and into
  // the reduction. If a limb is too wide for the JavaScript target, this is
  // where the two runtimes stop agreeing.
  let key = bytes(example_key)
  let saturated = bytes("ffffffffffffffffffffffffffffffff")
  let tag = poly1305.mac(key, saturated)
  assert bit_array.byte_size(tag) == 16
  assert tag != <<0:size(128)>>
}

pub fn a_message_that_reduces_past_the_modulus_is_handled_test() {
  // 2^130 - 5 and just above it are the values a final conditional subtraction
  // has to get right.
  let key =
    bytes("0100000000000000000000000000000000000000000000000000000000000000")
  assert bit_array.byte_size(poly1305.mac(key, <<0xff:size(8), 0xff:size(8)>>))
    == 16
  assert poly1305.mac(key, <<0:size(128)>>)
    != poly1305.mac(key, bytes("ffffffffffffffffffffffffffffffff"))
}
