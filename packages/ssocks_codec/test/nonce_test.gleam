//// The nonce counter, tested on its own.
////
//// This is the single most consequential fact in the whole wire format, and it
//// is not written down in the Shadowsocks AEAD specification prose. The counter
//// is **little-endian**: the first byte increments first. Meanwhile the payload
//// length field in the same protocol is **big-endian**. Implementations that
//// get this backwards produce frames that decrypt correctly against themselves
//// and against nothing else.
////
//// It is verified here rather than implicitly inside the framing state machine,
//// because a decoder test that fails from a reversed nonce looks exactly like
//// one that fails from wrong framing.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import ssocks/nonce
import vector.{bytes}

fn advanced(times: Int) -> BitArray {
  advance_loop(nonce.zero(), times) |> nonce.to_bytes
}

fn advance_loop(from: nonce.Nonce, times: Int) -> nonce.Nonce {
  case times {
    0 -> from
    _ -> advance_loop(nonce.next(from), times - 1)
  }
}

fn from(text: String) -> nonce.Nonce {
  let assert Ok(value) = nonce.from_bytes(bytes(text))
  value
}

// --- the direction, stated as plainly as possible ---------------------------

pub fn a_fresh_nonce_is_twelve_zero_bytes_test() {
  assert nonce.to_bytes(nonce.zero()) == bytes("000000000000000000000000")
}

pub fn incrementing_changes_the_first_byte_not_the_last_test() {
  // If this ever reads 000000000000000000000001, the counter has been made
  // big-endian and nothing will interoperate.
  assert advanced(1) == bytes("010000000000000000000000")
  assert advanced(2) == bytes("020000000000000000000000")
  assert advanced(9) == bytes("090000000000000000000000")
}

pub fn the_first_byte_fills_before_anything_else_moves_test() {
  assert advanced(254) == bytes("fe0000000000000000000000")
  assert advanced(255) == bytes("ff0000000000000000000000")
}

// --- carries ----------------------------------------------------------------

pub fn a_full_first_byte_carries_into_the_second_test() {
  assert advanced(256) == bytes("000100000000000000000000")
  assert advanced(257) == bytes("010100000000000000000000")
}

pub fn a_carry_propagates_across_two_byte_boundaries_at_once_test() {
  // 0xffff + 1 has to move the third byte, not just the second.
  assert nonce.next(from("ffff00000000000000000000")) |> nonce.to_bytes
    == bytes("000001000000000000000000")
}

pub fn a_carry_propagates_the_whole_way_up_test() {
  assert nonce.next(from("ffffffffffffffffffffff00")) |> nonce.to_bytes
    == bytes("000000000000000000000001")
}

pub fn the_counter_wraps_to_zero_when_every_byte_is_full_test() {
  // 2^96 nonces is unreachable in practice. Wrapping rather than growing keeps
  // the value twelve bytes wide no matter what, which is what the cipher needs.
  assert nonce.next(from("ffffffffffffffffffffffff")) |> nonce.to_bytes
    == bytes("000000000000000000000000")
}

// --- structure ---------------------------------------------------------------

pub fn a_nonce_is_always_twelve_bytes_test() {
  use times <- list.each([0, 1, 255, 256, 65_535, 65_536])
  assert bit_array.byte_size(advanced(times)) == 12
}

pub fn from_bytes_accepts_exactly_twelve_bytes_test() {
  assert nonce.from_bytes(bytes("000000000000000000000000")) |> is_ok
  assert nonce.from_bytes(bytes("0000000000000000000000")) == Error(Nil)
  assert nonce.from_bytes(bytes("00000000000000000000000000")) == Error(Nil)
  assert nonce.from_bytes(<<>>) == Error(Nil)
}

pub fn round_tripping_through_bytes_preserves_the_value_test() {
  let value = from("0102030405060708090a0b0c")
  let assert Ok(again) = nonce.from_bytes(nonce.to_bytes(value))
  assert nonce.to_bytes(again) == nonce.to_bytes(value)
}

// --- the property the whole construction rests on ---------------------------

pub fn successive_nonces_never_repeat_test() {
  // Reusing a nonce under one key is the catastrophic failure for AEAD. Over a
  // short run the counter must produce nothing but fresh values.
  let produced = collect(nonce.zero(), 600, [])
  assert list.length(produced) == 600
  assert list.length(list.unique(produced)) == 600
}

fn collect(
  from: nonce.Nonce,
  remaining: Int,
  acc: List(BitArray),
) -> List(BitArray) {
  case remaining {
    0 -> acc
    _ -> collect(nonce.next(from), remaining - 1, [nonce.to_bytes(from), ..acc])
  }
}

fn is_ok(result: Result(a, b)) -> Bool {
  case result {
    Ok(_) -> True
    Error(_) -> False
  }
}
