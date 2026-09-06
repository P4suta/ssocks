//// ChaCha20 as specified in RFC 8439, in portable Gleam.
////
//// Bun ships no ChaCha20 at all, so a platform-independent implementation is
//// what lets the codec keep its promise of running everywhere. It is also
//// useful where the platform does have one: two independent implementations
//// that must agree byte for byte is the strongest routine check available, and
//// the AEAD layer uses this one as a second opinion on the native cipher.
////
//// ### Integer widths
////
//// Gleam integers are arbitrary precision on Erlang and 64-bit floats on
//// JavaScript, so anything above 2^53 diverges between targets. This code stays
//// well inside that bound. Words are masked to 32 bits after every operation,
//// additions of two such words reach at most 2^33, and the largest shift is 16
//// places, which peaks at 2^48. Bitwise operations themselves are exact on both
//// targets. Every mask below is load bearing: without one, the Erlang target
//// would quietly carry oversized words rather than wrap.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/list

const word_mask = 0xffffffff

/// The ChaCha state, sixteen 32-bit words.
///
/// Written out as named fields rather than a list because the round function
/// addresses fixed positions. Naming them lets `double_round` read the same way
/// the specification does, which is what makes it checkable by eye.
type State {
  State(
    x0: Int,
    x1: Int,
    x2: Int,
    x3: Int,
    x4: Int,
    x5: Int,
    x6: Int,
    x7: Int,
    x8: Int,
    x9: Int,
    x10: Int,
    x11: Int,
    x12: Int,
    x13: Int,
    x14: Int,
    x15: Int,
  )
}

/// The ChaCha quarter round, RFC 8439 section 2.1.
pub fn quarter_round(a: Int, b: Int, c: Int, d: Int) -> #(Int, Int, Int, Int) {
  let a = add(a, b)
  let d = rotate(int.bitwise_exclusive_or(d, a), 16)

  let c = add(c, d)
  let b = rotate(int.bitwise_exclusive_or(b, c), 12)

  let a = add(a, b)
  let d = rotate(int.bitwise_exclusive_or(d, a), 8)

  let c = add(c, d)
  let b = rotate(int.bitwise_exclusive_or(b, c), 7)

  #(a, b, c, d)
}

fn add(a: Int, b: Int) -> Int {
  int.bitwise_and(a + b, word_mask)
}

fn rotate(value: Int, places: Int) -> Int {
  let left = int.bitwise_and(int.bitwise_shift_left(value, places), word_mask)
  let right = int.bitwise_shift_right(value, 32 - places)
  int.bitwise_or(left, right)
}

/// Produce the 64 byte keystream block for one counter value.
///
/// The key is 32 bytes and the nonce 12, both read as little-endian words. The
/// counter occupies word twelve.
pub fn block(key: BitArray, counter: Int, nonce: BitArray) -> BitArray {
  let initial = initial_state(key, counter, nonce)
  initial |> twenty_rounds |> add_state(initial) |> serialise
}

fn initial_state(key: BitArray, counter: Int, nonce: BitArray) -> State {
  // The four constants spell "expand 32-byte k" in ASCII.
  let assert <<
    k0:32-little,
    k1:32-little,
    k2:32-little,
    k3:32-little,
    k4:32-little,
    k5:32-little,
    k6:32-little,
    k7:32-little,
  >> = key
  let assert <<n0:32-little, n1:32-little, n2:32-little>> = nonce

  State(
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574,
    k0,
    k1,
    k2,
    k3,
    k4,
    k5,
    k6,
    k7,
    int.bitwise_and(counter, word_mask),
    n0,
    n1,
    n2,
  )
}

fn twenty_rounds(state: State) -> State {
  // Twenty rounds is ten column-and-diagonal pairs.
  state
  |> double_round
  |> double_round
  |> double_round
  |> double_round
  |> double_round
  |> double_round
  |> double_round
  |> double_round
  |> double_round
  |> double_round
}

fn double_round(s: State) -> State {
  // Column round.
  let #(x0, x4, x8, x12) = quarter_round(s.x0, s.x4, s.x8, s.x12)
  let #(x1, x5, x9, x13) = quarter_round(s.x1, s.x5, s.x9, s.x13)
  let #(x2, x6, x10, x14) = quarter_round(s.x2, s.x6, s.x10, s.x14)
  let #(x3, x7, x11, x15) = quarter_round(s.x3, s.x7, s.x11, s.x15)

  // Diagonal round.
  let #(x0, x5, x10, x15) = quarter_round(x0, x5, x10, x15)
  let #(x1, x6, x11, x12) = quarter_round(x1, x6, x11, x12)
  let #(x2, x7, x8, x13) = quarter_round(x2, x7, x8, x13)
  let #(x3, x4, x9, x14) = quarter_round(x3, x4, x9, x14)

  State(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)
}

/// Add the pre-round state back in. This is what stops the permutation from
/// being invertible, so omitting it would be a total break rather than a
/// wrong-looking output.
fn add_state(worked: State, initial: State) -> State {
  State(
    add(worked.x0, initial.x0),
    add(worked.x1, initial.x1),
    add(worked.x2, initial.x2),
    add(worked.x3, initial.x3),
    add(worked.x4, initial.x4),
    add(worked.x5, initial.x5),
    add(worked.x6, initial.x6),
    add(worked.x7, initial.x7),
    add(worked.x8, initial.x8),
    add(worked.x9, initial.x9),
    add(worked.x10, initial.x10),
    add(worked.x11, initial.x11),
    add(worked.x12, initial.x12),
    add(worked.x13, initial.x13),
    add(worked.x14, initial.x14),
    add(worked.x15, initial.x15),
  )
}

fn serialise(s: State) -> BitArray {
  <<
    s.x0:32-little,
    s.x1:32-little,
    s.x2:32-little,
    s.x3:32-little,
    s.x4:32-little,
    s.x5:32-little,
    s.x6:32-little,
    s.x7:32-little,
    s.x8:32-little,
    s.x9:32-little,
    s.x10:32-little,
    s.x11:32-little,
    s.x12:32-little,
    s.x13:32-little,
    s.x14:32-little,
    s.x15:32-little,
  >>
}

/// Encrypt or decrypt: the cipher is a keystream XOR, so one direction serves
/// both. `counter` is the block counter the first 64 bytes are keyed with.
pub fn encrypt(
  key: BitArray,
  counter: Int,
  nonce: BitArray,
  message: BitArray,
) -> BitArray {
  encrypt_loop(key, counter, nonce, message, [])
}

fn encrypt_loop(
  key: BitArray,
  counter: Int,
  nonce: BitArray,
  message: BitArray,
  acc: List(BitArray),
) -> BitArray {
  case message {
    <<>> -> joined(acc)
    <<whole:bytes-size(64), rest:bits>> ->
      encrypt_loop(key, int.bitwise_and(counter + 1, word_mask), nonce, rest, [
        xor(whole, block(key, counter, nonce)),
        ..acc
      ])
    partial -> {
      // The final block is truncated to the remaining length, never padded.
      let keystream = block(key, counter, nonce)
      let assert Ok(trimmed) =
        bit_array.slice(keystream, 0, bit_array.byte_size(partial))
      joined([xor(partial, trimmed), ..acc])
    }
  }
}

fn joined(acc: List(BitArray)) -> BitArray {
  acc |> list.reverse |> bit_array.concat
}

/// Combine a message with an equal length slice of keystream.
///
/// Both arguments must be the same length; `encrypt_loop` guarantees this by
/// trimming the keystream to the message before calling. The loop stops when
/// either side runs out, so a mismatch would silently shorten the output rather
/// than complain, which is why the trimming and this function stay adjacent.
///
/// A word-at-a-time fast path used to live here. It was removed: this cipher
/// only runs where the platform has none, the block function dominates the cost
/// either way, and one code path is one fewer place for an ordering mistake to
/// hide in something security relevant.
fn xor(left: BitArray, right: BitArray) -> BitArray {
  xor_loop(left, right, [])
}

fn xor_loop(left: BitArray, right: BitArray, acc: List(BitArray)) -> BitArray {
  case left, right {
    <<a:8, left_rest:bits>>, <<b:8, right_rest:bits>> ->
      xor_loop(left_rest, right_rest, [
        <<int.bitwise_exclusive_or(a, b):8>>,
        ..acc
      ])
    _, _ -> joined(acc)
  }
}
