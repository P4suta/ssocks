//// Ways to be unkind to a decoder.
////
//// This is public on purpose. The hard part of using an incremental decoder is
//// not the decoder, it is everything around it: the buffer a caller keeps, the
//// loop that decides when to read again, the place where a partial frame is
//// held between reads. That code lives in the caller and breaks in the caller,
//// and it breaks only against real networks, where a read stops in the middle
//// of a length field once a week.
////
//// So the generators this library tests itself with are here rather than in
//// its test directory, and anybody wiring `ssocks/stream` into their own IO
//// can point them at their own loop.
////
//// ```gleam
//// use pieces <- list.each(testing.every_split(whole_stream))
//// assert feed_my_loop(pieces) == expected
//// ```
////
//// Nothing here is random unless a seed is given, and a seed reproduces a run
//// exactly on Erlang and on every JavaScript runtime — the generator is a
//// Lehmer sequence rather than the platform's, because the platform's differs
//// between them and a seed would stop meaning the same thing.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/list

/// Every two-way split, including the two that are not really splits.
///
/// For `n` bytes this is `n + 1` groupings: nothing then everything, one byte
/// then the rest, and so on. This is the cheapest test that finds a decoder
/// which assumes a field arrives whole, and it finds it deterministically
/// rather than one time in a hundred against a real network.
pub fn every_split(bytes: BitArray) -> List(List(BitArray)) {
  let total = bit_array.byte_size(bytes)
  use at <- list.map(counting_to(total))
  [slice(bytes, 0, at), slice(bytes, at, total - at)]
}

/// One byte at a time.
///
/// The worst case, and the one that walks every starvation path there is. Also
/// the shape most likely to overflow a stack in a loop written with
/// non-tail-recursion, which is a real failure on the JavaScript target and not
/// on Erlang.
pub fn single_bytes(bytes: BitArray) -> List(BitArray) {
  single_loop(bytes, [])
}

fn single_loop(bytes: BitArray, acc: List(BitArray)) -> List(BitArray) {
  case bytes {
    <<first:8, rest:bits>> -> single_loop(rest, [<<first:8>>, ..acc])
    _ -> list.reverse(acc)
  }
}

/// Split at random boundaries, `count` different ways.
///
/// Where `every_split` is exhaustive and two-way, this is arbitrary and
/// many-way: a grouping like the network actually produces, with a reproducible
/// seed so that a failure can be run again.
pub fn random_splits(
  bytes: BitArray,
  seed seed: Int,
  count count: Int,
) -> List(List(BitArray)) {
  splits_loop(bytes, normalise(seed), count, [])
}

fn splits_loop(
  bytes: BitArray,
  state: Int,
  remaining: Int,
  acc: List(List(BitArray)),
) -> List(List(BitArray)) {
  case remaining {
    n if n <= 0 -> list.reverse(acc)
    _ -> {
      let #(pieces, state) = chop(bytes, state, [])
      splits_loop(bytes, state, remaining - 1, [pieces, ..acc])
    }
  }
}

fn chop(
  remaining: BitArray,
  state: Int,
  acc: List(BitArray),
) -> #(List(BitArray), Int) {
  let available = bit_array.byte_size(remaining)
  case available {
    0 -> #(list.reverse(acc), state)
    _ -> {
      let #(taken, state) = between(state, 1, available)
      chop(slice(remaining, taken, available - taken), state, [
        slice(remaining, 0, taken),
        ..acc
      ])
    }
  }
}

/// The same bytes with one byte changed, once for every position.
///
/// A decoder must refuse all of these. Not crash on them, and not accept them:
/// an authenticated format that tolerates a flipped bit somewhere is not
/// authenticating that part.
pub fn corruptions(bytes: BitArray) -> List(#(Int, BitArray)) {
  let total = bit_array.byte_size(bytes)
  use at <- list.map(counting_to(total - 1))
  #(at, altered(bytes, at))
}

fn altered(bytes: BitArray, at: Int) -> BitArray {
  let total = bit_array.byte_size(bytes)
  let assert Ok(<<byte:8>>) = bit_array.slice(bytes, at, 1)
  bit_array.concat([
    slice(bytes, 0, at),
    <<int.bitwise_exclusive_or(byte, 0xff):8>>,
    slice(bytes, at + 1, total - at - 1),
  ])
}

/// The same bytes cut short, at every length.
///
/// Every one of these must leave a decoder waiting rather than failing, right
/// up to the last byte: a stream that has not finished arriving is the normal
/// case, not an error.
pub fn truncations(bytes: BitArray) -> List(BitArray) {
  let total = bit_array.byte_size(bytes)
  use keep <- list.map(counting_to(total))
  slice(bytes, 0, keep)
}

// --- a portable deterministic generator ----------------------------------------

/// Lehmer's minimal standard generator.
///
/// Chosen because its widest intermediate, 16807 times 2^31, is about 2^45.
/// Gleam integers are 64-bit floats on JavaScript and lose precision above
/// 2^53, so a more usual 32-bit generator would produce a different sequence
/// there and a seed would stop meaning the same run on both targets.
const multiplier = 16_807

const modulus = 2_147_483_647

fn normalise(seed: Int) -> Int {
  case int.absolute_value(seed) % { modulus - 1 } {
    0 -> 1
    value -> value
  }
}

fn between(state: Int, low: Int, high: Int) -> #(Int, Int) {
  let state = multiplier * state % modulus
  case high <= low {
    True -> #(low, state)
    False -> #(low + state % { high - low + 1 }, state)
  }
}

// --- small helpers -------------------------------------------------------------

fn counting_to(last: Int) -> List(Int) {
  counting_loop(last, [])
}

fn counting_loop(value: Int, acc: List(Int)) -> List(Int) {
  case value < 0 {
    True -> acc
    False -> counting_loop(value - 1, [value, ..acc])
  }
}

fn slice(bytes: BitArray, at: Int, size: Int) -> BitArray {
  case bit_array.slice(bytes, at, size) {
    Ok(sliced) -> sliced
    Error(Nil) -> <<>>
  }
}
