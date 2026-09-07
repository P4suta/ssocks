//// Hostile input, in bulk.
////
//// Usage: `gleam run -m fuzz_smoke -- <rounds> <seed>`.
////
//// The property tests ask whether the codec is correct. This asks a narrower
//// and more operational question: can a peer make it fall over? Every decoder
//// here faces bytes chosen to be wrong in the ways that matter, and the only
//// acceptable answers are `Ok` and `Error`. A panic in a decoder is a denial of
//// service, because the bytes that trigger it come from whoever is connecting.
////
//// Three shapes of input are used, because random noise alone is a weak fuzzer
//// against a format with a salt at the front: noise never gets past the first
//// authentication, so it never exercises the framing at all.
////
////   - noise, which tests the outermost checks
////   - valid streams with one byte changed, which reach the AEAD
////   - valid streams truncated anywhere, which reach the starvation paths
////
//// The generator is a Lehmer sequence rather than the platform's, so a seed
//// reproduces a run exactly on Erlang and on every JavaScript runtime.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/bit_array
import gleam/int
import gleam/io
import gleam/list
import gleam/string
import ssocks/address
import ssocks/datagram
import ssocks/key
import ssocks/method
import ssocks/stream

pub fn main() -> Nil {
  case argv.load().arguments {
    [rounds, seed] -> {
      let assert Ok(rounds) = int.parse(rounds)
      let assert Ok(seed) = int.parse(seed)
      io.println(
        "fuzz_smoke: "
        <> int.to_string(rounds)
        <> " rounds, seed "
        <> int.to_string(seed),
      )

      let survived =
        noise(rounds, normalise_seed(seed), 0)
        + corruptions(rounds, normalise_seed(seed + 1), 0)
        + truncations(rounds, normalise_seed(seed + 2), 0)

      io.println(
        "fuzz_smoke: "
        <> int.to_string(survived)
        <> " hostile inputs handled without a crash",
      )
    }
    other -> {
      io.println(
        "fuzz_smoke: expected <rounds> <seed>, got " <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

fn session_key() -> key.Key {
  key.from_password(method.Aes256Gcm, "a fuzzing secret")
}

/// A valid stream to corrupt. Fixed content, so a failing round is reproducible
/// from the seed alone.
fn healthy_stream() -> BitArray {
  let #(encoder, salt) = stream.encoder(session_key())
  let #(_, framed) =
    stream.encode(encoder, <<
      "a payload of a reasonable length, twice over":utf8,
    >>)
  bit_array.concat([salt, framed])
}

// --- the three shapes ---------------------------------------------------------

fn noise(remaining: Int, state: Int, done: Int) -> Int {
  case remaining {
    0 -> done
    _ -> {
      let #(length, state) = between(state, 0, 400)
      let #(junk, state) = random_bytes(state, length, [])
      exercise(junk)
      noise(remaining - 1, state, done + 1)
    }
  }
}

fn corruptions(remaining: Int, state: Int, done: Int) -> Int {
  case remaining {
    0 -> done
    _ -> {
      let whole = healthy_stream()
      let size = bit_array.byte_size(whole)
      let #(at, state) = between(state, 0, size - 1)
      let #(delta, state) = between(state, 1, 255)
      exercise(alter(whole, at, delta))
      corruptions(remaining - 1, state, done + 1)
    }
  }
}

fn truncations(remaining: Int, state: Int, done: Int) -> Int {
  case remaining {
    0 -> done
    _ -> {
      let whole = healthy_stream()
      let #(keep, state) = between(state, 0, bit_array.byte_size(whole))
      let assert Ok(shortened) = bit_array.slice(whole, 0, keep)
      exercise(shortened)
      truncations(remaining - 1, state, done + 1)
    }
  }
}

/// Every decoder that takes bytes off a network, on one input.
///
/// The results are deliberately discarded. The assertion is that control
/// returns at all.
fn exercise(input: BitArray) -> Nil {
  let _ = stream.decode(stream.decoder(session_key()), input)
  let _ = feed_in_pieces(stream.decoder(session_key()), input)
  let _ = datagram.open(session_key(), input)
  let _ = datagram.salt_of(session_key(), input)
  let _ = address.decode(input)
  Nil
}

/// The same input again, one byte per call, which walks the starvation paths
/// that a single large call never reaches.
fn feed_in_pieces(decoder: stream.Decoder, input: BitArray) -> Nil {
  case input {
    <<first:8, rest:bits>> ->
      case stream.decode(decoder, <<first:8>>) {
        Ok(#(decoder, _)) -> feed_in_pieces(decoder, rest)
        Error(_) -> Nil
      }
    _ -> Nil
  }
}

fn alter(value: BitArray, at: Int, delta: Int) -> BitArray {
  let total = bit_array.byte_size(value)
  let assert Ok(head) = bit_array.slice(value, 0, at)
  let assert Ok(<<byte:8>>) = bit_array.slice(value, at, 1)
  let assert Ok(tail) = bit_array.slice(value, at + 1, total - at - 1)
  let changed = int.bitwise_exclusive_or(byte, delta)
  bit_array.concat([head, <<changed:8>>, tail])
}

// --- a portable deterministic generator ----------------------------------------

/// Lehmer's minimal standard generator.
///
/// Chosen because its widest intermediate, 16807 times 2^31, is about 2^45.
/// Gleam integers are 64-bit floats on JavaScript and lose precision above
/// 2^53, so a more usual 32-bit LCG would produce a different sequence there
/// and a seed would stop meaning the same run on both targets.
const multiplier = 16_807

const modulus = 2_147_483_647

fn normalise_seed(seed: Int) -> Int {
  case int.absolute_value(seed) % { modulus - 1 } {
    0 -> 1
    value -> value
  }
}

fn step(state: Int) -> Int {
  multiplier * state % modulus
}

fn between(state: Int, low: Int, high: Int) -> #(Int, Int) {
  let state = step(state)
  case high <= low {
    True -> #(low, state)
    False -> #(low + state % { high - low + 1 }, state)
  }
}

fn random_bytes(
  state: Int,
  count: Int,
  acc: List(BitArray),
) -> #(BitArray, Int) {
  case count {
    0 -> #(bit_array.concat(list.reverse(acc)), state)
    _ -> {
      let #(byte, state) = between(state, 0, 255)
      random_bytes(state, count - 1, [<<byte:8>>, ..acc])
    }
  }
}

@external(erlang, "erlang", "halt")
@external(javascript, "./property_smoke_ffi.mjs", "halt")
fn halt(code: Int) -> Nil
