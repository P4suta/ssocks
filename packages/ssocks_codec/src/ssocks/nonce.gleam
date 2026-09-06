//// The 96-bit AEAD nonce counter.
////
//// Shadowsocks starts every session at zero and advances by one after each
//// AEAD operation, which means twice per TCP chunk: once for the length header
//// and once for the payload.
////
//// ### The direction
////
//// The counter is **little-endian**. The first byte increments first and carries
//// into the second. This is not stated in the Shadowsocks AEAD prose; it is
//// what the reference implementations do, and it is easy to get backwards
//// because the payload length field in the very same protocol is big-endian.
//// An implementation that reverses it interoperates with itself and with
//// nothing else, so the direction has its own tests rather than being implied
//// by the framing.
////
//// ### Why this is a type
////
//// Reusing a nonce under one key is the catastrophic failure for AEAD: it
//// leaks the keystream, and for Poly1305 it leaks the authentication key. There
//// is deliberately no way to set a counter to an arbitrary value from outside a
//// session. `from_bytes` exists for tests and diagnostics, and nothing in the
//// codec accepts a nonce from a caller.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list

/// How many bytes wide the counter is.
pub const size = 12

/// A nonce counter. Advance it with `next`; there is no way to rewind one.
pub opaque type Nonce {
  Nonce(bytes: BitArray)
}

/// The value every session starts from.
pub fn zero() -> Nonce {
  Nonce(<<0:size(size * 8)>>)
}

/// The next counter value.
///
/// Wraps to zero after 2^96 increments. That is unreachable in practice, and
/// wrapping keeps the value exactly `size` bytes wide whatever happens, which
/// is what the cipher requires.
pub fn next(counter: Nonce) -> Nonce {
  Nonce(increment(counter.bytes, []))
}

/// Add one starting from the first byte, carrying upward while bytes are full.
fn increment(remaining: BitArray, done: List(BitArray)) -> BitArray {
  case remaining {
    // Every byte was 0xff, so the carry ran off the end and the counter wraps.
    <<>> -> rejoin(done, <<>>)
    <<0xff:8, rest:bits>> -> increment(rest, [<<0:8>>, ..done])
    // This byte absorbed the carry, so everything above it is untouched.
    <<byte:8, rest:bits>> -> rejoin([<<{ byte + 1 }:8>>, ..done], rest)
    _ -> rejoin(done, <<>>)
  }
}

fn rejoin(done: List(BitArray), untouched: BitArray) -> BitArray {
  done |> list.reverse |> list.append([untouched]) |> bit_array.concat
}

/// The counter as the bytes the cipher is given.
pub fn to_bytes(counter: Nonce) -> BitArray {
  counter.bytes
}

/// Build a counter from exactly `size` bytes.
///
/// For tests and diagnostics. No part of the codec takes a nonce from a caller,
/// so this cannot be used to force a repeat within a live session.
pub fn from_bytes(candidate: BitArray) -> Result(Nonce, Nil) {
  case bit_array.byte_size(candidate) == size {
    True -> Ok(Nonce(candidate))
    False -> Error(Nil)
  }
}
