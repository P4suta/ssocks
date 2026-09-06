//// Poly1305 as specified in RFC 8439, in portable Gleam.
////
//// ### Why limbs
////
//// Poly1305 is arithmetic modulo 2^130 - 5. Gleam integers are arbitrary
//// precision on Erlang but 64-bit floats on JavaScript, where anything above
//// 2^53 silently loses precision. Holding the accumulator as one number would
//// therefore produce correct tags on Erlang and wrong ones on JavaScript, which
//// is the worst shape a bug can have.
////
//// So the value is carried as seventeen 8-bit limbs, the layout TweetNaCl uses.
//// The widest intermediate is one limb times 320 times another limb, summed
//// seventeen times: at most 255 * 320 * 255 * 17, a little over 2^28. That is
//// three orders of magnitude inside the float64 exact range, so both targets
//// compute the same thing rather than merely agreeing on the test vectors.
////
//// ### Why a convolution
////
//// The reference implementation indexes `r` backwards inside the inner loop.
//// Lists do not index cheaply, so the same product is expressed as a dot
//// product against a per-position coefficient list built by reversing slices of
//// `r`. It computes exactly the reference expression, in list operations.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/list

/// Limb count. Seventeen 8-bit limbs cover the 130 bit accumulator with room
/// for the carry the reduction needs.
const limbs = 17

/// 2^136 - (2^130 - 5), so that adding it is subtracting the modulus.
const minus_p = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]

/// Authenticate `message` under a 32 byte one-time key, returning a 16 byte tag.
///
/// The key is one-time in the strict sense: authenticating two different
/// messages under the same key reveals the key. Callers must derive a fresh one
/// per message, which is what the AEAD construction above this does.
pub fn mac(key: BitArray, message: BitArray) -> BitArray {
  let assert <<r_bytes:bytes-size(16), s_bytes:bytes-size(16)>> = key

  let r = clamp(pad_to_limbs(to_list(r_bytes)))
  let s = pad_to_limbs(to_list(s_bytes))

  list.repeat(0, limbs)
  |> accumulate(r, message)
  |> reduce_once
  |> add(s)
  |> to_tag
}

/// Clear the bits the specification requires to be zero.
///
/// Limbs 3, 7, 11 and 15 keep their low four bits; limbs 4, 8 and 12 lose their
/// low two. This is what bounds the products so the polynomial evaluation
/// cannot overflow.
fn clamp(r: List(Int)) -> List(Int) {
  use limb, index <- list.index_map(r)
  case index {
    3 | 7 | 11 | 15 -> int.bitwise_and(limb, 15)
    4 | 8 | 12 -> int.bitwise_and(limb, 252)
    _ -> limb
  }
}

/// Fold every 16 byte block of the message into the accumulator.
fn accumulate(
  accumulator: List(Int),
  r: List(Int),
  message: BitArray,
) -> List(Int) {
  case message {
    <<>> -> accumulator
    <<whole:bytes-size(16), rest:bits>> ->
      accumulator
      |> add(block_limbs(to_list(whole), 16))
      |> multiply(r)
      |> accumulate(r, rest)
    partial -> {
      let bytes = to_list(partial)
      accumulator
      |> add(block_limbs(bytes, list.length(bytes)))
      |> multiply(r)
    }
  }
}

/// A message block as limbs, with the mandatory 1 bit just past its last byte.
///
/// For a whole block that 1 lands in limb sixteen. For a short final block it
/// lands immediately after the data, which is what makes a truncated message
/// authenticate differently from a padded one.
fn block_limbs(bytes: List(Int), length: Int) -> List(Int) {
  list.flatten([bytes, [1], list.repeat(0, limbs - length - 1)])
}

/// Add two limb vectors, propagating carries.
fn add(left: List(Int), right: List(Int)) -> List(Int) {
  add_loop(left, right, 0, [])
}

fn add_loop(
  left: List(Int),
  right: List(Int),
  carry: Int,
  acc: List(Int),
) -> List(Int) {
  case left, right {
    [a, ..left_rest], [b, ..right_rest] -> {
      let sum = carry + a + b
      add_loop(left_rest, right_rest, int.bitwise_shift_right(sum, 8), [
        int.bitwise_and(sum, 255),
        ..acc
      ])
    }
    _, _ -> list.reverse(acc)
  }
}

/// Multiply the accumulator by r modulo 2^130 - 5.
///
/// Position `i` of the product is the dot product of the accumulator with a
/// coefficient list: the first `i + 1` entries of `r` reversed, followed by the
/// remainder reversed and scaled by 320. The 320 is the modular fold, since
/// 2^136 is congruent to 320 modulo 2^130 - 5 at this limb width.
fn multiply(accumulator: List(Int), r: List(Int)) -> List(Int) {
  // The accumulator already has one entry per limb position, so mapping over it
  // with its own index walks exactly the positions the product needs.
  accumulator
  |> list.index_map(fn(_, position) {
    dot(accumulator, coefficients(r, position))
  })
  |> squeeze
}

fn coefficients(r: List(Int), position: Int) -> List(Int) {
  let below = r |> list.take(position + 1) |> list.reverse
  let above =
    r
    |> list.drop(position + 1)
    |> list.reverse
    |> list.map(fn(limb) { 320 * limb })
  list.append(below, above)
}

fn dot(left: List(Int), right: List(Int)) -> Int {
  list.map2(left, right, fn(a, b) { a * b }) |> int.sum
}

/// Carry the wide products back down to 8-bit limbs, folding anything above
/// 2^130 back in as a multiple of 5.
fn squeeze(wide: List(Int)) -> List(Int) {
  let carried = carry_low(wide)
  let top = last_limb(carried)

  // Bits at 2^130 and above are congruent to 5 times their value below.
  let folded = 5 * int.bitwise_shift_right(top, 2)
  let kept = int.bitwise_and(top, 3)

  let #(low, spill) = carry_from(carried, folded)
  replace_last(low, kept + spill)
}

fn carry_low(wide: List(Int)) -> List(Int) {
  let #(low, spill) = carry_from(wide, 0)
  replace_last(low, spill + last_limb(wide))
}

/// Walk the low sixteen limbs propagating a carry, and report what falls off
/// the end. The seventeenth limb is handled by the caller because the two uses
/// treat it differently.
fn carry_from(value: List(Int), initial: Int) -> #(List(Int), Int) {
  carry_loop(list.take(value, limbs - 1), initial, [])
}

fn carry_loop(
  value: List(Int),
  carry: Int,
  acc: List(Int),
) -> #(List(Int), Int) {
  case value {
    [] -> #(list.reverse(acc), carry)
    [limb, ..rest] -> {
      let sum = carry + limb
      carry_loop(rest, int.bitwise_shift_right(sum, 8), [
        int.bitwise_and(sum, 255),
        ..acc
      ])
    }
  }
}

/// Subtract the modulus once if the accumulator is at least as large as it.
///
/// Both candidates are computed and one is selected with a mask rather than a
/// branch, so the choice does not depend on secret data through control flow.
fn reduce_once(accumulator: List(Int)) -> List(Int) {
  let subtracted = add(accumulator, minus_p)

  // Adding `minus_p` is subtracting the modulus in 2^136 arithmetic. If the
  // accumulator was smaller than the modulus the result borrows, which shows up
  // as the top bit of the last limb being set.
  let borrowed = int.bitwise_shift_right(last_limb(subtracted), 7)
  let keep_original = borrowed * 255

  use original, reduced <- list.map2(accumulator, subtracted)
  int.bitwise_exclusive_or(
    reduced,
    int.bitwise_and(keep_original, int.bitwise_exclusive_or(original, reduced)),
  )
}

fn to_tag(accumulator: List(Int)) -> BitArray {
  accumulator
  |> list.take(16)
  |> list.map(fn(limb) { <<limb:8>> })
  |> bit_array.concat
}

// --- small list and byte helpers -------------------------------------------

fn to_list(bytes: BitArray) -> List(Int) {
  to_list_loop(bytes, [])
}

fn to_list_loop(bytes: BitArray, acc: List(Int)) -> List(Int) {
  case bytes {
    <<byte:8, rest:bits>> -> to_list_loop(rest, [byte, ..acc])
    _ -> list.reverse(acc)
  }
}

fn pad_to_limbs(bytes: List(Int)) -> List(Int) {
  list.append(bytes, list.repeat(0, limbs - list.length(bytes)))
}

fn last_limb(value: List(Int)) -> Int {
  case list.last(value) {
    Ok(limb) -> limb
    Error(_) -> 0
  }
}

fn replace_last(low: List(Int), top: Int) -> List(Int) {
  list.append(low, [top])
}
