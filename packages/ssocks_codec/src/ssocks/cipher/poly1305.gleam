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
//// So the value is carried as limbs, and the limb width is chosen by what the
//// widest intermediate comes to. With `L` limbs of `w` bits each covering the
//// 130 bit accumulator, position `p` of a product is a sum of `L` terms, each
//// an accumulator limb — under 2^(w+1) once a block has been added — times a
//// coefficient, which is an `r` limb under 2^w times the wrap factor
//// 2^(L*w) mod 2^130 - 5.
////
//// | | widest | headroom under 2^53 | multiply-adds per block |
//// | --- | --- | --- | --- |
//// | 8-bit x 17 | 2^29.4 | 12600000x | 289 |
//// | 13-bit x 10 | 2^32.6 | 1340000x | 100 |
//// | 17-bit x 8 | 2^46.3 | 102x | 64 |
//// | 22-bit x 6 | 2^51.9 | 2x | 36 |
//// | 26-bit x 5 | 2^57.6 | none | 25 |
////
//// The last row is the layout every C implementation uses, and it is the reason
//// they are written with 64-bit accumulators. It cannot be used here: on
//// JavaScript it would lose bits, silently, on one target only.
////
//// Seventeen 8-bit limbs is where this started — the layout TweetNaCl uses.
//// Eight 17-bit limbs is the same arithmetic at the widest radix that still
//// leaves two orders of magnitude of headroom, and it does a quarter of the
//// multiplying. 22-bit and 16-bit are faster still and are not taken: a margin
//// of two is a margin that one unexamined carry could spend.
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

/// Limb count. Eight 17-bit limbs cover the 130 bit accumulator with room for
/// the carry the reduction needs — 136 bits in all. See the module header for
/// why the radix is this and not wider.
const limbs = 8

/// The radix, and the mask and shifts that follow from it.
const limb_bits = 17

const limb_mask = 131_071

/// 2^136 is congruent to 320 modulo 2^130 - 5, which is what a product wrapping
/// past the top limb is multiplied by.
const wrap = 320

/// 2^130 sits at bit 11 of the top limb, which covers bits 119 to 135.
const above_130 = 11

const below_130 = 2047

/// 2^136 - (2^130 - 5), so that adding it is subtracting the modulus.
///
/// 2^136 - 2^130 is 63 times 2^130, and 2^130 is bit 11 of the top limb, so the
/// top limb is 63 * 2^11.
const minus_p = [5, 0, 0, 0, 0, 0, 0, 129_024]

/// Authenticate `message` under a 32 byte one-time key, returning a 16 byte tag.
///
/// The key is one-time in the strict sense: authenticating two different
/// messages under the same key reveals the key. Callers must derive a fresh one
/// per message, which is what the AEAD construction above this does.
pub fn mac(key: BitArray, message: BitArray) -> BitArray {
  let assert <<r_bytes:bytes-size(16), s_bytes:bytes-size(16)>> = key

  let r = limbs_of(clamp(r_bytes))
  let s = limbs_of(s_bytes)

  // The coefficient rows depend only on `r`, which is fixed for the whole
  // message, so they are built once here rather than once per limb position per
  // block — which is what `multiply` used to do. Rebuilding them was Θ(n) list
  // construction in the length of the message for something that is Θ(1); the
  // arithmetic below is unchanged, it just stops re-deriving its own operands.
  list.repeat(0, limbs)
  |> accumulate(rows(r), message)
  |> reduce_once
  |> add(s)
  |> to_tag
}

/// Clear the bits the specification requires to be zero.
///
/// Bytes 3, 7, 11 and 15 keep their low four bits; bytes 4, 8 and 12 lose their
/// low two. This is what bounds the products so the polynomial evaluation
/// cannot overflow. It is done on the bytes because that is the unit the
/// specification names them in; the limbs no longer line up with them.
fn clamp(r: BitArray) -> BitArray {
  let assert <<
    b0:8,
    b1:8,
    b2:8,
    b3:8,
    b4:8,
    b5:8,
    b6:8,
    b7:8,
    b8:8,
    b9:8,
    b10:8,
    b11:8,
    b12:8,
    b13:8,
    b14:8,
    b15:8,
  >> = r

  <<
    b0:8,
    b1:8,
    b2:8,
    { int.bitwise_and(b3, 15) }:8,
    { int.bitwise_and(b4, 252) }:8,
    b5:8,
    b6:8,
    { int.bitwise_and(b7, 15) }:8,
    { int.bitwise_and(b8, 252) }:8,
    b9:8,
    b10:8,
    { int.bitwise_and(b11, 15) }:8,
    { int.bitwise_and(b12, 252) }:8,
    b13:8,
    b14:8,
    { int.bitwise_and(b15, 15) }:8,
  >>
}

/// Fold every 16 byte block of the message into the accumulator.
fn accumulate(
  accumulator: List(Int),
  rows: List(List(Int)),
  message: BitArray,
) -> List(Int) {
  case message {
    <<>> -> accumulator
    <<whole:bytes-size(16), rest:bits>> ->
      accumulator
      |> add(whole_block(whole))
      |> multiply(rows)
      |> accumulate(rows, rest)
    partial ->
      accumulator
      |> add(final_block(partial))
      |> multiply(rows)
  }
}

/// A whole block, with the mandatory 1 bit at 2^128.
fn whole_block(block: BitArray) -> List(Int) {
  case limbs_of(block) {
    // 2^128 is bit 9 of the top limb, which covers bits 119 to 135.
    [l0, l1, l2, l3, l4, l5, l6, l7] -> [l0, l1, l2, l3, l4, l5, l6, l7 + 512]
    other -> other
  }
}

/// A short final block, with the 1 bit immediately after the data.
///
/// Where that 1 lands is what makes a truncated message authenticate
/// differently from a padded one. Appending the byte and filling the rest of
/// the block with zeros puts it in exactly that place, and lets one packing
/// serve both kinds of block — worth more than saving the fill, which happens
/// once per message rather than once per block.
fn final_block(block: BitArray) -> List(Int) {
  let filling = 15 - bit_array.byte_size(block)
  limbs_of(bit_array.concat([block, <<1>>, ..list.repeat(<<0>>, filling)]))
}

/// Sixteen bytes as eight limbs, least significant first.
///
/// Poly1305 reads a block as a little-endian number, so turning the bytes round
/// puts the most significant bit first and lets the limbs be read off as plain
/// bit fields. Nine bits at the top rather than seventeen because 128 is seven
/// seventeens and nine.
fn limbs_of(block: BitArray) -> List(Int) {
  let assert <<
    b0:8,
    b1:8,
    b2:8,
    b3:8,
    b4:8,
    b5:8,
    b6:8,
    b7:8,
    b8:8,
    b9:8,
    b10:8,
    b11:8,
    b12:8,
    b13:8,
    b14:8,
    b15:8,
  >> = block

  let assert <<l7:9, l6:17, l5:17, l4:17, l3:17, l2:17, l1:17, l0:17>> = <<
    b15:8,
    b14:8,
    b13:8,
    b12:8,
    b11:8,
    b10:8,
    b9:8,
    b8:8,
    b7:8,
    b6:8,
    b5:8,
    b4:8,
    b3:8,
    b2:8,
    b1:8,
    b0:8,
  >>

  [l0, l1, l2, l3, l4, l5, l6, l7]
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
      add_loop(left_rest, right_rest, int.bitwise_shift_right(sum, limb_bits), [
        int.bitwise_and(sum, limb_mask),
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
fn multiply(accumulator: List(Int), rows: List(List(Int))) -> List(Int) {
  // One row per limb position, in order, so this walks exactly the positions
  // the product needs.
  rows
  |> list.map(fn(row) { dot(accumulator, row) })
  |> squeeze
}

/// The coefficient row for every limb position, built once per message.
///
/// `r` has one entry per limb position, so walking it with its own index walks
/// exactly the positions a product needs.
fn rows(r: List(Int)) -> List(List(Int)) {
  list.index_map(r, fn(_, position) { coefficients(r, position) })
}

fn coefficients(r: List(Int), position: Int) -> List(Int) {
  let below = r |> list.take(position + 1) |> list.reverse
  let above =
    r
    |> list.drop(position + 1)
    |> list.reverse
    |> list.map(fn(limb) { wrap * limb })
  list.append(below, above)
}

fn dot(left: List(Int), right: List(Int)) -> Int {
  list.map2(left, right, fn(a, b) { a * b }) |> int.sum
}

/// Carry the wide products back down to single limbs, folding anything above
/// 2^130 back in as a multiple of 5.
fn squeeze(wide: List(Int)) -> List(Int) {
  let carried = carry_low(wide)
  let top = last_limb(carried)

  // Bits at 2^130 and above are congruent to 5 times their value below.
  let folded = 5 * int.bitwise_shift_right(top, above_130)
  let kept = int.bitwise_and(top, below_130)

  let #(low, spill) = carry_from(carried, folded)
  replace_last(low, kept + spill)
}

fn carry_low(wide: List(Int)) -> List(Int) {
  let #(low, spill) = carry_from(wide, 0)
  replace_last(low, spill + last_limb(wide))
}

/// Walk all but the top limb propagating a carry, and report what falls off the
/// end. The top limb is handled by the caller because the two uses treat it
/// differently.
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
      carry_loop(rest, int.bitwise_shift_right(sum, limb_bits), [
        int.bitwise_and(sum, limb_mask),
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
  let borrowed = int.bitwise_shift_right(last_limb(subtracted), limb_bits - 1)
  let keep_original = borrowed * limb_mask

  use original, reduced <- list.map2(accumulator, subtracted)
  int.bitwise_exclusive_or(
    reduced,
    int.bitwise_and(keep_original, int.bitwise_exclusive_or(original, reduced)),
  )
}

/// The low 128 bits, as sixteen little-endian bytes.
///
/// The top limb carries two bits above the tag, and they are dropped here
/// rather than reduced away: the tag is the accumulator modulo 2^128, which is
/// what the specification asks for once the key's second half has been added.
fn to_tag(accumulator: List(Int)) -> BitArray {
  let assert [l0, l1, l2, l3, l4, l5, l6, l7] = accumulator

  let assert <<
    b15:8,
    b14:8,
    b13:8,
    b12:8,
    b11:8,
    b10:8,
    b9:8,
    b8:8,
    b7:8,
    b6:8,
    b5:8,
    b4:8,
    b3:8,
    b2:8,
    b1:8,
    b0:8,
  >> = <<
    { int.bitwise_and(l7, 511) }:9,
    l6:17,
    l5:17,
    l4:17,
    l3:17,
    l2:17,
    l1:17,
    l0:17,
  >>

  <<
    b0:8,
    b1:8,
    b2:8,
    b3:8,
    b4:8,
    b5:8,
    b6:8,
    b7:8,
    b8:8,
    b9:8,
    b10:8,
    b11:8,
    b12:8,
    b13:8,
    b14:8,
    b15:8,
  >>
}

// --- small list and byte helpers -------------------------------------------

fn last_limb(value: List(Int)) -> Int {
  case list.last(value) {
    Ok(limb) -> limb
    Error(_) -> 0
  }
}

fn replace_last(low: List(Int), top: Int) -> List(Int) {
  list.append(low, [top])
}
