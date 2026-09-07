// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/result
import ssocks/key
import ssocks/method
import ssocks/stream
import ssocks/testing

fn session() -> key.Key {
  key.from_password(method.Aes256Gcm, "a secret for chaos")
}

fn a_stream() -> BitArray {
  let #(encoder, salt) = stream.encoder(session())
  let #(_, framed) =
    stream.encode(encoder, <<"a payload of a reasonable length":utf8>>)
  bit_array.concat([salt, framed])
}

fn payload() -> BitArray {
  <<"a payload of a reasonable length":utf8>>
}

// --- the generators say what they say ------------------------------------------

pub fn every_split_covers_every_boundary_test() {
  let bytes = <<1, 2, 3, 4>>
  let splits = testing.every_split(bytes)

  // Five ways to cut four bytes in two, counting the two ends.
  assert list.length(splits) == 5
  assert list.first(splits) == Ok([<<>>, <<1, 2, 3, 4>>])
  assert list.last(splits) == Ok([<<1, 2, 3, 4>>, <<>>])
}

pub fn every_split_loses_nothing_test() {
  let bytes = a_stream()
  use pieces <- list.each(testing.every_split(bytes))
  assert bit_array.concat(pieces) == bytes
}

pub fn single_bytes_is_one_piece_per_byte_test() {
  let bytes = a_stream()
  let pieces = testing.single_bytes(bytes)

  assert list.length(pieces) == bit_array.byte_size(bytes)
  assert bit_array.concat(pieces) == bytes
}

pub fn random_splits_lose_nothing_and_repeat_with_a_seed_test() {
  let bytes = a_stream()

  let runs = testing.random_splits(bytes, seed: 4242, count: 20)
  assert list.length(runs) == 20
  list.each(runs, fn(pieces) {
    assert bit_array.concat(pieces) == bytes
  })

  // The same seed is the same run, which is what makes a failure reportable.
  assert testing.random_splits(bytes, seed: 4242, count: 20) == runs
  assert testing.random_splits(bytes, seed: 4243, count: 20) != runs
}

pub fn corruptions_change_exactly_one_byte_test() {
  let bytes = <<1, 2, 3, 4>>
  let changed = testing.corruptions(bytes)

  assert list.length(changed) == 4
  use pair <- list.each(changed)
  let #(at, altered) = pair
  assert bit_array.byte_size(altered) == 4
  assert altered != bytes
  assert bit_array.slice(altered, at, 1) != bit_array.slice(bytes, at, 1)
}

pub fn truncations_cover_every_length_test() {
  let bytes = <<1, 2, 3, 4>>
  assert testing.truncations(bytes)
    == [<<>>, <<1>>, <<1, 2>>, <<1, 2, 3>>, <<1, 2, 3, 4>>]
}

// --- and they find what they are for --------------------------------------------

pub fn a_decoder_survives_every_split_test() {
  // The property the whole codec rests on, stated with the public generators
  // so that a caller can state it about their own loop the same way.
  let whole = a_stream()

  use pieces <- list.each(testing.every_split(whole))
  let assert Ok(#(_, chunks)) = feed(pieces)
  assert bit_array.concat(chunks) == payload()
}

pub fn a_decoder_survives_one_byte_at_a_time_test() {
  let assert Ok(#(_, chunks)) = feed(testing.single_bytes(a_stream()))
  assert bit_array.concat(chunks) == payload()
}

pub fn a_decoder_survives_arbitrary_groupings_test() {
  use pieces <- list.each(testing.random_splits(a_stream(), seed: 77, count: 60))
  let assert Ok(#(_, chunks)) = feed(pieces)
  assert bit_array.concat(chunks) == payload()
}

pub fn a_decoder_refuses_every_corruption_test() {
  // One flipped byte anywhere must be caught. A format that tolerates one is
  // not authenticating that part of itself.
  let whole = a_stream()

  use pair <- list.each(testing.corruptions(whole))
  let #(_, altered) = pair
  assert feed([altered]) != Ok(#(stream.decoder(session()), [payload()]))
  assert produced(altered) != Ok(payload())
}

pub fn a_decoder_waits_through_every_truncation_test() {
  // Every prefix of a valid stream is a valid stream that has not finished.
  // Failing on one would mean closing connections that were merely slow.
  let whole = a_stream()
  let total = bit_array.byte_size(whole)

  use shortened <- list.each(testing.truncations(whole))
  let assert Ok(so_far) = produced(shortened)

  // Only the last one has a whole chunk in it; every other prefix is a stream
  // still arriving, and produces nothing without complaining.
  let expected = case bit_array.byte_size(shortened) == total {
    True -> payload()
    False -> <<>>
  }
  assert so_far == expected
}

// --- helpers ------------------------------------------------------------------

fn feed(
  pieces: List(BitArray),
) -> Result(#(stream.Decoder, List(BitArray)), stream.StreamError) {
  list.try_fold(pieces, #(stream.decoder(session()), []), fn(state, piece) {
    let #(decoder, so_far) = state
    use #(decoder, more) <- result.try(stream.decode(decoder, piece))
    Ok(#(decoder, list.append(so_far, more)))
  })
}

fn produced(bytes: BitArray) -> Result(BitArray, stream.StreamError) {
  feed([bytes]) |> result.map(fn(pair) { bit_array.concat(pair.1) })
}
