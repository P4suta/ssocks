//// The TCP framing, which is where hand-written Shadowsocks implementations
//// usually break.
////
//// A stream is a salt followed by chunks, each of which is a two byte length
//// sealed under one nonce and then that many payload bytes sealed under the
//// next. TCP delivers none of that in the shape it was sent: a read can stop in
//// the middle of the salt, between a length and its tag, or halfway through a
//// payload. So the decoder is fed at every possible byte boundary below and has
//// to produce the same plaintext every time.
////
//// The other thing pinned here is that the nonce advances only when an AEAD
//// operation succeeds. If a length decrypts but its payload has not arrived, the
//// counter must stay where it is, or the next call decrypts against the wrong
//// nonce and the connection dies for no visible reason.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/option
import gleam/result
import ssocks/internal/aead
import ssocks/key
import ssocks/method
import ssocks/nonce
import ssocks/stream
import vector.{bytes}

const every_method = [
  method.Aes128Gcm,
  method.Aes256Gcm,
  method.ChaCha20Poly1305,
]

fn test_key() -> key.Key {
  key.from_password(method.Aes256Gcm, "a shared secret")
}

fn fixed_salt() -> BitArray {
  bytes(
    "0102030405060708090a0b0c0d0e0f10
     1112131415161718191a1b1c1d1e1f20",
  )
}

/// A whole stream: the salt, then one chunk per plaintext handed in.
fn sealed(plaintexts: List(BitArray)) -> BitArray {
  let assert Ok(#(encoder, salt)) =
    stream.encoder_with_salt(test_key(), fixed_salt())
  let #(_, body) =
    list.fold(plaintexts, #(encoder, <<>>), fn(state, plaintext) {
      let #(encoder, so_far) = state
      let #(encoder, produced) = stream.encode(encoder, plaintext)
      #(encoder, bit_array.concat([so_far, produced]))
    })
  bit_array.concat([salt, body])
}

fn feed(
  decoder: stream.Decoder,
  pieces: List(BitArray),
) -> Result(#(stream.Decoder, List(BitArray)), stream.StreamError) {
  list.try_fold(pieces, #(decoder, []), fn(state, piece) {
    let #(decoder, produced) = state
    use #(decoder, more) <- result.try(stream.decode(decoder, piece))
    Ok(#(decoder, list.append(produced, more)))
  })
}

fn joined(pieces: List(BitArray)) -> BitArray {
  bit_array.concat(pieces)
}

// --- the salt -----------------------------------------------------------------

pub fn an_encoder_emits_a_salt_of_the_methods_length_test() {
  use chosen <- list.each(every_method)
  let #(_, salt) = stream.encoder(key.from_password(chosen, "secret"))
  assert bit_array.byte_size(salt) == method.salt_size(chosen)
}

pub fn two_encoders_do_not_share_a_salt_test() {
  // Salt reuse under one master key is what the replay filter exists to catch,
  // and it starts here: every session must draw a fresh one.
  let #(_, one) = stream.encoder(test_key())
  let #(_, other) = stream.encoder(test_key())
  assert one != other
}

pub fn a_fixed_salt_makes_the_whole_stream_reproducible_test() {
  // Needed for vectors and for any failure to be reproducible at all.
  assert sealed([<<"hello":utf8>>]) == sealed([<<"hello":utf8>>])
}

pub fn a_salt_of_the_wrong_length_is_refused_test() {
  assert stream.encoder_with_salt(test_key(), bytes("0102030405"))
    == Error(stream.BadSaltLength(expected: 32, actual: 5))
  assert stream.encoder_with_salt(test_key(), <<>>)
    == Error(stream.BadSaltLength(expected: 32, actual: 0))
}

pub fn the_decoder_reports_the_salt_once_it_has_read_one_test() {
  // The server needs this to check the salt against its replay filter, and it
  // cannot know it before the first bytes arrive.
  let decoder = stream.decoder(test_key())
  assert stream.salt(decoder) == option.None

  let assert Ok(#(decoder, _)) = stream.decode(decoder, fixed_salt())
  assert stream.salt(decoder) == option.Some(fixed_salt())
}

// --- chunk shape ---------------------------------------------------------------

pub fn a_chunk_is_a_sealed_length_then_a_sealed_payload_test() {
  // 2 bytes of length, 16 of tag, n of payload, 16 more of tag.
  use size <- list.each([1, 5, 100, 1000, 16_383])
  let #(_, salt) = stream.encoder(test_key())
  let assert Ok(#(encoder, _)) = stream.encoder_with_salt(test_key(), salt)
  let #(_, produced) = stream.encode(encoder, filler(size))
  assert bit_array.byte_size(produced) == 2 + 16 + size + 16
}

pub fn a_payload_over_the_chunk_limit_is_split_test() {
  // 16383 is the largest a two byte length with two reserved bits can describe.
  let assert Ok(#(encoder, _)) =
    stream.encoder_with_salt(test_key(), fixed_salt())
  let #(_, produced) = stream.encode(encoder, filler(16_384))
  // One full chunk plus a one byte chunk.
  assert bit_array.byte_size(produced)
    == { 2 + 16 + 16_383 + 16 } + { 2 + 16 + 1 + 16 }
}

pub fn a_large_payload_is_split_into_as_many_chunks_as_it_needs_test() {
  let assert Ok(#(encoder, _)) =
    stream.encoder_with_salt(test_key(), fixed_salt())
  let #(_, produced) = stream.encode(encoder, filler(50_000))
  // 50000 = 3 * 16383 + 851
  assert bit_array.byte_size(produced)
    == 3 * { 2 + 16 + 16_383 + 16 } + { 2 + 16 + 851 + 16 }
}

pub fn encoding_nothing_produces_nothing_test() {
  // An empty chunk would burn two nonces and tell the far end nothing.
  let assert Ok(#(encoder, _)) =
    stream.encoder_with_salt(test_key(), fixed_salt())
  let #(after, produced) = stream.encode(encoder, <<>>)
  assert produced == <<>>

  // And the encoder must be untouched, so the next chunk still starts at the
  // nonce the far end expects.
  let #(_, first) = stream.encode(after, <<"x":utf8>>)
  let assert Ok(#(encoder, _)) =
    stream.encoder_with_salt(test_key(), fixed_salt())
  let #(_, same) = stream.encode(encoder, <<"x":utf8>>)
  assert first == same
}

// --- round trips ----------------------------------------------------------------

pub fn a_stream_round_trips_test() {
  use chosen <- list.each(every_method)
  let session_key = key.from_password(chosen, "secret")
  let #(encoder, salt) = stream.encoder(session_key)
  let message = <<"the quick brown fox":utf8>>
  let #(_, body) = stream.encode(encoder, message)

  let assert Ok(#(_, produced)) =
    feed(stream.decoder(session_key), [salt, body])
  assert joined(produced) == message
}

pub fn several_chunks_round_trip_in_order_test() {
  let messages = [<<"one":utf8>>, <<"two":utf8>>, <<"three":utf8>>]
  let assert Ok(#(_, produced)) =
    feed(stream.decoder(test_key()), [sealed(messages)])
  assert joined(produced) == joined(messages)
}

pub fn a_payload_larger_than_one_chunk_round_trips_test() {
  let message = filler(40_000)
  let assert Ok(#(_, produced)) =
    feed(stream.decoder(test_key()), [sealed([message])])
  assert joined(produced) == message
}

pub fn every_size_around_the_chunk_boundary_round_trips_test() {
  use size <- list.each([
    0, 1, 2, 16, 16_382, 16_383, 16_384, 16_385, 32_766, 32_767, 32_768,
  ])
  let message = filler(size)
  let assert Ok(#(_, produced)) =
    feed(stream.decoder(test_key()), [sealed([message])])
  assert joined(produced) == message
}

// --- the test this module exists for --------------------------------------------

pub fn a_stream_decodes_the_same_however_the_bytes_arrive_test() {
  // Split the encoded stream at every single byte boundary and feed it as two
  // pieces. TCP is allowed to do this and eventually will.
  let message = <<"a message long enough to span a few reads":utf8>>
  let whole = sealed([message])
  let total = bit_array.byte_size(whole)

  use at <- list.each(counting_up_to(total))
  let assert Ok(head) = bit_array.slice(whole, 0, at)
  let assert Ok(tail) = bit_array.slice(whole, at, total - at)

  let assert Ok(#(_, produced)) = feed(stream.decoder(test_key()), [head, tail])
  assert joined(produced) == message
}

pub fn a_stream_decodes_one_byte_at_a_time_test() {
  // The pathological case: every read returns a single byte. Nothing may be
  // lost, duplicated or reordered, and the nonce must not advance on the reads
  // that produce nothing.
  let message = <<"one byte at a time":utf8>>
  let whole = sealed([message])

  let assert Ok(#(_, produced)) =
    feed(stream.decoder(test_key()), single_bytes(whole))
  assert joined(produced) == message
}

pub fn a_multi_chunk_stream_decodes_one_byte_at_a_time_test() {
  let messages = [filler(16_383), filler(1), filler(500)]
  let assert Ok(#(_, produced)) =
    feed(stream.decoder(test_key()), single_bytes(sealed(messages)))
  assert joined(produced) == joined(messages)
}

pub fn a_starved_decoder_produces_nothing_and_stays_usable_test() {
  let message = <<"deferred":utf8>>
  let whole = sealed([message])
  let total = bit_array.byte_size(whole)

  // Everything but the last byte cannot complete the final chunk.
  let assert Ok(head) = bit_array.slice(whole, 0, total - 1)
  let assert Ok(last) = bit_array.slice(whole, total - 1, 1)

  let assert Ok(#(decoder, nothing)) =
    stream.decode(stream.decoder(test_key()), head)
  assert nothing == []

  let assert Ok(#(_, produced)) = stream.decode(decoder, last)
  assert joined(produced) == message
}

pub fn feeding_empty_input_changes_nothing_test() {
  let message = <<"unchanged":utf8>>
  let whole = sealed([message])

  let assert Ok(#(_, produced)) =
    feed(stream.decoder(test_key()), [<<>>, whole, <<>>, <<>>])
  assert joined(produced) == message
}

// --- rejection ------------------------------------------------------------------

pub fn a_stream_under_the_wrong_key_does_not_authenticate_test() {
  let other = key.from_password(method.Aes256Gcm, "a different secret")
  let assert Error(failure) =
    feed(stream.decoder(other), [sealed([<<"secret":utf8>>])])
  assert is_authentication_failure(failure)
}

pub fn an_altered_length_header_is_caught_before_the_payload_test() {
  // The salt is 32 bytes, so byte 32 is the first byte of the sealed length.
  let whole = sealed([<<"payload":utf8>>])
  let assert Ok(damaged) = flip_byte(whole, 32)

  let assert Error(failure) = feed(stream.decoder(test_key()), [damaged])
  assert stream.stage_of(failure) == option.Some(stream.LengthHeader)
}

pub fn an_altered_payload_is_caught_after_its_length_test() {
  // 32 salt + 2 length + 16 tag puts byte 50 inside the sealed payload.
  let whole = sealed([<<"payload":utf8>>])
  let assert Ok(damaged) = flip_byte(whole, 50)

  let assert Error(failure) = feed(stream.decoder(test_key()), [damaged])
  assert stream.stage_of(failure) == option.Some(stream.Payload)
}

pub fn an_altered_salt_makes_everything_after_it_fail_test() {
  let whole = sealed([<<"payload":utf8>>])
  let assert Ok(damaged) = flip_byte(whole, 0)

  let assert Error(failure) = feed(stream.decoder(test_key()), [damaged])
  assert is_authentication_failure(failure)
}

pub fn a_failure_says_where_it_happened_test() {
  // A bare "did not authenticate" leaves nothing to act on. Chunk index, stage
  // and nonce together say whether the framing drifted or the key is wrong.
  let messages = [<<"one":utf8>>, <<"two":utf8>>, <<"three":utf8>>]
  let whole = sealed(messages)
  // The third chunk's payload: 32 salt, then two chunks of 2+16+3+16 = 37,
  // then 2 + 16 into the third.
  let assert Ok(damaged) = flip_byte(whole, 32 + 37 + 37 + 18)

  let assert Error(failure) = feed(stream.decoder(test_key()), [damaged])
  assert stream.stage_of(failure) == option.Some(stream.Payload)
  assert stream.chunk_of(failure) == option.Some(2)
  // Two AEAD operations per chunk, so chunk 2's payload uses nonce 5.
  assert stream.nonce_of(failure) == option.Some(nonce_after(5))
}

pub fn a_length_above_the_chunk_limit_is_refused_test() {
  // Constructed by hand, because the encoder will never produce one. The frame
  // authenticates, so this is a peer that is misbehaving rather than an
  // attacker guessing.
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let #(sealed_length, tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce.to_bytes(nonce.zero()), <<>>, <<
      0x40,
      0x00,
    >>)
  let frame = bit_array.concat([fixed_salt(), sealed_length, tag])

  assert feed(stream.decoder(test_key()), [frame])
    == Error(stream.ChunkTooLarge(length: 0x4000))
}

pub fn the_decoder_never_holds_more_than_one_chunk_test() {
  // A peer cannot make the decoder accumulate: it consumes as soon as a frame
  // is complete, so what it retains is bounded by one largest-possible chunk
  // whatever the peer sends. That is the property, and it is asserted at every
  // step of a multi-chunk stream rather than assumed.
  let whole = sealed([filler(16_383), filler(1), filler(100)])

  let final =
    list.fold(
      single_bytes(whole),
      stream.decoder(test_key()),
      fn(decoder, byte) {
        let assert Ok(#(decoder, _)) = stream.decode(decoder, byte)
        assert stream.buffered(decoder) <= stream.max_buffered
        decoder
      },
    )
  assert stream.buffered(final) == 0
}

pub fn a_starved_decoder_holds_exactly_what_it_was_given_test() {
  // Half a chunk stays put until the rest arrives; nothing is dropped and
  // nothing is decoded early.
  let assert Ok(#(decoder, produced)) =
    feed(stream.decoder(test_key()), [fixed_salt(), filler(9)])
  assert produced == []
  assert stream.buffered(decoder) == 9
}

pub fn the_buffer_bound_is_one_whole_chunk_test() {
  // Spelled out so a change to either constant has to be deliberate.
  assert stream.max_buffered
    == 2 + method.tag_size + method.max_payload_size + method.tag_size
}

// --- what the encoder and decoder agree about -----------------------------------

pub fn the_decoder_reads_a_frame_built_by_hand_test() {
  // Built from the AEAD primitives directly rather than by the encoder, so this
  // checks the framing against an independent construction instead of against
  // itself.
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let payload = <<"built by hand":utf8>>
  let length = bit_array.byte_size(payload)

  let #(sealed_length, length_tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce.to_bytes(nonce.zero()), <<>>, <<
      length:16,
    >>)
  let #(sealed_payload, payload_tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce_after(1), <<>>, payload)

  let frame =
    bit_array.concat([
      fixed_salt(),
      sealed_length,
      length_tag,
      sealed_payload,
      payload_tag,
    ])

  let assert Ok(#(_, produced)) = feed(stream.decoder(test_key()), [frame])
  assert joined(produced) == payload
}

pub fn the_encoder_produces_exactly_that_frame_test() {
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let payload = <<"built by hand":utf8>>

  let #(sealed_length, length_tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce.to_bytes(nonce.zero()), <<>>, <<
      13:16,
    >>)
  let #(sealed_payload, payload_tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce_after(1), <<>>, payload)

  assert sealed([payload])
    == bit_array.concat([
      fixed_salt(),
      sealed_length,
      length_tag,
      sealed_payload,
      payload_tag,
    ])
}

pub fn the_length_field_is_big_endian_test() {
  // 0x0102 must be 258, not 513. The nonce beside it is little-endian.
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let #(sealed_length, length_tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce.to_bytes(nonce.zero()), <<>>, <<
      0x01,
      0x02,
    >>)
  let payload = filler(258)
  let #(sealed_payload, payload_tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce_after(1), <<>>, payload)

  let assert Ok(#(_, produced)) =
    feed(stream.decoder(test_key()), [
      bit_array.concat([
        fixed_salt(),
        sealed_length,
        length_tag,
        sealed_payload,
        payload_tag,
      ]),
    ])
  assert joined(produced) == payload
}

// --- helpers ---------------------------------------------------------------------

fn nonce_after(steps: Int) -> BitArray {
  advance(nonce.zero(), steps) |> nonce.to_bytes
}

fn advance(from: nonce.Nonce, steps: Int) -> nonce.Nonce {
  case steps {
    0 -> from
    _ -> advance(nonce.next(from), steps - 1)
  }
}

fn filler(size: Int) -> BitArray {
  <<0x5a:8>> |> list.repeat(size) |> bit_array.concat
}

fn single_bytes(value: BitArray) -> List(BitArray) {
  // Tail recursive on purpose. The obvious shape, consing onto a recursive
  // call, holds one stack frame per byte and overflows on the JavaScript
  // target while passing on Erlang.
  single_bytes_loop(value, [])
}

fn single_bytes_loop(value: BitArray, acc: List(BitArray)) -> List(BitArray) {
  case value {
    <<first:8, rest:bits>> -> single_bytes_loop(rest, [<<first:8>>, ..acc])
    _ -> list.reverse(acc)
  }
}

fn flip_byte(value: BitArray, at: Int) -> Result(BitArray, Nil) {
  use head <- result.try(bit_array.slice(value, 0, at))
  use target <- result.try(bit_array.slice(value, at, 1))
  use tail <- result.try(bit_array.slice(
    value,
    at + 1,
    bit_array.byte_size(value) - at - 1,
  ))
  let assert <<byte:8>> = target
  Ok(bit_array.concat([head, <<{ byte + 1 }:8>>, tail]))
}

fn is_authentication_failure(failure: stream.StreamError) -> Bool {
  case failure {
    stream.AuthenticationFailed(..) -> True
    _ -> False
  }
}

fn counting_up_to(last: Int) -> List(Int) {
  counting_loop(last, [])
}

fn counting_loop(value: Int, acc: List(Int)) -> List(Int) {
  case value < 0 {
    True -> acc
    False -> counting_loop(value - 1, [value, ..acc])
  }
}
