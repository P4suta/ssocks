//// The TCP framing, with no sockets anywhere near it.
////
//// A stream is a salt followed by chunks. Each chunk is a two byte payload
//// length sealed under one nonce, then that many payload bytes sealed under the
//// next, so the nonce advances twice per chunk.
////
//// ### Feed it whatever arrives
////
//// `decode` takes any number of bytes, in any grouping, and returns the whole
//// plaintext chunks that became available. A read that stops in the middle of
//// the salt, between a length and its tag, or halfway through a payload returns
//// an empty list and a decoder that remembers where it was. This is the part
//// that hand-written implementations get wrong, so it is the part with the most
//// tests.
////
//// The rule that makes it work: **the nonce advances only when an AEAD
//// operation succeeds.** When a length decrypts but its payload has not arrived,
//// the length is remembered and the counter stays put. Advancing early, or
//// decrypting the length twice, both desynchronise the stream in ways that look
//// from the outside like a wrong key.
////
//// ### What a caller cannot do
////
//// There is no way to set a nonce, and no way to reuse one. The counter lives
//// inside the encoder, advances on its own, and is never accepted as an
//// argument. Nonce reuse is the catastrophic failure for AEAD, and here it is
//// not merely discouraged, it is unsayable.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import ssocks/internal/aead
import ssocks/key.{type Key}
import ssocks/method
import ssocks/nonce.{type Nonce}

/// Bytes in a chunk's length field.
const length_field_size = 2

/// The most a decoder can be holding at any moment.
///
/// One length field, its tag, the largest payload a length field can describe,
/// and its tag. The framing is self-bounding: bytes are consumed as soon as a
/// frame completes, so a peer cannot make the decoder accumulate beyond this
/// however it sends them.
pub const max_buffered = 16_417

/// Which AEAD operation in a chunk failed.
pub type Stage {
  LengthHeader
  Payload
}

/// Why a stream could not be read or an encoder could not be built.
pub type StreamError {
  /// A frame did not authenticate.
  ///
  /// The extra fields are the difference between a minute of diagnosis and an
  /// afternoon of it. A failure at chunk 0 in the length header usually means
  /// the wrong key or a reused salt; one deep into a stream usually means the
  /// framing drifted; and the nonce says which of the two counters disagreed.
  AuthenticationFailed(stage: Stage, chunk: Int, nonce: BitArray, buffered: Int)
  /// The peer sent a length the protocol does not permit. It authenticated, so
  /// this is a misbehaving peer rather than a forgery.
  ChunkTooLarge(length: Int)
  /// A salt of the wrong size was supplied to `encoder_with_salt`.
  BadSaltLength(expected: Int, actual: Int)
}

/// The stage a failure happened at, when the failure has one.
pub fn stage_of(error: StreamError) -> Option(Stage) {
  case error {
    AuthenticationFailed(stage:, ..) -> Some(stage)
    _ -> None
  }
}

/// The chunk index a failure happened at, counting from zero.
pub fn chunk_of(error: StreamError) -> Option(Int) {
  case error {
    AuthenticationFailed(chunk:, ..) -> Some(chunk)
    _ -> None
  }
}

/// The nonce in use when a failure happened.
///
/// Not secret, and the single most useful number to compare against the other
/// end of a connection that will not talk.
pub fn nonce_of(error: StreamError) -> Option(BitArray) {
  case error {
    AuthenticationFailed(nonce:, ..) -> Some(nonce)
    _ -> None
  }
}

// --- encoding -------------------------------------------------------------------

/// Writes one direction of a stream. Advance it by using its return value; an
/// encoder that is used twice will repeat a nonce.
pub opaque type Encoder {
  Encoder(method: method.Method, subkey: BitArray, counter: Nonce)
}

/// Start a stream with a fresh random salt.
///
/// Returns the encoder and the salt, which must be the first thing written to
/// the connection. This is the one function in the codec that is not a pure
/// function of its arguments.
pub fn encoder(session_key: Key) -> #(Encoder, BitArray) {
  let salt =
    crypto.strong_random_bytes(method.salt_size(key.method(session_key)))
  let assert Ok(started) = encoder_with_salt(session_key, salt)
  started
}

/// Start a stream with a salt you choose.
///
/// For tests, vectors, and reproducing a failure. Production code wants
/// `encoder`: a salt that repeats under one master key is exactly what replay
/// protection exists to reject.
pub fn encoder_with_salt(
  session_key: Key,
  salt: BitArray,
) -> Result(#(Encoder, BitArray), StreamError) {
  let expected = method.salt_size(key.method(session_key))
  case bit_array.byte_size(salt) {
    actual if actual == expected ->
      Ok(#(
        Encoder(
          key.method(session_key),
          key.derive_subkey(session_key, salt),
          nonce.zero(),
        ),
        salt,
      ))
    actual -> Error(BadSaltLength(expected:, actual:))
  }
}

/// Frame a payload of any size.
///
/// Splitting at the protocol's chunk limit is done here so callers never have
/// to think about it. An empty payload produces no bytes and leaves the encoder
/// untouched, rather than emitting an empty chunk that would spend two nonces
/// to say nothing.
pub fn encode(encoder: Encoder, plaintext: BitArray) -> #(Encoder, BitArray) {
  encode_loop(encoder, plaintext, [])
}

fn encode_loop(
  encoder: Encoder,
  remaining: BitArray,
  acc: List(BitArray),
) -> #(Encoder, BitArray) {
  let available = bit_array.byte_size(remaining)
  case available {
    0 -> #(encoder, acc |> list.reverse |> bit_array.concat)
    _ -> {
      let size = int.min(available, method.max_payload_size)
      let assert Ok(chunk) = bit_array.slice(remaining, 0, size)
      let assert Ok(rest) = bit_array.slice(remaining, size, available - size)
      let #(encoder, framed) = encode_chunk(encoder, chunk, size)
      encode_loop(encoder, rest, [framed, ..acc])
    }
  }
}

fn encode_chunk(
  encoder: Encoder,
  chunk: BitArray,
  size: Int,
) -> #(Encoder, BitArray) {
  // The length is big-endian while the nonce beside it counts little-endian.
  let #(sealed_length, length_tag) = seal(encoder, encoder.counter, <<size:16>>)

  let counter = nonce.next(encoder.counter)
  let #(sealed_payload, payload_tag) = seal(encoder, counter, chunk)

  #(
    Encoder(..encoder, counter: nonce.next(counter)),
    bit_array.concat([sealed_length, length_tag, sealed_payload, payload_tag]),
  )
}

fn seal(
  encoder: Encoder,
  counter: Nonce,
  plaintext: BitArray,
) -> #(BitArray, BitArray) {
  aead.seal(
    encoder.method,
    encoder.subkey,
    nonce.to_bytes(counter),
    <<>>,
    plaintext,
  )
}

// --- decoding -------------------------------------------------------------------

/// Reads one direction of a stream, remembering whatever did not complete.
pub opaque type Decoder {
  Decoder(
    session_key: Key,
    state: State,
    buffer: BitArray,
    salt: Option(BitArray),
    chunk: Int,
  )
}

type State {
  AwaitingSalt
  AwaitingLength(subkey: BitArray, counter: Nonce)
  /// The length authenticated but its payload has not all arrived. Holding the
  /// length here is what keeps the nonce from advancing twice for one chunk.
  AwaitingPayload(subkey: BitArray, counter: Nonce, length: Int)
}

/// A decoder positioned at the start of a stream.
pub fn decoder(session_key: Key) -> Decoder {
  Decoder(session_key, AwaitingSalt, <<>>, None, 0)
}

/// The salt this stream opened with, once enough bytes have arrived to know it.
///
/// A server checks this against its replay filter. It is `None` until the first
/// `salt_size` bytes have been fed.
pub fn salt(decoder: Decoder) -> Option(BitArray) {
  decoder.salt
}

/// How many bytes the decoder is holding for a frame that is not yet complete.
///
/// Always at most `max_buffered`. Useful when a connection has gone quiet and
/// the question is whether the far end stopped mid-frame.
pub fn buffered(decoder: Decoder) -> Int {
  bit_array.byte_size(decoder.buffer)
}

/// How many whole chunks this decoder has read.
pub fn chunks_read(decoder: Decoder) -> Int {
  decoder.chunk
}

/// Feed whatever arrived, and take whatever became complete.
///
/// Returns an empty list when nothing completed, which is ordinary rather than
/// exceptional. Any error is terminal: the stream cannot be resynchronised, and
/// the connection should be closed.
pub fn decode(
  decoder: Decoder,
  bytes: BitArray,
) -> Result(#(Decoder, List(BitArray)), StreamError) {
  Decoder(..decoder, buffer: bit_array.concat([decoder.buffer, bytes]))
  |> decode_loop([])
}

fn decode_loop(
  decoder: Decoder,
  produced: List(BitArray),
) -> Result(#(Decoder, List(BitArray)), StreamError) {
  case decoder.state {
    AwaitingSalt -> decode_salt(decoder, produced)
    AwaitingLength(subkey, counter) ->
      decode_length(decoder, subkey, counter, produced)
    AwaitingPayload(subkey, counter, length) ->
      decode_payload(decoder, subkey, counter, length, produced)
  }
}

fn decode_salt(
  decoder: Decoder,
  produced: List(BitArray),
) -> Result(#(Decoder, List(BitArray)), StreamError) {
  let size = method.salt_size(key.method(decoder.session_key))
  case take(decoder.buffer, size) {
    Error(_) -> starved(decoder, produced)
    Ok(#(salt, rest)) ->
      decode_loop(
        Decoder(
          ..decoder,
          state: AwaitingLength(
            key.derive_subkey(decoder.session_key, salt),
            nonce.zero(),
          ),
          buffer: rest,
          salt: Some(salt),
        ),
        produced,
      )
  }
}

fn decode_length(
  decoder: Decoder,
  subkey: BitArray,
  counter: Nonce,
  produced: List(BitArray),
) -> Result(#(Decoder, List(BitArray)), StreamError) {
  case split_sealed(decoder.buffer, length_field_size) {
    Error(_) -> starved(decoder, produced)
    Ok(#(ciphertext, tag, rest)) ->
      case open(decoder, subkey, counter, ciphertext, tag) {
        Error(_) -> Error(failure(decoder, LengthHeader, counter))
        Ok(plaintext) -> {
          let assert <<length:16>> = plaintext
          case length > method.max_payload_size {
            True -> Error(ChunkTooLarge(length:))
            False ->
              decode_loop(
                Decoder(
                  ..decoder,
                  state: AwaitingPayload(subkey, nonce.next(counter), length),
                  buffer: rest,
                ),
                produced,
              )
          }
        }
      }
  }
}

fn decode_payload(
  decoder: Decoder,
  subkey: BitArray,
  counter: Nonce,
  length: Int,
  produced: List(BitArray),
) -> Result(#(Decoder, List(BitArray)), StreamError) {
  case split_sealed(decoder.buffer, length) {
    Error(_) -> starved(decoder, produced)
    Ok(#(ciphertext, tag, rest)) ->
      case open(decoder, subkey, counter, ciphertext, tag) {
        Error(_) -> Error(failure(decoder, Payload, counter))
        Ok(plaintext) ->
          decode_loop(
            Decoder(
              ..decoder,
              state: AwaitingLength(subkey, nonce.next(counter)),
              buffer: rest,
              chunk: decoder.chunk + 1,
            ),
            [plaintext, ..produced],
          )
      }
  }
}

fn starved(
  decoder: Decoder,
  produced: List(BitArray),
) -> Result(#(Decoder, List(BitArray)), StreamError) {
  Ok(#(decoder, list.reverse(produced)))
}

fn open(
  decoder: Decoder,
  subkey: BitArray,
  counter: Nonce,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, Nil) {
  aead.open(
    key.method(decoder.session_key),
    subkey,
    nonce.to_bytes(counter),
    <<>>,
    ciphertext,
    tag,
  )
}

fn failure(decoder: Decoder, stage: Stage, counter: Nonce) -> StreamError {
  AuthenticationFailed(
    stage:,
    chunk: decoder.chunk,
    nonce: nonce.to_bytes(counter),
    buffered: bit_array.byte_size(decoder.buffer),
  )
}

/// Split off `size` bytes of ciphertext plus its tag, if both are present.
fn split_sealed(
  buffer: BitArray,
  size: Int,
) -> Result(#(BitArray, BitArray, BitArray), Nil) {
  use #(sealed, rest) <- result.try(take(buffer, size + method.tag_size))
  use ciphertext <- result.try(bit_array.slice(sealed, 0, size))
  use tag <- result.try(bit_array.slice(sealed, size, method.tag_size))
  Ok(#(ciphertext, tag, rest))
}

fn take(buffer: BitArray, count: Int) -> Result(#(BitArray, BitArray), Nil) {
  let total = bit_array.byte_size(buffer)
  case total >= count {
    False -> Error(Nil)
    True -> {
      use head <- result.try(bit_array.slice(buffer, 0, count))
      use tail <- result.try(bit_array.slice(buffer, count, total - count))
      Ok(#(head, tail))
    }
  }
}
