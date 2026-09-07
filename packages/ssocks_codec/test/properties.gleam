//// Properties, stated once and run at two scales.
////
//// The unit tests pin the cases a person thought of. These state what has to
//// hold for every input, and qcheck goes looking for a counterexample. When it
//// finds one it shrinks it, so a failure arrives as the smallest input that
//// still breaks rather than as whatever random 200 byte payload happened to
//// trip it.
////
//// The same properties run twice: a few hundred cases inside `gleam test`, and
//// tens of thousands from `mise run test-property`. Both take an explicit seed,
//// so any failure is reproducible by rerunning with the seed it reports.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/result
import qcheck
import ssocks/address
import ssocks/datagram
import ssocks/internal/hex
import ssocks/key
import ssocks/method
import ssocks/nonce
import ssocks/stream

/// Every property, under one configuration.
pub fn check_all(config: qcheck.Config) -> Nil {
  hex_round_trips(config)
  addresses_round_trip(config)
  streams_round_trip_under_arbitrary_chunking(config)
  datagrams_round_trip(config)
  nonces_do_not_repeat(config)
  decoders_never_crash(config)
}

fn session_key() -> key.Key {
  key.from_password(method.Aes256Gcm, "a property secret")
}

// --- generators ------------------------------------------------------------

fn byte() -> qcheck.Generator(Int) {
  qcheck.bounded_int(0, 255)
}

fn bytes_up_to(length: Int) -> qcheck.Generator(BitArray) {
  qcheck.generic_list(byte(), qcheck.bounded_int(0, length))
  |> qcheck.map(from_bytes)
}

fn from_bytes(values: List(Int)) -> BitArray {
  values |> list.map(fn(value) { <<value:8>> }) |> bit_array.concat
}

fn any_address() -> qcheck.Generator(address.Address) {
  qcheck.from_generators(any_ipv4(), [any_domain(), any_ipv6()])
}

fn any_port() -> qcheck.Generator(Int) {
  qcheck.bounded_int(0, 65_535)
}

fn any_ipv4() -> qcheck.Generator(address.Address) {
  qcheck.map2(
    qcheck.fixed_length_list_from(byte(), 4),
    any_port(),
    fn(octets, port) {
      let assert [a, b, c, d] = octets
      let assert Ok(built) = address.ipv4(#(a, b, c, d), port)
      built
    },
  )
}

fn any_ipv6() -> qcheck.Generator(address.Address) {
  qcheck.map2(
    qcheck.fixed_length_list_from(qcheck.bounded_int(0, 0xffff), 8),
    any_port(),
    fn(groups, port) {
      let assert Ok(built) = address.ipv6(groups, port)
      built
    },
  )
}

fn any_domain() -> qcheck.Generator(address.Address) {
  // Letters and dots only. The point of the property is the encoding, not the
  // question of what a hostname may contain.
  qcheck.map2(
    qcheck.generic_string(
      qcheck.codepoint_from_strings("a", ["b", "z", ".", "-", "0", "9"]),
      qcheck.bounded_int(1, 60),
    ),
    any_port(),
    fn(name, port) {
      let assert Ok(built) = address.domain(name, port)
      built
    },
  )
}

// --- the properties --------------------------------------------------------

fn hex_round_trips(config: qcheck.Config) -> Nil {
  use value <- qcheck.run(config, bytes_up_to(200))
  assert hex.decode(hex.encode(value)) == Ok(value)
}

fn addresses_round_trip(config: qcheck.Config) -> Nil {
  use built <- qcheck.run(config, any_address())

  // Through the wire format...
  assert address.decode(address.encode(built))
    == Ok(address.Complete(built, <<>>))
  // ...and through the textual one.
  assert address.parse(address.to_string(built)) == Ok(built)
}

fn streams_round_trip_under_arbitrary_chunking(config: qcheck.Config) -> Nil {
  // The property the whole codec rests on: what a stream decodes to must not
  // depend on how the bytes were grouped when they arrived.
  use #(payload, sizes) <- qcheck.run(
    config,
    qcheck.tuple2(
      bytes_up_to(2000),
      qcheck.generic_list(qcheck.bounded_int(1, 300), qcheck.bounded_int(0, 20)),
    ),
  )

  let #(encoder, salt) = stream.encoder(session_key())
  let #(_, framed) = stream.encode(encoder, payload)
  let whole = bit_array.concat([salt, framed])

  let assert Ok(#(_, produced)) =
    feed(stream.decoder(session_key()), chop(whole, sizes))
  assert bit_array.concat(produced) == payload
}

fn datagrams_round_trip(config: qcheck.Config) -> Nil {
  use #(target, payload) <- qcheck.run(
    config,
    qcheck.tuple2(any_address(), bytes_up_to(1200)),
  )

  let packet = datagram.seal(session_key(), target, payload)
  assert datagram.open(session_key(), packet) == Ok(#(target, payload))
}

fn nonces_do_not_repeat(config: qcheck.Config) -> Nil {
  // Advancing from an arbitrary point must not land back on it, at any of the
  // byte boundaries where a carry happens.
  use steps <- qcheck.run(config, qcheck.bounded_int(1, 600))
  let produced = walk(nonce.zero(), steps, [])
  assert list.length(list.unique(produced)) == list.length(produced)
}

fn decoders_never_crash(config: qcheck.Config) -> Nil {
  // Arbitrary bytes must produce Ok or Error, never a panic. A server that dies
  // on a malformed frame hands an attacker a denial of service.
  use junk <- qcheck.run(config, bytes_up_to(300))

  let _ = stream.decode(stream.decoder(session_key()), junk)
  let _ = datagram.open(session_key(), junk)
  let _ = datagram.salt_of(session_key(), junk)
  let _ = address.decode(junk)
  Nil
}

// --- helpers ---------------------------------------------------------------

fn walk(from: nonce.Nonce, steps: Int, acc: List(BitArray)) -> List(BitArray) {
  case steps {
    0 -> acc
    _ -> walk(nonce.next(from), steps - 1, [nonce.to_bytes(from), ..acc])
  }
}

/// Split `whole` into pieces of the given sizes, with anything left over as a
/// final piece. An empty size list means one piece.
fn chop(whole: BitArray, sizes: List(Int)) -> List(BitArray) {
  chop_loop(whole, sizes, [])
}

fn chop_loop(
  remaining: BitArray,
  sizes: List(Int),
  acc: List(BitArray),
) -> List(BitArray) {
  let available = bit_array.byte_size(remaining)
  case sizes, available {
    _, 0 -> list.reverse(acc)
    [], _ -> list.reverse([remaining, ..acc])
    [size, ..rest], _ -> {
      let taken = case size > available {
        True -> available
        False -> size
      }
      let assert Ok(piece) = bit_array.slice(remaining, 0, taken)
      let assert Ok(tail) = bit_array.slice(remaining, taken, available - taken)
      chop_loop(tail, rest, [piece, ..acc])
    }
  }
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
