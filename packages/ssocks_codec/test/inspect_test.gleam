// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/string
import ssocks/address
import ssocks/datagram
import ssocks/inspect
import ssocks/key
import ssocks/method
import ssocks/stream

fn session() -> key.Key {
  key.from_password(method.Aes256Gcm, "a secret for reading dumps")
}

fn target() -> address.Address {
  let assert Ok(where) = address.parse("example.org:443")
  where
}

/// A client's stream: salt, then the target address and a payload.
fn a_stream() -> BitArray {
  let #(encoder, salt) = stream.encoder(session())
  let #(_, framed) =
    stream.encode(
      encoder,
      bit_array.concat([address.encode(target()), <<"body":utf8>>]),
    )
  bit_array.concat([salt, framed])
}

// --- what a good stream says --------------------------------------------------

pub fn a_whole_stream_is_walked_field_by_field_test() {
  let dump = inspect.stream(session(), a_stream())

  assert string.contains(dump, "salt (32 bytes)")
  assert string.contains(dump, "chunk 0 length, sealed")
  assert string.contains(dump, "chunk 0 payload, sealed")
  // The nonce is the thing most worth seeing, and it advances twice per chunk.
  assert string.contains(dump, "nonce 000000000000000000000000")
  assert string.contains(dump, "nonce 010000000000000000000000")
  assert string.contains(dump, "end of what was given")
}

pub fn the_target_address_is_read_out_of_the_first_chunk_test() {
  // This is most of the value: a dump that says which host the stream is
  // asking for turns a wire mismatch into a sentence.
  let dump = inspect.stream(session(), a_stream())

  assert string.contains(dump, "example.org:443")
  assert string.contains(dump, "4 bytes of payload")
}

pub fn several_chunks_are_numbered_and_the_nonce_keeps_going_test() {
  let #(encoder, salt) = stream.encoder(session())
  let #(encoder, first) = stream.encode(encoder, address.encode(target()))
  let #(_, second) = stream.encode(encoder, <<"and more":utf8>>)

  let dump = inspect.stream(session(), bit_array.concat([salt, first, second]))

  assert string.contains(dump, "chunk 1 length, sealed")
  assert string.contains(dump, "nonce 020000000000000000000000")
  assert string.contains(dump, "nonce 030000000000000000000000")
}

// --- what a broken stream says ------------------------------------------------

pub fn a_stream_cut_short_says_where_and_what_was_needed_test() {
  // Half a salt is the most common thing to be holding when a connection has
  // gone quiet, and "ends here, needing" is what distinguishes it from a
  // stream that is wrong.
  let assert Ok(half) = bit_array.slice(a_stream(), 0, 20)
  let dump = inspect.stream(session(), half)

  assert string.contains(dump, "ends here, needing 32 bytes")
  assert string.contains(dump, "salt")
}

pub fn a_stream_cut_inside_a_payload_says_how_much_was_wanted_test() {
  let whole = a_stream()
  let assert Ok(most) =
    bit_array.slice(whole, 0, bit_array.byte_size(whole) - 5)
  let dump = inspect.stream(session(), most)

  assert string.contains(dump, "ends here, needing")
  assert string.contains(dump, "whose length said")
}

pub fn a_wrong_key_fails_at_chunk_zero_and_says_so_test() {
  // The single most common report: "it does not work". This is the line that
  // tells the difference between a wrong password and a framing bug.
  let other = key.from_password(method.Aes256Gcm, "the wrong secret")
  let dump = inspect.stream(other, a_stream())

  assert string.contains(dump, "did not authenticate")
  assert string.contains(dump, "Chunk 0")
  assert string.contains(dump, "password")
}

pub fn a_tampered_payload_fails_further_in_test() {
  let whole = a_stream()
  let total = bit_array.byte_size(whole)
  let assert Ok(head) = bit_array.slice(whole, 0, total - 3)
  let assert Ok(tail) = bit_array.slice(whole, total - 2, 2)
  let tampered = bit_array.concat([head, <<0xff>>, tail])

  let dump = inspect.stream(session(), tampered)

  assert string.contains(dump, "chunk 0 length, sealed")
  assert string.contains(dump, "did not authenticate")
  assert string.contains(dump, "payload")
}

// --- packets and headers ------------------------------------------------------

pub fn a_packet_is_described_test() {
  let packet = datagram.seal(session(), target(), <<"over udp":utf8>>)
  let dump = inspect.packet(session(), packet)

  assert string.contains(dump, "salt (32 bytes)")
  assert string.contains(dump, "all-zero nonce")
  assert string.contains(dump, "example.org:443")
  assert string.contains(dump, "8 bytes")
}

pub fn a_packet_that_does_not_open_says_so_test() {
  let other = key.from_password(method.Aes256Gcm, "the wrong secret")
  let dump = inspect.packet(other, datagram.seal(session(), target(), <<"x">>))

  assert string.contains(dump, "did not open")
}

pub fn a_header_is_described_on_its_own_test() {
  let dump = inspect.header(address.encode(target()))

  assert string.contains(dump, "address header")
  assert string.contains(dump, "example.org:443")
}

pub fn a_short_header_says_how_many_more_bytes_test() {
  let encoded = address.encode(target())
  let assert Ok(most) = bit_array.slice(encoded, 0, 3)

  assert string.contains(inspect.header(most), "ends here, needing")
}

// --- what is never printed ----------------------------------------------------

pub fn a_dump_never_contains_key_material_test() {
  // Everything here decrypts, so everything here holds a key. A dump is
  // exactly the sort of thing that gets pasted into a bug report.
  let master = <<0xa7:size(8)-unit(8), 0xa7:size(24)-unit(8)>>
  let assert Ok(session) = key.from_bytes(method.Aes256Gcm, master)
  let subkey = key.derive_subkey(session, <<7:256>>)

  let #(encoder, salt) = stream.encoder(session)
  let #(_, framed) = stream.encode(encoder, address.encode(target()))
  let dump = inspect.stream(session, bit_array.concat([salt, framed]))

  assert !string.contains(dump, hex_of(master))
  assert !string.contains(dump, hex_of(subkey))
  assert !string.contains(dump, "167, 167, 167")
}

fn hex_of(value: BitArray) -> String {
  case bit_array.base16_encode(value) {
    text -> string.lowercase(text)
  }
}
