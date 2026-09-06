//// The UDP packet format, which is the TCP one with the framing taken away.
////
//// A packet is a salt, then one sealed blob holding the target address followed
//// by the payload, then a tag. There is no length field and no chunking,
//// because a datagram either arrives whole or does not arrive.
////
//// Two differences from the stream matter and are pinned below. The nonce is
//// always twelve zero bytes, because each packet carries a fresh salt and so
//// derives a subkey it will never reuse. And a short packet is a malformed
//// packet: unlike TCP there is no "the rest is still coming".

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import ssocks/address
import ssocks/datagram
import ssocks/internal/aead
import ssocks/key
import ssocks/method
import ssocks/nonce
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

fn target() -> address.Address {
  let assert Ok(value) = address.parse("example.com:53")
  value
}

fn sealed(payload: BitArray) -> BitArray {
  let assert Ok(packet) =
    datagram.seal_with_salt(test_key(), fixed_salt(), target(), payload)
  packet
}

// --- round trips ----------------------------------------------------------------

pub fn a_packet_round_trips_under_every_method_test() {
  use chosen <- list.each(every_method)
  let session_key = key.from_password(chosen, "secret")
  let payload = <<"a dns query, more or less":utf8>>

  let packet = datagram.seal(session_key, target(), payload)
  assert datagram.open(session_key, packet) == Ok(#(target(), payload))
}

pub fn every_address_kind_round_trips_test() {
  use text <- list.each(["example.com:53", "1.2.3.4:53", "[2001:db8::1]:53"])
  let assert Ok(destination) = address.parse(text)
  let payload = <<"payload":utf8>>

  let packet = datagram.seal(test_key(), destination, payload)
  assert datagram.open(test_key(), packet) == Ok(#(destination, payload))
}

pub fn an_empty_payload_round_trips_test() {
  // A datagram with no payload is unusual but legal, and it must not be
  // confused with a truncated one.
  let packet = datagram.seal(test_key(), target(), <<>>)
  assert datagram.open(test_key(), packet) == Ok(#(target(), <<>>))
}

pub fn a_large_payload_round_trips_test() {
  // UDP has no chunking, so size is bounded by the datagram and not by us.
  let payload = filler(60_000)
  let packet = datagram.seal(test_key(), target(), payload)
  assert datagram.open(test_key(), packet) == Ok(#(target(), payload))
}

// --- shape ------------------------------------------------------------------------

pub fn a_packet_is_a_salt_a_sealed_body_and_a_tag_test() {
  use size <- list.each([0, 1, 100, 1400])
  let payload = filler(size)
  let packet = datagram.seal(test_key(), target(), payload)
  let header = bit_array.byte_size(address.encode(target()))

  assert bit_array.byte_size(packet) == 32 + header + size + 16
}

pub fn every_packet_draws_a_fresh_salt_test() {
  // The subkey comes from the salt alone, so a repeated salt means a repeated
  // subkey under a fixed all-zero nonce, which is a total break.
  let one = datagram.seal(test_key(), target(), <<"same":utf8>>)
  let other = datagram.seal(test_key(), target(), <<"same":utf8>>)
  assert one != other
  assert datagram.salt_of(test_key(), one)
    != datagram.salt_of(test_key(), other)
}

pub fn a_fixed_salt_makes_a_packet_reproducible_test() {
  assert sealed(<<"same":utf8>>) == sealed(<<"same":utf8>>)
}

pub fn a_salt_of_the_wrong_length_is_refused_test() {
  assert datagram.seal_with_salt(test_key(), bytes("0102"), target(), <<>>)
    == Error(datagram.BadSaltLength(expected: 32, actual: 2))
}

pub fn the_salt_can_be_read_without_decrypting_test() {
  // A server checks the salt against its replay filter before spending any
  // cryptography on a packet that it is going to drop anyway.
  assert datagram.salt_of(test_key(), sealed(<<"x":utf8>>)) == Ok(fixed_salt())
}

pub fn reading_the_salt_of_a_runt_packet_fails_test() {
  assert datagram.salt_of(test_key(), bytes("0102"))
    == Error(datagram.TooShort(needed_at_least: 32, actual: 2))
}

// --- the all-zero nonce -----------------------------------------------------------

pub fn a_packet_is_sealed_under_an_all_zero_nonce_test() {
  // Built independently from the primitives. Every packet has its own salt, so
  // the subkey is never reused and a fixed nonce is safe; using a counter here
  // instead would simply fail to interoperate.
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let body = bit_array.concat([address.encode(target()), <<"payload":utf8>>])
  let #(ciphertext, tag) =
    aead.seal(
      method.Aes256Gcm,
      subkey,
      nonce.to_bytes(nonce.zero()),
      <<>>,
      body,
    )

  assert sealed(<<"payload":utf8>>)
    == bit_array.concat([fixed_salt(), ciphertext, tag])
}

pub fn the_decoder_reads_a_packet_built_by_hand_test() {
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let body = bit_array.concat([address.encode(target()), <<"by hand":utf8>>])
  let #(ciphertext, tag) =
    aead.seal(
      method.Aes256Gcm,
      subkey,
      nonce.to_bytes(nonce.zero()),
      <<>>,
      body,
    )

  assert datagram.open(
      test_key(),
      bit_array.concat([fixed_salt(), ciphertext, tag]),
    )
    == Ok(#(target(), <<"by hand":utf8>>))
}

// --- rejection ---------------------------------------------------------------------

pub fn a_packet_under_the_wrong_key_does_not_authenticate_test() {
  let other = key.from_password(method.Aes256Gcm, "a different secret")
  assert datagram.open(other, sealed(<<"secret":utf8>>))
    == Error(datagram.AuthenticationFailed)
}

pub fn an_altered_packet_does_not_authenticate_test() {
  use at <- list.each([0, 10, 31, 32, 40])
  let assert Ok(damaged) = flip_byte(sealed(<<"payload":utf8>>), at)
  assert datagram.open(test_key(), damaged)
    == Error(datagram.AuthenticationFailed)
}

pub fn a_truncated_packet_does_not_authenticate_test() {
  let packet = sealed(<<"payload":utf8>>)
  let assert Ok(shortened) =
    bit_array.slice(packet, 0, bit_array.byte_size(packet) - 1)
  assert datagram.open(test_key(), shortened)
    == Error(datagram.AuthenticationFailed)
}

pub fn a_packet_too_short_to_hold_a_salt_and_tag_is_refused_test() {
  // Refused on size before any cryptography, and the numbers say why.
  assert datagram.open(test_key(), <<>>)
    == Error(datagram.TooShort(needed_at_least: 48, actual: 0))
  assert datagram.open(test_key(), filler(47))
    == Error(datagram.TooShort(needed_at_least: 48, actual: 47))
  // 48 is a salt and a tag with an empty body, which is short but well formed
  // enough to attempt.
  assert datagram.open(test_key(), filler(48))
    == Error(datagram.AuthenticationFailed)
}

pub fn a_packet_whose_address_is_cut_off_is_refused_test() {
  // Authenticates, so this is a peer that built a bad packet rather than an
  // attacker. Unlike TCP there is no more data coming, so a partial address is
  // an error and not a wait.
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let assert Ok(partial) = bit_array.slice(address.encode(target()), 0, 4)
  let #(ciphertext, tag) =
    aead.seal(
      method.Aes256Gcm,
      subkey,
      nonce.to_bytes(nonce.zero()),
      <<>>,
      partial,
    )

  assert datagram.open(
      test_key(),
      bit_array.concat([fixed_salt(), ciphertext, tag]),
    )
    == Error(datagram.TruncatedAddress)
}

pub fn a_packet_with_an_unknown_address_type_is_refused_test() {
  let subkey = key.derive_subkey(test_key(), fixed_salt())
  let #(ciphertext, tag) =
    aead.seal(method.Aes256Gcm, subkey, nonce.to_bytes(nonce.zero()), <<>>, <<
      0x02,
      1,
      2,
      3,
      4,
      0,
      80,
    >>)

  assert datagram.open(
      test_key(),
      bit_array.concat([fixed_salt(), ciphertext, tag]),
    )
    == Error(datagram.MalformedAddress(address.UnknownAddressType(0x02)))
}

// --- helpers -------------------------------------------------------------------------

fn filler(size: Int) -> BitArray {
  <<0x5a:8>> |> list.repeat(size) |> bit_array.concat
}

fn flip_byte(value: BitArray, at: Int) -> Result(BitArray, Nil) {
  let total = bit_array.byte_size(value)
  let assert Ok(head) = bit_array.slice(value, 0, at)
  let assert Ok(<<byte:8>>) = bit_array.slice(value, at, 1)
  let assert Ok(tail) = bit_array.slice(value, at + 1, total - at - 1)
  Ok(bit_array.concat([head, <<{ byte + 1 }:8>>, tail]))
}
