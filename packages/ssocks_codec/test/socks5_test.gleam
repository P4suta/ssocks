//// SOCKS5, checked against literal bytes rather than against itself.
////
//// A round trip through one implementation cannot tell a correct encoding from
//// one that is consistently wrong, so the wire shapes here are written out as
//// hex and compared byte for byte. The incremental cases matter for the same
//// reason `ssocks/stream` has so many: a greeting, a request and a reply all
//// arrive over TCP, and a read can stop anywhere inside one.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/string
import ssocks/address
import ssocks/internal/hex
import ssocks/socks5
import ssocks/testing

fn bytes(text: String) -> BitArray {
  let assert Ok(value) = hex.decode(text)
  value
}

/// `encode_greeting` and `encode_choice` refuse values the wire cannot hold, so
/// the tests that are about the bytes unwrap here and the ones that are about
/// the refusals call them directly.
fn greeting(offered: List(socks5.Authentication)) -> BitArray {
  let assert Ok(written) = socks5.encode_greeting(offered)
  written
}

fn choice(chosen: socks5.Authentication) -> BitArray {
  let assert Ok(written) = socks5.encode_choice(chosen)
  written
}

fn target(text: String) -> address.Address {
  let assert Ok(where) = address.parse(text)
  where
}

// --- the greeting ---------------------------------------------------------------

pub fn a_greeting_is_a_version_a_count_and_the_methods_test() {
  assert greeting([socks5.NoAuthentication]) == bytes("050100")

  assert greeting([socks5.NoAuthentication, socks5.Other(2)])
    == bytes("05020002")
}

pub fn a_greeting_that_cannot_be_written_is_refused_test() {
  // An encoder whose output its own decoder rejects is worth catching here
  // rather than on somebody else's socket. `NMETHODS = 0` is exactly that.
  assert socks5.encode_greeting([]) == Error(socks5.NoMethodsOffered)

  let many = list.repeat(socks5.NoAuthentication, 256)
  assert socks5.encode_greeting(many) == Error(socks5.TooManyMethods(256))

  // `Other` holds a raw byte and a caller can put anything in an `Int`.
  // Truncating would put a different method on the wire than was asked for.
  assert socks5.encode_greeting([socks5.Other(300)])
    == Error(socks5.NotAByte(300))
  assert socks5.encode_choice(socks5.Other(-1)) == Error(socks5.NotAByte(-1))
}

pub fn a_greeting_round_trips_test() {
  let offered = [socks5.NoAuthentication, socks5.Other(0x02)]

  assert socks5.decode_greeting(greeting(offered))
    == Ok(socks5.Complete(offered, <<>>))
}

pub fn a_greeting_keeps_what_followed_it_test() {
  let written = greeting([socks5.NoAuthentication])

  assert socks5.decode_greeting(<<written:bits, "after":utf8>>)
    == Ok(socks5.Complete([socks5.NoAuthentication], <<"after":utf8>>))
}

pub fn every_prefix_of_a_greeting_asks_for_more_test() {
  // A prefix of a valid greeting is a valid greeting that has not finished.
  // Treating one as an error closes clients that were merely slow.
  let written = greeting([socks5.NoAuthentication, socks5.Other(2)])

  use prefix <- list.each(short_of(written))
  let assert Ok(socks5.NeedMoreBytes(_)) = socks5.decode_greeting(prefix)
}

/// Every prefix except the whole thing. `testing.truncations` includes the
/// complete bytes, which is a message rather than a prefix of one.
fn short_of(bytes: BitArray) -> List(BitArray) {
  let whole = bit_array.byte_size(bytes)
  testing.truncations(bytes)
  |> list.filter(fn(prefix) { bit_array.byte_size(prefix) < whole })
}

pub fn a_greeting_that_is_not_socks5_says_so_test() {
  // SOCKS4 begins with 4, and anything pointed at the wrong port begins with
  // whatever it begins with.
  assert socks5.decode_greeting(bytes("0401")) == Error(socks5.WrongVersion(4))
  assert socks5.decode_greeting(bytes("4745"))
    == Error(socks5.WrongVersion(0x47))
}

pub fn a_greeting_offering_nothing_is_refused_test() {
  assert socks5.decode_greeting(bytes("0500")) == Error(socks5.NoMethodsOffered)
}

pub fn a_choice_round_trips_test() {
  assert choice(socks5.NoAuthentication) == bytes("0500")
  assert choice(socks5.NoneAcceptable) == bytes("05ff")

  assert socks5.decode_choice(bytes("0500"))
    == Ok(socks5.Complete(socks5.NoAuthentication, <<>>))
  assert socks5.decode_choice(bytes("05ff"))
    == Ok(socks5.Complete(socks5.NoneAcceptable, <<>>))
}

pub fn a_half_read_choice_asks_for_more_test() {
  assert socks5.decode_choice(<<>>) == Ok(socks5.NeedMoreBytes(2))
  assert socks5.decode_choice(bytes("05")) == Ok(socks5.NeedMoreBytes(2))
}

// --- the request ----------------------------------------------------------------

pub fn a_request_is_three_bytes_then_the_shadowsocks_header_test() {
  // The piece Shadowsocks borrowed is everything from the address type byte
  // on, which is why `ssocks/address` serves both.
  assert socks5.encode_request(socks5.Connect, target("1.2.3.4:80"))
    == bytes("050100" <> "01010203040050")

  assert socks5.encode_request(socks5.Connect, target("example.com:443"))
    == bytes("050100" <> "030b6578616d706c652e636f6d01bb")
}

pub fn a_request_round_trips_for_every_address_kind_test() {
  use where <- list.each([
    target("1.2.3.4:80"),
    target("example.com:443"),
    target("[2001:db8::1]:8388"),
  ])

  assert socks5.decode_request(socks5.encode_request(socks5.Connect, where))
    == Ok(socks5.Complete(#(socks5.Connect, where), <<>>))
}

pub fn every_command_round_trips_test() {
  use command <- list.each([socks5.Connect, socks5.Bind, socks5.Associate])

  let where = target("1.2.3.4:80")

  assert socks5.decode_request(socks5.encode_request(command, where))
    == Ok(socks5.Complete(#(command, where), <<>>))
}

pub fn every_prefix_of_a_request_asks_for_more_and_says_how_much_test() {
  // The incremental claim, at every cut: a prefix asks for more, and the
  // number it asks for is more than it already has. A decoder that answered
  // with a number it had already passed would loop for ever.
  let written = socks5.encode_request(socks5.Connect, target("example.com:443"))

  use prefix <- list.each(short_of(written))
  let assert Ok(socks5.NeedMoreBytes(needed)) = socks5.decode_request(prefix)
  assert needed > bit_array.byte_size(prefix)
}

pub fn a_reserved_byte_that_is_not_zero_is_refused_test() {
  // RFC 1928 fixes it at zero. A peer that puts something else there is not
  // speaking this protocol, and guessing would relay somewhere on its say-so.
  assert socks5.decode_request(bytes("05019901010203040050"))
    == Error(socks5.ReservedNotZero(0x99))
}

pub fn an_unknown_command_is_named_test() {
  assert socks5.decode_request(bytes("05090001010203040050"))
    == Error(socks5.UnknownCommand(9))
}

pub fn a_request_for_an_address_type_that_is_not_one_is_refused_test() {
  assert socks5.decode_request(bytes("05010009ff"))
    == Error(socks5.MalformedAddress(address.UnknownAddressType(9)))
}

// --- the reply ------------------------------------------------------------------

pub fn a_reply_is_a_version_an_outcome_and_a_bound_address_test() {
  assert socks5.encode_reply(socks5.Succeeded, socks5.unspecified())
    == bytes("05000001000000000000")

  assert socks5.encode_reply(socks5.CommandNotSupported, socks5.unspecified())
    == bytes("05070001000000000000")
}

pub fn every_reply_code_round_trips_test() {
  use outcome <- list.each([
    socks5.Succeeded,
    socks5.GeneralFailure,
    socks5.NotAllowed,
    socks5.NetworkUnreachable,
    socks5.HostUnreachable,
    socks5.ConnectionRefused,
    socks5.TtlExpired,
    socks5.CommandNotSupported,
    socks5.AddressNotSupported,
  ])

  assert socks5.decode_reply(socks5.encode_reply(outcome, socks5.unspecified()))
    == Ok(socks5.Complete(#(outcome, socks5.unspecified()), <<>>))
}

pub fn an_unknown_reply_code_is_named_test() {
  assert socks5.decode_reply(bytes("050a0001000000000000"))
    == Error(socks5.UnknownReply(0x0a))
}

pub fn every_prefix_of_a_reply_asks_for_more_test() {
  let written = socks5.encode_reply(socks5.Succeeded, target("1.2.3.4:80"))

  use prefix <- list.each(short_of(written))
  let assert Ok(socks5.NeedMoreBytes(_)) = socks5.decode_reply(prefix)
}

// --- relayed datagrams ------------------------------------------------------------

pub fn a_datagram_header_is_two_reserved_bytes_a_fragment_and_an_address_test() {
  assert socks5.encode_datagram(target("1.2.3.4:80"), <<"hello":utf8>>)
    == <<bytes("00000001010203040050"):bits, "hello":utf8>>
}

pub fn a_datagram_round_trips_test() {
  let written = socks5.encode_datagram(target("example.com:443"), <<1, 2, 3>>)

  assert socks5.decode_datagram(written)
    == Ok(#(target("example.com:443"), <<1, 2, 3>>))
}

pub fn a_datagram_with_an_empty_payload_round_trips_test() {
  let written = socks5.encode_datagram(target("1.2.3.4:80"), <<>>)

  assert socks5.decode_datagram(written) == Ok(#(target("1.2.3.4:80"), <<>>))
}

pub fn a_fragmented_datagram_is_refused_rather_than_delivered_test() {
  // Delivering a piece as though it were the whole would corrupt the payload
  // silently, which is the worst of the available answers.
  assert socks5.decode_datagram(bytes("00000701010203040050"))
    == Error(socks5.Fragmented(7))
}

pub fn a_datagram_that_ends_inside_its_header_is_malformed_test() {
  // Unlike a stream, nothing more is coming.
  let assert Error(socks5.TooShort(..)) =
    socks5.decode_datagram(bytes("00000001010203"))

  let assert Error(socks5.TooShort(..)) = socks5.decode_datagram(bytes("0000"))
}

pub fn a_datagram_with_a_reserved_byte_set_is_refused_test() {
  assert socks5.decode_datagram(bytes("01000001010203040050"))
    == Error(socks5.ReservedNotZero(1))
  assert socks5.decode_datagram(bytes("00010001010203040050"))
    == Error(socks5.ReservedNotZero(1))
}

// --- saying what went wrong -------------------------------------------------------

pub fn every_refusal_has_a_sentence_of_its_own_test() {
  use reason <- list.each([
    socks5.WrongVersion(4),
    socks5.NoMethodsOffered,
    socks5.ReservedNotZero(9),
    socks5.UnknownCommand(9),
    socks5.UnknownReply(9),
    socks5.MalformedAddress(address.UnknownAddressType(9)),
    socks5.TooManyMethods(256),
    socks5.NotAByte(300),
    socks5.Fragmented(2),
    socks5.TooShort(needed_at_least: 10, actual: 3),
  ])

  let sentence = socks5.explain(reason)
  assert sentence != ""
  // A sentence, not the variant's name with brackets round it.
  assert sentence != string.inspect(reason)
  assert string.contains(sentence, " ")
}

pub fn a_refusal_never_quotes_the_host_test() {
  // A SOCKS5 request carries the host somebody is visiting. That is not a
  // thing to put in a log line by default, so no refusal here repeats it.
  let assert Error(reason) =
    socks5.decode_request(bytes("05019901010203040050"))

  assert !string.contains(socks5.explain(reason), "1.2.3.4")
}
