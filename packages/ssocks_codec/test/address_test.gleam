//// The target address header, which is the first thing a Shadowsocks client
//// sends and the first thing a server reads.
////
//// It is the SOCKS5 address encoding: a type byte, then the address, then a
//// two byte port. The port is **big-endian**, in the same protocol whose nonce
//// counter is little-endian, so it is asserted here as a literal rather than
//// left to a round trip that would agree with itself either way.
////
//// Decoding is split three ways instead of two. A header can be malformed, or
//// complete, or simply not all here yet: the address arrives inside the
//// plaintext stream and a chunk boundary can fall in the middle of it. Treating
//// "not yet" as an error would drop connections that were merely slow.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/string
import ssocks/address
import vector.{bytes}

fn ipv4(a: Int, b: Int, c: Int, d: Int, port: Int) -> address.Address {
  let assert Ok(value) = address.ipv4(#(a, b, c, d), port)
  value
}

fn domain(name: String, port: Int) -> address.Address {
  let assert Ok(value) = address.domain(name, port)
  value
}

fn ipv6(groups: List(Int), port: Int) -> address.Address {
  let assert Ok(value) = address.ipv6(groups, port)
  value
}

fn parsed(text: String) -> address.Address {
  let assert Ok(value) = address.parse(text)
  value
}

// --- the wire format ---------------------------------------------------------

pub fn an_ipv4_address_encodes_as_type_one_test() {
  assert address.encode(ipv4(1, 2, 3, 4, 80)) == bytes("01 01020304 0050")
}

pub fn a_domain_encodes_as_type_three_with_a_length_prefix_test() {
  // 03, then one length byte, then the name, then the port.
  assert address.encode(domain("example.com", 443))
    == bit_array.concat([
      <<0x03, 11>>,
      <<"example.com":utf8>>,
      bytes("01bb"),
    ])
}

pub fn an_ipv6_address_encodes_as_type_four_test() {
  assert address.encode(ipv6([0, 0, 0, 0, 0, 0, 0, 1], 80))
    == bytes("04 00000000000000000000000000000001 0050")
}

pub fn the_port_is_big_endian_test() {
  // The nonce counter in this same protocol is little-endian. Getting these two
  // the same way round is a classic way to build something that talks only to
  // itself, so the byte order is pinned here as a literal.
  assert address.encode(ipv4(0, 0, 0, 0, 1)) == bytes("01 00000000 0001")
  assert address.encode(ipv4(0, 0, 0, 0, 256)) == bytes("01 00000000 0100")
  assert address.encode(ipv4(0, 0, 0, 0, 443)) == bytes("01 00000000 01bb")
  assert address.encode(ipv4(0, 0, 0, 0, 65_535)) == bytes("01 00000000 ffff")
}

// --- decoding ----------------------------------------------------------------

pub fn every_address_kind_round_trips_through_the_wire_test() {
  use original <- list.each([
    ipv4(192, 168, 1, 1, 8388),
    ipv4(255, 255, 255, 255, 65_535),
    ipv4(0, 0, 0, 0, 0),
    domain("example.com", 443),
    domain("a", 1),
    ipv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443),
  ])

  assert address.decode(address.encode(original))
    == Ok(address.Complete(original, <<>>))
}

pub fn decoding_returns_whatever_followed_the_header_test() {
  // The payload begins immediately after the address, with no separator, so the
  // decoder has to hand back exactly what it did not consume.
  let payload = <<"GET / HTTP/1.1":utf8>>
  let framed =
    bit_array.concat([address.encode(domain("example.com", 80)), payload])

  assert address.decode(framed)
    == Ok(address.Complete(domain("example.com", 80), payload))
}

pub fn a_header_split_by_a_chunk_boundary_asks_for_more_rather_than_failing_test() {
  let whole = address.encode(domain("example.com", 443))
  let total = bit_array.byte_size(whole)

  use taken <- list.each(counting_up_to(total - 1))
  let assert Ok(prefix) = bit_array.slice(whole, 0, taken)
  let assert Ok(address.NeedMoreBytes(at_least)) = address.decode(prefix)
  assert at_least > taken
  assert at_least <= total
}

pub fn an_empty_input_needs_at_least_the_type_byte_test() {
  assert address.decode(<<>>) == Ok(address.NeedMoreBytes(1))
}

pub fn an_unknown_address_type_is_rejected_test() {
  // 0x02 was never assigned; anything outside 1, 3 and 4 is a protocol error or
  // a decryption that went wrong upstream.
  assert address.decode(<<0x02, 0, 0, 0, 0, 0, 0>>)
    == Error(address.UnknownAddressType(0x02))
  assert address.decode(<<0x00, 0, 0>>) == Error(address.UnknownAddressType(0))
  assert address.decode(<<0xff, 0, 0>>)
    == Error(address.UnknownAddressType(0xff))
}

pub fn a_zero_length_domain_is_rejected_test() {
  // A length of zero would decode to an empty host, which cannot be connected
  // to. It is refused rather than passed along.
  assert address.decode(<<0x03, 0x00, 0x00, 0x50>>)
    == Error(address.EmptyDomainOnWire)
}

pub fn a_domain_that_is_not_utf8_is_rejected_test() {
  assert address.decode(<<0x03, 0x02, 0xff, 0xfe, 0x00, 0x50>>)
    == Error(address.DomainNotUtf8)
}

// --- constructing ------------------------------------------------------------

pub fn a_port_outside_sixteen_bits_is_refused_test() {
  assert address.domain("example.com", 65_536)
    == Error(address.PortOutOfRange(65_536))
  assert address.domain("example.com", -1) == Error(address.PortOutOfRange(-1))
  assert address.ipv4(#(1, 2, 3, 4), 70_000)
    == Error(address.PortOutOfRange(70_000))
}

pub fn an_octet_outside_a_byte_is_refused_test() {
  assert address.ipv4(#(256, 0, 0, 0), 80)
    == Error(address.OctetOutOfRange(256))
  assert address.ipv4(#(0, 0, 0, -1), 80) == Error(address.OctetOutOfRange(-1))
}

pub fn an_ipv6_group_outside_sixteen_bits_is_refused_test() {
  assert address.ipv6([0x10000, 0, 0, 0, 0, 0, 0, 0], 80)
    == Error(address.GroupOutOfRange(0x10000))
}

pub fn ipv6_needs_exactly_eight_groups_test() {
  assert address.ipv6([0, 0, 0, 0, 0, 0, 0], 80)
    == Error(address.WrongGroupCount(7))
  assert address.ipv6([], 80) == Error(address.WrongGroupCount(0))
}

pub fn an_empty_domain_is_refused_test() {
  assert address.domain("", 80) == Error(address.EmptyDomain)
}

pub fn a_domain_longer_than_the_length_byte_is_refused_test() {
  // The wire carries one length byte, so 255 is the ceiling. The limit is on
  // bytes, not characters, which matters for internationalised names.
  let two_hundred_and_fifty_five = repeat_text("a", 255)
  assert address.domain(two_hundred_and_fifty_five, 80) |> is_ok

  let too_long = repeat_text("a", 256)
  assert address.domain(too_long, 80) == Error(address.DomainTooLong(256))
}

pub fn domain_length_is_measured_in_bytes_not_characters_test() {
  // Each of these is three bytes of UTF-8, so 86 of them is 258 bytes and does
  // not fit even though it is only 86 characters.
  let long = repeat_text("あ", 86)
  assert address.domain(long, 80) == Error(address.DomainTooLong(258))
  assert address.domain(repeat_text("あ", 85), 80) |> is_ok
}

// --- parsing text ------------------------------------------------------------

pub fn a_host_and_port_pair_parses_test() {
  assert address.parse("example.com:443") == Ok(domain("example.com", 443))
  assert address.parse("1.2.3.4:80") == Ok(ipv4(1, 2, 3, 4, 80))
}

pub fn a_dotted_quad_becomes_an_ipv4_address_not_a_domain_test() {
  // Sending 1.2.3.4 as a domain name would work, but it wastes bytes and asks
  // the far end to resolve something that is already an address.
  assert address.encode(parsed("127.0.0.1:8080")) == bytes("01 7f000001 1f90")
}

pub fn something_that_only_looks_like_a_dotted_quad_stays_a_domain_test() {
  assert address.parse("1.2.3.4.5:80") == Ok(domain("1.2.3.4.5", 80))
  assert address.parse("1.2.3.256:80") == Ok(domain("1.2.3.256", 80))
  assert address.parse("1.2.3:80") == Ok(domain("1.2.3", 80))
}

pub fn a_bracketed_ipv6_literal_parses_test() {
  assert address.parse("[::1]:80") == Ok(ipv6([0, 0, 0, 0, 0, 0, 0, 1], 80))
  assert address.parse("[2001:db8::1]:443")
    == Ok(ipv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443))
  assert address.parse("[2001:db8:0:0:0:0:0:1]:443")
    == Ok(ipv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443))
  assert address.parse("[::]:1") == Ok(ipv6([0, 0, 0, 0, 0, 0, 0, 0], 1))
  assert address.parse("[fe80::1234:5678:9abc:def0]:22")
    == Ok(ipv6([0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0], 22))
}

pub fn text_without_a_port_is_refused_test() {
  // Silently defaulting the port would connect somewhere the caller did not
  // ask for.
  assert address.parse("example.com")
    == Error(address.MissingPort("example.com"))
  assert address.parse("1.2.3.4") == Error(address.MissingPort("1.2.3.4"))
}

pub fn text_with_an_unusable_port_is_refused_test() {
  assert address.parse("example.com:") == Error(address.MalformedPort(""))
  assert address.parse("example.com:http")
    == Error(address.MalformedPort("http"))
  assert address.parse("example.com:99999")
    == Error(address.PortOutOfRange(99_999))
}

pub fn a_malformed_ipv6_literal_is_refused_test() {
  assert address.parse("[not-an-address]:80")
    == Error(address.MalformedIpv6("not-an-address"))
  assert address.parse("[::1:80") == Error(address.MalformedIpv6("::1:80"))
  assert address.parse("[1:2:3:4:5:6:7:8:9]:80")
    == Error(address.MalformedIpv6("1:2:3:4:5:6:7:8:9"))
  assert address.parse("[1::2::3]:80")
    == Error(address.MalformedIpv6("1::2::3"))
}

pub fn empty_text_is_refused_test() {
  assert address.parse("") == Error(address.MissingPort(""))
}

// --- rendering ---------------------------------------------------------------

pub fn rendering_produces_text_that_parses_back_test() {
  use original <- list.each([
    ipv4(192, 168, 1, 1, 8388),
    domain("example.com", 443),
    ipv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443),
    ipv6([0, 0, 0, 0, 0, 0, 0, 1], 80),
  ])
  assert address.parse(address.to_string(original)) == Ok(original)
}

pub fn an_ipv6_address_renders_inside_brackets_test() {
  // Without brackets the port colon is ambiguous with the address colons.
  assert address.to_string(ipv6([0, 0, 0, 0, 0, 0, 0, 1], 80)) == "[::1]:80"
}

pub fn the_host_and_port_can_be_read_back_test() {
  assert address.host(domain("example.com", 443)) == "example.com"
  assert address.port(domain("example.com", 443)) == 443
  assert address.host(ipv4(1, 2, 3, 4, 80)) == "1.2.3.4"
  assert address.host(ipv6([0, 0, 0, 0, 0, 0, 0, 1], 80)) == "::1"
}

// --- helpers -----------------------------------------------------------------

fn repeat_text(unit: String, times: Int) -> String {
  unit |> list.repeat(times) |> string.concat
}

fn is_ok(result: Result(a, b)) -> Bool {
  case result {
    Ok(_) -> True
    Error(_) -> False
  }
}

/// The integers 0 through `last` inclusive. `gleam/list` has no range function.
fn counting_up_to(last: Int) -> List(Int) {
  counting_loop(last, [])
}

fn counting_loop(value: Int, acc: List(Int)) -> List(Int) {
  case value < 0 {
    True -> acc
    False -> counting_loop(value - 1, [value, ..acc])
  }
}
