//// Where a connection is going: the target address header.
////
//// A Shadowsocks client opens a session by sending this, then the payload,
//// with nothing in between. It is the SOCKS5 address encoding: one type byte,
//// then the address, then a two byte port.
////
//// ### Two byte orders in one protocol
////
//// The port here is big-endian. The nonce counter in the same protocol is
//// little-endian. Nothing marks the difference on the wire, so both are pinned
//// by tests that assert literal bytes rather than round trips.
////
//// ### Three outcomes, not two
////
//// The header travels inside the plaintext stream, so a chunk boundary can
//// land in the middle of it. `decode` therefore answers "complete", "not all
//// here yet" or "malformed" separately. Folding the middle case into an error
//// would drop connections that were only slow, and folding it into success
//// would invent an address nobody sent.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string

/// A target address and port.
///
/// Opaque because every way of building one enforces something the wire format
/// requires: a port that fits in two bytes, a domain that fits behind a single
/// length byte, octets and groups in range.
pub opaque type Address {
  Ipv4(octets: #(Int, Int, Int, Int), port: Int)
  Ipv6(groups: List(Int), port: Int)
  Domain(name: String, port: Int)
}

/// Why an address could not be built from what a caller supplied.
pub type AddressError {
  PortOutOfRange(port: Int)
  OctetOutOfRange(octet: Int)
  GroupOutOfRange(group: Int)
  WrongGroupCount(count: Int)
  EmptyDomain
  DomainTooLong(bytes: Int)
  /// Text with no port at all. Defaulting one would connect somewhere the
  /// caller did not ask for, so it is refused instead.
  MissingPort(text: String)
  MalformedPort(text: String)
  MalformedIpv6(text: String)
}

/// Why bytes on the wire could not be an address header.
pub type DecodeError {
  UnknownAddressType(byte: Int)
  EmptyDomainOnWire
  DomainNotUtf8
}

/// What `decode` found.
pub type DecodeOutcome {
  /// A whole header, and whatever bytes followed it.
  Complete(address: Address, rest: BitArray)
  /// Not a failure. The header needs at least this many bytes in total, and
  /// fewer than that have arrived.
  NeedMoreBytes(at_least: Int)
}

const address_type_ipv4 = 1

const address_type_domain = 3

const address_type_ipv6 = 4

const max_port = 65_535

/// The longest domain a single length byte can describe.
const max_domain_bytes = 255

// --- constructing ------------------------------------------------------------

/// An IPv4 address and port.
pub fn ipv4(
  octets: #(Int, Int, Int, Int),
  port: Int,
) -> Result(Address, AddressError) {
  use port <- result.try(checked_port(port))
  let #(a, b, c, d) = octets
  use _ <- result.try(list.try_map([a, b, c, d], checked_octet))
  Ok(Ipv4(octets, port))
}

/// An IPv6 address, as eight 16-bit groups, and a port.
pub fn ipv6(groups: List(Int), port: Int) -> Result(Address, AddressError) {
  use port <- result.try(checked_port(port))
  case list.length(groups) {
    8 -> {
      use _ <- result.try(list.try_map(groups, checked_group))
      Ok(Ipv6(groups, port))
    }
    count -> Error(WrongGroupCount(count))
  }
}

/// A domain name and port, to be resolved at the far end.
pub fn domain(name: String, port: Int) -> Result(Address, AddressError) {
  use port <- result.try(checked_port(port))
  // The wire carries a byte count, not a character count, which is what makes
  // an internationalised name run out of room sooner than it looks.
  case bit_array.byte_size(<<name:utf8>>) {
    0 -> Error(EmptyDomain)
    size if size > max_domain_bytes -> Error(DomainTooLong(size))
    _ -> Ok(Domain(name, port))
  }
}

fn checked_port(port: Int) -> Result(Int, AddressError) {
  case port >= 0 && port <= max_port {
    True -> Ok(port)
    False -> Error(PortOutOfRange(port))
  }
}

fn checked_octet(octet: Int) -> Result(Int, AddressError) {
  case octet >= 0 && octet <= 255 {
    True -> Ok(octet)
    False -> Error(OctetOutOfRange(octet))
  }
}

fn checked_group(group: Int) -> Result(Int, AddressError) {
  case group >= 0 && group <= 0xffff {
    True -> Ok(group)
    False -> Error(GroupOutOfRange(group))
  }
}

// --- reading ------------------------------------------------------------------

/// The port, as an integer.
pub fn port(address: Address) -> Int {
  case address {
    Ipv4(_, port) -> port
    Ipv6(_, port) -> port
    Domain(_, port) -> port
  }
}

/// The host alone, without the port and without IPv6 brackets.
pub fn host(address: Address) -> String {
  case address {
    Ipv4(#(a, b, c, d), _) ->
      [a, b, c, d] |> list.map(int.to_string) |> string.join(".")
    Ipv6(groups, _) -> render_ipv6(groups)
    Domain(name, _) -> name
  }
}

/// The address as text that `parse` accepts again.
///
/// IPv6 is bracketed, because otherwise the port colon cannot be told apart
/// from the address colons.
pub fn to_string(address: Address) -> String {
  case address {
    Ipv6(_, _) -> "[" <> host(address) <> "]:" <> int.to_string(port(address))
    _ -> host(address) <> ":" <> int.to_string(port(address))
  }
}

// --- the wire format ----------------------------------------------------------

/// Encode the header exactly as it goes on the wire.
pub fn encode(address: Address) -> BitArray {
  case address {
    Ipv4(#(a, b, c, d), port) -> <<
      address_type_ipv4:8,
      a:8,
      b:8,
      c:8,
      d:8,
      port:16,
    >>
    Ipv6(groups, port) ->
      bit_array.concat([
        <<address_type_ipv6:8>>,
        groups |> list.map(fn(group) { <<group:16>> }) |> bit_array.concat,
        <<port:16>>,
      ])
    Domain(name, port) -> {
      let encoded = <<name:utf8>>
      bit_array.concat([
        <<address_type_domain:8, bit_array.byte_size(encoded):8>>,
        encoded,
        <<port:16>>,
      ])
    }
  }
}

/// Read a header from the front of `bytes`.
pub fn decode(bytes: BitArray) -> Result(DecodeOutcome, DecodeError) {
  case bytes {
    <<>> -> Ok(NeedMoreBytes(1))
    <<1:8, rest:bits>> -> decode_ipv4(rest)
    <<3:8, rest:bits>> -> decode_domain(rest)
    <<4:8, rest:bits>> -> decode_ipv6(rest)
    <<other:8, _:bits>> -> Error(UnknownAddressType(other))
    _ -> Ok(NeedMoreBytes(1))
  }
}

fn decode_ipv4(rest: BitArray) -> Result(DecodeOutcome, DecodeError) {
  case rest {
    <<a:8, b:8, c:8, d:8, port:16, tail:bits>> ->
      Ok(Complete(Ipv4(#(a, b, c, d), port), tail))
    _ -> Ok(NeedMoreBytes(1 + 4 + 2))
  }
}

fn decode_ipv6(rest: BitArray) -> Result(DecodeOutcome, DecodeError) {
  case rest {
    <<
      g0:16,
      g1:16,
      g2:16,
      g3:16,
      g4:16,
      g5:16,
      g6:16,
      g7:16,
      port:16,
      tail:bits,
    >> -> Ok(Complete(Ipv6([g0, g1, g2, g3, g4, g5, g6, g7], port), tail))
    _ -> Ok(NeedMoreBytes(1 + 16 + 2))
  }
}

fn decode_domain(rest: BitArray) -> Result(DecodeOutcome, DecodeError) {
  case rest {
    // The length byte has not arrived, so the total is not yet knowable beyond
    // the type byte and the length byte itself.
    <<>> -> Ok(NeedMoreBytes(2))
    <<0:8, _:bits>> -> Error(EmptyDomainOnWire)
    <<length:8, body:bits>> ->
      case body {
        <<name:bytes-size(length), port:16, tail:bits>> ->
          case bit_array.to_string(name) {
            Ok(text) -> Ok(Complete(Domain(text, port), tail))
            Error(_) -> Error(DomainNotUtf8)
          }
        _ -> Ok(NeedMoreBytes(1 + 1 + length + 2))
      }
    _ -> Ok(NeedMoreBytes(2))
  }
}

// --- parsing text --------------------------------------------------------------

/// Parse `host:port`, `1.2.3.4:port` or `[::1]:port`.
pub fn parse(text: String) -> Result(Address, AddressError) {
  case string.starts_with(text, "[") {
    True -> parse_bracketed(text)
    False -> parse_plain(text)
  }
}

fn parse_plain(text: String) -> Result(Address, AddressError) {
  // The port is after the last colon, so that a stray colon in a hostname does
  // not silently move it.
  case split_on_last_colon(text) {
    Error(_) -> Error(MissingPort(text))
    Ok(#(host, port_text)) -> {
      use port <- result.try(parse_port(port_text))
      case parse_dotted_quad(host) {
        // A literal address is sent as one rather than as a name, which saves
        // bytes and saves the far end a lookup it does not need.
        Ok(octets) -> ipv4(octets, port)
        Error(_) -> domain(host, port)
      }
    }
  }
}

fn parse_bracketed(text: String) -> Result(Address, AddressError) {
  case string.split_once(text, "]:") {
    Error(_) -> Error(MalformedIpv6(string.drop_start(text, 1)))
    Ok(#(head, port_text)) -> {
      let inner = string.drop_start(head, 1)
      use port <- result.try(parse_port(port_text))
      case parse_ipv6(inner) {
        Error(_) -> Error(MalformedIpv6(inner))
        Ok(groups) -> ipv6(groups, port)
      }
    }
  }
}

fn parse_port(text: String) -> Result(Int, AddressError) {
  case int.parse(text) {
    Error(_) -> Error(MalformedPort(text))
    Ok(port) -> checked_port(port)
  }
}

fn split_on_last_colon(text: String) -> Result(#(String, String), Nil) {
  case string.split(text, ":") {
    [_] -> Error(Nil)
    parts -> {
      let count = list.length(parts)
      let host = parts |> list.take(count - 1) |> string.join(":")
      use tail <- result.try(list.last(parts))
      Ok(#(host, tail))
    }
  }
}

fn parse_dotted_quad(text: String) -> Result(#(Int, Int, Int, Int), Nil) {
  case string.split(text, ".") {
    [a, b, c, d] -> {
      use a <- result.try(parse_decimal_octet(a))
      use b <- result.try(parse_decimal_octet(b))
      use c <- result.try(parse_decimal_octet(c))
      use d <- result.try(parse_decimal_octet(d))
      Ok(#(a, b, c, d))
    }
    _ -> Error(Nil)
  }
}

fn parse_decimal_octet(text: String) -> Result(Int, Nil) {
  case int.parse(text) {
    Ok(value) if value >= 0 && value <= 255 -> Ok(value)
    _ -> Error(Nil)
  }
}

/// Parse the textual form of an IPv6 address, including `::` compression.
fn parse_ipv6(text: String) -> Result(List(Int), Nil) {
  case string.split(text, "::") {
    // No compression: every group has to be written out.
    [single] ->
      case hex_groups(single) {
        Ok(groups) if groups != [] ->
          case list.length(groups) == 8 {
            True -> Ok(groups)
            False -> Error(Nil)
          }
        _ -> Error(Nil)
      }

    [before, after] -> {
      use head <- result.try(hex_groups_or_empty(before))
      use tail <- result.try(hex_groups_or_empty(after))
      // The elision must stand for at least one group, otherwise the address
      // was already complete and should have been written without it.
      case 8 - list.length(head) - list.length(tail) {
        missing if missing >= 1 ->
          Ok(list.flatten([head, list.repeat(0, missing), tail]))
        _ -> Error(Nil)
      }
    }

    // More than one elision is ambiguous, so it is not an address.
    _ -> Error(Nil)
  }
}

fn hex_groups_or_empty(text: String) -> Result(List(Int), Nil) {
  case text {
    "" -> Ok([])
    _ -> hex_groups(text)
  }
}

fn hex_groups(text: String) -> Result(List(Int), Nil) {
  text |> string.split(":") |> list.try_map(parse_hex_group)
}

fn parse_hex_group(text: String) -> Result(Int, Nil) {
  case string.length(text) >= 1 && string.length(text) <= 4 {
    False -> Error(Nil)
    True ->
      case int.base_parse(text, 16) {
        Ok(value) if value >= 0 && value <= 0xffff -> Ok(value)
        _ -> Error(Nil)
      }
  }
}

// --- rendering IPv6 ------------------------------------------------------------

/// Render groups in the shortest conventional form.
///
/// The longest run of two or more zero groups collapses to `::`. A single zero
/// group is written out, because `1:0:2:...` is not shorter than `1::2:...` and
/// the uncompressed form is unambiguous.
fn render_ipv6(groups: List(Int)) -> String {
  case longest_zero_run(groups) {
    #(_, length) if length < 2 ->
      groups |> list.map(hex_group_to_string) |> string.join(":")
    #(start, length) -> {
      let before = groups |> list.take(start) |> list.map(hex_group_to_string)
      let after =
        groups
        |> list.drop(start + length)
        |> list.map(hex_group_to_string)
      string.join(before, ":") <> "::" <> string.join(after, ":")
    }
  }
}

fn hex_group_to_string(group: Int) -> String {
  group |> int.to_base16 |> string.lowercase
}

/// The start index and length of the longest run of zero groups.
fn longest_zero_run(groups: List(Int)) -> #(Int, Int) {
  zero_run_loop(groups, 0, 0, 0, 0, 0)
}

fn zero_run_loop(
  remaining: List(Int),
  index: Int,
  current_start: Int,
  current_length: Int,
  best_start: Int,
  best_length: Int,
) -> #(Int, Int) {
  case remaining {
    [] ->
      case current_length > best_length {
        True -> #(current_start, current_length)
        False -> #(best_start, best_length)
      }
    [0, ..rest] -> {
      let started = case current_length {
        0 -> index
        _ -> current_start
      }
      zero_run_loop(
        rest,
        index + 1,
        started,
        current_length + 1,
        best_start,
        best_length,
      )
    }
    [_, ..rest] -> {
      let #(best_start, best_length) = case current_length > best_length {
        True -> #(current_start, current_length)
        False -> #(best_start, best_length)
      }
      zero_run_loop(rest, index + 1, 0, 0, best_start, best_length)
    }
  }
}
