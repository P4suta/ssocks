//// SOCKS5, from RFC 1928, with no sockets in it.
////
//// This is the protocol a browser speaks to a local proxy. Shadowsocks borrowed
//// one piece of it — the target address encoding, which is `ssocks/address` —
//// and left the rest behind, so the rest is here: the greeting, the method
//// selection, the request, the reply, and the header on a relayed datagram.
////
//// ### Both directions, on purpose
////
//// A server half alone would only ever be checked against this package's own
//// client, and the same mistake made in both would pass every test while
//// nobody else could talk to it. A real `sslocal` is a SOCKS5 *server*, so the
//// client half is what lets a test put a foreign implementation on the other
//// end of this code. That is the same argument the wire interoperability tests
//// already make, and it is the only one that can say the bytes are right
//// rather than merely agreed upon.
////
//// ### Three outcomes when reading
////
//// A greeting, a request and a reply all arrive over TCP, so a read can stop
//// in the middle of one. `decode_*` therefore answers "complete", "not all here
//// yet" or "malformed" separately, exactly as `ssocks/address` does. Folding
//// the middle case into an error would drop clients that were merely slow.
////
//// A datagram is different: it arrives whole or not at all, so
//// `decode_datagram` has two outcomes and short is malformed.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/list
import ssocks/address.{type Address}

/// The only version of SOCKS this speaks.
pub const version = 5

/// What a client is asking the proxy to do.
pub type Command {
  /// Open a TCP connection to the target. The only one `ssocks/local` serves.
  Connect
  /// Listen for an inbound connection on the client's behalf. Not implemented:
  /// it needs a second listening socket per request with no way to secure it,
  /// and essentially nothing uses it.
  Bind
  /// Relay datagrams for the client. Served when the proxy has a UDP relay to
  /// send them through.
  Associate
}

/// An authentication method, by the byte the protocol gives it.
pub type Authentication {
  /// `0x00`, and the only one implemented here. A local proxy is reached over
  /// the loopback interface; a password on that hop protects against nothing
  /// that being on the machine does not already defeat.
  NoAuthentication
  /// `0xff`. What a server answers when nothing offered was acceptable. A
  /// client never offers it.
  NoneAcceptable
  /// Anything else, kept as its byte so a refusal can say what was asked for.
  Other(byte: Int)
}

/// The outcome byte in a reply.
pub type Reply {
  Succeeded
  GeneralFailure
  NotAllowed
  NetworkUnreachable
  HostUnreachable
  ConnectionRefused
  TtlExpired
  /// The command is not one this proxy serves. `Bind` always earns this.
  CommandNotSupported
  AddressNotSupported
}

/// Why some bytes could not be the message they were read as.
pub type Socks5Error {
  /// A first byte that is not 5. Usually SOCKS4, or something that is not
  /// SOCKS at all pointed at the wrong port.
  WrongVersion(version: Int)
  /// A greeting offering nothing. There is no method to choose and no way to
  /// proceed.
  NoMethodsOffered
  /// The reserved byte was not zero. RFC 1928 fixes it at zero, and a peer that
  /// puts something else there is not speaking this protocol.
  ReservedNotZero(byte: Int)
  UnknownCommand(byte: Int)
  UnknownReply(byte: Int)
  MalformedAddress(reason: address.DecodeError)
  /// A relayed datagram asking to be reassembled. `ssocks/local` does not
  /// implement fragments and says so rather than delivering a piece of a
  /// payload as though it were the whole of one.
  Fragmented(fragment: Int)
  /// A datagram that ends before its header does. A datagram arrives whole or
  /// not at all, so this is malformed rather than incomplete.
  TooShort(needed_at_least: Int, actual: Int)
}

/// What a `decode_*` found.
pub type Outcome(message) {
  /// A whole message, and whatever bytes followed it.
  Complete(message: message, rest: BitArray)
  /// Not a failure. The message needs at least this many bytes in total, and
  /// fewer than that have arrived.
  NeedMoreBytes(at_least: Int)
}

// --- the greeting ---------------------------------------------------------------

/// Read a client's greeting: which authentication methods it offers.
pub fn decode_greeting(
  bytes: BitArray,
) -> Result(Outcome(List(Authentication)), Socks5Error) {
  case bytes {
    <<5, count:8, rest:bits>> ->
      case count {
        0 -> Error(NoMethodsOffered)
        _ ->
          case rest {
            <<offered:bytes-size(count), tail:bits>> ->
              Ok(Complete(authentications(offered, []), tail))
            _ -> Ok(NeedMoreBytes(2 + count))
          }
      }

    <<other:8, _:bits>> if other != 5 -> Error(WrongVersion(other))
    _ -> Ok(NeedMoreBytes(2))
  }
}

fn authentications(
  bytes: BitArray,
  acc: List(Authentication),
) -> List(Authentication) {
  case bytes {
    <<byte:8, rest:bits>> ->
      authentications(rest, [authentication(byte), ..acc])
    _ -> list.reverse(acc)
  }
}

/// Write a client's greeting.
pub fn encode_greeting(offered: List(Authentication)) -> BitArray {
  let bytes =
    list.fold(offered, <<>>, fn(acc, one) {
      <<acc:bits, { authentication_byte(one) }:8>>
    })

  <<version:8, { list.length(offered) }:8, bytes:bits>>
}

/// Read a server's choice of method.
pub fn decode_choice(
  bytes: BitArray,
) -> Result(Outcome(Authentication), Socks5Error) {
  case bytes {
    <<5, chosen:8, rest:bits>> -> Ok(Complete(authentication(chosen), rest))
    <<other:8, _:bits>> if other != 5 -> Error(WrongVersion(other))
    _ -> Ok(NeedMoreBytes(2))
  }
}

/// Write a server's choice of method.
pub fn encode_choice(chosen: Authentication) -> BitArray {
  <<version:8, { authentication_byte(chosen) }:8>>
}

fn authentication(byte: Int) -> Authentication {
  case byte {
    0x00 -> NoAuthentication
    0xff -> NoneAcceptable
    _ -> Other(byte)
  }
}

fn authentication_byte(one: Authentication) -> Int {
  case one {
    NoAuthentication -> 0x00
    NoneAcceptable -> 0xff
    Other(byte) -> byte
  }
}

// --- the request and its reply ---------------------------------------------------

/// Read a client's request: what to do, and where.
pub fn decode_request(
  bytes: BitArray,
) -> Result(Outcome(#(Command, Address)), Socks5Error) {
  case bytes {
    <<5, command:8, reserved:8, rest:bits>> -> {
      use _ <- try(reserved_is_zero(reserved))
      use command <- try(command_of(command))
      use outcome <- try(target(rest))

      Ok(case outcome {
        NeedMoreBytes(at_least) -> NeedMoreBytes(3 + at_least)
        Complete(where, tail) -> Complete(#(command, where), tail)
      })
    }

    <<other:8, _:bits>> if other != 5 -> Error(WrongVersion(other))
    _ -> Ok(NeedMoreBytes(3))
  }
}

/// Write a client's request.
pub fn encode_request(command: Command, where: Address) -> BitArray {
  <<
    version:8,
    { command_byte(command) }:8,
    0:8,
    { address.encode(where) }:bits,
  >>
}

/// Read a server's reply: how it went, and the address it bound.
pub fn decode_reply(
  bytes: BitArray,
) -> Result(Outcome(#(Reply, Address)), Socks5Error) {
  case bytes {
    <<5, outcome:8, reserved:8, rest:bits>> -> {
      use _ <- try(reserved_is_zero(reserved))
      use outcome <- try(reply_of(outcome))
      use decoded <- try(target(rest))

      Ok(case decoded {
        NeedMoreBytes(at_least) -> NeedMoreBytes(3 + at_least)
        Complete(bound, tail) -> Complete(#(outcome, bound), tail)
      })
    }

    <<other:8, _:bits>> if other != 5 -> Error(WrongVersion(other))
    _ -> Ok(NeedMoreBytes(3))
  }
}

/// Write a server's reply.
///
/// The bound address is what the client is told the proxy is using on its
/// behalf. A proxy that has nothing meaningful to report there sends
/// `unspecified`, which every client accepts.
pub fn encode_reply(outcome: Reply, bound: Address) -> BitArray {
  <<version:8, { reply_byte(outcome) }:8, 0:8, { address.encode(bound) }:bits>>
}

/// `0.0.0.0:0`, for a reply with no meaningful address to report.
pub fn unspecified() -> Address {
  let assert Ok(where) = address.ipv4(#(0, 0, 0, 0), 0)
  where
}

// --- relayed datagrams -----------------------------------------------------------

/// Read the header on a datagram a client sent to be relayed.
///
/// Whole or nothing: a datagram that ends inside its header is malformed rather
/// than incomplete, because nothing more is coming.
pub fn decode_datagram(
  bytes: BitArray,
) -> Result(#(Address, BitArray), Socks5Error) {
  case bytes {
    <<first:8, second:8, fragment:8, rest:bits>> ->
      case first, second, fragment {
        0, 0, 0 ->
          case target(rest) {
            Error(reason) -> Error(reason)
            Ok(NeedMoreBytes(at_least)) ->
              Error(TooShort(
                needed_at_least: 3 + at_least,
                actual: bit_array.byte_size(bytes),
              ))
            Ok(Complete(where, payload)) -> Ok(#(where, payload))
          }

        0, 0, _ -> Error(Fragmented(fragment))
        0, other, _ -> Error(ReservedNotZero(other))
        other, _, _ -> Error(ReservedNotZero(other))
      }

    _ -> Error(TooShort(needed_at_least: 4, actual: bit_array.byte_size(bytes)))
  }
}

/// Write the header on a datagram to be relayed, and the payload after it.
pub fn encode_datagram(where: Address, payload: BitArray) -> BitArray {
  <<0:8, 0:8, 0:8, { address.encode(where) }:bits, payload:bits>>
}

// --- naming the bytes ------------------------------------------------------------

fn command_of(byte: Int) -> Result(Command, Socks5Error) {
  case byte {
    0x01 -> Ok(Connect)
    0x02 -> Ok(Bind)
    0x03 -> Ok(Associate)
    _ -> Error(UnknownCommand(byte))
  }
}

fn command_byte(command: Command) -> Int {
  case command {
    Connect -> 0x01
    Bind -> 0x02
    Associate -> 0x03
  }
}

fn reply_of(byte: Int) -> Result(Reply, Socks5Error) {
  case byte {
    0x00 -> Ok(Succeeded)
    0x01 -> Ok(GeneralFailure)
    0x02 -> Ok(NotAllowed)
    0x03 -> Ok(NetworkUnreachable)
    0x04 -> Ok(HostUnreachable)
    0x05 -> Ok(ConnectionRefused)
    0x06 -> Ok(TtlExpired)
    0x07 -> Ok(CommandNotSupported)
    0x08 -> Ok(AddressNotSupported)
    _ -> Error(UnknownReply(byte))
  }
}

fn reply_byte(outcome: Reply) -> Int {
  case outcome {
    Succeeded -> 0x00
    GeneralFailure -> 0x01
    NotAllowed -> 0x02
    NetworkUnreachable -> 0x03
    HostUnreachable -> 0x04
    ConnectionRefused -> 0x05
    TtlExpired -> 0x06
    CommandNotSupported -> 0x07
    AddressNotSupported -> 0x08
  }
}

/// A sentence for a person.
///
/// None of these quote the bytes they were given. A SOCKS5 request carries the
/// host somebody is visiting, which is not a thing to put in a log line by
/// default.
pub fn explain(reason: Socks5Error) -> String {
  case reason {
    WrongVersion(version) ->
      "this is not SOCKS5: the first byte was "
      <> int.to_string(version)
      <> " rather than 5. SOCKS4 and anything that is not SOCKS at all look "
      <> "like this."
    NoMethodsOffered ->
      "the greeting offered no authentication methods, so there is nothing to "
      <> "choose and no way to go on."
    ReservedNotZero(byte) ->
      "the reserved byte was "
      <> int.to_string(byte)
      <> " rather than 0, which RFC 1928 fixes it at."
    UnknownCommand(byte) ->
      "command " <> int.to_string(byte) <> " is not one RFC 1928 defines."
    UnknownReply(byte) ->
      "reply code " <> int.to_string(byte) <> " is not one RFC 1928 defines."
    MalformedAddress(reason) ->
      "the target address is not one: " <> address.explain_decode(reason)
    Fragmented(fragment) ->
      "the datagram is fragment "
      <> int.to_string(fragment)
      <> " of a larger one. Reassembly is not implemented, and delivering a "
      <> "piece as though it were the whole would corrupt the payload."
    TooShort(needed_at_least:, actual:) ->
      "the datagram is "
      <> int.to_string(actual)
      <> " bytes and its header alone needs "
      <> int.to_string(needed_at_least)
      <> ". A datagram arrives whole or not at all, so this is malformed "
      <> "rather than unfinished."
  }
}

fn reserved_is_zero(byte: Int) -> Result(Nil, Socks5Error) {
  case byte {
    0 -> Ok(Nil)
    _ -> Error(ReservedNotZero(byte))
  }
}

/// The address part, which is the piece Shadowsocks borrowed.
fn target(bytes: BitArray) -> Result(Outcome(Address), Socks5Error) {
  case address.decode(bytes) {
    Error(reason) -> Error(MalformedAddress(reason))
    Ok(address.NeedMoreBytes(at_least)) -> Ok(NeedMoreBytes(at_least))
    Ok(address.Complete(where, rest)) -> Ok(Complete(where, rest))
  }
}

fn try(
  result: Result(a, Socks5Error),
  then: fn(a) -> Result(b, Socks5Error),
) -> Result(b, Socks5Error) {
  case result {
    Error(reason) -> Error(reason)
    Ok(value) -> then(value)
  }
}
