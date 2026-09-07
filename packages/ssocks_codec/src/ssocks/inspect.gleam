//// Read a Shadowsocks stream the way the protocol reads it, and say so.
////
//// Protocol bugs here are silent. The symptom is always the same — nothing
//// gets through — and the causes are not distinguishable from the outside: a
//// nonce advanced once too often, a length field read the wrong way round, a
//// tag length left to a default. A hex dump of the bytes tells you nothing,
//// because the bytes are supposed to look like noise.
////
//// So this walks a stream exactly as `ssocks/stream` does and prints what it
//// found at every step, with the offsets, the nonces and the lengths that the
//// decoder was working with. A mismatch with another implementation goes from
//// a day of guessing to a minute of reading two dumps side by side.
////
//// ```text
//// 0000  0102030405060708…  salt (32 bytes)
//// 0020  a41f               chunk 0 length, sealed
//// 0022  ee0b40…(16)        tag, nonce 000000000000000000000000
////                          -> length 21
//// 0034  9c2ab1…(21)        chunk 0 payload, sealed
//// 0049  774e02…(16)        tag, nonce 010000000000000000000000
////                          -> 21 bytes: example.org:443 then 4 bytes
//// ```
////
//// Everything here needs the key, because everything here decrypts. Nothing is
//// printed that an attacker holding the ciphertext could not already compute
//// with the key, and the key itself never appears.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import ssocks/address
import ssocks/datagram
import ssocks/internal/aead
import ssocks/internal/hex
import ssocks/key.{type Key}
import ssocks/method
import ssocks/nonce.{type Nonce}

/// Describe a TCP stream, starting at its salt.
///
/// Works on a whole stream or on however much of one arrived; a truncated
/// stream is reported as truncated, with what was still needed.
pub fn stream(session: Key, bytes: BitArray) -> String {
  let size = method.salt_size(key.method(session))

  case take(bytes, size) {
    Error(Nil) ->
      starved(
        0,
        bit_array.byte_size(bytes),
        size,
        "the salt, which every stream opens with",
      )

    Ok(#(salt, rest)) ->
      [
        row(0, salt, "salt (" <> int.to_string(size) <> " bytes)"),
        ..chunks(
          key.derive_subkey(session, salt),
          key.method(session),
          nonce.zero(),
          rest,
          size,
          0,
          True,
        )
      ]
      |> string.join("\n")
  }
}

/// Describe a UDP packet.
pub fn packet(session: Key, bytes: BitArray) -> String {
  let salt_size = method.salt_size(key.method(session))
  let total = bit_array.byte_size(bytes)

  case take(bytes, salt_size) {
    Error(Nil) ->
      starved(0, total, salt_size, "the salt, which every packet opens with")

    Ok(#(salt, _)) -> {
      let head =
        row(0, salt, "salt (" <> int.to_string(salt_size) <> " bytes)")
        <> "\n"
        <> row(
          salt_size,
          slice_or_empty(bytes, salt_size, total - salt_size),
          "sealed, one box under an all-zero nonce",
        )

      case datagram.open(session, bytes) {
        Error(reason) ->
          head <> "\n" <> note("did not open: " <> string.inspect(reason))
        Ok(#(target, payload)) ->
          head
          <> "\n"
          <> note(
            "-> "
            <> address.to_string(target)
            <> " then "
            <> int.to_string(bit_array.byte_size(payload))
            <> " bytes",
          )
      }
    }
  }
}

/// Describe a target address header, which is what the first plaintext bytes
/// of a stream are.
pub fn header(bytes: BitArray) -> String {
  case address.decode(bytes) {
    Ok(address.Complete(target, rest)) ->
      row(0, bytes, "address header")
      <> "\n"
      <> note(
        "-> "
        <> address.to_string(target)
        <> ", then "
        <> int.to_string(bit_array.byte_size(rest))
        <> " bytes of payload",
      )
    Ok(address.NeedMoreBytes(at_least)) ->
      starved(
        0,
        bit_array.byte_size(bytes),
        at_least,
        "an address header, which is one type byte then a host and a port",
      )
    Error(reason) ->
      row(0, bytes, "not an address header")
      <> "\n"
      <> note(string.inspect(reason))
  }
}

/// A plain annotated hex dump, for bytes that are not any of the above.
pub fn dump(bytes: BitArray) -> String {
  row(0, bytes, int.to_string(bit_array.byte_size(bytes)) <> " bytes")
}

// --- walking a stream ---------------------------------------------------------

fn chunks(
  subkey: BitArray,
  chosen: method.Method,
  counter: Nonce,
  remaining: BitArray,
  at: Int,
  index: Int,
  first: Bool,
) -> List(String) {
  case bit_array.byte_size(remaining) {
    0 -> [note("end of what was given, cleanly between chunks")]
    _ -> length_of(subkey, chosen, counter, remaining, at, index, first)
  }
}

fn length_of(
  subkey: BitArray,
  chosen: method.Method,
  counter: Nonce,
  remaining: BitArray,
  at: Int,
  index: Int,
  first: Bool,
) -> List(String) {
  let sealed = 2 + method.tag_size

  case take(remaining, sealed) {
    Error(Nil) -> [
      starved(
        at,
        bit_array.byte_size(remaining),
        sealed,
        "a chunk length, which is two bytes and a "
          <> int.to_string(method.tag_size)
          <> " byte tag",
      ),
    ]

    Ok(#(box, rest)) -> {
      let assert Ok(ciphertext) = bit_array.slice(box, 0, 2)
      let assert Ok(tag) = bit_array.slice(box, 2, method.tag_size)

      let lines = [
        row(
          at,
          ciphertext,
          "chunk " <> int.to_string(index) <> " length, sealed",
        ),
        row(at + 2, tag, "tag, nonce " <> hex.encode(nonce.to_bytes(counter))),
      ]

      case
        aead.open(
          chosen,
          subkey,
          nonce.to_bytes(counter),
          <<>>,
          ciphertext,
          tag,
        )
      {
        Error(Nil) -> list.append(lines, [failure(index, "length", counter)])

        // The length is big-endian, while the nonce beside it counts in
        // little-endian. That asymmetry is in the protocol, and getting it
        // backwards is the single most common way to build a stream that
        // authenticates its length and then reads nonsense.
        Ok(<<length:16>>) ->
          list.append(lines, [
            note("-> length " <> int.to_string(length)),
            ..payload_of(
              subkey,
              chosen,
              nonce.next(counter),
              rest,
              at + sealed,
              index,
              length,
              first,
            )
          ])

        Ok(other) ->
          list.append(lines, [
            note(
              "-> a length field that is not two bytes: "
              <> hex.encode(other)
              <> ". This cannot happen through this library and means the "
              <> "cipher is not the one the far end used.",
            ),
          ])
      }
    }
  }
}

fn payload_of(
  subkey: BitArray,
  chosen: method.Method,
  counter: Nonce,
  remaining: BitArray,
  at: Int,
  index: Int,
  length: Int,
  first: Bool,
) -> List(String) {
  let sealed = length + method.tag_size

  case take(remaining, sealed) {
    Error(Nil) -> [
      starved(
        at,
        bit_array.byte_size(remaining),
        sealed,
        "chunk "
          <> int.to_string(index)
          <> ", whose length said "
          <> int.to_string(length)
          <> " bytes",
      ),
    ]

    Ok(#(box, rest)) -> {
      let assert Ok(ciphertext) = bit_array.slice(box, 0, length)
      let assert Ok(tag) = bit_array.slice(box, length, method.tag_size)

      let lines = [
        row(
          at,
          ciphertext,
          "chunk " <> int.to_string(index) <> " payload, sealed",
        ),
        row(
          at + length,
          tag,
          "tag, nonce " <> hex.encode(nonce.to_bytes(counter)),
        ),
      ]

      case
        aead.open(
          chosen,
          subkey,
          nonce.to_bytes(counter),
          <<>>,
          ciphertext,
          tag,
        )
      {
        Error(Nil) -> list.append(lines, [failure(index, "payload", counter)])

        Ok(plaintext) ->
          list.append(lines, [
            note("-> " <> describe(plaintext, first)),
            ..chunks(
              subkey,
              chosen,
              nonce.next(counter),
              rest,
              at + sealed,
              index + 1,
              False,
            )
          ])
      }
    }
  }
}

/// The first plaintext of a client's stream is the target address, and saying
/// so is most of the value of reading one of these at all.
fn describe(plaintext: BitArray, first: Bool) -> String {
  let size = int.to_string(bit_array.byte_size(plaintext)) <> " bytes"

  case first, address.decode(plaintext) {
    True, Ok(address.Complete(target, rest)) ->
      size
      <> ": "
      <> address.to_string(target)
      <> " then "
      <> int.to_string(bit_array.byte_size(rest))
      <> " bytes of payload"
    True, _ ->
      size
      <> ", which is not an address header. In a stream from a client the "
      <> "first bytes are the target; in one from a server they are payload."
    False, _ -> size
  }
}

// --- lines --------------------------------------------------------------------

/// Wide enough for an offset, an abbreviated field and a sentence.
const hex_width = 18

fn row(at: Int, value: BitArray, meaning: String) -> String {
  offset(at) <> "  " <> pad(abbreviate(value)) <> "  " <> meaning
}

fn note(meaning: String) -> String {
  "                        " <> meaning
}

fn failure(index: Int, part: String, counter: Nonce) -> String {
  note(
    "-> did not authenticate. Chunk "
    <> int.to_string(index)
    <> ", "
    <> part
    <> ", nonce "
    <> hex.encode(nonce.to_bytes(counter))
    <> ". On chunk 0 this is the password, the method or the salt; further in "
    <> "it means the framing drifted, and the nonce says by how much.",
  )
}

fn starved(at: Int, have: Int, want: Int, what: String) -> String {
  offset(at)
  <> "  "
  <> pad("(" <> int.to_string(have) <> ")")
  <> "  ends here, needing "
  <> int.to_string(want)
  <> " bytes for "
  <> what
}

fn offset(at: Int) -> String {
  hex.encode(<<at:16>>)
}

fn abbreviate(value: BitArray) -> String {
  let size = bit_array.byte_size(value)
  let text = hex.encode(value)

  case string.length(text) > hex_width {
    False -> text
    True ->
      string.slice(text, 0, hex_width - 8) <> "…(" <> int.to_string(size) <> ")"
  }
}

fn pad(text: String) -> String {
  string.pad_end(text, hex_width, " ")
}

fn take(value: BitArray, size: Int) -> Result(#(BitArray, BitArray), Nil) {
  let total = bit_array.byte_size(value)
  case total >= size {
    False -> Error(Nil)
    True -> {
      let assert Ok(head) = bit_array.slice(value, 0, size)
      let assert Ok(tail) = bit_array.slice(value, size, total - size)
      Ok(#(head, tail))
    }
  }
}

fn slice_or_empty(value: BitArray, at: Int, size: Int) -> BitArray {
  case bit_array.slice(value, at, size) {
    Ok(sliced) -> sliced
    Error(Nil) -> <<>>
  }
}
