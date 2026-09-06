//// The UDP packet format: the stream format with the framing taken away.
////
//// A packet is a salt, then one sealed blob holding the target address
//// followed by the payload, then a tag. No length field and no chunking,
//// because a datagram either arrives whole or does not arrive at all.
////
//// ### Why the nonce is all zeros
////
//// Every packet draws its own salt, so every packet derives a subkey it will
//// never use again, and a fixed nonce under a one-use key is safe. That is what
//// makes the salt non-negotiable: repeating one repeats the subkey, and a
//// repeated subkey under a fixed nonce is a total break rather than a
//// degradation. `seal` draws a fresh salt every time and there is no way to ask
//// it not to.
////
//// ### Short is malformed here
////
//// The stream decoder answers "not all here yet" because TCP will send more.
//// A datagram will not, so a packet that ends inside its address header is an
//// error and says so.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/crypto
import gleam/result
import ssocks/address.{type Address}
import ssocks/internal/aead
import ssocks/key.{type Key}
import ssocks/method

/// Why a packet could not be built or read.
pub type DatagramError {
  /// Smaller than a salt and a tag, so it cannot be a packet whatever it holds.
  TooShort(needed_at_least: Int, actual: Int)
  /// The packet did not authenticate: a wrong key, a wrong salt, or tampering.
  /// Which of those is not distinguished, because the caller cannot act on the
  /// difference and an attacker could.
  AuthenticationFailed
  /// A salt of the wrong size was supplied to `seal_with_salt`.
  BadSaltLength(expected: Int, actual: Int)
  /// The packet authenticated but its address header is not one.
  MalformedAddress(reason: address.DecodeError)
  /// The packet authenticated but ends inside its address header.
  TruncatedAddress
}

/// Build a packet with a fresh random salt.
///
/// This is the only impure function here, and drawing the salt is why.
pub fn seal(session_key: Key, target: Address, payload: BitArray) -> BitArray {
  let salt =
    crypto.strong_random_bytes(method.salt_size(key.method(session_key)))
  let assert Ok(packet) = seal_with_salt(session_key, salt, target, payload)
  packet
}

/// Build a packet with a salt you choose.
///
/// For tests and vectors. Production code wants `seal`: a repeated salt here is
/// worse than it is on a stream, because the nonce is fixed.
pub fn seal_with_salt(
  session_key: Key,
  salt: BitArray,
  target: Address,
  payload: BitArray,
) -> Result(BitArray, DatagramError) {
  let expected = method.salt_size(key.method(session_key))
  case bit_array.byte_size(salt) {
    actual if actual != expected -> Error(BadSaltLength(expected:, actual:))
    _ -> {
      let body = bit_array.concat([address.encode(target), payload])
      let #(ciphertext, tag) =
        aead.seal(
          key.method(session_key),
          key.derive_subkey(session_key, salt),
          zero_nonce(),
          <<>>,
          body,
        )
      Ok(bit_array.concat([salt, ciphertext, tag]))
    }
  }
}

/// Read a packet, returning where it is bound and what it carries.
pub fn open(
  session_key: Key,
  packet: BitArray,
) -> Result(#(Address, BitArray), DatagramError) {
  let salt_size = method.salt_size(key.method(session_key))
  // A packet has to hold at least a salt and a tag. Anything smaller cannot be
  // one whatever it contains, and is refused before any cryptography.
  let smallest = salt_size + method.tag_size
  let actual = bit_array.byte_size(packet)
  use _ <- result.try(case actual >= smallest {
    True -> Ok(Nil)
    False -> Error(TooShort(needed_at_least: smallest, actual:))
  })

  let assert Ok(salt) = bit_array.slice(packet, 0, salt_size)

  let body_size = actual - salt_size - method.tag_size
  let assert Ok(ciphertext) = bit_array.slice(packet, salt_size, body_size)
  let assert Ok(tag) =
    bit_array.slice(packet, salt_size + body_size, method.tag_size)

  use body <- result.try(
    aead.open(
      key.method(session_key),
      key.derive_subkey(session_key, salt),
      zero_nonce(),
      <<>>,
      ciphertext,
      tag,
    )
    |> result.replace_error(AuthenticationFailed),
  )

  // From here the bytes are authentic, so anything wrong with them is a peer
  // that built a bad packet rather than an attacker probing.
  case address.decode(body) {
    Error(reason) -> Error(MalformedAddress(reason))
    Ok(address.NeedMoreBytes(_)) -> Error(TruncatedAddress)
    Ok(address.Complete(target, payload)) -> Ok(#(target, payload))
  }
}

/// The salt at the front of a packet, without decrypting anything.
///
/// A server checks this against its replay filter first, so a packet it is
/// going to drop costs it no cryptography.
pub fn salt_of(
  session_key: Key,
  packet: BitArray,
) -> Result(BitArray, DatagramError) {
  // Only the salt itself is needed here. Whether the rest of the packet is
  // well formed is `open`'s question, and asking it now would refuse packets
  // the replay filter should still get to see.
  let salt_size = method.salt_size(key.method(session_key))
  let actual = bit_array.byte_size(packet)

  case actual >= salt_size {
    False -> Error(TooShort(needed_at_least: salt_size, actual:))
    True -> {
      let assert Ok(salt) = bit_array.slice(packet, 0, salt_size)
      Ok(salt)
    }
  }
}

fn zero_nonce() -> BitArray {
  <<0:size(method.nonce_size * 8)>>
}
