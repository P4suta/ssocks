//// AEAD_CHACHA20_POLY1305 from RFC 8439 section 2.8, in portable Gleam.
////
//// The construction is short but has two details that are easy to get wrong in
//// a way that still round-trips against itself and fails against every other
//// implementation:
////
////   - the authenticated data and the ciphertext are each zero padded up to a
////     multiple of 16 bytes before being fed to the MAC, and
////   - their two lengths are appended as 64-bit little-endian integers.
////
//// Both regions are padded independently, and a length is appended even when
//// the region is empty.
////
//// The block counter also differs between the two uses of ChaCha20: block zero
//// produces the one-time Poly1305 key, and the payload is encrypted starting
//// from block one. Reusing block zero for the payload would leak the MAC key.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/crypto
import ssocks/cipher/chacha20
import ssocks/cipher/poly1305

const tag_size = 16

/// Derive the one-time Poly1305 key for a message.
///
/// This is the first 32 bytes of ChaCha20 block zero. It is public because
/// RFC 8439 publishes a vector for it, and being able to check this step alone
/// separates "the key derivation is wrong" from "the MAC is wrong".
pub fn one_time_key(key: BitArray, nonce: BitArray) -> BitArray {
  let assert Ok(derived) = bit_array.slice(chacha20.block(key, 0, nonce), 0, 32)
  derived
}

/// Encrypt and authenticate, returning the ciphertext and its 16 byte tag.
pub fn seal(
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  plaintext: BitArray,
) -> #(BitArray, BitArray) {
  let ciphertext = chacha20.encrypt(key, 1, nonce, plaintext)
  let tag =
    poly1305.mac(
      one_time_key(key, nonce),
      mac_input(associated_data, ciphertext),
    )
  #(ciphertext, tag)
}

/// Verify and decrypt. Returns `Error(Nil)` if anything at all fails to
/// authenticate, without saying which part, because a caller cannot act on the
/// difference and an attacker could.
///
/// The tag is checked before the plaintext is produced, so a forged frame is
/// never decrypted.
pub fn open(
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, Nil) {
  // The tag arrives from the network, so its length is not to be trusted. Check
  // it before comparing: a constant-time comparison of mismatched lengths is
  // either an error or a lie, depending on the implementation underneath.
  case bit_array.byte_size(tag) == tag_size {
    False -> Error(Nil)
    True -> {
      let expected =
        poly1305.mac(
          one_time_key(key, nonce),
          mac_input(associated_data, ciphertext),
        )
      case crypto.secure_compare(expected, tag) {
        False -> Error(Nil)
        // ChaCha20 is a keystream XOR, so decrypting is encrypting again.
        True -> Ok(chacha20.encrypt(key, 1, nonce, ciphertext))
      }
    }
  }
}

/// The exact byte sequence the MAC is computed over.
fn mac_input(associated_data: BitArray, ciphertext: BitArray) -> BitArray {
  let associated_length = bit_array.byte_size(associated_data)
  let ciphertext_length = bit_array.byte_size(ciphertext)

  bit_array.concat([
    associated_data,
    padding(associated_length),
    ciphertext,
    padding(ciphertext_length),
    <<associated_length:64-little>>,
    <<ciphertext_length:64-little>>,
  ])
}

/// Zero bytes to round a region up to a multiple of 16, and nothing at all when
/// it already is. An implementation that always pads a full block instead would
/// pass its own round-trip tests and fail against every other implementation.
fn padding(length: Int) -> BitArray {
  case length % 16 {
    0 -> <<>>
    remainder -> <<0:size({ 16 - remainder } * 8)>>
  }
}
