//// The two key derivations Shadowsocks AEAD needs.
////
//// HKDF-SHA1 (RFC 5869) turns a master key and a per-session salt into the
//// subkey a connection actually encrypts with. EVP_BytesToKey is OpenSSL's
//// password stretcher, and Shadowsocks uses it to turn a human password into a
//// master key of the right length.
////
//// Extract and expand are separate public functions even though only the
//// combined form is used in anger. RFC 5869 publishes the intermediate PRK for
//// every test case, so keeping the seam open lets a failure name which half
//// broke instead of only reporting that the final bytes differ.
////
//// EVP_BytesToKey is MD5-based and deliberately not hardened. It exists to
//// interoperate with the deployed protocol, not because it is a good password
//// hash. Prefer a random key over a password wherever the choice exists.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/crypto
import gleam/list

/// SHA-1 produces 20 byte digests, which sets the block size HKDF chains over.
const sha1_digest_size = 20

/// MD5 produces 16 byte digests, which sets the block size EVP_BytesToKey
/// chains over.
const md5_digest_size = 16

/// HKDF extract: absorb the input keying material into a pseudorandom key.
///
/// An empty salt behaves the same as a salt of `sha1_digest_size` zero bytes,
/// because HMAC zero-pads keys shorter than its block size. RFC 5869 describes
/// both and they are the same operation.
pub fn extract(salt: BitArray, ikm: BitArray) -> BitArray {
  crypto.hmac(ikm, crypto.Sha1, salt)
}

/// HKDF expand: stretch a pseudorandom key into `length` bytes of output.
///
/// The counter appended to each block is a single byte, so RFC 5869 caps the
/// output at 255 times the digest size. Shadowsocks only ever asks for 16 or
/// 32, far inside that bound.
pub fn expand(prk: BitArray, info: BitArray, length: Int) -> BitArray {
  expand_loop(prk, info, length, 1, <<>>, 0, [])
}

fn expand_loop(
  prk: BitArray,
  info: BitArray,
  length: Int,
  counter: Int,
  previous: BitArray,
  produced: Int,
  blocks: List(BitArray),
) -> BitArray {
  case produced >= length {
    True -> take(blocks, length)
    False -> {
      // T(n) = HMAC(PRK, T(n-1) || info || n). The chain into the previous
      // block is what makes the output longer than one digest safe to use.
      let block =
        crypto.hmac(<<previous:bits, info:bits, counter:8>>, crypto.Sha1, prk)
      expand_loop(
        prk,
        info,
        length,
        counter + 1,
        block,
        produced + sha1_digest_size,
        [block, ..blocks],
      )
    }
  }
}

/// Derive `length` bytes from a master key and a salt, the way SIP004 specifies.
///
/// The info string is fixed by the protocol to the ASCII text `ss-subkey`.
pub fn session_subkey(
  master: BitArray,
  salt: BitArray,
  length: Int,
) -> BitArray {
  hkdf_sha1(master, salt, <<"ss-subkey":utf8>>, length)
}

/// Extract then expand, the ordinary way to use HKDF.
pub fn hkdf_sha1(
  ikm: BitArray,
  salt: BitArray,
  info: BitArray,
  length: Int,
) -> BitArray {
  expand(extract(salt, ikm), info, length)
}

/// OpenSSL EVP_BytesToKey with MD5, no salt and a single iteration, which is
/// what Shadowsocks uses to turn a password into a master key.
pub fn evp_bytes_to_key(password: String, length: Int) -> BitArray {
  evp_loop(<<password:utf8>>, length, <<>>, 0, [])
}

fn evp_loop(
  password: BitArray,
  length: Int,
  previous: BitArray,
  produced: Int,
  blocks: List(BitArray),
) -> BitArray {
  case produced >= length {
    True -> take(blocks, length)
    False -> {
      // D(1) = MD5(password); D(n) = MD5(D(n-1) || password).
      let block = crypto.hash(crypto.Md5, <<previous:bits, password:bits>>)
      evp_loop(password, length, block, produced + md5_digest_size, [
        block,
        ..blocks
      ])
    }
  }
}

/// Concatenate accumulated blocks, newest first, and cut to `length` bytes.
///
/// Callers only reach here once they have produced at least `length` bytes, so
/// the slice cannot fail.
fn take(blocks: List(BitArray), length: Int) -> BitArray {
  let joined = blocks |> list.reverse |> bit_array.concat
  let assert Ok(output) = bit_array.slice(joined, 0, length)
  output
}
