//// Key derivation is checked against published vectors rather than against
//// itself. HKDF-SHA1 comes from RFC 5869 Appendix A test cases 4 to 7, and
//// EVP_BytesToKey is anchored to the MD5 of the password, which any language
//// can reproduce independently.
////
//// Extract and expand are asserted separately on purpose. When a derived key
//// is wrong, knowing which of the two halves broke is the difference between a
//// minute of work and an afternoon of it.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import ssocks/internal/hex
import ssocks/internal/kdf

fn bytes(text: String) -> BitArray {
  let assert Ok(decoded) = hex.decode(text)
  decoded
}

// --- RFC 5869 A.4: basic case with SHA-1 -----------------------------------

const tc4_ikm = "0b0b0b0b0b0b0b0b0b0b0b"

const tc4_salt = "000102030405060708090a0b0c"

const tc4_info = "f0f1f2f3f4f5f6f7f8f9"

const tc4_prk = "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"

const tc4_okm = "085a01ea1b10f36933068b56efa5ad81
                 a4f14b822f5b091568a9cdd4f155fda2
                 c22e422478d305f3f896"

pub fn rfc5869_case_4_extracts_the_published_pseudorandom_key_test() {
  assert kdf.extract(bytes(tc4_salt), bytes(tc4_ikm)) == bytes(tc4_prk)
}

pub fn rfc5869_case_4_expands_the_published_output_keying_material_test() {
  assert kdf.expand(bytes(tc4_prk), bytes(tc4_info), 42) == bytes(tc4_okm)
}

pub fn rfc5869_case_4_derives_end_to_end_test() {
  assert kdf.hkdf_sha1(bytes(tc4_ikm), bytes(tc4_salt), bytes(tc4_info), 42)
    == bytes(tc4_okm)
}

// --- RFC 5869 A.5: longer inputs, and output spanning five SHA-1 blocks -----

const tc5_ikm = "000102030405060708090a0b0c0d0e0f
                 101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f
                 303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f"

const tc5_salt = "606162636465666768696a6b6c6d6e6f
                  707172737475767778797a7b7c7d7e7f
                  808182838485868788898a8b8c8d8e8f
                  909192939495969798999a9b9c9d9e9f
                  a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

const tc5_info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                  c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
                  d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                  e0e1e2e3e4e5e6e7e8e9eaebecedeeef
                  f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

const tc5_prk = "8adae09a2a307059478d309b26c4115a224cfaf6"

const tc5_okm = "0bd770a74d1160f7c9f12cd5912a06eb
                 ff6adcae899d92191fe4305673ba2ffe
                 8fa3f1a4e5ad79f3f334b3b202b2173c
                 486ea37ce3d397ed034c7f9dfeb15c5e
                 927336d0441f4c4300e2cff0d0900b52
                 d3b4"

pub fn rfc5869_case_5_extracts_the_published_pseudorandom_key_test() {
  assert kdf.extract(bytes(tc5_salt), bytes(tc5_ikm)) == bytes(tc5_prk)
}

pub fn rfc5869_case_5_expands_across_multiple_hash_blocks_test() {
  // 82 bytes needs five SHA-1 blocks, so this is the case that catches a
  // counter that never increments or a chain that forgets the previous block.
  assert kdf.expand(bytes(tc5_prk), bytes(tc5_info), 82) == bytes(tc5_okm)
}

// --- RFC 5869 A.6 and A.7: empty and absent salt ---------------------------

const tc6_ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"

const tc6_prk = "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"

const tc6_okm = "0ac1af7002b3d761d1e55298da9d0506
                 b9ae52057220a306e07b6b87e8df21d0
                 ea00033de03984d34918"

pub fn rfc5869_case_6_handles_empty_salt_and_empty_info_test() {
  assert kdf.extract(<<>>, bytes(tc6_ikm)) == bytes(tc6_prk)
  assert kdf.expand(bytes(tc6_prk), <<>>, 42) == bytes(tc6_okm)
}

const tc7_ikm = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

const tc7_prk = "2adccada18779e7c2077ad2eb19d3f3e731385dd"

const tc7_okm = "2c91117204d745f3500d636a62f64f0a
                 b3bae548aa53d423b0d1f27ebba6f5e5
                 673a081d70cce7acfc48"

const twenty_zero_bytes = "0000000000000000000000000000000000000000"

pub fn rfc5869_case_7_treats_an_absent_salt_as_hashlen_zero_bytes_test() {
  assert kdf.extract(bytes(twenty_zero_bytes), bytes(tc7_ikm)) == bytes(tc7_prk)
  assert kdf.expand(bytes(tc7_prk), <<>>, 42) == bytes(tc7_okm)
}

pub fn an_empty_salt_and_a_block_of_zero_bytes_derive_the_same_key_test() {
  // HMAC zero-pads a short key to the block size, so RFC 5869's "salt is
  // optional" and "defaults to HashLen zeros" are the same operation. Asserting
  // it keeps a future rewrite from special-casing one and not the other.
  let ikm = bytes(tc7_ikm)
  assert kdf.extract(<<>>, ikm) == kdf.extract(bytes(twenty_zero_bytes), ikm)
}

pub fn expanding_zero_bytes_yields_nothing_test() {
  assert kdf.expand(bytes(tc4_prk), bytes(tc4_info), 0) == <<>>
}

// --- Shadowsocks session subkeys -------------------------------------------

const master = "0102030405060708090a0b0c0d0e0f10"

const some_salt = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

pub fn a_session_subkey_is_hkdf_over_the_ss_subkey_info_string_test() {
  // SIP004 fixes info to the ASCII string "ss-subkey". Spelling it out here
  // means a typo in the implementation constant fails loudly.
  assert kdf.session_subkey(bytes(master), bytes(some_salt), 16)
    == kdf.hkdf_sha1(bytes(master), bytes(some_salt), <<"ss-subkey":utf8>>, 16)
}

pub fn a_session_subkey_has_exactly_the_requested_length_test() {
  assert bit_array.byte_size(kdf.session_subkey(
      bytes(master),
      bytes(some_salt),
      16,
    ))
    == 16
  assert bit_array.byte_size(kdf.session_subkey(
      bytes(master),
      bytes(some_salt),
      32,
    ))
    == 32
}

pub fn different_salts_derive_different_subkeys_test() {
  let one =
    kdf.session_subkey(
      bytes(master),
      bytes("00000000000000000000000000000000"),
      32,
    )
  let two =
    kdf.session_subkey(
      bytes(master),
      bytes("00000000000000000000000000000001"),
      32,
    )
  assert one != two
}

pub fn different_master_keys_derive_different_subkeys_test() {
  let one =
    kdf.session_subkey(
      bytes("00000000000000000000000000000000"),
      bytes(some_salt),
      32,
    )
  let two =
    kdf.session_subkey(
      bytes("00000000000000000000000000000001"),
      bytes(some_salt),
      32,
    )
  assert one != two
}

// --- EVP_BytesToKey --------------------------------------------------------

pub fn evp_bytes_to_key_reproduces_the_openssl_derivation_test() {
  // Independently produced by running OpenSSL's algorithm over Node's MD5.
  assert kdf.evp_bytes_to_key("", 16)
    == bytes("d41d8cd98f00b204e9800998ecf8427e")
  assert kdf.evp_bytes_to_key("test", 16)
    == bytes("098f6bcd4621d373cade4e832627b4f6")
  assert kdf.evp_bytes_to_key("test", 32)
    == bytes(
      "098f6bcd4621d373cade4e832627b4f6
       0a9172716ae6428409885b8b829ccb05",
    )
  assert kdf.evp_bytes_to_key("password", 32)
    == bytes(
      "5f4dcc3b5aa765d61d8327deb882cf99
       2b95990a9151374abd8ff8c5a7a0fe08",
    )
  assert kdf.evp_bytes_to_key("mypassword", 16)
    == bytes("34819d7beeabb9260a5c854bc85b3e44")
}

pub fn evp_bytes_to_key_treats_the_password_as_utf8_test() {
  assert kdf.evp_bytes_to_key("日本語", 32)
    == bytes(
      "00110af8b4393ef3f72c50be5b332bec
       759918a376c43e67b84e5d9f359f64b0",
    )
}

pub fn the_first_block_of_a_derived_key_is_the_md5_of_the_password_test() {
  // A second, structural check on the same values. 5f4dcc3b...cf99 is the
  // widely published MD5 of "password", so this anchors the vectors above to
  // something outside this repository.
  assert kdf.evp_bytes_to_key("password", 16)
    == bytes("5f4dcc3b5aa765d61d8327deb882cf99")
}

pub fn a_longer_key_extends_a_shorter_one_for_the_same_password_test() {
  let short = kdf.evp_bytes_to_key("test", 16)
  let long = kdf.evp_bytes_to_key("test", 32)
  let assert <<prefix:bytes-size(16), _:bits>> = long
  assert prefix == short
}

pub fn deriving_zero_bytes_yields_nothing_test() {
  assert kdf.evp_bytes_to_key("password", 0) == <<>>
}
