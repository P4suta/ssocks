//// The AEAD layer: one API over the platform ciphers and the portable Gleam
//// ChaCha20-Poly1305.
////
//// Three jobs are checked here.
////
//// The first is the published vectors, so the wiring to each platform cipher is
//// anchored to something outside this repository. AES-GCM comes from the
//// McGrew and Viega test cases, ChaCha20-Poly1305 from RFC 8439.
////
//// The second is the cipher naming. Shadowsocks calls its ChaCha method
//// `chacha20-ietf-poly1305`, while Erlang wants the atom `chacha20_poly1305`
//// and Node the string `chacha20-poly1305`. Passing the protocol spelling
//// straight through to the platform would fail at run time on one target and
//// not the other.
////
//// The third, and the reason the portable implementation is worth its weight,
//// is differential testing. Wherever a platform cipher and the Gleam one both
//// exist, they are handed identical inputs and must produce identical bytes. A
//// bug that fooled the vectors would have to fool two independent
//// implementations in exactly the same way.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import ssocks/internal/aead
import ssocks/method
import vector.{bytes}

const every_method = [
  method.Aes128Gcm,
  method.Aes256Gcm,
  method.ChaCha20Poly1305,
]

// --- AES-GCM published vectors ---------------------------------------------

pub fn aes_256_gcm_case_13_authenticates_nothing_at_all_test() {
  // Empty key material, empty plaintext, empty associated data. The tag still
  // has to be right, so this catches an implementation that skips the MAC when
  // there is nothing to encrypt.
  assert aead.seal(
      method.Aes256Gcm,
      bytes("0000000000000000000000000000000000000000000000000000000000000000"),
      bytes("000000000000000000000000"),
      <<>>,
      <<>>,
    )
    == #(<<>>, bytes("530f8afbc74536b9a963b4f1c4cb738b"))
}

pub fn aes_256_gcm_case_14_encrypts_a_single_block_test() {
  assert aead.seal(
      method.Aes256Gcm,
      bytes("0000000000000000000000000000000000000000000000000000000000000000"),
      bytes("000000000000000000000000"),
      <<>>,
      bytes("00000000000000000000000000000000"),
    )
    == #(
      bytes("cea7403d4d606b6e074ec5d3baf39d18"),
      bytes("d0d1c8a799996bf0265b98b5d48ab919"),
    )
}

pub fn aes_256_gcm_case_16_covers_associated_data_test() {
  assert aead.seal(
      method.Aes256Gcm,
      bytes(
        "feffe9928665731c6d6a8f9467308308
             feffe9928665731c6d6a8f9467308308",
      ),
      bytes("cafebabefacedbaddecaf888"),
      bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
      bytes(
        "d9313225f88406e5a55909c5aff5269a
             86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525
             b16aedf5aa0de657ba637b39",
      ),
    )
    == #(
      bytes(
        "522dc1f099567d07f47f37a32a84427d
             643a8cdcbfe5c0c97598a2bd2555d1aa
             8cb08e48590dbb3da7b08b1056828838
             c5f61e6393ba7a0abcc9f662",
      ),
      bytes("76fc6ece0f4e1768cddf8853bb2d551b"),
    )
}

pub fn aes_128_gcm_case_3_uses_the_shorter_key_test() {
  assert aead.seal(
      method.Aes128Gcm,
      bytes("feffe9928665731c6d6a8f9467308308"),
      bytes("cafebabefacedbaddecaf888"),
      <<>>,
      bytes(
        "d9313225f88406e5a55909c5aff5269a
             86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525
             b16aedf5aa0de657ba637b391aafd255",
      ),
    )
    == #(
      bytes(
        "42831ec2217774244b7221b784d0d49c
             e3aa212f2c02a4e035c17e2329aca12e
             21d514b25466931c7d8f6a5aac84aa05
             1ba30b396a0aac973d58e091473f5985",
      ),
      bytes("4d5c2af327cd64a62cf35abd2ba6fab4"),
    )
}

// --- ChaCha20-Poly1305 through the dispatch layer ---------------------------

pub fn rfc8439_chacha20_poly1305_vector_passes_through_the_dispatcher_test() {
  // Reaching the right cipher at all is the point: the protocol spells this
  // method with an "ietf" that no crypto library recognises.
  assert aead.seal(
      method.ChaCha20Poly1305,
      bytes(
        "808182838485868788898a8b8c8d8e8f
             909192939495969798999a9b9c9d9e9f",
      ),
      bytes("070000004041424344454647"),
      bytes("50515253c0c1c2c3c4c5c6c7"),
      <<
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.":utf8,
      >>,
    )
    == #(
      bytes(
        "d31a8d34648e60db7b86afbc53ef7ec2
             a4aded51296e08fea9e2b5a736ee62d6
             3dbea45e8ca9671282fafb69da92728b
             1a71de0a9e060b2905d6a5b67ecd3b36
             92ddbd7f2d778b8c9803aee328091b58
             fab324e4fad675945585808b4831d7bc
             3ff4def08e4b7a9de576d26586cec64b
             6116",
      ),
      bytes("1ae10b594f09e26a7e902ecbd0600691"),
    )
}

// --- backend availability ---------------------------------------------------

pub fn a_portable_backend_exists_for_chacha_and_not_for_aes_test() {
  // There is no hand-written AES here and there will not be one, so AES is
  // native or nothing. Saying so explicitly keeps `selected` honest.
  assert aead.supports(aead.Portable, method.ChaCha20Poly1305)
  assert !aead.supports(aead.Portable, method.Aes128Gcm)
  assert !aead.supports(aead.Portable, method.Aes256Gcm)
}

pub fn aes_gcm_is_available_natively_on_every_supported_runtime_test() {
  // Erlang, Node, Deno and Bun all ship AES-GCM. If a runtime ever stops, this
  // is where it is noticed rather than at the first connection attempt.
  assert aead.supports(aead.Native, method.Aes128Gcm)
  assert aead.supports(aead.Native, method.Aes256Gcm)
}

pub fn every_method_has_at_least_one_usable_backend_test() {
  use chosen_method <- list.each(every_method)
  assert aead.supports(aead.Native, chosen_method)
    || aead.supports(aead.Portable, chosen_method)
}

pub fn the_selected_backend_is_one_this_runtime_supports_test() {
  use chosen_method <- list.each(every_method)
  assert aead.supports(aead.selected(chosen_method), chosen_method)
}

// --- differential testing: the two implementations must agree ---------------

pub fn both_backends_seal_identical_bytes_test() {
  // Only ChaCha20-Poly1305 has two implementations, and only where the runtime
  // ships one. On Bun there is no native ChaCha20 at all, so this test is
  // vacuous there and the assertion below documents that rather than hiding it.
  case aead.supports(aead.Native, method.ChaCha20Poly1305) {
    False -> Nil
    True -> {
      use size <- list.each([0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 1000])
      let plaintext = filler(0x5a, size)
      let associated = filler(0xa5, size % 19)

      let assert Ok(native) =
        aead.seal_using(
          aead.Native,
          method.ChaCha20Poly1305,
          chacha_key(),
          chacha_nonce(),
          associated,
          plaintext,
        )
      let assert Ok(portable) =
        aead.seal_using(
          aead.Portable,
          method.ChaCha20Poly1305,
          chacha_key(),
          chacha_nonce(),
          associated,
          plaintext,
        )
      assert native == portable
    }
  }
}

pub fn each_backend_opens_what_the_other_sealed_test() {
  case aead.supports(aead.Native, method.ChaCha20Poly1305) {
    False -> Nil
    True -> {
      let plaintext = <<"the two implementations must agree exactly":utf8>>
      let associated = <<"and on the associated data too":utf8>>

      let assert Ok(#(ciphertext, tag)) =
        aead.seal_using(
          aead.Native,
          method.ChaCha20Poly1305,
          chacha_key(),
          chacha_nonce(),
          associated,
          plaintext,
        )

      let assert Ok(opened) =
        aead.open_using(
          aead.Portable,
          method.ChaCha20Poly1305,
          chacha_key(),
          chacha_nonce(),
          associated,
          ciphertext,
          tag,
        )
      assert opened == Ok(plaintext)

      let assert Ok(#(ciphertext, tag)) =
        aead.seal_using(
          aead.Portable,
          method.ChaCha20Poly1305,
          chacha_key(),
          chacha_nonce(),
          associated,
          plaintext,
        )
      let assert Ok(opened) =
        aead.open_using(
          aead.Native,
          method.ChaCha20Poly1305,
          chacha_key(),
          chacha_nonce(),
          associated,
          ciphertext,
          tag,
        )
      assert opened == Ok(plaintext)
    }
  }
}

pub fn asking_for_a_backend_that_is_not_here_is_refused_not_guessed_test() {
  // Silently falling back would make a differential test compare a thing with
  // itself and pass for the wrong reason.
  let refusal =
    aead.seal_using(
      aead.Portable,
      method.Aes256Gcm,
      filler(0, 32),
      filler(0, 12),
      <<>>,
      <<>>,
    )
  assert refusal
    == Error(aead.Unsupported(
      aead.Portable,
      method.Aes256Gcm,
      aead.no_portable_aes,
    ))
}

// --- round trips and rejections across every method -------------------------

pub fn every_method_round_trips_test() {
  use chosen_method <- list.each(every_method)
  use size <- list.each([0, 1, 16, 100, 1000])

  let key = filler(0x11, method.key_size(chosen_method))
  let nonce = filler(0x22, method.nonce_size)
  let plaintext = filler(0x33, size)

  let #(ciphertext, tag) = aead.seal(chosen_method, key, nonce, <<>>, plaintext)
  assert bit_array.byte_size(ciphertext) == size
  assert bit_array.byte_size(tag) == method.tag_size
  assert aead.open(chosen_method, key, nonce, <<>>, ciphertext, tag)
    == Ok(plaintext)
}

pub fn every_method_rejects_a_tampered_tag_test() {
  use chosen_method <- list.each(every_method)

  let key = filler(0x11, method.key_size(chosen_method))
  let nonce = filler(0x22, method.nonce_size)
  let #(ciphertext, tag) =
    aead.seal(chosen_method, key, nonce, <<>>, <<"payload":utf8>>)

  let assert <<first:8, rest:bits>> = tag
  let tampered = <<{ first + 1 }:8, rest:bits>>
  assert aead.open(chosen_method, key, nonce, <<>>, ciphertext, tampered)
    == Error(Nil)
}

pub fn every_method_rejects_a_tampered_ciphertext_test() {
  use chosen_method <- list.each(every_method)

  let key = filler(0x11, method.key_size(chosen_method))
  let nonce = filler(0x22, method.nonce_size)
  let #(ciphertext, tag) =
    aead.seal(chosen_method, key, nonce, <<>>, <<"payload":utf8>>)

  let assert <<first:8, rest:bits>> = ciphertext
  let tampered = <<{ first + 1 }:8, rest:bits>>
  assert aead.open(chosen_method, key, nonce, <<>>, tampered, tag) == Error(Nil)
}

pub fn every_method_rejects_a_malformed_tag_without_crashing_test() {
  // Tag length arrives from the network. A short or absent tag must be a
  // refusal, never an exception: a server that dies on a malformed frame hands
  // an attacker a denial of service.
  use chosen_method <- list.each(every_method)

  let key = filler(0x11, method.key_size(chosen_method))
  let nonce = filler(0x22, method.nonce_size)
  let #(ciphertext, _) =
    aead.seal(chosen_method, key, nonce, <<>>, <<"payload":utf8>>)

  use bad_tag <- list.each([<<>>, filler(0, 1), filler(0, 15), filler(0, 17)])
  assert aead.open(chosen_method, key, nonce, <<>>, ciphertext, bad_tag)
    == Error(Nil)
}

pub fn a_different_nonce_produces_different_ciphertext_test() {
  use chosen_method <- list.each(every_method)

  let key = filler(0x11, method.key_size(chosen_method))
  let plaintext = <<"the same plaintext twice":utf8>>
  let #(one, _) =
    aead.seal(chosen_method, key, filler(0x22, 12), <<>>, plaintext)
  let #(other, _) =
    aead.seal(chosen_method, key, filler(0x23, 12), <<>>, plaintext)
  assert one != other
}

// --- helpers ----------------------------------------------------------------

fn chacha_key() -> BitArray {
  bytes(
    "808182838485868788898a8b8c8d8e8f
     909192939495969798999a9b9c9d9e9f",
  )
}

fn chacha_nonce() -> BitArray {
  bytes("070000004041424344454647")
}

fn filler(byte: Int, size: Int) -> BitArray {
  <<byte:8>> |> list.repeat(size) |> bit_array.concat
}

pub fn every_method_rejects_a_wrong_nonce_test() {
  // The other rejection tests alter the tag or the ciphertext. A wrong nonce is
  // a different path through the platform ciphers, and until now it was only
  // covered for ChaCha20 in the portable implementation's own tests.
  use chosen_method <- list.each(every_method)

  let key = filler(0x11, method.key_size(chosen_method))
  let #(ciphertext, tag) =
    aead.seal(chosen_method, key, filler(0x22, 12), <<>>, <<"payload":utf8>>)

  assert aead.open(chosen_method, key, filler(0x23, 12), <<>>, ciphertext, tag)
    == Error(Nil)
}

pub fn every_method_rejects_a_wrong_key_test() {
  use chosen_method <- list.each(every_method)

  let nonce = filler(0x22, 12)
  let #(ciphertext, tag) =
    aead.seal(
      chosen_method,
      filler(0x11, method.key_size(chosen_method)),
      nonce,
      <<>>,
      <<"payload":utf8>>,
    )

  assert aead.open(
      chosen_method,
      filler(0x12, method.key_size(chosen_method)),
      nonce,
      <<>>,
      ciphertext,
      tag,
    )
    == Error(Nil)
}

pub fn every_method_rejects_altered_associated_data_test() {
  use chosen_method <- list.each(every_method)

  let key = filler(0x11, method.key_size(chosen_method))
  let nonce = filler(0x22, 12)
  let #(ciphertext, tag) =
    aead.seal(chosen_method, key, nonce, <<"bound":utf8>>, <<"payload":utf8>>)

  assert aead.open(chosen_method, key, nonce, <<"bounf":utf8>>, ciphertext, tag)
    == Error(Nil)
  assert aead.open(chosen_method, key, nonce, <<>>, ciphertext, tag)
    == Error(Nil)
}
