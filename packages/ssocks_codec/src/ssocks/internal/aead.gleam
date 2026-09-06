//// One AEAD interface over two kinds of implementation.
////
//// AES-GCM comes from the platform and only from the platform: there is no
//// hand-written AES here and there should not be one. ChaCha20-Poly1305 comes
//// from the platform where the platform has it, and from `chacha20poly1305`
//// where it does not, which today means Bun.
////
//// ### The cipher name is translated here and nowhere else
////
//// Shadowsocks calls its ChaCha method `chacha20-ietf-poly1305`. No crypto
//// library recognises that name; Erlang wants the atom `chacha20_poly1305` and
//// Node the string `chacha20-poly1305`. The protocol spelling belongs to
//// `ssocks/method` and stops at this module's boundary.
////
//// ### Why a backend can be pinned
////
//// `seal_using` and `open_using` exist so the two implementations can be handed
//// identical inputs and compared. That is the strongest routine check this
//// package has: a bug subtle enough to survive the published vectors would have
//// to occur identically in two independent implementations. They are also what
//// to reach for when a platform crypto library is the suspect.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import ssocks/cipher/chacha20_poly1305
import ssocks/method.{type Method}

/// Which implementation performs the operation.
pub type Backend {
  /// The runtime's own crypto library.
  Native
  /// The ChaCha20-Poly1305 written in Gleam in this package.
  Portable
}

/// A backend that cannot run a method on this runtime.
pub type Unsupported {
  Unsupported(backend: Backend, method: Method, reason: String)
}

/// Explanation attached to every refusal to run AES portably.
pub const no_portable_aes = "ssocks contains no hand-written AES. AES-GCM is available only through the runtime's own crypto library."

/// Can this runtime run `backend` for `chosen_method`?
pub fn supports(backend: Backend, chosen_method: Method) -> Bool {
  case backend, chosen_method {
    Portable, method.ChaCha20Poly1305 -> True
    Portable, _ -> False
    Native, _ ->
      native_available(
        cipher_name(chosen_method),
        method.key_size(chosen_method),
      )
  }
}

/// The backend `seal` and `open` will use for a method on this runtime.
///
/// Native is preferred wherever it exists: it is faster, and it is the
/// implementation the rest of the world has been auditing for years.
pub fn selected(chosen_method: Method) -> Backend {
  case supports(Native, chosen_method) {
    True -> Native
    False -> Portable
  }
}

/// Encrypt and authenticate with whichever backend this runtime provides.
pub fn seal(
  chosen_method: Method,
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  plaintext: BitArray,
) -> #(BitArray, BitArray) {
  let assert Ok(sealed) =
    seal_using(
      selected(chosen_method),
      chosen_method,
      key,
      nonce,
      associated_data,
      plaintext,
    )
  sealed
}

/// Verify and decrypt with whichever backend this runtime provides.
///
/// `Error(Nil)` means the frame did not authenticate, and says no more than
/// that: the caller cannot act on the difference between a wrong tag and a
/// wrong key, and an attacker should not learn it either.
pub fn open(
  chosen_method: Method,
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, Nil) {
  case
    open_using(
      selected(chosen_method),
      chosen_method,
      key,
      nonce,
      associated_data,
      ciphertext,
      tag,
    )
  {
    Ok(opened) -> opened
    Error(_) -> Error(Nil)
  }
}

/// Encrypt with one named backend, refusing rather than falling back.
///
/// The refusal matters: a silent fallback would make a differential test
/// compare an implementation with itself and pass for the wrong reason.
pub fn seal_using(
  backend: Backend,
  chosen_method: Method,
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  plaintext: BitArray,
) -> Result(#(BitArray, BitArray), Unsupported) {
  case supports(backend, chosen_method), backend {
    False, _ -> Error(unsupported(backend, chosen_method))
    True, Portable ->
      Ok(chacha20_poly1305.seal(key, nonce, associated_data, plaintext))
    True, Native ->
      Ok(native_seal(
        cipher_name(chosen_method),
        key,
        nonce,
        associated_data,
        plaintext,
      ))
  }
}

/// Decrypt with one named backend.
///
/// The outer result answers "could this runtime run it at all", the inner one
/// "did the frame authenticate". Keeping them apart means a test can tell a
/// missing cipher from a rejected forgery.
pub fn open_using(
  backend: Backend,
  chosen_method: Method,
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(Result(BitArray, Nil), Unsupported) {
  case supports(backend, chosen_method) {
    False -> Error(unsupported(backend, chosen_method))
    True ->
      // Tag length arrives from the network. Checking it here rather than in
      // each backend keeps a malformed tag behaving the same way everywhere.
      case bit_array.byte_size(tag) == method.tag_size {
        False -> Ok(Error(Nil))
        True ->
          Ok(case backend {
            Portable ->
              chacha20_poly1305.open(
                key,
                nonce,
                associated_data,
                ciphertext,
                tag,
              )
            Native ->
              native_open(
                cipher_name(chosen_method),
                key,
                nonce,
                associated_data,
                ciphertext,
                tag,
              )
          })
      }
  }
}

fn unsupported(backend: Backend, chosen_method: Method) -> Unsupported {
  let reason = case backend {
    Portable -> no_portable_aes
    Native ->
      "this runtime's crypto library does not provide "
      <> cipher_name(chosen_method)
  }
  Unsupported(backend, chosen_method, reason)
}

/// The name the crypto libraries know a method by.
///
/// Note the ChaCha case. This is the only place the two spellings meet.
fn cipher_name(chosen_method: Method) -> String {
  case chosen_method {
    method.Aes128Gcm -> "aes-128-gcm"
    method.Aes256Gcm -> "aes-256-gcm"
    method.ChaCha20Poly1305 -> "chacha20-poly1305"
  }
}

@external(erlang, "ssocks_aead_ffi", "available")
@external(javascript, "./ssocks_aead_ffi.mjs", "available")
fn native_available(cipher: String, key_size: Int) -> Bool

@external(erlang, "ssocks_aead_ffi", "seal")
@external(javascript, "./ssocks_aead_ffi.mjs", "seal")
fn native_seal(
  cipher: String,
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  plaintext: BitArray,
) -> #(BitArray, BitArray)

@external(erlang, "ssocks_aead_ffi", "open")
@external(javascript, "./ssocks_aead_ffi.mjs", "open")
fn native_open(
  cipher: String,
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, Nil)
