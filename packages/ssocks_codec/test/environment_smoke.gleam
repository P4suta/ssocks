//// Report which AEAD backend this runtime actually gets.
////
//// The test suite proves every method works somewhere. This says where, which
//// is the question you have when one runtime is slow, or when a change to the
//// dispatch logic quietly stops using the native cipher everywhere.
////
//// Run with `mise run backends`.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/io
import gleam/list
import gleam/string
import ssocks/internal/aead
import ssocks/method

pub fn main() -> Nil {
  io.println("method                  native  portable  selected")
  io.println("----------------------  ------  --------  --------")

  use chosen <- list.each([
    method.Aes128Gcm,
    method.Aes256Gcm,
    method.ChaCha20Poly1305,
  ])

  io.println(
    pad(method.to_string(chosen), 24)
    <> pad(yes_no(aead.supports(aead.Native, chosen)), 8)
    <> pad(yes_no(aead.supports(aead.Portable, chosen)), 10)
    <> backend_name(aead.selected(chosen)),
  )
}

fn yes_no(value: Bool) -> String {
  case value {
    True -> "yes"
    False -> "no"
  }
}

fn backend_name(backend: aead.Backend) -> String {
  case backend {
    aead.Native -> "native"
    aead.Portable -> "portable"
  }
}

fn pad(text: String, width: Int) -> String {
  string.pad_end(text, to: width, with: " ")
}
