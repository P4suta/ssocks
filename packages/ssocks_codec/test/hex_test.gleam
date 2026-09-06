//// Hex is the substrate every other test in this package stands on: published
//// protocol vectors arrive as hex text, and every diagnostic dump emits it.
//// It is therefore tested before anything that uses it.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import ssocks/internal/hex

pub fn decoding_an_empty_string_yields_an_empty_bit_array_test() {
  assert hex.decode("") == Ok(<<>>)
}

pub fn decoding_accepts_both_letter_cases_test() {
  assert hex.decode("0a1b") == Ok(<<0x0a, 0x1b>>)
  assert hex.decode("0A1B") == Ok(<<0x0a, 0x1b>>)
  assert hex.decode("0a1B") == Ok(<<0x0a, 0x1b>>)
}

pub fn decoding_covers_the_whole_byte_range_test() {
  assert hex.decode("00") == Ok(<<0x00>>)
  assert hex.decode("7f") == Ok(<<0x7f>>)
  assert hex.decode("80") == Ok(<<0x80>>)
  assert hex.decode("ff") == Ok(<<0xff>>)
}

pub fn decoding_ignores_the_whitespace_that_published_vectors_are_wrapped_in_test() {
  // RFC and spec vectors are printed across several indented lines. Being able
  // to paste them verbatim is what keeps a transcription error from becoming a
  // fake test failure.
  assert hex.decode(" 0a 1b ") == Ok(<<0x0a, 0x1b>>)
  assert hex.decode("0a\n  1b\t") == Ok(<<0x0a, 0x1b>>)
  assert hex.decode("\n\n") == Ok(<<>>)
}

pub fn decoding_rejects_an_odd_number_of_digits_test() {
  assert hex.decode("a") == Error(Nil)
  assert hex.decode("0a1") == Error(Nil)
}

pub fn decoding_rejects_characters_outside_the_hex_alphabet_test() {
  assert hex.decode("0g") == Error(Nil)
  assert hex.decode("zz") == Error(Nil)
  assert hex.decode("0x0a") == Error(Nil)
  assert hex.decode("-1") == Error(Nil)
}

pub fn encoding_produces_lower_case_pairs_with_leading_zeroes_test() {
  assert hex.encode(<<>>) == ""
  assert hex.encode(<<0x00>>) == "00"
  assert hex.encode(<<0x0a, 0x1b>>) == "0a1b"
  assert hex.encode(<<0xff, 0x00, 0x7f>>) == "ff007f"
}

pub fn encoding_then_decoding_returns_the_original_bytes_test() {
  let original = <<0, 1, 2, 127, 128, 200, 255, 42>>
  assert hex.decode(hex.encode(original)) == Ok(original)
}

pub fn decoding_then_encoding_returns_the_original_text_test() {
  let text = "00010203f0f1f2f3ff"
  let assert Ok(bytes) = hex.decode(text)
  assert hex.encode(bytes) == text
}
