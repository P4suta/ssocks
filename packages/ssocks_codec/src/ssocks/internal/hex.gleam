//// Hex text to and from bytes.
////
//// Two callers justify this module. Tests paste published protocol vectors in
//// exactly the wrapped, indented form the specifications print them in, so
//// decoding tolerates whitespace. Diagnostics render captured frames as hex, so
//// encoding is stable and lower case, which keeps dumps diffable.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string

/// Render bytes as lower case hex, two digits per byte.
pub fn encode(bytes: BitArray) -> String {
  encode_loop(bytes, [])
}

fn encode_loop(bytes: BitArray, acc: List(String)) -> String {
  case bytes {
    <<byte:8, rest:bits>> -> encode_loop(rest, [byte_to_hex(byte), ..acc])
    _ -> acc |> list.reverse |> string.concat
  }
}

fn byte_to_hex(byte: Int) -> String {
  digit_to_char(byte / 16) <> digit_to_char(byte % 16)
}

fn digit_to_char(value: Int) -> String {
  case value {
    0 -> "0"
    1 -> "1"
    2 -> "2"
    3 -> "3"
    4 -> "4"
    5 -> "5"
    6 -> "6"
    7 -> "7"
    8 -> "8"
    9 -> "9"
    10 -> "a"
    11 -> "b"
    12 -> "c"
    13 -> "d"
    14 -> "e"
    _ -> "f"
  }
}

/// Parse hex text into bytes, ignoring the whitespace that published vectors
/// are wrapped in. Any other character, or an odd digit count, is an error.
pub fn decode(text: String) -> Result(BitArray, Nil) {
  text
  |> string.to_graphemes
  |> list.filter(is_not_whitespace)
  |> decode_loop([])
}

fn is_not_whitespace(character: String) -> Bool {
  case character {
    " " | "\n" | "\r" | "\t" -> False
    _ -> True
  }
}

fn decode_loop(
  characters: List(String),
  acc: List(BitArray),
) -> Result(BitArray, Nil) {
  case characters {
    [] -> Ok(bit_array.concat(list.reverse(acc)))
    [_] -> Error(Nil)
    [high, low, ..rest] -> {
      use high <- result.try(char_to_digit(high))
      use low <- result.try(char_to_digit(low))
      let byte = high * 16 + low
      decode_loop(rest, [<<byte:8>>, ..acc])
    }
  }
}

fn char_to_digit(character: String) -> Result(Int, Nil) {
  case character {
    "0" -> Ok(0)
    "1" -> Ok(1)
    "2" -> Ok(2)
    "3" -> Ok(3)
    "4" -> Ok(4)
    "5" -> Ok(5)
    "6" -> Ok(6)
    "7" -> Ok(7)
    "8" -> Ok(8)
    "9" -> Ok(9)
    "a" | "A" -> Ok(10)
    "b" | "B" -> Ok(11)
    "c" | "C" -> Ok(12)
    "d" | "D" -> Ok(13)
    "e" | "E" -> Ok(14)
    "f" | "F" -> Ok(15)
    _ -> Error(Nil)
  }
}
