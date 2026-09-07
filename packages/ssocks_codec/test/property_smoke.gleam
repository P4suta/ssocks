//// The same properties, run long.
////
//// Usage: `gleam run -m property_smoke -- <cases> <seed>`.
////
//// Both numbers are explicit so a failure is reproducible: rerun with the same
//// pair and the identical sequence of inputs is generated again.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/int
import gleam/io
import gleam/string
import properties
import qcheck

pub fn main() -> Nil {
  case argv.load().arguments {
    [cases, seed] -> {
      let assert Ok(cases) = int.parse(cases)
      let assert Ok(seed) = int.parse(seed)
      io.println(
        "property_smoke: "
        <> int.to_string(cases)
        <> " cases per property, seed "
        <> int.to_string(seed),
      )
      properties.check_all(qcheck.config(
        test_count: cases,
        max_retries: 1,
        seed: qcheck.seed(seed),
      ))
      io.println("property_smoke: every property held")
    }
    other -> {
      io.println(
        "property_smoke: expected <cases> <seed>, got "
        <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

@external(erlang, "erlang", "halt")
@external(javascript, "./property_smoke_ffi.mjs", "halt")
fn halt(code: Int) -> Nil
