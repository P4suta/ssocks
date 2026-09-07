//// A plain TCP echo server, standing in for whatever a client actually wants
//// to reach.
////
//// Shared by the relay spike and the server tests: both need something on the
//// far side of the proxy whose answers are predictable byte for byte, so that
//// any difference is the proxy's doing.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bytes_tree
import gleam/erlang/process
import gleam/option.{None}
import glisten

/// Start on an ephemeral port and return it.
pub fn start() -> Int {
  let name = process.new_name("ssocks_echo_target")

  let assert Ok(_) =
    glisten.new(fn(_) { #(Nil, None) }, fn(state, message, connection) {
      case message {
        glisten.Packet(bytes) -> {
          let assert Ok(_) =
            glisten.send(connection, bytes_tree.from_bit_array(bytes))
          glisten.continue(state)
        }
        glisten.User(_) -> glisten.continue(state)
      }
    })
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  glisten.get_server_info(name, 1000).port
}
