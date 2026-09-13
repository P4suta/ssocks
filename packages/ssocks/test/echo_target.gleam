//// A plain TCP echo server, standing in for whatever a client actually wants
//// to reach.
////
//// Shared by the relay spike and the server tests: both need something on the
//// far side of the proxy whose answers are predictable byte for byte, so that
//// any difference is the proxy's doing.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/option.{None}
import glisten

/// What the target saw. Only the closing is interesting: it is how a test
/// learns that the proxy let go of its end.
pub type Event {
  Arrived(BitArray)
  Closed
}

/// Start on an ephemeral port and return it.
pub fn start() -> Int {
  let #(port, _) = watched()
  port
}

/// As `start`, and say what happens on the connections it accepts.
///
/// The close is the point. A relay that drops its client without letting go of
/// the target leaves this socket open, and nothing else in a test can see that
/// — the client is gone, the server's handler is gone, and the only witness is
/// the far end that never heard anything about it.
pub fn watched() -> #(Int, Subject(Event)) {
  let name = process.new_name("ssocks_echo_target")
  let events = process.new_subject()

  let assert Ok(_) =
    glisten.new(fn(_) { #(Nil, None) }, fn(state, message, connection) {
      case message {
        glisten.Packet(bytes) -> {
          process.send(events, Arrived(bytes))
          let assert Ok(_) =
            glisten.send(connection, bytes_tree.from_bit_array(bytes))
          glisten.continue(state)
        }
        glisten.User(_) -> glisten.continue(state)
      }
    })
    |> glisten.with_close(fn(_) { process.send(events, Closed) })
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  #(glisten.get_server_info(name, 1000).port, events)
}
