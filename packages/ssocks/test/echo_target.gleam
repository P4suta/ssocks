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
import gleam/option.{type Option, None, Some}
import glisten

/// What the target saw. Only the closing is interesting: it is how a test
/// learns that the proxy let go of its end.
pub type Event {
  Arrived(BitArray)
  Closed
}

/// Start on an ephemeral port and return it.
///
/// Says nothing about what it sees. That matters: a `Subject` is only ever
/// received on by its owner, so a version of this that built one and handed it
/// nowhere would leave a message in the caller's mailbox for every packet and
/// every close, and nothing would ever take them out again.
pub fn start() -> Int {
  listen(None)
}

/// As `start`, and say what happens on the connections it accepts.
///
/// The close is the point. A relay that drops its client without letting go of
/// the target leaves this socket open, and nothing else in a test can see that
/// — the client is gone, the server's handler is gone, and the only witness is
/// the far end that never heard anything about it.
pub fn watched() -> #(Int, Subject(Event)) {
  let events = process.new_subject()
  #(listen(Some(events)), events)
}

fn listen(events: Option(Subject(Event))) -> Int {
  let name = process.new_name("ssocks_echo_target")

  let tell = fn(event: Event) {
    case events {
      Some(events) -> process.send(events, event)
      None -> Nil
    }
  }

  let assert Ok(_) =
    glisten.new(fn(_) { #(Nil, None) }, fn(state, message, connection) {
      case message {
        glisten.Packet(bytes) -> {
          tell(Arrived(bytes))
          let assert Ok(_) =
            glisten.send(connection, bytes_tree.from_bit_array(bytes))
          glisten.continue(state)
        }
        glisten.User(_) -> glisten.continue(state)
      }
    })
    |> glisten.with_close(fn(_) { tell(Closed) })
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  glisten.get_server_info(name, 1000).port
}
