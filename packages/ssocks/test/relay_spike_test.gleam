//// Why a relay cannot own both of its sockets in one process.
////
//// A Shadowsocks server moves bytes both ways: what the client sends goes
//// upstream, and what upstream answers comes back. glisten gives a process per
//// connection and delivers the client's packets to its loop.
////
//// The obvious shape — open the upstream socket in that same process and let
//// `mug` deliver its packets there too — does not work, and fails in the worst
//// available way. Both libraries select the raw Erlang `{tcp, Socket, Data}`
//// record and neither discriminates on which socket it came from, so the
//// upstream's reply is handed to the handler as though the client had sent it.
//// In a relay that means the answer is forwarded straight back upstream.
//// Nothing errors; the connection simply hangs. `mug`'s own documentation says
//// as much: one socket per process.
////
//// This file is the evidence, and it is in two halves. The first *reproduces
//// the failure*, which is what makes it evidence rather than a claim: a
//// handler is given bytes its client never sent. The second shows
//// `ssocks/internal/upstream` — the real module, not a copy of it — putting
//// the upstream socket in a process of its own and the confusion going away.
////
//// It used to be a reimplementation of `upstream` sitting beside it, which
//// meant `ssocks/internal/upstream` could have been deleted outright and every
//// test here would still have passed.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import echo_target
import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/option.{type Option, None, Some}
import glisten
import mug
import ssocks/address
import ssocks/internal/upstream

pub fn the_echo_server_alone_works_test() {
  // The control: whatever the two relays below do, the target itself answers.
  let port = echo_target.start()

  let assert Ok(client) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  let assert Ok(_) = mug.send(client, <<"direct":utf8>>)
  assert mug.receive(client, timeout_milliseconds: 2000)
    == Ok(<<"direct":utf8>>)

  let _ = mug.shutdown(client)
}

// --- the failure, reproduced ------------------------------------------------------

/// What the confused handler reports to the test.
type Seen {
  Seen(BitArray)
}

pub fn a_handler_holding_both_sockets_is_handed_bytes_its_client_never_sent_test() {
  // The whole reason `ssocks/internal/upstream` exists. The handler below opens
  // its upstream socket in its own process, which is the arrangement anybody
  // would try first. The target answers `pong`; the client sent `ping` and
  // nothing else. If the handler sees `pong` as a packet from its client, the
  // two sockets are indistinguishable to it — and a relay in that state
  // forwards the target's answer back to the target.
  let target = pong_target()
  let seen = process.new_subject()
  let port = confused_relay(target, seen)

  let assert Ok(client) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  let assert Ok(_) = mug.send(client, <<"ping":utf8>>)

  // What the client really sent.
  assert process.receive(seen, 2000) == Ok(Seen(<<"ping":utf8>>))
  // And what it did not.
  assert process.receive(seen, 2000) == Ok(Seen(<<"pong":utf8>>))

  let _ = mug.shutdown(client)
}

/// A handler that opens its upstream socket in its own process, and reports
/// every packet glisten hands it.
fn confused_relay(target: Int, seen: Subject(Seen)) -> Int {
  let name = process.new_name("ssocks_spike_confused")

  let assert Ok(_) =
    glisten.new(fn(_) { #(False, None) }, fn(reached, message, _) {
      case message {
        glisten.User(_) -> glisten.continue(reached)

        glisten.Packet(bytes) -> {
          process.send(seen, Seen(bytes))

          case reached {
            True -> glisten.continue(reached)
            False -> {
              // The mistake, in one place: this process now owns two sockets
              // and has no way to tell their messages apart.
              let assert Ok(socket) =
                mug.new("127.0.0.1", port: target)
                |> mug.timeout(milliseconds: 2000)
                |> mug.connect()
              let assert Ok(_) = mug.send(socket, bytes)
              mug.receive_next_packet_as_message(socket)
              glisten.continue(True)
            }
          }
        }
      }
    })
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  glisten.get_server_info(name, 1000).port
}

/// A target that answers something the client never sent, so that a packet
/// arriving from it is unmistakable.
fn pong_target() -> Int {
  let name = process.new_name("ssocks_spike_pong")

  let assert Ok(_) =
    glisten.new(fn(_) { #(Nil, None) }, fn(state, message, connection) {
      case message {
        glisten.Packet(_) -> {
          let assert Ok(_) =
            glisten.send(connection, bytes_tree.from_bit_array(<<"pong":utf8>>))
          glisten.continue(state)
        }
        glisten.User(_) -> glisten.continue(state)
      }
    })
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  glisten.get_server_info(name, 1000).port
}

// --- the arrangement that works ---------------------------------------------------

type Relay {
  Relay(
    events: Subject(upstream.Event),
    commands: Option(Subject(upstream.Command)),
    /// Bytes that arrived before the upstream socket was ready.
    waiting: List(BitArray),
    target: address.Address,
  )
}

pub fn a_relay_built_on_the_upstream_module_keeps_them_apart_test() {
  // The same shape as `ssocks/server`, with `ssocks/internal/upstream` owning
  // the second socket. The target here is a plain echo, so what comes back is
  // what went out — and it comes back to the client rather than to the target.
  let port = working_relay(echo_target.start())

  let assert Ok(client) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  let assert Ok(_) = mug.send(client, <<"through and back":utf8>>)
  assert mug.receive(client, timeout_milliseconds: 2000)
    == Ok(<<"through and back":utf8>>)

  // And again, to show both sockets are still armed after the first exchange.
  let assert Ok(_) = mug.send(client, <<"and again":utf8>>)
  assert mug.receive(client, timeout_milliseconds: 2000)
    == Ok(<<"and again":utf8>>)

  let _ = mug.shutdown(client)
}

fn working_relay(target: Int) -> Int {
  let name = process.new_name("ssocks_spike_relay")
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))

  let assert Ok(_) =
    glisten.new(
      fn(_) {
        // The events subject belongs to the handler process, so it exists
        // before the upstream does and the selector can be installed up front.
        let events = process.new_subject()
        #(
          Relay(events, None, [], where),
          Some(process.new_selector() |> process.select(events)),
        )
      },
      relay_loop,
    )
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  glisten.get_server_info(name, 1000).port
}

fn relay_loop(
  state: Relay,
  message: glisten.Message(upstream.Event),
  connection: glisten.Connection(upstream.Event),
) -> glisten.Next(Relay, glisten.Message(upstream.Event)) {
  case message, state.commands {
    // Nothing upstream yet. Start reaching for it and hold what arrived.
    glisten.Packet(bytes), None -> {
      case state.waiting {
        [] ->
          upstream.start(state.target, within: 2000, reporting: state.events)
        _ -> Nil
      }
      glisten.continue(Relay(..state, waiting: [bytes, ..state.waiting]))
    }

    glisten.Packet(bytes), Some(commands) -> {
      process.send(commands, upstream.Write(bytes))
      glisten.continue(state)
    }

    glisten.User(upstream.Ready(commands)), _ -> {
      upstream.flush(commands, state.waiting)
      glisten.continue(Relay(..state, commands: Some(commands), waiting: []))
    }

    glisten.User(upstream.Arrived(bytes)), _ -> {
      let assert Ok(_) =
        glisten.send(connection, bytes_tree.from_bit_array(bytes))
      // The flow control `upstream` waits on: nothing more is read from the
      // target until the handler says it has sent this on.
      case state.commands {
        Some(commands) -> process.send(commands, upstream.More)
        None -> Nil
      }
      glisten.continue(state)
    }

    glisten.User(upstream.Unreachable(_)), _ -> glisten.stop()
    glisten.User(upstream.Gone(_)), _ -> glisten.stop()
  }
}
