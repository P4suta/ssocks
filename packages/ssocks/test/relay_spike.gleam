//// How a relay owns two sockets at once.
////
//// A Shadowsocks server moves bytes both ways: what the client sends goes
//// upstream, and what upstream answers comes back. glisten gives a process per
//// connection and delivers the client's packets to its loop.
////
//// The obvious shape — open the upstream socket in that same process and fold
//// `mug.select_tcp_messages` into glisten's selector — does not work, and
//// fails in the worst available way. Both libraries select the raw Erlang
//// `{tcp, Socket, Data}` record and neither discriminates on which socket it
//// came from, so the upstream reply is delivered to the handler as if the
//// client had sent it. In a relay that means the answer is forwarded straight
//// back upstream. Nothing errors; the connection simply hangs. `mug`'s own
//// documentation says as much: one socket per process.
////
//// So the upstream socket gets a process of its own, and the two talk over a
//// `Subject`, which is addressed rather than pattern-matched and therefore
//// cannot be confused with anything else. This file is the evidence that the
//// arrangement works, and the reason `server.gleam` is not written the other
//// way.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import glisten
import mug

// --- what the two processes say to each other --------------------------------

type Command {
  Write(BitArray)
}

type Event {
  Ready(Subject(Command))
  Arrived(BitArray)
  Gone
}

/// What the upstream process selects on: its orders, and its one socket.
type Inbox {
  FromHandler(Command)
  FromSocket(mug.TcpMessage)
}

type Relay {
  Relay(
    events: Subject(Event),
    upstream: Option(Subject(Command)),
    /// Bytes that arrived before the upstream socket was ready. In the real
    /// server this is where the first payload waits while the target is being
    /// reached.
    waiting: List(BitArray),
    echo_port: Int,
  )
}

pub fn the_echo_server_alone_works_test() {
  let echo_port = start_echo()

  let assert Ok(client) =
    mug.new("127.0.0.1", port: echo_port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  let assert Ok(_) = mug.send(client, <<"direct":utf8>>)
  assert mug.receive(client, timeout_milliseconds: 2000)
    == Ok(<<"direct":utf8>>)
  let _ = mug.shutdown(client)
}

pub fn a_relay_can_own_both_sockets_across_two_processes_test() {
  let relay_port = start_relay(start_echo())

  let assert Ok(client) =
    mug.new("127.0.0.1", port: relay_port)
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

// --- the upstream process -----------------------------------------------------

fn start_upstream(port: Int, events: Subject(Event)) -> Nil {
  process.spawn(fn() {
    case
      mug.new("127.0.0.1", port: port)
      |> mug.timeout(milliseconds: 2000)
      |> mug.connect()
    {
      Error(_) -> process.send(events, Gone)
      Ok(socket) -> {
        // Created here, so that orders arrive in this process's mailbox.
        let commands = process.new_subject()
        process.send(events, Ready(commands))
        mug.receive_next_packet_as_message(socket)

        upstream_loop(
          socket,
          process.new_selector()
            |> process.select_map(commands, FromHandler)
            |> mug.select_tcp_messages(FromSocket),
          events,
        )
      }
    }
  })
  Nil
}

fn upstream_loop(
  socket: mug.Socket,
  selector: process.Selector(Inbox),
  events: Subject(Event),
) -> Nil {
  case process.selector_receive_forever(selector) {
    FromHandler(Write(bytes)) -> {
      let _ = mug.send(socket, bytes)
      upstream_loop(socket, selector, events)
    }
    FromSocket(mug.Packet(_, bytes)) -> {
      process.send(events, Arrived(bytes))
      // Active-once: one message per arming.
      mug.receive_next_packet_as_message(socket)
      upstream_loop(socket, selector, events)
    }
    FromSocket(mug.SocketClosed(_)) -> process.send(events, Gone)
    FromSocket(mug.TcpError(_, _)) -> process.send(events, Gone)
  }
}

// --- the two servers ----------------------------------------------------------

/// A plain TCP echo, standing in for the target a real server would reach.
fn start_echo() -> Int {
  let name = process.new_name("ssocks_spike_echo")

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

fn start_relay(echo_port: Int) -> Int {
  let name = process.new_name("ssocks_spike_relay")

  let assert Ok(_) =
    glisten.new(
      fn(_) {
        // The events subject belongs to the handler process, so it exists
        // before the upstream does and the selector can be installed up front.
        let events = process.new_subject()
        #(
          Relay(events, None, [], echo_port),
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
  message: glisten.Message(Event),
  connection: glisten.Connection(Event),
) -> glisten.Next(Relay, glisten.Message(Event)) {
  case message, state.upstream {
    // Nothing upstream yet. Start reaching for it and hold what arrived.
    glisten.Packet(bytes), None -> {
      case state.waiting {
        [] -> start_upstream(state.echo_port, state.events)
        _ -> Nil
      }
      glisten.continue(Relay(..state, waiting: [bytes, ..state.waiting]))
    }

    glisten.Packet(bytes), Some(commands) -> {
      process.send(commands, Write(bytes))
      glisten.continue(state)
    }

    glisten.User(Ready(commands)), _ -> {
      flush(commands, state.waiting)
      glisten.continue(Relay(..state, upstream: Some(commands), waiting: []))
    }

    glisten.User(Arrived(bytes)), _ -> {
      let assert Ok(_) =
        glisten.send(connection, bytes_tree.from_bit_array(bytes))
      glisten.continue(state)
    }

    glisten.User(Gone), _ -> glisten.stop()
  }
}

/// Oldest first: `waiting` is built by prepending.
fn flush(commands: Subject(Command), waiting: List(BitArray)) -> Nil {
  use bytes <- list.each(list.reverse(waiting))
  process.send(commands, Write(bytes))
}
