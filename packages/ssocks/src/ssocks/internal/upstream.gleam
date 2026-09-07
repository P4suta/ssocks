//// The socket to the target, and the process that owns it.
////
//// A relay has two sockets and can only have one of them in any given process.
//// `glisten` and `mug` both select the raw Erlang `{tcp, Socket, Data}` record
//// and neither discriminates on which socket it came from, so a handler that
//// opened an upstream socket of its own would receive the target's replies as
//// though the client had sent them — and forward them straight back upstream.
//// Nothing errors. The connection hangs. `test/relay_spike.gleam` demonstrates
//// both the failure and this arrangement.
////
//// So the upstream socket lives here, alone, and the two processes talk over
//// `Subject`s, which are addressed rather than pattern-matched and cannot be
//// confused with anything else in a mailbox.
////
//// Connecting happens inside the spawned process, because whoever calls
//// `mug.connect` becomes the socket's controlling process and only the
//// controlling process may read from it. The handler therefore learns that the
//// target was reached by being told, not by waiting.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process.{type Subject}
import gleam/list
import mug
import ssocks/address

/// What the handler asks of the upstream.
pub type Command {
  Write(BitArray)
  Close
}

/// What the upstream tells the handler.
pub type Event {
  /// The target was reached. Everything held back can go now.
  Ready(Subject(Command))
  /// The target could not be reached, or was reached and has gone away. Either
  /// way there is nothing left to relay.
  Unreachable(reason: mug.ConnectError)
  Arrived(BitArray)
  Gone
}

/// What this process selects on: its orders, and its one socket.
type Inbox {
  FromHandler(Command)
  FromSocket(mug.TcpMessage)
}

/// Reach `target` and report back on `events`.
///
/// Returns immediately. Success or failure arrives as `Ready` or `Unreachable`.
pub fn start(
  target: address.Address,
  within timeout: Int,
  reporting events: Subject(Event),
) -> Nil {
  process.spawn(fn() {
    case
      mug.new(address.host(target), port: address.port(target))
      |> mug.timeout(milliseconds: timeout)
      |> mug.connect()
    {
      Error(reason) -> process.send(events, Unreachable(reason))
      Ok(socket) -> {
        // Created here so that orders land in this process's mailbox.
        let commands = process.new_subject()
        process.send(events, Ready(commands))
        mug.receive_next_packet_as_message(socket)

        loop(
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

fn loop(
  socket: mug.Socket,
  selector: process.Selector(Inbox),
  events: Subject(Event),
) -> Nil {
  case process.selector_receive_forever(selector) {
    FromHandler(Write(bytes)) -> {
      case mug.send(socket, bytes) {
        Ok(_) -> loop(socket, selector, events)
        // A write that fails means the target is gone; the read side would
        // find out too, but not necessarily soon.
        Error(_) -> process.send(events, Gone)
      }
    }

    FromHandler(Close) -> {
      let _ = mug.shutdown(socket)
      Nil
    }

    FromSocket(mug.Packet(_, bytes)) -> {
      process.send(events, Arrived(bytes))
      // Active-once: one message per arming.
      mug.receive_next_packet_as_message(socket)
      loop(socket, selector, events)
    }

    FromSocket(mug.SocketClosed(_)) -> process.send(events, Gone)
    FromSocket(mug.TcpError(_, _)) -> process.send(events, Gone)
  }
}

/// Send everything that was held back while the target was being reached,
/// oldest first. Callers accumulate by prepending, so this reverses.
pub fn flush(commands: Subject(Command), held: List(BitArray)) -> Nil {
  use bytes <- list.each(list.reverse(held))
  process.send(commands, Write(bytes))
}
