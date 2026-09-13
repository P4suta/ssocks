//// The connection to the Shadowsocks server, and the process that owns it.
////
//// `ssocks/internal/upstream` is this module's mirror image: there, a server's
//// handler needs a plain socket to a target; here, a local proxy's handler
//// needs a Shadowsocks connection to a server. Both exist for the same reason,
//// which `upstream` states in full — glisten and mug select the same raw
//// `{tcp, Socket, Data}` record without saying which socket it came from, so a
//// handler that opened a second socket of its own would be handed the far
//// end's bytes as though its client had sent them.
////
//// Connecting happens inside the spawned process, because whoever calls
//// `mug.connect` becomes the socket's controlling process and only the
//// controlling process may read from it.
////
//// ### Flow control, both ways
////
//// Nothing is read from the server until the handler asks for `More`, and
//// `Drain` answers only once everything queued before it has been written.
//// Together they mean neither side can make this process's mailbox, or the
//// handler's, grow without bound. Same arrangement as `upstream`.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process.{type Subject}
import gleam/list
import mug
import ssocks/address
import ssocks/client
import ssocks/url

/// What the handler asks of the tunnel.
pub type Command {
  Write(BitArray)
  /// Arm the connection for one more packet from the server.
  More
  /// Answer on `reply` once everything sent before this has been written.
  Drain(reply: Subject(Nil))
  Close
}

/// What the tunnel tells the handler.
pub type Event {
  /// The server was reached. Everything held back can go now.
  ///
  /// Reached, not authenticated: Shadowsocks says nothing on connect, and a
  /// wrong password looks exactly like a server that has not answered yet.
  /// That is the protocol's doing, not this module's.
  Ready(Subject(Command))
  /// The server could not be reached at all.
  Unreachable(reason: client.ClientError)
  Arrived(BitArray)
  /// The far end is gone, or stopped making sense. A wrong password arrives
  /// here, as a framing failure on the first chunk.
  Gone(reason: Ending)
}

/// How a tunnel ended.
pub type Ending {
  /// The server closed cleanly, or the socket did.
  Closed
  /// Something arrived that did not authenticate or did not decode.
  Failed(reason: client.ClientError)
}

/// What this process selects on: its orders, and its one connection.
type Inbox {
  FromHandler(Command)
  FromServer(mug.TcpMessage)
}

/// Reach the Shadowsocks server and ask it for `target`.
///
/// Returns immediately. Success or failure arrives as `Ready` or `Unreachable`.
pub fn start(
  config: url.Config,
  target: address.Address,
  within timeout: Int,
  reporting events: Subject(Event),
) -> Nil {
  // Whoever is asking. Monitored below so that a handler which ends without
  // saying so does not leave this process holding a socket for ever.
  let handler = process.self()

  process.spawn(fn() {
    case client.connect_to(config, target, within: timeout) {
      Error(reason) -> process.send(events, Unreachable(reason))
      Ok(connection) -> {
        // Created here so that orders land in this process's mailbox.
        let commands = process.new_subject()
        process.send(events, Ready(commands))
        client.receive_next_message(connection)

        let watching = process.monitor(handler)

        loop(
          connection,
          process.new_selector()
            |> process.select_map(commands, FromHandler)
            |> process.select_specific_monitor(watching, fn(_) {
              FromHandler(Close)
            })
            |> client.select_messages(FromServer),
          events,
        )
      }
    }
  })
  Nil
}

fn loop(
  connection: client.Connection,
  selector: process.Selector(Inbox),
  events: Subject(Event),
) -> Nil {
  case process.selector_receive_forever(selector) {
    FromHandler(Write(bytes)) ->
      case client.send(connection, bytes) {
        Ok(connection) -> loop(connection, selector, events)
        // A write that fails means the server is gone; the read side would
        // find out too, but not necessarily soon.
        Error(reason) -> process.send(events, Gone(Failed(reason)))
      }

    FromHandler(More) -> {
      client.receive_next_message(connection)
      loop(connection, selector, events)
    }

    FromHandler(Drain(reply)) -> {
      process.send(reply, Nil)
      loop(connection, selector, events)
    }

    FromHandler(Close) -> {
      client.close(connection)
      Nil
    }

    FromServer(message) ->
      case client.handle_message(connection, message) {
        Error(reason) -> process.send(events, Gone(Failed(reason)))
        Ok(#(_, client.Ended)) -> process.send(events, Gone(Closed))

        Ok(#(connection, client.Chunks(chunks))) -> {
          case chunks {
            // The read landed inside a frame. Nothing to hand on, and nothing
            // to wait for either: ask for the rest at once, because the
            // handler has no reason to send `More` for bytes it never saw.
            [] -> client.receive_next_message(connection)
            _ -> process.send(events, Arrived(list.fold(chunks, <<>>, append)))
          }
          loop(connection, selector, events)
        }
      }
  }
}

fn append(accumulated: BitArray, chunk: BitArray) -> BitArray {
  <<accumulated:bits, chunk:bits>>
}

/// Send everything that was held back while the server was being reached,
/// oldest first. Callers accumulate by prepending, so this reverses.
pub fn flush(commands: Subject(Command), held: List(BitArray)) -> Nil {
  use bytes <- list.each(list.reverse(held))
  process.send(commands, Write(bytes))
}

/// Wait until the server has been written everything sent so far.
///
/// Bounded, and it does not raise: a tunnel that has gone away has nothing left
/// to drain, and a handler waiting on a reply that is never coming would be a
/// connection that stopped for good.
pub fn drain(commands: Subject(Command), within timeout: Int) -> Nil {
  case process.subject_owner(commands) {
    Error(Nil) -> Nil
    Ok(running) -> {
      let reply = process.new_subject()
      let watching = process.monitor(running)
      process.send(commands, Drain(reply))

      let _ =
        process.new_selector()
        |> process.select_map(reply, fn(_) { Nil })
        |> process.select_specific_monitor(watching, fn(_) { Nil })
        |> process.selector_receive(timeout)

      process.demonitor_process(watching)
      Nil
    }
  }
}
