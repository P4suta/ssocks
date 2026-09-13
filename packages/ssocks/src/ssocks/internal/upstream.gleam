//// The socket to the target, and the process that owns it.
////
//// A relay has two sockets and can only have one of them in any given process.
//// `glisten` and `mug` both select the raw Erlang `{tcp, Socket, Data}` record
//// and neither discriminates on which socket it came from, so a handler that
//// opened an upstream socket of its own would receive the target's replies as
//// though the client had sent them — and forward them straight back upstream.
//// Nothing errors. The connection hangs. `test/relay_spike_test.gleam`
//// reproduces that failure — a handler being handed bytes its client never
//// sent — and then shows this module making it go away.
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
  /// Arm the socket for one more packet from the target.
  ///
  /// Nothing is read until this arrives, so the target is read at the rate the
  /// handler writes to the client and no faster. See `loop`.
  More
  /// Answer on `reply` once everything sent before this has been written.
  ///
  /// Messages are handled in order, so a reply to this means every `Write`
  /// queued ahead of it has been through `mug.send`. That is what lets the
  /// handler stop reading its client until the target has caught up.
  Drain(reply: Subject(Nil))
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
  /// The target is no longer there, and why.
  ///
  /// It used to be a bare `Gone`, which meant a relay could tell its caller
  /// that a connection had ended and never which of "the target hung up" and
  /// "the write failed" it was — the two an operator most wants apart.
  Gone(reason: Ending)
}

/// How a connection to a target ended.
pub type Ending {
  /// The target closed cleanly, or the socket did.
  Closed
  /// A read or a write failed.
  Failed(reason: mug.Error)
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
  // Whoever is asking. Monitored below, because a handler can end without
  // saying so and this process must not outlive it.
  let handler = process.self()

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

        // The link `spawn` makes is not enough. A handler that ends normally —
        // which is what a closed client socket produces — does not travel down
        // a link, so this process would sit in `selector_receive_forever` with
        // a socket open, waiting for a message from something that no longer
        // exists. The monitor turns that into the close it should have been.
        let watching = process.monitor(handler)

        loop(
          socket,
          process.new_selector()
            |> process.select_map(commands, FromHandler)
            |> process.select_specific_monitor(watching, fn(_) {
              FromHandler(Close)
            })
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
        Error(reason) -> process.send(events, Gone(Failed(reason)))
      }
    }

    FromHandler(Close) -> {
      let _ = mug.shutdown(socket)
      Nil
    }

    FromHandler(More) -> {
      // Active-once: one message per arming. The arming is here rather than
      // straight after `Arrived` below, which is the whole of the flow control
      // in this direction — a target faster than the client would otherwise
      // fill the handler's mailbox with replies it has not sent on yet, and
      // nothing bounds a mailbox.
      mug.receive_next_packet_as_message(socket)
      loop(socket, selector, events)
    }

    FromHandler(Drain(reply)) -> {
      // Everything queued before this has already been through `mug.send`,
      // because messages are handled in order. Saying so is the whole job.
      process.send(reply, Nil)
      loop(socket, selector, events)
    }

    FromSocket(mug.Packet(_, bytes)) -> {
      process.send(events, Arrived(bytes))
      loop(socket, selector, events)
    }

    FromSocket(mug.SocketClosed(_)) -> process.send(events, Gone(Closed))
    FromSocket(mug.TcpError(_, reason)) ->
      process.send(events, Gone(Failed(reason)))
  }
}

/// Send everything that was held back while the target was being reached,
/// oldest first. Callers accumulate by prepending, so this reverses.
pub fn flush(commands: Subject(Command), held: List(BitArray)) -> Nil {
  use bytes <- list.each(list.reverse(held))
  process.send(commands, Write(bytes))
}

/// Wait until the target has been written everything sent so far.
///
/// The handler calls this when it has queued more than it is willing to hold,
/// and blocking here is the point: glisten re-arms a connection's socket when
/// its handler returns, so not returning is the only way to stop reading a
/// client that is outrunning the target it is talking to.
///
/// Bounded, and it does not raise. An upstream that has gone away has nothing
/// left to drain, and a handler waiting on a reply that is never coming would
/// be a connection that stopped for good.
pub fn drain(commands: Subject(Command), within timeout: Int) -> Nil {
  case process.subject_owner(commands) {
    Error(Nil) -> Nil
    Ok(running) -> {
      let reply = process.new_subject()
      let watching = process.monitor(running)
      process.send(commands, Drain(reply))

      // Only this subject and this monitor are selected on, so anything else
      // already in the mailbox — a reply from the target, a timer — stays
      // there and is handled as soon as this returns.
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
