//// The replay filter, shared.
////
//// `ssocks/replay` is a pure value: one connection's worth of it is useless,
//// because the question it answers — has this salt been used before? — spans
//// every connection under a key. So it lives in one process and everybody asks.
////
//// ### Share one across TCP and UDP
////
//// The specification's requirement is that a salt be unique for the lifetime of
//// a master key, not for the lifetime of a transport. A UDP packet carries its
//// own salt and counts. Two guards, one per transport, would let a salt seen
//// over TCP be replayed over UDP, which is the same attack with an extra step.
////
//// ```gleam
//// let assert Ok(guard) = replay_guard.start()
//// server.new(session) |> server.with_replay_guard(guard)
//// udp.relay(session) |> udp.with_replay_guard(guard)
//// ```
////
//// A server given no guard starts one of its own, which is right for a single
//// server and wrong the moment there are two.
////
//// ### It is a bottleneck on purpose
////
//// Every connection asks this one process before it proceeds. That is the cost
//// of the guarantee; the work per call is a dictionary lookup and an insert,
//// and the pruning that could be expensive happens only when the table is full.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process.{type Subject}
import gleam/otp/actor
import gleam/result
import ssocks/internal/clock
import ssocks/replay

pub opaque type Guard {
  Guard(messages: Subject(Message))
}

pub opaque type Message {
  Observe(reply: Subject(Result(Nil, replay.ReplayError)), salt: BitArray)
  Size(reply: Subject(Int))
}

/// Start a guard with the default window and capacity.
pub fn start() -> Result(Guard, actor.StartError) {
  start_with(replay.new())
}

/// Start a guard over a filter configured by the caller.
pub fn start_with(filter: replay.Filter) -> Result(Guard, actor.StartError) {
  actor.new(filter)
  |> actor.on_message(handle)
  |> actor.start
  |> result.map(fn(started: actor.Started(Subject(Message))) {
    Guard(started.data)
  })
}

fn handle(
  filter: replay.Filter,
  message: Message,
) -> actor.Next(replay.Filter, Message) {
  case message {
    Size(reply) -> {
      process.send(reply, replay.size(filter))
      actor.continue(filter)
    }

    Observe(reply, salt) ->
      // The clock lives here rather than in `replay`, which takes the time as
      // an argument precisely so that it can stay platform-free and its expiry
      // tests can choose numbers instead of waiting.
      case replay.observe(filter, salt, clock.now_ms()) {
        Ok(filter) -> {
          process.send(reply, Ok(Nil))
          actor.continue(filter)
        }
        Error(reason) -> {
          process.send(reply, Error(reason))
          actor.continue(filter)
        }
      }
  }
}

/// Record a salt, or refuse it.
///
/// Blocks the caller until the guard answers. A server calls this once per
/// connection, before it relays anything.
pub fn observe(
  guard: Guard,
  salt: BitArray,
  within timeout: Int,
) -> Result(Nil, replay.ReplayError) {
  process.call(guard.messages, timeout, Observe(_, salt))
}

/// How many salts are being remembered. Diagnostic.
pub fn size(guard: Guard, within timeout: Int) -> Int {
  process.call(guard.messages, timeout, Size)
}
