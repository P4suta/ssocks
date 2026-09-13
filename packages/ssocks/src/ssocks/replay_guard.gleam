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
//// Share one across transports, not across keys. The filter is keyed on the
//// salt alone, so two servers with different passwords behind one guard would
//// be answering each other's question — which is harmless in practice, since
//// salts are 32 random bytes and a collision is not a thing that happens, but
//// it is not what the specification asks for and not what this is for.
////
//// ### Nobody is taken down by asking
////
//// Every connection and every datagram asks this one process before it
//// proceeds, so "the guard is not there" has to be an answer rather than an
//// exception. A bare `process.call` raises when the callee is gone, which would
//// turn one dead actor into every connection handler crashing with it. Both
//// questions here monitor instead, and say `Unavailable`.
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
  Stop
}

/// Why a salt was not recorded.
pub type Refusal {
  /// The filter has seen this salt, or has no room left to remember it.
  Refused(reason: replay.ReplayError)
  /// There was nobody to ask: the guard was stopped, it went down, or it did
  /// not answer inside the timeout. Callers should treat this as a refusal
  /// rather than a pass — a guard that cannot answer is not a guard that said
  /// yes.
  Unavailable
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
    Stop -> actor.stop()

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
) -> Result(Nil, Refusal) {
  case ask(guard, timeout, Observe(_, salt)) {
    Error(Nil) -> Error(Unavailable)
    Ok(Error(reason)) -> Error(Refused(reason))
    Ok(Ok(Nil)) -> Ok(Nil)
  }
}

/// How many salts are being remembered. Diagnostic.
///
/// `Error(Nil)` means there was nobody to answer. Asking is the sort of thing a
/// caller does on a timer to draw a graph, and a caller on a timer should not
/// be brought down by the guard it is watching going away.
pub fn size(guard: Guard, within timeout: Int) -> Result(Int, Nil) {
  ask(guard, timeout, Size)
}

/// Stop the guard and forget every salt it was holding.
///
/// Waits for it to be gone before returning, so a caller that starts another
/// one afterwards cannot be answered by the old filter. `Error(Nil)` means that
/// did not happen inside `stop_timeout`.
pub fn stop(guard: Guard) -> Result(Nil, Nil) {
  case process.subject_owner(guard.messages) {
    // Nothing to wait for; being gone is what was asked for.
    Error(Nil) -> Ok(Nil)
    Ok(running) -> {
      let watching = process.monitor(running)
      process.send(guard.messages, Stop)

      let stopped =
        process.new_selector()
        |> process.select_specific_monitor(watching, fn(_) { Nil })
        |> process.selector_receive(stop_timeout)

      process.demonitor_process(watching)
      stopped
    }
  }
}

/// A sentence for a person.
pub fn explain(refusal: Refusal) -> String {
  case refusal {
    Refused(reason) -> replay.explain(reason)
    Unavailable ->
      "the replay filter did not answer. It was stopped, it went down, or it "
      <> "is too far behind to reply in time. Nothing was relayed, because a "
      <> "guard that cannot answer has not said yes."
  }
}

/// Ask the guard something without being taken down if it is not there.
///
/// Monitoring rather than checking liveness first: a guard that is alive when
/// asked can be gone before it answers, and a bare receive would then wait out
/// the whole timeout for a message that is never coming.
fn ask(
  guard: Guard,
  timeout: Int,
  question: fn(Subject(answer)) -> Message,
) -> Result(answer, Nil) {
  use running <- result.try(process.subject_owner(guard.messages))

  let reply = process.new_subject()
  let watching = process.monitor(running)
  process.send(guard.messages, question(reply))

  let answer =
    process.new_selector()
    |> process.select_map(reply, Ok)
    |> process.select_specific_monitor(watching, fn(_) { Error(Nil) })
    |> process.selector_receive(timeout)

  process.demonitor_process(watching)
  result.flatten(answer)
}

/// Long enough for a full table to be dropped, short enough that a guard which
/// is never going to answer does not hold up the caller.
const stop_timeout = 5000
