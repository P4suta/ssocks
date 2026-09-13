//// How many of something are live, with a ceiling.
////
//// A TCP server's connections each get a process of their own, so no one of
//// them can count the others. The count lives here instead, and every
//// connection claims a place in it before it does anything else.
////
//// ### Claiming and counting are one message
////
//// Asking "how many are there" and then deciding whether to accept would be
//// two messages with a gap in the middle, and the gap is where two connections
//// both read `limit - 1` and both proceed. `claim` answers the question and
//// takes the place in the same call, so the ceiling is a ceiling rather than a
//// suggestion.
////
//// ### Not being there is an answer
////
//// Every accept asks this one process, so "it is gone" has to be a value
//// rather than an exception — a bare `process.call` raises, which would turn
//// one dead counter into every connection crashing with it. The same reasoning
//// as `ssocks/replay_guard`, and the same shape.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process.{type Subject}
import gleam/otp/actor
import gleam/result

pub opaque type Tally {
  Tally(messages: Subject(Message))
}

pub opaque type Message {
  Claim(reply: Subject(Result(Int, Nil)), limit: Int)
  Release
  Count(reply: Subject(Int))
  Stop
}

/// Start a counter at zero.
pub fn start() -> Result(Tally, actor.StartError) {
  actor.new(0)
  |> actor.on_message(handle)
  |> actor.start
  |> result.map(fn(started: actor.Started(Subject(Message))) {
    Tally(started.data)
  })
}

fn handle(live: Int, message: Message) -> actor.Next(Int, Message) {
  case message {
    Stop -> actor.stop()

    Count(reply) -> {
      process.send(reply, live)
      actor.continue(live)
    }

    Release ->
      // Clamped, because a release without a claim would otherwise make the
      // count negative and the ceiling unreachable ever after.
      actor.continue(case live > 0 {
        True -> live - 1
        False -> 0
      })

    Claim(reply, limit) ->
      case live < limit {
        False -> {
          process.send(reply, Error(Nil))
          actor.continue(live)
        }
        True -> {
          process.send(reply, Ok(live + 1))
          actor.continue(live + 1)
        }
      }
  }
}

/// Take a place if there is one under `limit`, and say how many are live now.
///
/// `Error(Nil)` means the ceiling was reached, or that there was nobody to ask.
/// Both are refusals: a counter that cannot answer has not granted anything,
/// and proceeding would make the ceiling meaningless exactly when it is least
/// able to be checked.
pub fn claim(
  tally: Tally,
  limit: Int,
  within timeout: Int,
) -> Result(Int, Nil) {
  result.flatten(ask(tally, timeout, Claim(_, limit)))
}

/// Give a place back. Sent and not waited on: whoever is releasing is on its
/// way out and has nothing to do with the answer.
pub fn release(tally: Tally) -> Nil {
  process.send(tally.messages, Release)
}

/// How many are live right now. Diagnostic.
pub fn count(tally: Tally, within timeout: Int) -> Result(Int, Nil) {
  ask(tally, timeout, Count)
}

/// Stop the counter, waiting for it to be gone.
pub fn stop(tally: Tally) -> Result(Nil, Nil) {
  case process.subject_owner(tally.messages) {
    Error(Nil) -> Ok(Nil)
    Ok(running) -> {
      let watching = process.monitor(running)
      process.send(tally.messages, Stop)

      let stopped =
        process.new_selector()
        |> process.select_specific_monitor(watching, fn(_) { Nil })
        |> process.selector_receive(stop_timeout)

      process.demonitor_process(watching)
      stopped
    }
  }
}

/// Ask without being taken down if it is not there.
///
/// Monitoring rather than checking liveness first: a counter that is alive when
/// asked can be gone before it answers, and a bare receive would then wait out
/// the whole timeout for a message that is never coming.
fn ask(
  tally: Tally,
  timeout: Int,
  question: fn(Subject(answer)) -> Message,
) -> Result(answer, Nil) {
  use running <- result.try(process.subject_owner(tally.messages))

  let reply = process.new_subject()
  let watching = process.monitor(running)
  process.send(tally.messages, question(reply))

  let answer =
    process.new_selector()
    |> process.select_map(reply, Ok)
    |> process.select_specific_monitor(watching, fn(_) { Error(Nil) })
    |> process.selector_receive(timeout)

  process.demonitor_process(watching)
  result.flatten(answer)
}

const stop_timeout = 5000
