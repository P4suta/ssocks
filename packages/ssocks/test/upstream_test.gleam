//// The process that owns the socket to the target.
////
//// `ssocks/internal/upstream` exists because glisten and mug both select the
//// raw `{tcp, Socket, Data}` record without discriminating on which socket it
//// came from — `test/relay_spike_test.gleam` demonstrates that. What is tested
//// here is the part that is not about sockets at all: the flow control, which
//// is the difference between a relay that is bounded and one that is not.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import echo_target
import gleam/erlang/process.{type Subject}
import gleam/int
import ssocks/address
import ssocks/internal/upstream

fn reach(port: Int) -> #(Subject(upstream.Event), Subject(upstream.Command)) {
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  let events = process.new_subject()

  upstream.start(where, within: 2000, reporting: events)
  let assert Ok(upstream.Ready(commands)) = process.receive(events, 2000)

  #(events, commands)
}

pub fn a_target_is_reached_and_relays_both_ways_test() {
  let #(events, commands) = reach(echo_target.start())

  process.send(commands, upstream.Write(<<"hello":utf8>>))
  assert process.receive(events, 2000) == Ok(upstream.Arrived(<<"hello":utf8>>))

  process.send(commands, upstream.Close)
}

pub fn a_target_that_is_not_there_is_reported_test() {
  let assert Ok(where) = address.parse("127.0.0.1:1")
  let events = process.new_subject()

  upstream.start(where, within: 1000, reporting: events)

  let assert Ok(upstream.Unreachable(_)) = process.receive(events, 3000)
}

pub fn nothing_is_read_from_the_target_until_more_is_asked_for_test() {
  // The whole of the flow control in this direction. Without it the socket is
  // re-armed the instant a packet is handed on, so a target faster than the
  // client fills the handler's mailbox with replies it has not sent yet — and
  // nothing bounds a mailbox.
  let #(events, commands) = reach(echo_target.start())

  process.send(commands, upstream.Write(<<"one":utf8>>))
  assert process.receive(events, 2000) == Ok(upstream.Arrived(<<"one":utf8>>))

  // The echo answers this at once, and it must not be read.
  process.send(commands, upstream.Write(<<"two":utf8>>))
  assert process.receive(events, 300) == Error(Nil)

  process.send(commands, upstream.More)
  assert process.receive(events, 2000) == Ok(upstream.Arrived(<<"two":utf8>>))

  process.send(commands, upstream.Close)
}

pub fn drain_answers_only_after_what_came_before_it_test() {
  // What lets a handler stop reading a client that is outrunning its target:
  // messages are handled in order, so a reply here means every write queued
  // ahead of it has been through the socket.
  let #(events, commands) = reach(echo_target.start())

  process.send(commands, upstream.Write(<<"first":utf8>>))
  upstream.drain(commands, within: 2000)

  // The write really did happen before `drain` answered, so the echo's reply
  // is already on its way rather than still queued behind it.
  assert process.receive(events, 2000) == Ok(upstream.Arrived(<<"first":utf8>>))

  process.send(commands, upstream.Close)
}

pub fn draining_an_upstream_that_is_gone_returns_test() {
  // A handler waiting on a reply that is never coming would be a connection
  // that stopped for good.
  let #(_, commands) = reach(echo_target.start())
  process.send(commands, upstream.Close)

  // No assertion beyond arriving here: the claim is that this returns at all.
  upstream.drain(commands, within: 500)
}
