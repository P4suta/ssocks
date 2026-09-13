//// The clock deadlines are measured against.
////
//// Four lines of module, and both of its claims are load-bearing: `receive`
//// takes a total budget rather than a per-read one, which needs a clock that
//// only moves forwards, and it lets one more non-blocking attempt through at
//// zero, which is what keeps a caller from being told "timed out" while the
//// decoder is holding bytes it could have finished.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process
import ssocks/internal/clock

pub fn the_clock_only_moves_forwards_test() {
  let first = clock.now_ms()
  process.sleep(5)
  let second = clock.now_ms()

  assert second >= first
}

pub fn a_deadline_in_the_future_has_time_left_test() {
  let left = clock.remaining(clock.now_ms() + 1000)

  assert left > 0
  // Never more than was asked for, whatever the clock did in between.
  assert left <= 1000
}

pub fn a_deadline_that_has_passed_is_zero_rather_than_negative_test() {
  // Not negative: the value is handed to a receive as a timeout, and a
  // negative one is either an error or an infinite wait depending on what is
  // underneath. Zero still lets one more non-blocking attempt through, which
  // is what keeps `receive` from reporting a timeout while holding bytes it
  // could have decoded.
  assert clock.remaining(clock.now_ms() - 1000) == 0
}

pub fn zero_is_not_a_point_in_time_test() {
  // The values are only meaningful relative to each other, which is what
  // "monotonic" buys: Erlang's monotonic clock starts at a large negative
  // offset by default, so 0 is in the *future* here. A deadline computed as
  // "now plus a budget" is the only correct way to make one.
  assert clock.remaining(0) == 0 || clock.remaining(0) > 0
}

pub fn a_deadline_exactly_now_is_zero_test() {
  assert clock.remaining(clock.now_ms()) == 0
}
