//// A clock for deadlines.
////
//// The codec package takes `now_ms` as an argument wherever it needs a time,
//// so that it can stay free of any platform dependency. This package does not
//// have that constraint and does need to know when a read has taken too long.
////
//// Monotonic rather than wall clock. A deadline computed from a clock that can
//// step backwards — an NTP correction, a manual change — is a deadline that
//// can be missed by an arbitrary amount, and the whole point of having one is
//// that a peer sending one byte at a time cannot hold a connection open
//// forever. The values are only meaningful relative to each other.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Milliseconds since an arbitrary point, moving only forwards.
@external(erlang, "ssocks_clock_ffi", "now_ms")
pub fn now_ms() -> Int

/// How much of a budget is left, never negative.
///
/// A zero here still lets one more non-blocking attempt through, which is what
/// keeps `receive` from reporting a timeout while holding bytes it could have
/// decoded.
pub fn remaining(deadline: Int) -> Int {
  case deadline - now_ms() {
    left if left > 0 -> left
    _ -> 0
  }
}
