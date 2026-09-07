//// Refusing a salt that has been used before.
////
//// Shadowsocks asks that a salt be unique for the lifetime of a master key.
//// The reason is concrete: the salt is what turns the master key into a
//// session key, so two streams opened with the same salt are encrypted under
//// the same key with the same counter, and an observer who recorded the first
//// one gets the second for free. Replaying a recorded handshake is the cheap
//// version of the same attack, and a server that keeps no record cannot tell
//// it from an ordinary connection.
////
//// Most implementations skip this. It is the one part of the specification
//// that costs memory and does nothing visible when it works.
////
//// ### Pure, with the clock passed in
////
//// There is no time in this module. `observe` is told what time it is, which
//// keeps `ssocks_codec` free of any platform dependency and makes every
//// expiry test a matter of choosing numbers rather than waiting. The IO
//// package wraps this in an actor — see `ssocks/replay_guard` — because the
//// state has to be shared across connections and across TCP and UDP alike:
//// the specification's requirement is per key, not per transport.
////
//// ### What the two limits are for
////
//// The window bounds how long a salt is remembered. Forever is not an option;
//// the table would grow for as long as the server runs, which is a slower
//// version of the attack it defends against.
////
//// The capacity bounds how many are remembered at once, because an attacker
//// chooses how many arrive. When nothing can be pruned and the table is full,
//// refusing the connection is the answer that bounds the damage: the
//// alternative is that the server dies rather than that a connection does.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/dict.{type Dict}
import gleam/int

/// Sixty seconds. Long enough to cover a replay arriving behind the original
/// on a different path, short enough that the table stays small.
pub const default_window = 60_000

/// A million salts, which at 32 bytes each is tens of megabytes of keys before
/// any overhead. Large enough never to be reached by honest traffic on one
/// server, small enough to be a bound.
pub const default_capacity = 1_000_000

/// Salts seen recently.
pub opaque type Filter {
  Filter(seen: Dict(BitArray, Int), window: Int, capacity: Int)
}

/// Why a salt was not accepted.
pub type ReplayError {
  /// This exact salt has been seen inside the window. The salt itself is
  /// carried because it travels in the clear at the head of every stream, so
  /// it is not a secret, and it is the only handle a log has on the connection.
  AlreadySeen(salt: BitArray)
  /// The table is full of entries too recent to prune.
  CapacityExceeded(limit: Int)
}

/// A filter with the default window and capacity.
pub fn new() -> Filter {
  Filter(dict.new(), default_window, default_capacity)
}

/// How long a salt is remembered, in milliseconds.
pub fn with_window(filter: Filter, milliseconds: Int) -> Filter {
  Filter(..filter, window: milliseconds)
}

/// How many salts may be remembered at once.
pub fn with_capacity(filter: Filter, entries: Int) -> Filter {
  Filter(..filter, capacity: entries)
}

/// Record a salt, or refuse it.
///
/// `now_ms` need only be consistent with itself. A clock that steps backwards
/// makes the filter forget later than it meant to, which is the safe direction.
pub fn observe(
  filter: Filter,
  salt: BitArray,
  now_ms: Int,
) -> Result(Filter, ReplayError) {
  case dict.get(filter.seen, salt) {
    Ok(at) if now_ms - at < filter.window -> Error(AlreadySeen(salt))
    _ -> {
      // Pruning is done here rather than on a timer so that this module needs
      // no timer, and only when it is needed so that the ordinary path stays
      // a single lookup and a single insert.
      let filter = case dict.size(filter.seen) < filter.capacity {
        True -> filter
        False -> prune(filter, now_ms)
      }

      case dict.size(filter.seen) < filter.capacity {
        False -> Error(CapacityExceeded(limit: filter.capacity))
        True ->
          Ok(Filter(..filter, seen: dict.insert(filter.seen, salt, now_ms)))
      }
    }
  }
}

/// How many salts are being remembered.
pub fn size(filter: Filter) -> Int {
  dict.size(filter.seen)
}

/// The window this filter was built with, in milliseconds.
pub fn window(filter: Filter) -> Int {
  filter.window
}

/// Drop everything older than the window.
///
/// An entry from the future — a clock that stepped backwards — is kept, since
/// forgetting early is the direction that lets a replay through.
fn prune(filter: Filter, now_ms: Int) -> Filter {
  Filter(
    ..filter,
    seen: dict.filter(filter.seen, fn(_, at) { now_ms - at < filter.window }),
  )
}

/// A sentence for a person.
pub fn explain(reason: ReplayError) -> String {
  case reason {
    AlreadySeen(_) ->
      "this salt has been seen before. Either a connection was replayed, or "
      <> "two clients are sharing a password and one of them is generating "
      <> "salts badly."
    CapacityExceeded(limit) ->
      "the replay filter is holding its limit of "
      <> int.to_string(limit)
      <> " salts, all too recent to forget. Connections are being refused "
      <> "rather than the table being allowed to grow; if this is honest "
      <> "traffic, raise the capacity or shorten the window."
  }
}
