// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/list
import gleam/string
import ssocks/replay

fn salt(marker: Int) -> BitArray {
  <<marker:32, 0:224>>
}

/// This stdlib has no `list.range`; the other test modules count the same way.
fn counting_up_to(last: Int) -> List(Int) {
  counting_loop(last, [])
}

fn counting_loop(value: Int, acc: List(Int)) -> List(Int) {
  case value < 1 {
    True -> acc
    False -> counting_loop(value - 1, [value, ..acc])
  }
}

// --- what it is for -----------------------------------------------------------

pub fn a_salt_seen_once_is_accepted_test() {
  let assert Ok(_) = replay.observe(replay.new(), salt(1), 0)
}

pub fn the_same_salt_twice_is_refused_test() {
  // The specification asks that a salt be unique for the lifetime of a master
  // key. A server that does not track them lets an observer replay a recorded
  // handshake, and the reply comes back under a keystream that observer has
  // already seen used once.
  let assert Ok(filter) = replay.observe(replay.new(), salt(1), 0)

  assert replay.observe(filter, salt(1), 1)
    == Error(replay.AlreadySeen(salt(1)))
}

pub fn different_salts_are_all_accepted_test() {
  let filter =
    list.fold(counting_up_to(50), replay.new(), fn(filter, marker) {
      let assert Ok(filter) = replay.observe(filter, salt(marker), marker)
      filter
    })

  assert replay.size(filter) == 50
}

// --- forgetting ---------------------------------------------------------------

pub fn a_salt_is_forgotten_once_its_window_has_passed_test() {
  // Remembering forever is not an option: the table would grow without bound
  // for as long as the server runs, which is a slower version of the attack it
  // is defending against.
  let filter = replay.new() |> replay.with_window(1000)
  let assert Ok(filter) = replay.observe(filter, salt(1), 0)

  assert replay.observe(filter, salt(1), 999)
    == Error(replay.AlreadySeen(salt(1)))
  let assert Ok(_) = replay.observe(filter, salt(1), 1001)
}

pub fn expired_entries_do_not_accumulate_test() {
  // Pruning has to happen without being asked, or the window bounds only what
  // is refused and not what is stored.
  let filter =
    replay.new() |> replay.with_window(100) |> replay.with_capacity(8)

  let filter =
    list.fold(counting_up_to(40), filter, fn(filter, marker) {
      let assert Ok(filter) = replay.observe(filter, salt(marker), marker * 50)
      filter
    })

  assert replay.size(filter) <= 8
}

// --- the limit ----------------------------------------------------------------

pub fn a_flood_of_fresh_salts_is_refused_rather_than_remembered_test() {
  // Every entry costs memory and an attacker chooses how many arrive. Once
  // nothing can be pruned, refusing is the only answer that bounds the damage:
  // the alternative is that the server dies rather than that a connection does.
  let filter =
    replay.new() |> replay.with_capacity(4) |> replay.with_window(10_000)

  let filter =
    list.fold(counting_up_to(4), filter, fn(filter, marker) {
      let assert Ok(filter) = replay.observe(filter, salt(marker), 0)
      filter
    })

  assert replay.observe(filter, salt(99), 0)
    == Error(replay.CapacityExceeded(limit: 4))
}

pub fn room_made_by_expiry_is_room_again_test() {
  let filter =
    replay.new() |> replay.with_capacity(2) |> replay.with_window(100)

  let assert Ok(filter) = replay.observe(filter, salt(1), 0)
  let assert Ok(filter) = replay.observe(filter, salt(2), 0)
  assert replay.observe(filter, salt(3), 0)
    == Error(replay.CapacityExceeded(limit: 2))

  // Once the first two have aged out, the third fits.
  let assert Ok(filter) = replay.observe(filter, salt(3), 200)
  assert replay.size(filter) == 1
}

// --- time is an argument ------------------------------------------------------

pub fn a_clock_that_goes_backwards_does_not_resurrect_a_salt_test() {
  // `now_ms` comes from the caller and this package cannot make assumptions
  // about it. Going backwards must not let a salt through again.
  let filter = replay.new() |> replay.with_window(1000)
  let assert Ok(filter) = replay.observe(filter, salt(1), 5000)

  assert replay.observe(filter, salt(1), 4000)
    == Error(replay.AlreadySeen(salt(1)))
}

pub fn explain_says_which_limit_was_reached_test() {
  assert string.contains(replay.explain(replay.AlreadySeen(salt(1))), "salt")
  assert string.contains(replay.explain(replay.CapacityExceeded(limit: 4)), "4")
}
