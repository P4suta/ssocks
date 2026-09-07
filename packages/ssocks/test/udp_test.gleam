// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process.{type Subject}
import gleam/int
import glip
import ssocks/address
import ssocks/datagram
import ssocks/key
import ssocks/method
import ssocks/replay_guard
import ssocks/udp
import toss
import udp_echo

const password = "a udp secret"

fn session() -> key.Key {
  key.from_password(method.Aes256Gcm, password)
}

fn start(
  configure: fn(udp.Builder) -> udp.Builder,
) -> #(udp.Relay, Subject(udp.Event)) {
  let watched = process.new_subject()

  let assert Ok(relaying) =
    udp.relay(session())
    |> udp.bind("127.0.0.1")
    |> udp.watching(fn(event) { process.send(watched, event) })
    |> configure
    |> udp.start(0)

  #(relaying, watched)
}

fn plain(builder: udp.Builder) -> udp.Builder {
  builder
}

fn loopback() -> glip.IpAddress {
  let assert Ok(ip) = glip.parse_ip("127.0.0.1")
  ip
}

fn target_at(port: Int) -> address.Address {
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  where
}

/// A bare UDP socket standing in for a client.
fn client() -> toss.Socket {
  let assert Ok(socket) = toss.open(toss.new(port: 0))
  socket
}

/// Send one sealed packet and wait for the sealed answer.
fn round_trip(
  socket: toss.Socket,
  relaying: udp.Relay,
  target: address.Address,
  payload: BitArray,
) -> Result(#(address.Address, BitArray), Nil) {
  let packet = datagram.seal(session(), target, payload)
  let assert Ok(_) =
    toss.send_to(socket, loopback(), udp.port(relaying), packet)

  case toss.receive(socket, max_length: 65_535, timeout_milliseconds: 3000) {
    Error(_) -> Error(Nil)
    Ok(#(_, _, returned)) ->
      case datagram.open(session(), returned) {
        Error(_) -> Error(Nil)
        Ok(pair) -> Ok(pair)
      }
  }
}

// --- relaying -----------------------------------------------------------------

pub fn a_datagram_reaches_a_target_and_the_reply_comes_back_test() {
  let echoing = udp_echo.start()
  let #(relaying, _) = start(plain)

  assert round_trip(client(), relaying, target_at(echoing), <<"ping":utf8>>)
    == Ok(#(target_at(echoing), <<"ping":utf8>>))

  udp.stop(relaying)
}

pub fn each_client_gets_its_own_replies_test() {
  // Two clients share the listening socket, so the relay has to remember which
  // outbound socket belongs to which of them. Getting that wrong sends one
  // client's traffic to the other, which is worse than losing it.
  let echoing = udp_echo.start()
  let #(relaying, _) = start(plain)

  let first = client()
  let second = client()

  assert round_trip(first, relaying, target_at(echoing), <<"first":utf8>>)
    == Ok(#(target_at(echoing), <<"first":utf8>>))
  assert round_trip(second, relaying, target_at(echoing), <<"second":utf8>>)
    == Ok(#(target_at(echoing), <<"second":utf8>>))

  assert udp.sessions(relaying, within: 1000) == Ok(2)
  udp.stop(relaying)
}

pub fn one_client_sending_twice_keeps_one_session_test() {
  let echoing = udp_echo.start()
  let #(relaying, _) = start(plain)
  let socket = client()

  let assert Ok(_) =
    round_trip(socket, relaying, target_at(echoing), <<"one":utf8>>)
  let assert Ok(_) =
    round_trip(socket, relaying, target_at(echoing), <<"two":utf8>>)

  assert udp.sessions(relaying, within: 1000) == Ok(1)
  udp.stop(relaying)
}

pub fn a_large_payload_survives_the_relay_test() {
  // One datagram, no framing: the packet is as big as the payload plus the
  // header and the tag, and it either arrives or it does not.
  let echoing = udp_echo.start()
  let #(relaying, _) = start(plain)
  let payload = filler(1200)

  assert round_trip(client(), relaying, target_at(echoing), payload)
    == Ok(#(target_at(echoing), payload))

  udp.stop(relaying)
}

// --- refusing -----------------------------------------------------------------

pub fn a_packet_that_does_not_authenticate_is_dropped_in_silence_test() {
  // Answering anything at all would say a Shadowsocks relay is here, which is
  // the one thing the port should not say to somebody who cannot authenticate.
  let #(relaying, watched) = start(plain)
  let socket = client()

  let assert Ok(_) =
    toss.send_to(socket, loopback(), udp.port(relaying), <<
      "not a shadowsocks packet at all, not even close":utf8,
    >>)

  let assert Ok(udp.Rejected(udp.NotAuthentic(_))) =
    process.receive(watched, 2000)
  assert toss.receive(socket, max_length: 65_535, timeout_milliseconds: 300)
    == Error(toss.Timeout)

  udp.stop(relaying)
}

pub fn a_replayed_packet_is_refused_test() {
  let echoing = udp_echo.start()
  let #(relaying, watched) = start(plain)
  let socket = client()

  // The same bytes twice: same salt, so the second is a replay.
  let packet = datagram.seal(session(), target_at(echoing), <<"once":utf8>>)

  let assert Ok(_) =
    toss.send_to(socket, loopback(), udp.port(relaying), packet)
  let assert Ok(udp.SessionOpened(_)) = process.receive(watched, 2000)
  let assert Ok(udp.Forwarded(_, _)) = process.receive(watched, 2000)

  // The echo answers the first packet, and that answer is an event too. Waiting
  // for it here rather than letting it race the next assertion: without this
  // the test asks for the rejection and is handed the reply to the packet
  // before it, which is a failure that says nothing about replay.
  let assert Ok(udp.Returned(_, _)) = process.receive(watched, 2000)

  let assert Ok(_) =
    toss.send_to(socket, loopback(), udp.port(relaying), packet)
  let assert Ok(udp.Rejected(udp.Replayed(_))) = process.receive(watched, 2000)

  udp.stop(relaying)
}

pub fn a_relay_and_a_server_can_share_one_replay_filter_test() {
  // The specification's requirement is per key, not per transport. A salt seen
  // over one must not be usable over the other.
  let echoing = udp_echo.start()
  let assert Ok(guard) = replay_guard.start()
  let #(relaying, watched) = start(udp.with_replay_guard(_, guard))

  let packet = datagram.seal(session(), target_at(echoing), <<"shared":utf8>>)
  let assert Ok(salt) = datagram.salt_of(session(), packet)

  // Something else under the same key saw this salt first.
  let assert Ok(_) = replay_guard.observe(guard, salt, within: 1000)

  let assert Ok(_) =
    toss.send_to(client(), loopback(), udp.port(relaying), packet)
  let assert Ok(udp.Rejected(udp.Replayed(_))) = process.receive(watched, 2000)

  udp.stop(relaying)
}

// --- the table ----------------------------------------------------------------

pub fn a_quiet_session_is_swept_test() {
  // Nothing ever tells a UDP relay that a client has finished, so entries have
  // to leave on their own or the table is a memory leak with a schedule.
  let echoing = udp_echo.start()
  let #(relaying, watched) =
    start(fn(builder) {
      builder
      |> udp.with_session_timeout(150)
      |> udp.with_sweep_interval(100)
    })

  let assert Ok(_) =
    round_trip(client(), relaying, target_at(echoing), <<"then quiet":utf8>>)
  assert udp.sessions(relaying, within: 1000) == Ok(1)

  let assert Ok(udp.SessionExpired(remaining)) = wait_for_expiry(watched)
  assert remaining == 0
  assert udp.sessions(relaying, within: 1000) == Ok(0)

  udp.stop(relaying)
}

pub fn the_table_has_a_ceiling_test() {
  // UDP source addresses are forged for free, so the number of entries is
  // chosen by whoever is sending. At the ceiling the least recently used goes.
  let echoing = udp_echo.start()
  let #(relaying, _) = start(udp.with_max_sessions(_, 2))

  let assert Ok(_) =
    round_trip(client(), relaying, target_at(echoing), <<"a":utf8>>)
  let assert Ok(_) =
    round_trip(client(), relaying, target_at(echoing), <<"b":utf8>>)
  let assert Ok(_) =
    round_trip(client(), relaying, target_at(echoing), <<"c":utf8>>)

  assert udp.sessions(relaying, within: 1000) == Ok(2)
  udp.stop(relaying)
}

// --- helpers ------------------------------------------------------------------

fn wait_for_expiry(watched: Subject(udp.Event)) -> Result(udp.Event, Nil) {
  case process.receive(watched, 3000) {
    Ok(udp.SessionExpired(remaining)) -> Ok(udp.SessionExpired(remaining))
    Ok(_) -> wait_for_expiry(watched)
    Error(Nil) -> Error(Nil)
  }
}

// --- stopping -----------------------------------------------------------------

pub fn asking_a_relay_that_has_stopped_is_an_error_not_a_crash_test() {
  let #(relaying, _) = start(plain)
  assert udp.sessions(relaying, within: 1000) == Ok(0)

  udp.stop(relaying)

  // Two claims at once. That the answer is an error rather than an exception:
  // a caller polling a relay for its size should not be brought down by the
  // relay going away. And that this is not a race: `stop` waits for the relay
  // to be gone, so by the time it returns there is nothing left to answer.
  assert udp.sessions(relaying, within: 1000) == Error(Nil)
}

pub fn the_port_is_free_once_stop_returns_test() {
  let #(relaying, _) = start(plain)
  let port = udp.port(relaying)

  udp.stop(relaying)

  // The practical reason `stop` waits. A relay's socket is closed by the
  // runtime when its process ends, so a stop that returned early would leave a
  // window in which the port is still taken and this rebind would fail.
  let assert Ok(second) =
    udp.relay(session())
    |> udp.bind("127.0.0.1")
    |> udp.start(port)

  assert udp.port(second) == port
  udp.stop(second)
}

fn filler(size: Int) -> BitArray {
  filling(size, <<>>)
}

fn filling(remaining: Int, acc: BitArray) -> BitArray {
  case remaining {
    0 -> acc
    _ -> {
      let byte = remaining * 31 % 256
      filling(remaining - 1, <<acc:bits, byte:8>>)
    }
  }
}
