// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import echo_target
import gleam/bit_array
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import mug
import ssocks/address
import ssocks/client
import ssocks/key
import ssocks/method
import ssocks/replay
import ssocks/replay_guard
import ssocks/server
import ssocks/stream
import ssocks/url

const password = "a server secret"

fn session() -> key.Key {
  key.from_password(method.Aes256Gcm, password)
}

fn config_for(port: Int) -> url.Config {
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  url.new(method.Aes256Gcm, password, where)
}

/// A server on an ephemeral port, plus a subject carrying everything it
/// noticed. The builder is handed in so each test can change one thing.
///
/// The server itself comes back rather than only its port, because every test
/// here has to give the port up again: a listener that outlives its test holds
/// a socket for the rest of the run, and `stop` is the thing being relied on.
fn start(
  configure: fn(server.Builder) -> server.Builder,
) -> #(server.Server, Subject(server.Event)) {
  let watched = process.new_subject()

  let assert Ok(listening) =
    server.new(session())
    |> server.watching(fn(event) { process.send(watched, event) })
    |> configure
    |> server.start(0)

  #(listening, watched)
}

fn plain(builder: server.Builder) -> server.Builder {
  builder
}

/// The next event of interest, skipping the two that every connection
/// produces.
///
/// `Finished` is skipped here and asserted on its own in
/// `a_client_that_hangs_up_finishes_the_connection_test`, because otherwise
/// every test that opens a second connection would have to know how many
/// connections the first one closed.
fn notable(
  watched: Subject(server.Event),
  within: Int,
) -> Result(server.Event, Nil) {
  case process.receive(watched, within) {
    Ok(server.Accepted) | Ok(server.Finished) -> notable(watched, within)
    other -> other
  }
}

// --- relaying -----------------------------------------------------------------

pub fn a_client_reaches_a_target_through_the_server_test() {
  // The whole point, end to end: this library's client, this library's server,
  // and a plain TCP target that knows nothing about either.
  let target = echo_target.start()
  let #(listening, _) = start(plain)
  let port = server.port(listening)

  let assert Ok(connection) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(connection) = client.send(connection, <<"through":utf8>>)
  let assert Ok(#(connection, returned)) =
    client.receive(connection, within: 2000)

  assert returned == <<"through":utf8>>
  client.close(connection)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn a_payload_spanning_several_chunks_survives_the_relay_test() {
  let target = echo_target.start()
  let #(listening, _) = start(plain)
  let port = server.port(listening)
  let payload = filler(40_000)

  let assert Ok(connection) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(connection) = client.send(connection, payload)
  let assert Ok(returned) = collect(connection, 40_000, <<>>)

  assert returned == payload
  client.close(connection)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn the_server_says_which_target_it_was_asked_for_test() {
  let target = echo_target.start()
  let #(listening, watched) = start(plain)
  let port = server.port(listening)

  let assert Ok(connection) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(_) = client.send(connection, <<"x":utf8>>)

  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))
  assert notable(watched, 2000) == Ok(server.Handshook(where))
  client.close(connection)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn a_handshake_arriving_one_byte_at_a_time_still_completes_test() {
  // The target address header can be split across reads, and a server that
  // assumed it arrives whole would fail only against slow links and small MTUs
  // — which is to say, in production and not in testing.
  let target = echo_target.start()
  let #(listening, _) = start(plain)
  let port = server.port(listening)

  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))
  let #(encoder, salt) = stream.encoder(session())
  let #(_, framed) =
    stream.encode(
      encoder,
      bit_array.concat([address.encode(where), <<"drip":utf8>>]),
    )

  let assert Ok(socket) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  dribble(socket, bit_array.concat([salt, framed]))

  let assert Ok(reply) = mug.receive(socket, timeout_milliseconds: 3000)
  let assert Ok(#(_, chunks)) = stream.decode(stream.decoder(session()), reply)

  assert bit_array.concat(chunks) == <<"drip":utf8>>
  let _ = mug.shutdown(socket)

  let assert Ok(Nil) = server.stop(listening)
}

// --- limits --------------------------------------------------------------------

pub fn connections_are_counted_test() {
  let target = echo_target.start()
  let #(listening, _) = start(plain)
  let port = server.port(listening)

  assert server.connections(listening, within: 1000) == Ok(0)

  let assert Ok(one) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(one) = client.send(one, <<"hello":utf8>>)
  let assert Ok(#(one, _)) = client.receive(one, within: 2000)

  assert server.connections(listening, within: 1000) == Ok(1)

  client.close(one)
  let assert Ok(Nil) = server.stop(listening)
}

pub fn the_ceiling_turns_connections_away_test() {
  // A ceiling is visible from the outside in a way `Drain` is not, which is
  // why it is high by default rather than tight. What it buys is a bound on
  // how many sockets an unauthenticated peer can hold open at once.
  let target = echo_target.start()
  let #(listening, watched) = start(server.with_max_connections(_, 1))
  let port = server.port(listening)

  let assert Ok(one) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(one) = client.send(one, <<"hello":utf8>>)
  let assert Ok(#(one, _)) = client.receive(one, within: 2000)

  // The second is refused rather than queued, and says so.
  let assert Ok(two) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  assert accounted(watched, 2000) == Ok(server.Refused)
  assert mug.receive(two, timeout_milliseconds: 2000) == Error(mug.Closed)

  // A refused connection took no place in the count, so the first still has it.
  assert server.connections(listening, within: 1000) == Ok(1)

  client.close(one)
  let assert Ok(Nil) = server.stop(listening)
}

pub fn a_connection_that_goes_quiet_is_closed_test() {
  // Before this, only the handshake was bounded: an authenticated peer could
  // hold two processes and two sockets for as long as it liked by saying
  // nothing at all.
  let target = echo_target.start()
  let #(listening, watched) = start(server.with_idle_timeout(_, 300))
  let port = server.port(listening)

  let assert Ok(connection) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(connection) = client.send(connection, <<"hello":utf8>>)
  let assert Ok(#(connection, _)) = client.receive(connection, within: 2000)

  assert accounted(watched, 3000) == Ok(server.Idled)
  assert client.receive(connection, within: 2000)
    == Error(client.ReadFailed(mug.Closed))

  client.close(connection)
  let assert Ok(Nil) = server.stop(listening)
}

pub fn more_held_than_allowed_closes_the_connection_test() {
  // `held` grows while the target is being reached, which is bounded only by
  // `with_connect_timeout` — ten seconds of whatever the peer can push, in one
  // process's memory. The first payload arrives before the target is reached,
  // every time, so this is the cap being exercised rather than a race.
  let target = echo_target.start()
  let #(listening, watched) = start(server.with_max_pending_bytes(_, 64))
  let port = server.port(listening)

  let assert Ok(connection) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(_) = client.send(connection, <<0:size(4096)>>)

  let assert Ok(server.Overflowed(_)) = accounted(watched, 2000)

  client.close(connection)
  let assert Ok(Nil) = server.stop(listening)
}

pub fn a_server_without_a_guard_relays_a_replayed_salt_test() {
  // The specification asks for the check, and `without_replay_guard` is the
  // only way to skip it — reasonable only when something else is doing it.
  // Until this test, nothing reached that branch at all.
  let target = echo_target.start()
  let #(listening, watched) = start(server.without_replay_guard)
  let port = server.port(listening)

  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))
  let salt = <<19:256>>

  let assert Ok(one) = open_with_salt(port, where, salt)
  let assert Ok(server.Handshook(_)) = notable(watched, 2000)
  let _ = mug.shutdown(one)

  // The same salt again, and no filter to remember it.
  let assert Ok(two) = open_with_salt(port, where, salt)
  let assert Ok(server.Handshook(_)) = notable(watched, 2000)
  let _ = mug.shutdown(two)

  let assert Ok(Nil) = server.stop(listening)
}

// --- the listener's lifetime ---------------------------------------------------

pub fn the_port_is_free_once_stop_returns_test() {
  // The practical reason `stop` waits. A listening socket is closed by the
  // runtime when its owner ends, so a stop that returned early would leave a
  // window in which the port is still taken and this rebind would fail.
  let #(listening, _) = start(plain)
  let port = server.port(listening)

  let assert Ok(Nil) = server.stop(listening)

  let assert Ok(second) =
    server.new(session())
    |> server.bind("127.0.0.1")
    |> server.start(port)

  assert server.port(second) == port
  let assert Ok(Nil) = server.stop(second)
}

pub fn stopping_twice_is_not_an_error_test() {
  let #(listening, _) = start(plain)

  let assert Ok(Nil) = server.stop(listening)
  // Being gone is what was asked for, so asking again is not a failure.
  assert server.stop(listening) == Ok(Nil)
}

pub fn an_interface_that_is_not_an_address_is_refused_test() {
  // glisten panics on one it cannot parse, and the fallback a panic leaves is
  // no fallback at all. Worse would be quietly listening on every interface:
  // a typo would publish a server the operator meant to keep on one address.
  assert server.new(session())
    |> server.bind("127.0.0.0.1")
    |> server.start(0)
    == Error(server.BadInterface("127.0.0.0.1"))
}

pub fn a_client_that_hangs_up_lets_go_of_the_target_test() {
  // glisten ends a handler normally when its socket closes, and a normal exit
  // does not travel down a link. Without `on_close` the process holding the
  // socket to the target would stay parked on a selector for ever: one leaked
  // process and one leaked file descriptor for every client that hangs up.
  let #(target, seen) = echo_target.watched()
  let #(listening, watched) = start(plain)
  let port = server.port(listening)

  let assert Ok(connection) =
    client.connect(
      config_for(port),
      to: "127.0.0.1:" <> int.to_string(target),
      within: 2000,
    )
  let assert Ok(connection) = client.send(connection, <<"hello":utf8>>)
  let assert Ok(#(connection, <<"hello":utf8>>)) =
    client.receive(connection, within: 2000)

  // The target is connected and has answered, so there is something to leak.
  let assert Ok(echo_target.Arrived(_)) = process.receive(seen, 2000)

  client.close(connection)

  // Both halves of the claim: the target's socket is released, and the
  // connection is accounted for rather than left open in the event stream.
  assert process.receive(seen, 2000) == Ok(echo_target.Closed)
  assert accounted(watched, 2000) == Ok(server.Finished)

  let assert Ok(Nil) = server.stop(listening)
}

/// The next event, skipping the two that setting a connection up produces.
///
/// Unlike `notable` this lets `Finished` through, which is what the tests that
/// use it are looking for: whether a connection was accounted for at the end.
fn accounted(
  watched: Subject(server.Event),
  within: Int,
) -> Result(server.Event, Nil) {
  case process.receive(watched, within) {
    Ok(server.Accepted) | Ok(server.Handshook(_)) -> accounted(watched, within)
    other -> other
  }
}

// --- probing ------------------------------------------------------------------

pub fn a_wrong_password_is_reported_as_a_probe_test() {
  let #(listening, watched) = start(plain)
  let port = server.port(listening)
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  let wrong = url.new(method.Aes256Gcm, "not the secret", where)

  let assert Ok(connection) =
    client.connect(wrong, to: "example.org:443", within: 2000)
  let assert Ok(_) = client.send(connection, <<"a request":utf8>>)

  let assert Ok(server.Probed(server.AuthenticationFailed(_))) =
    notable(watched, 2000)
  client.close(connection)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn a_probe_is_drained_rather_than_closed_by_default_test() {
  // Closing on a failed handshake is how active probing has identified
  // Shadowsocks servers. The default has to look like a port that swallows
  // whatever it is given.
  let #(listening, watched) = start(plain)
  let port = server.port(listening)
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  let wrong = url.new(method.Aes256Gcm, "not the secret", where)

  let assert Ok(connection) =
    client.connect(wrong, to: "example.org:443", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"a request":utf8>>)

  let assert Ok(server.Probed(_)) = notable(watched, 2000)

  // Still open: a read finds nothing rather than a closed socket, and more
  // can still be written without error.
  let assert Error(client.ReadFailed(mug.Timeout)) =
    client.receive(connection, within: 300)
  let assert Ok(_) = client.send(connection, <<"still here":utf8>>)

  client.close(connection)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn close_now_closes_a_probe_test() {
  let #(listening, watched) = start(server.on_probe(_, server.CloseNow))
  let port = server.port(listening)
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  let wrong = url.new(method.Aes256Gcm, "not the secret", where)

  let assert Ok(connection) =
    client.connect(wrong, to: "example.org:443", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"a request":utf8>>)

  let assert Ok(server.Probed(_)) = notable(watched, 2000)
  let assert Error(client.ReadFailed(mug.Closed)) =
    client.receive(connection, within: 2000)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn a_connection_that_says_nothing_is_a_probe_too_test() {
  // The third thing a prober does: open a socket and wait to see what the
  // other end does about it.
  let #(listening, watched) =
    start(fn(builder) {
      builder
      |> server.with_handshake_timeout(200)
      |> server.on_probe(server.CloseNow)
    })
  let port = server.port(listening)

  let assert Ok(socket) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  assert notable(watched, 3000) == Ok(server.Probed(server.Silent))
  assert mug.receive(socket, timeout_milliseconds: 2000) == Error(mug.Closed)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn bytes_that_authenticate_but_are_not_an_address_are_a_probe_test() {
  // A peer holding the right key and speaking a different protocol. Not an
  // authentication failure, and still not something to relay.
  let #(listening, watched) = start(plain)
  let port = server.port(listening)

  let #(encoder, salt) = stream.encoder(session())
  // Address type 0x09 is not one of the three the protocol defines.
  let #(_, framed) = stream.encode(encoder, <<0x09, 0xff, 0xff>>)

  let assert Ok(socket) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()
  let assert Ok(_) = mug.send(socket, bit_array.concat([salt, framed]))

  assert notable(watched, 2000) == Ok(server.Probed(server.MalformedHeader))
  let _ = mug.shutdown(socket)

  let assert Ok(Nil) = server.stop(listening)
}

// --- replay -------------------------------------------------------------------

pub fn the_same_salt_twice_is_refused_test() {
  let target = echo_target.start()
  let #(listening, watched) = start(plain)
  let port = server.port(listening)

  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))
  let salt = <<7:256>>

  // The first connection goes through.
  let assert Ok(first) = open_with_salt(port, where, salt)
  let assert Ok(server.Handshook(_)) = notable(watched, 2000)
  let _ = mug.shutdown(first)

  // The second, replaying that salt, does not.
  let assert Ok(second) = open_with_salt(port, where, salt)
  let assert Ok(server.Probed(server.Replayed(_))) = notable(watched, 2000)
  let _ = mug.shutdown(second)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn two_servers_can_share_one_replay_filter_test() {
  // The specification's requirement is per key, not per listener. Two servers
  // with separate filters would let a salt seen by one be replayed at the
  // other.
  let target = echo_target.start()
  let assert Ok(guard) = replay_guard.start()

  let #(first, first_watched) = start(server.with_replay_guard(_, guard))
  let #(second, second_watched) = start(server.with_replay_guard(_, guard))

  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))
  let salt = <<11:256>>

  let assert Ok(one) = open_with_salt(server.port(first), where, salt)
  let assert Ok(server.Handshook(_)) = notable(first_watched, 2000)
  let _ = mug.shutdown(one)

  let assert Ok(two) = open_with_salt(server.port(second), where, salt)
  let assert Ok(server.Probed(server.Replayed(_))) =
    notable(second_watched, 2000)
  let _ = mug.shutdown(two)

  let assert Ok(Nil) = replay_guard.stop(guard)

  let assert Ok(Nil) = server.stop(first)
  let assert Ok(Nil) = server.stop(second)
}

pub fn a_salt_is_not_recorded_until_a_chunk_authenticates_test() {
  // The filter is bounded and is meant to be shared with the UDP relay, so an
  // entry that anyone can add by sending 32 bytes of noise is a way to fill it
  // from the outside and have it start refusing honest traffic on both
  // transports. Nothing is recorded until the first chunk has authenticated.
  let assert Ok(guard) = replay_guard.start()
  let #(listening, watched) = start(server.with_replay_guard(_, guard))
  let port = server.port(listening)

  let assert Ok(socket) =
    mug.new("127.0.0.1", port: port) |> mug.timeout(2000) |> mug.connect()
  // A whole salt's worth of bytes, and nothing that could authenticate.
  let assert Ok(_) = mug.send(socket, <<0:256>>)
  let assert Ok(_) = mug.send(socket, <<0:256>>)

  let assert Ok(server.Probed(server.AuthenticationFailed(_))) =
    notable(watched, 2000)

  assert replay_guard.size(guard, within: 1000) == Ok(0)

  let _ = mug.shutdown(socket)
  let assert Ok(Nil) = replay_guard.stop(guard)

  let assert Ok(Nil) = server.stop(listening)
}

pub fn a_guard_remembers_across_calls_test() {
  let assert Ok(guard) = replay_guard.start()

  assert replay_guard.observe(guard, <<1:256>>, within: 1000) == Ok(Nil)
  assert replay_guard.observe(guard, <<1:256>>, within: 1000)
    == Error(replay_guard.Refused(replay.AlreadySeen(<<1:256>>)))
  assert replay_guard.size(guard, within: 1000) == Ok(1)

  let assert Ok(Nil) = replay_guard.stop(guard)
}

pub fn a_guard_that_is_gone_answers_rather_than_raising_test() {
  // A dead guard used to take its caller down with it: `observe` and `size`
  // were bare `process.call`s, and every connection handler calls `observe`.
  // One actor going away would have become every connection crashing with it.
  let assert Ok(guard) = replay_guard.start()
  let assert Ok(Nil) = replay_guard.stop(guard)

  assert replay_guard.size(guard, within: 1000) == Error(Nil)
  assert replay_guard.observe(guard, <<2:256>>, within: 1000)
    == Error(replay_guard.Unavailable)
}

pub fn a_guard_can_be_started_over_a_configured_filter_test() {
  // `start_with` is the only way to choose the window and the capacity, since
  // neither builder takes a filter.
  let assert Ok(guard) =
    replay_guard.start_with(replay.new() |> replay.with_capacity(1))

  assert replay_guard.observe(guard, <<3:256>>, within: 1000) == Ok(Nil)
  assert replay_guard.observe(guard, <<4:256>>, within: 1000)
    == Error(replay_guard.Refused(replay.CapacityExceeded(1)))

  let assert Ok(Nil) = replay_guard.stop(guard)
}

// --- targets that are not there ------------------------------------------------

pub fn an_unreachable_target_closes_the_connection_test() {
  let #(listening, watched) = start(server.with_connect_timeout(_, 500))
  let port = server.port(listening)

  // Port 1 on loopback, which nothing should be listening on.
  let assert Ok(connection) =
    client.connect(config_for(port), to: "127.0.0.1:1", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"nobody home":utf8>>)

  let assert Ok(server.Handshook(_)) = notable(watched, 2000)
  let assert Ok(server.TargetUnreachable(_)) = notable(watched, 3000)
  let assert Error(client.ReadFailed(mug.Closed)) =
    client.receive(connection, within: 3000)

  let assert Ok(Nil) = server.stop(listening)
}

// --- helpers ------------------------------------------------------------------

/// Open a raw connection carrying a chosen salt, so a test can replay one.
fn open_with_salt(
  port: Int,
  target: address.Address,
  salt: BitArray,
) -> Result(mug.Socket, mug.ConnectError) {
  let assert Ok(#(encoder, prologue)) =
    stream.encoder_with_salt(session(), salt)
  let #(_, framed) =
    stream.encode(
      encoder,
      bit_array.concat([address.encode(target), <<"hello":utf8>>]),
    )

  case
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()
  {
    Error(reason) -> Error(reason)
    Ok(socket) -> {
      let assert Ok(_) = mug.send(socket, bit_array.concat([prologue, framed]))
      Ok(socket)
    }
  }
}

fn dribble(socket: mug.Socket, bytes: BitArray) -> Nil {
  case bytes {
    <<first:8, rest:bits>> -> {
      let assert Ok(_) = mug.send(socket, <<first:8>>)
      dribble(socket, rest)
    }
    _ -> Nil
  }
}

fn collect(
  connection: client.Connection,
  wanted: Int,
  so_far: BitArray,
) -> Result(BitArray, client.ClientError) {
  case bit_array.byte_size(so_far) >= wanted {
    True -> Ok(so_far)
    False ->
      case client.receive(connection, within: 5000) {
        Error(reason) -> Error(reason)
        Ok(#(connection, more)) ->
          collect(connection, wanted, bit_array.append(so_far, more))
      }
  }
}

fn filler(size: Int) -> BitArray {
  <<0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x5a, 0xa5>>
  |> list.repeat(size / 8 + 1)
  |> bit_array.concat
  |> take(size)
}

fn take(value: BitArray, size: Int) -> BitArray {
  let assert Ok(sliced) = bit_array.slice(value, 0, size)
  sliced
}
