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
fn start(
  configure: fn(server.Builder) -> server.Builder,
) -> #(Int, Subject(server.Event)) {
  let watched = process.new_subject()

  let assert Ok(listening) =
    server.new(session())
    |> server.watching(fn(event) { process.send(watched, event) })
    |> configure
    |> server.start(0)

  #(server.port(listening), watched)
}

fn plain(builder: server.Builder) -> server.Builder {
  builder
}

/// The next event of interest, skipping the ones every connection produces.
fn notable(
  watched: Subject(server.Event),
  within: Int,
) -> Result(server.Event, Nil) {
  case process.receive(watched, within) {
    Ok(server.Accepted) -> notable(watched, within)
    other -> other
  }
}

// --- relaying -----------------------------------------------------------------

pub fn a_client_reaches_a_target_through_the_server_test() {
  // The whole point, end to end: this library's client, this library's server,
  // and a plain TCP target that knows nothing about either.
  let target = echo_target.start()
  let #(port, _) = start(plain)

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
}

pub fn a_payload_spanning_several_chunks_survives_the_relay_test() {
  let target = echo_target.start()
  let #(port, _) = start(plain)
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
}

pub fn the_server_says_which_target_it_was_asked_for_test() {
  let target = echo_target.start()
  let #(port, watched) = start(plain)

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
}

pub fn a_handshake_arriving_one_byte_at_a_time_still_completes_test() {
  // The target address header can be split across reads, and a server that
  // assumed it arrives whole would fail only against slow links and small MTUs
  // — which is to say, in production and not in testing.
  let target = echo_target.start()
  let #(port, _) = start(plain)

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
}

// --- probing ------------------------------------------------------------------

pub fn a_wrong_password_is_reported_as_a_probe_test() {
  let #(port, watched) = start(plain)
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  let wrong = url.new(method.Aes256Gcm, "not the secret", where)

  let assert Ok(connection) =
    client.connect(wrong, to: "example.org:443", within: 2000)
  let assert Ok(_) = client.send(connection, <<"a request":utf8>>)

  let assert Ok(server.Probed(server.AuthenticationFailed(_))) =
    notable(watched, 2000)
  client.close(connection)
}

pub fn a_probe_is_drained_rather_than_closed_by_default_test() {
  // Closing on a failed handshake is how active probing has identified
  // Shadowsocks servers. The default has to look like a port that swallows
  // whatever it is given.
  let #(port, watched) = start(plain)
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
}

pub fn close_now_closes_a_probe_test() {
  let #(port, watched) = start(server.on_probe(_, server.CloseNow))
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  let wrong = url.new(method.Aes256Gcm, "not the secret", where)

  let assert Ok(connection) =
    client.connect(wrong, to: "example.org:443", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"a request":utf8>>)

  let assert Ok(server.Probed(_)) = notable(watched, 2000)
  let assert Error(client.ReadFailed(mug.Closed)) =
    client.receive(connection, within: 2000)
}

pub fn a_connection_that_says_nothing_is_a_probe_too_test() {
  // The third thing a prober does: open a socket and wait to see what the
  // other end does about it.
  let #(port, watched) =
    start(fn(builder) {
      builder
      |> server.with_handshake_timeout(200)
      |> server.on_probe(server.CloseNow)
    })

  let assert Ok(socket) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  assert notable(watched, 3000) == Ok(server.Probed(server.Silent))
  assert mug.receive(socket, timeout_milliseconds: 2000) == Error(mug.Closed)
}

pub fn bytes_that_authenticate_but_are_not_an_address_are_a_probe_test() {
  // A peer holding the right key and speaking a different protocol. Not an
  // authentication failure, and still not something to relay.
  let #(port, watched) = start(plain)

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
}

// --- replay -------------------------------------------------------------------

pub fn the_same_salt_twice_is_refused_test() {
  let target = echo_target.start()
  let #(port, watched) = start(plain)

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
}

pub fn two_servers_can_share_one_replay_filter_test() {
  // The specification's requirement is per key, not per listener. Two servers
  // with separate filters would let a salt seen by one be replayed at the
  // other.
  let target = echo_target.start()
  let assert Ok(guard) = replay_guard.start()

  let #(first_port, first_watched) = start(server.with_replay_guard(_, guard))
  let #(second_port, second_watched) = start(server.with_replay_guard(_, guard))

  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))
  let salt = <<11:256>>

  let assert Ok(one) = open_with_salt(first_port, where, salt)
  let assert Ok(server.Handshook(_)) = notable(first_watched, 2000)
  let _ = mug.shutdown(one)

  let assert Ok(two) = open_with_salt(second_port, where, salt)
  let assert Ok(server.Probed(server.Replayed(_))) =
    notable(second_watched, 2000)
  let _ = mug.shutdown(two)
}

pub fn a_guard_remembers_across_calls_test() {
  let assert Ok(guard) = replay_guard.start()

  assert replay_guard.observe(guard, <<1:256>>, within: 1000) == Ok(Nil)
  assert replay_guard.observe(guard, <<1:256>>, within: 1000)
    == Error(replay.AlreadySeen(<<1:256>>))
  assert replay_guard.size(guard, within: 1000) == 1
}

// --- targets that are not there ------------------------------------------------

pub fn an_unreachable_target_closes_the_connection_test() {
  let #(port, watched) = start(server.with_connect_timeout(_, 500))

  // Port 1 on loopback, which nothing should be listening on.
  let assert Ok(connection) =
    client.connect(config_for(port), to: "127.0.0.1:1", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"nobody home":utf8>>)

  let assert Ok(server.Handshook(_)) = notable(watched, 2000)
  let assert Ok(server.TargetUnreachable(_)) = notable(watched, 3000)
  let assert Error(client.ReadFailed(mug.Closed)) =
    client.receive(connection, within: 3000)
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
