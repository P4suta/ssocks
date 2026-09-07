// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import shadowsocks_echo
import ssocks
import ssocks/address
import ssocks/client
import ssocks/key
import ssocks/method
import ssocks/url

fn session() -> key.Key {
  key.from_password(method.Aes256Gcm, "a client secret")
}

fn config_for(port: Int) -> url.Config {
  let assert Ok(server) = address.parse("127.0.0.1:" <> int.to_string(port))
  url.new(method.Aes256Gcm, "a client secret", server)
}

// --- the ordinary path --------------------------------------------------------

pub fn a_client_gets_its_bytes_back_test() {
  let #(port, _) = shadowsocks_echo.start(session())

  let assert Ok(connection) =
    client.connect(config_for(port), to: "example.org:443", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"a request":utf8>>)
  let assert Ok(#(connection, returned)) =
    client.receive(connection, within: 2000)

  assert returned == <<"a request":utf8>>
  client.close(connection)
}

pub fn the_target_address_reaches_the_server_test() {
  // The header a client writes before its first payload byte is what tells the
  // server where to connect. If it were wrong, every connection would open onto
  // the wrong host and nothing else in the exchange would notice.
  let #(port, observed) = shadowsocks_echo.start(session())

  let assert Ok(connection) =
    client.connect(config_for(port), to: "example.org:443", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"anything":utf8>>)

  let assert Ok(target) = address.parse("example.org:443")
  assert shadowsocks_echo.next(observed, 2000)
    == Ok(shadowsocks_echo.Target(target))

  client.close(connection)
}

pub fn an_ipv6_target_reaches_the_server_test() {
  let #(port, observed) = shadowsocks_echo.start(session())

  let assert Ok(connection) =
    client.connect(config_for(port), to: "[2001:db8::1]:443", within: 2000)
  let assert Ok(_) = client.send(connection, <<"x":utf8>>)

  let assert Ok(target) = address.parse("[2001:db8::1]:443")
  assert shadowsocks_echo.next(observed, 2000)
    == Ok(shadowsocks_echo.Target(target))

  client.close(connection)
}

pub fn a_reply_spanning_several_chunks_arrives_whole_test() {
  // 40000 bytes is three chunks. The server splits and the client reassembles,
  // and the boundaries fall wherever TCP puts them rather than where either
  // side chose.
  let #(port, _) = shadowsocks_echo.start(session())
  let payload = filler(40_000)

  let assert Ok(connection) =
    client.connect(config_for(port), to: "example.org:443", within: 2000)
  let assert Ok(connection) = client.send(connection, payload)
  let assert Ok(#(connection, returned)) = collect(connection, 40_000, <<>>)

  assert returned == payload
  client.close(connection)
}

pub fn several_sends_share_one_connection_test() {
  // The nonce advances across calls, so the second request is encrypted under
  // a counter the first one moved. A client that reset it per call would work
  // once and then fail.
  let #(port, _) = shadowsocks_echo.start(session())

  let assert Ok(connection) =
    client.connect(config_for(port), to: "example.org:443", within: 2000)

  let assert Ok(connection) = client.send(connection, <<"first":utf8>>)
  let assert Ok(#(connection, first)) = client.receive(connection, within: 2000)
  assert first == <<"first":utf8>>

  let assert Ok(connection) = client.send(connection, <<"second":utf8>>)
  let assert Ok(#(connection, second)) =
    client.receive(connection, within: 2000)
  assert second == <<"second":utf8>>

  client.close(connection)
}

// --- what goes wrong ----------------------------------------------------------

pub fn a_closed_port_is_reported_as_such_test() {
  // Port 1 on loopback, which nothing should be listening on.
  let assert Error(reason) =
    client.connect(config_for(1), to: "example.org:443", within: 1000)

  assert is_unreachable(reason)
  assert string.contains(client.explain(reason), "server")
}

pub fn a_reply_that_does_not_authenticate_is_a_framing_error_test() {
  let port = shadowsocks_echo.start_garbage()

  let assert Ok(connection) =
    client.connect(config_for(port), to: "example.org:443", within: 2000)
  let assert Ok(connection) = client.send(connection, <<"hello":utf8>>)

  let assert Error(client.Framing(_)) = client.receive(connection, within: 2000)
  client.close(connection)
}

pub fn receive_gives_up_at_its_deadline_test() {
  // The echo answers what it is sent and nothing more, so a receive with
  // nothing outstanding has to come back on its own rather than hang.
  let #(port, _) = shadowsocks_echo.start(session())

  let assert Ok(connection) =
    client.connect(config_for(port), to: "example.org:443", within: 2000)

  let started = now_ms()
  let assert Error(client.ReadFailed(_)) =
    client.receive(connection, within: 300)
  let elapsed = now_ms() - started

  // Generous, but it has to prove the deadline is a deadline and not a
  // per-read timeout applied over and over.
  assert elapsed < 2000
  client.close(connection)
}

pub fn a_wrong_password_cannot_be_read_by_the_server_test() {
  let #(port, observed) = shadowsocks_echo.start(session())
  let assert Ok(server) = address.parse("127.0.0.1:" <> int.to_string(port))
  let wrong = url.new(method.Aes256Gcm, "not the secret", server)

  let assert Ok(connection) =
    client.connect(wrong, to: "example.org:443", within: 2000)
  let assert Ok(_) = client.send(connection, <<"a request":utf8>>)

  let assert Ok(shadowsocks_echo.DecodeFailed(_)) =
    shadowsocks_echo.next(observed, 2000)
}

// --- the promise on the front of the README -----------------------------------

pub fn a_url_is_all_it_takes_test() {
  let #(port, _) = shadowsocks_echo.start(session())
  let uri =
    url.to_string(config_for(port))
    |> string.append("#a test server")

  let assert Ok(config) = ssocks.from_uri(uri)
  let assert Ok(returned) = {
    use connection <- ssocks.with_connection(config, "example.org:443", 2000)
    let assert Ok(connection) = ssocks.send(connection, <<"three lines":utf8>>)
    let assert Ok(#(_, returned)) = ssocks.receive(connection, within: 2000)
    returned
  }

  assert returned == <<"three lines":utf8>>
}

// --- helpers ------------------------------------------------------------------

fn is_unreachable(reason: client.ClientError) -> Bool {
  case reason {
    client.CouldNotReach(_) -> True
    _ -> False
  }
}

fn collect(
  connection: client.Connection,
  wanted: Int,
  so_far: BitArray,
) -> Result(#(client.Connection, BitArray), client.ClientError) {
  case bit_array.byte_size(so_far) >= wanted {
    True -> Ok(#(connection, so_far))
    False ->
      case client.receive(connection, within: 2000) {
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

@external(erlang, "ssocks_clock_ffi", "now_ms")
fn now_ms() -> Int
