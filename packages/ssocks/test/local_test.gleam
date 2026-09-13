//// The SOCKS5 proxy, driven by a SOCKS5 client.
////
//// The end-to-end case is the whole stack at once: a plain TCP echo, this
//// library's Shadowsocks server in front of it, this library's proxy in front
//// of that, and a SOCKS5 client here. Every layer this repository has, in the
//// order a browser would meet them.
////
//// That it is all this library's own code is the limit of what these can say.
//// `scripts/socks5-interop.mjs` is what puts a foreign implementation on the
//// other end.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import echo_target
import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/option
import glip
import glisten
import mug
import ssocks/address
import ssocks/key
import ssocks/local
import ssocks/method
import ssocks/server
import ssocks/socks5
import ssocks/udp
import ssocks/url
import toss
import udp_echo

const password = "a local secret"

fn session() -> key.Key {
  key.from_password(method.Aes256Gcm, password)
}

fn config_for(port: Int) -> url.Config {
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  url.new(method.Aes256Gcm, password, where)
}

/// A Shadowsocks server and a proxy pointed at it, plus what the proxy noticed.
fn stack(
  configure: fn(local.Builder) -> local.Builder,
) -> #(server.Server, local.Proxy, Subject(local.Event)) {
  let assert Ok(listening) =
    server.new(session()) |> server.bind("127.0.0.1") |> server.start(0)

  let watched = process.new_subject()

  let assert Ok(proxy) =
    local.new(config_for(server.port(listening)))
    |> local.watching(fn(event) { process.send(watched, event) })
    |> configure
    |> local.start(0)

  #(listening, proxy, watched)
}

fn plain(builder: local.Builder) -> local.Builder {
  builder
}

fn tear_down(listening: server.Server, proxy: local.Proxy) -> Nil {
  let assert Ok(Nil) = local.stop(proxy)
  let assert Ok(Nil) = server.stop(listening)
  Nil
}

fn connect(port: Int) -> mug.Socket {
  let assert Ok(socket) =
    mug.new("127.0.0.1", port: port)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()
  socket
}

/// Read until `decode` says it has a whole message, the way a client must.
fn until(
  socket: mug.Socket,
  so_far: BitArray,
  decode: fn(BitArray) -> Result(socks5.Outcome(message), socks5.Socks5Error),
) -> #(message, BitArray) {
  let assert Ok(outcome) = decode(so_far)
  case outcome {
    socks5.Complete(message, rest) -> #(message, rest)
    socks5.NeedMoreBytes(_) -> {
      let assert Ok(more) = mug.receive(socket, timeout_milliseconds: 2000)
      until(socket, <<so_far:bits, more:bits>>, decode)
    }
  }
}

/// Greet, ask for `target`, and come back with the socket ready to relay.
fn through(port: Int, target: String) -> mug.Socket {
  let socket = connect(port)
  let assert Ok(where) = address.parse(target)

  let assert Ok(_) =
    mug.send(socket, socks5.encode_greeting([socks5.NoAuthentication]))
  let #(chosen, _) = until(socket, <<>>, socks5.decode_choice)
  assert chosen == socks5.NoAuthentication

  let assert Ok(_) =
    mug.send(socket, socks5.encode_request(socks5.Connect, where))
  let #(#(outcome, _), _) = until(socket, <<>>, socks5.decode_reply)
  assert outcome == socks5.Succeeded

  socket
}

// --- the whole stack ---------------------------------------------------------------

pub fn a_socks5_client_reaches_a_target_through_shadowsocks_test() {
  let target = echo_target.start()
  let #(listening, proxy, _) = stack(plain)

  let socket = through(local.port(proxy), "127.0.0.1:" <> int.to_string(target))

  let assert Ok(_) = mug.send(socket, <<"hello":utf8>>)
  assert mug.receive(socket, timeout_milliseconds: 2000) == Ok(<<"hello":utf8>>)

  let _ = mug.shutdown(socket)
  tear_down(listening, proxy)
}

pub fn a_payload_spanning_several_chunks_survives_the_proxy_test() {
  // Over the protocol's 16383 byte chunk limit, so the framing has to split it
  // and put it back together with two more layers in the way than usual.
  let target = echo_target.start()
  let #(listening, proxy, _) = stack(plain)

  let socket = through(local.port(proxy), "127.0.0.1:" <> int.to_string(target))

  let payload = filler(40_000)
  let assert Ok(_) = mug.send(socket, payload)

  assert gather(socket, <<>>, bit_array.byte_size(payload)) == payload

  let _ = mug.shutdown(socket)
  tear_down(listening, proxy)
}

pub fn a_greeting_and_a_request_arriving_one_byte_at_a_time_still_work_test() {
  // The incremental claim, through the real listener rather than the codec:
  // a read can stop anywhere inside a SOCKS5 message.
  let target = echo_target.start()
  let #(listening, proxy, _) = stack(plain)

  let socket = connect(local.port(proxy))
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))

  dribble(socket, socks5.encode_greeting([socks5.NoAuthentication]))
  let #(chosen, _) = until(socket, <<>>, socks5.decode_choice)
  assert chosen == socks5.NoAuthentication

  dribble(socket, socks5.encode_request(socks5.Connect, where))
  let #(#(outcome, _), _) = until(socket, <<>>, socks5.decode_reply)
  assert outcome == socks5.Succeeded

  let assert Ok(_) = mug.send(socket, <<"slow":utf8>>)
  assert mug.receive(socket, timeout_milliseconds: 2000) == Ok(<<"slow":utf8>>)

  let _ = mug.shutdown(socket)
  tear_down(listening, proxy)
}

pub fn a_client_that_writes_its_request_with_its_greeting_is_served_test() {
  // Ordinary, and the case a greeting parser that dropped its remainder would
  // hang on for ever.
  let target = echo_target.start()
  let #(listening, proxy, _) = stack(plain)

  let socket = connect(local.port(proxy))
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(target))

  let assert Ok(_) =
    mug.send(socket, <<
      { socks5.encode_greeting([socks5.NoAuthentication]) }:bits,
      { socks5.encode_request(socks5.Connect, where) }:bits,
    >>)

  let #(chosen, rest) = until(socket, <<>>, socks5.decode_choice)
  assert chosen == socks5.NoAuthentication
  let #(#(outcome, _), _) = until(socket, rest, socks5.decode_reply)
  assert outcome == socks5.Succeeded

  let _ = mug.shutdown(socket)
  tear_down(listening, proxy)
}

// --- UDP ASSOCIATE --------------------------------------------------------------------

pub fn an_association_relays_datagrams_both_ways_test() {
  // The whole UDP path: a SOCKS5 client asks for an association, wraps a
  // payload in the little header RFC 1928 specifies, and this proxy unwraps it,
  // seals it for a Shadowsocks relay, and does the reverse for the reply.
  //
  // The TCP server and the UDP relay share a port number on purpose: one
  // `ss://` configuration names one address, and TCP and UDP ports are separate
  // namespaces, so that is what a real deployment looks like too.
  let answering = udp_echo.start()
  let assert Ok(listening) =
    server.new(session()) |> server.bind("127.0.0.1") |> server.start(0)
  let port = server.port(listening)
  let assert Ok(relaying) =
    udp.relay(session()) |> udp.bind("127.0.0.1") |> udp.start(port)

  let watched = process.new_subject()
  let assert Ok(proxy) =
    local.new(config_for(port))
    |> local.watching(fn(event) { process.send(watched, event) })
    |> local.start(0)

  let socket = connect(local.port(proxy))
  let assert Ok(_) =
    mug.send(socket, socks5.encode_greeting([socks5.NoAuthentication]))
  let #(_, _) = until(socket, <<>>, socks5.decode_choice)

  // `0.0.0.0:0` is what clients actually send: they are behind their own NAT
  // and do not know where they will appear from.
  let assert Ok(unknown) = address.parse("0.0.0.0:0")
  let assert Ok(_) =
    mug.send(socket, socks5.encode_request(socks5.Associate, unknown))

  let #(#(outcome, where), _) = until(socket, <<>>, socks5.decode_reply)
  assert outcome == socks5.Succeeded
  assert notable(watched, 2000) == Ok(local.Associated(where))

  let assert Ok(sending) = toss.open(toss.new(port: 0))
  let assert Ok(ip) = glip.parse_ip(address.host(where))
  let target = target_at(answering)

  let assert Ok(Nil) =
    toss.send_to(
      sending,
      ip,
      address.port(where),
      socks5.encode_datagram(target, <<"through udp":utf8>>),
    )

  let assert Ok(#(_, _, back)) =
    toss.receive(sending, max_length: 65_535, timeout_milliseconds: 5000)

  assert socks5.decode_datagram(back) == Ok(#(target, <<"through udp":utf8>>))

  toss.close(sending)
  let _ = mug.shutdown(socket)
  let assert Ok(Nil) = local.stop(proxy)
  let assert Ok(Nil) = udp.stop(relaying)
  let assert Ok(Nil) = server.stop(listening)
}

fn target_at(port: Int) -> address.Address {
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  where
}

// --- what it will not do ------------------------------------------------------------

pub fn bind_is_answered_with_command_not_supported_test() {
  // Refused with a code rather than dropped: this is a local client that asked
  // for something real, and telling it why is the point.
  let #(listening, proxy, watched) = stack(plain)

  let socket = connect(local.port(proxy))
  let assert Ok(where) = address.parse("1.2.3.4:80")

  let assert Ok(_) =
    mug.send(socket, socks5.encode_greeting([socks5.NoAuthentication]))
  let #(_, _) = until(socket, <<>>, socks5.decode_choice)

  let assert Ok(_) = mug.send(socket, socks5.encode_request(socks5.Bind, where))
  let #(#(outcome, _), _) = until(socket, <<>>, socks5.decode_reply)

  assert outcome == socks5.CommandNotSupported
  assert notable(watched, 2000)
    == Ok(local.Declined(socks5.CommandNotSupported))

  let _ = mug.shutdown(socket)
  tear_down(listening, proxy)
}

pub fn a_client_offering_no_method_we_have_is_told_so_test() {
  let #(listening, proxy, watched) = stack(plain)

  let socket = connect(local.port(proxy))
  let assert Ok(_) =
    mug.send(socket, socks5.encode_greeting([socks5.Other(0x02)]))

  let #(chosen, _) = until(socket, <<>>, socks5.decode_choice)
  assert chosen == socks5.NoneAcceptable
  assert notable(watched, 2000) == Ok(local.Declined(socks5.NotAllowed))

  let _ = mug.shutdown(socket)
  tear_down(listening, proxy)
}

pub fn bytes_that_are_not_socks5_are_closed_without_an_answer_test() {
  // Unlike `ssocks/server`, there is nothing to conceal here — a proxy on
  // loopback is not hiding from a prober. But there is also nothing useful to
  // say to a peer that is not speaking the protocol.
  let #(listening, proxy, watched) = stack(plain)

  let socket = connect(local.port(proxy))
  let assert Ok(_) = mug.send(socket, <<"GET / HTTP/1.1\r\n":utf8>>)

  let assert Ok(local.Malformed(socks5.WrongVersion(0x47))) =
    notable(watched, 2000)
  assert mug.receive(socket, timeout_milliseconds: 2000) == Error(mug.Closed)

  tear_down(listening, proxy)
}

pub fn a_server_that_is_not_there_is_reported_as_unreachable_test() {
  // Port 1 on loopback, which nothing should be listening on.
  let assert Ok(nowhere) = address.parse("127.0.0.1:1")
  let watched = process.new_subject()

  let assert Ok(proxy) =
    local.new(url.new(method.Aes256Gcm, password, nowhere))
    |> local.with_connect_timeout(500)
    |> local.watching(fn(event) { process.send(watched, event) })
    |> local.start(0)

  let socket = connect(local.port(proxy))
  let assert Ok(where) = address.parse("1.2.3.4:80")

  let assert Ok(_) =
    mug.send(socket, socks5.encode_greeting([socks5.NoAuthentication]))
  let #(_, _) = until(socket, <<>>, socks5.decode_choice)
  let assert Ok(_) =
    mug.send(socket, socks5.encode_request(socks5.Connect, where))

  let #(#(outcome, _), _) = until(socket, <<>>, socks5.decode_reply)
  assert outcome == socks5.HostUnreachable

  let _ = mug.shutdown(socket)
  let assert Ok(Nil) = local.stop(proxy)
}

pub fn a_far_end_that_is_not_shadowsocks_is_reported_test() {
  // Worth having because the neighbouring failure is silent. A server with the
  // wrong password says nothing at all — `Drain` is the point of it — so a
  // client just waits, and `Idled` is all that ever arrives. Something that
  // answers with bytes that are not a stream is the case that can be named,
  // and naming it is what keeps `Requested` followed by nothing meaningful.
  let watched = process.new_subject()
  let assert Ok(where) =
    address.parse("127.0.0.1:" <> int.to_string(noise_target()))

  let assert Ok(proxy) =
    local.new(url.new(method.Aes256Gcm, password, where))
    |> local.watching(fn(event) { process.send(watched, event) })
    |> local.start(0)

  let socket = through(local.port(proxy), "127.0.0.1:80")
  let assert Ok(_) = mug.send(socket, <<"anything":utf8>>)

  let assert Ok(local.Broke(_)) = notable(watched, 3000)
  assert mug.receive(socket, timeout_milliseconds: 2000) == Error(mug.Closed)

  let _ = mug.shutdown(socket)
  let assert Ok(Nil) = local.stop(proxy)
}

/// A target that answers with enough bytes to be read as a salt and a chunk
/// header, and not with bytes that authenticate as one.
///
/// An echo would not do: echoing a Shadowsocks stream back returns a valid
/// stream under the same key, salt and all, which the client decodes happily.
fn noise_target() -> Int {
  let name = process.new_name("ssocks_local_noise")

  let assert Ok(_) =
    glisten.new(fn(_) { #(Nil, option.None) }, fn(state, message, connection) {
      case message {
        glisten.Packet(_) -> {
          let assert Ok(_) =
            glisten.send(connection, bytes_tree.from_bit_array(<<0:size(512)>>))
          glisten.continue(state)
        }
        glisten.User(_) -> glisten.continue(state)
      }
    })
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  glisten.get_server_info(name, 1000).port
}

// --- the listener's lifetime ----------------------------------------------------------

pub fn the_port_is_free_once_stop_returns_test() {
  let #(listening, proxy, _) = stack(plain)
  let port = local.port(proxy)

  let assert Ok(Nil) = local.stop(proxy)

  let assert Ok(second) =
    local.new(config_for(server.port(listening))) |> local.start(port)

  assert local.port(second) == port
  let assert Ok(Nil) = local.stop(second)
  let assert Ok(Nil) = server.stop(listening)
}

pub fn an_interface_that_is_not_an_address_is_refused_test() {
  assert local.new(config_for(1))
    |> local.bind("127.0.0.0.1")
    |> local.start(0)
    == Error(local.BadInterface("127.0.0.0.1"))
}

pub fn the_ceiling_turns_connections_away_test() {
  let target = echo_target.start()
  let #(listening, proxy, watched) = stack(local.with_max_connections(_, 1))

  let one = through(local.port(proxy), "127.0.0.1:" <> int.to_string(target))
  assert local.connections(proxy, within: 1000) == Ok(1)

  let two = connect(local.port(proxy))
  assert notable(watched, 2000) == Ok(local.Refused)
  assert mug.receive(two, timeout_milliseconds: 2000) == Error(mug.Closed)

  let _ = mug.shutdown(one)
  tear_down(listening, proxy)
}

// --- helpers --------------------------------------------------------------------------

/// The next event of interest, skipping the ones every connection produces.
fn notable(
  watched: Subject(local.Event),
  within: Int,
) -> Result(local.Event, Nil) {
  case process.receive(watched, within) {
    Ok(local.Accepted) | Ok(local.Finished) | Ok(local.Requested(_)) ->
      notable(watched, within)
    other -> other
  }
}

/// Send one byte per write, which is the worst a real network does.
fn dribble(socket: mug.Socket, bytes: BitArray) -> Nil {
  use one <- list.each(single_bytes(bytes, []))
  let assert Ok(_) = mug.send(socket, one)
  Nil
}

fn single_bytes(bytes: BitArray, acc: List(BitArray)) -> List(BitArray) {
  case bytes {
    <<one:8, rest:bits>> -> single_bytes(rest, [<<one:8>>, ..acc])
    _ -> list.reverse(acc)
  }
}

/// Read until `wanted` bytes have arrived.
fn gather(socket: mug.Socket, so_far: BitArray, wanted: Int) -> BitArray {
  case bit_array.byte_size(so_far) >= wanted {
    True -> so_far
    False -> {
      let assert Ok(more) = mug.receive(socket, timeout_milliseconds: 5000)
      gather(socket, <<so_far:bits, more:bits>>, wanted)
    }
  }
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
