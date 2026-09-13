//// The UDP client, against this library's own relay.
////
//// What these can say is limited in exactly the way the wire interoperability
//// tests exist to point out: a writer checked only against its own reader
//// agrees with itself. `scripts/udp-client-interop.mjs` is what puts a real
//// `ssserver` on the other end. These cover the parts that are this module's
//// own — the socket, the reply's source address, and what happens when
//// something arrives that is not a packet.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/int
import gleam/list
import gleam/string
import glip
import ssocks/address
import ssocks/datagram
import ssocks/key
import ssocks/method
import ssocks/udp
import ssocks/udp_client
import toss
import udp_echo

const password = "a udp client secret"

fn session() -> key.Key {
  key.from_password(method.Aes256Gcm, password)
}

fn target_at(port: Int) -> address.Address {
  let assert Ok(where) = address.parse("127.0.0.1:" <> int.to_string(port))
  where
}

/// A relay on an ephemeral port, and a client pointed at it.
fn pair() -> #(udp.Relay, udp_client.Client) {
  let assert Ok(relaying) =
    udp.relay(session()) |> udp.bind("127.0.0.1") |> udp.start(0)

  let assert Ok(sending) =
    udp_client.open(session(), through: target_at(udp.port(relaying)))

  #(relaying, sending)
}

pub fn a_payload_goes_out_and_comes_back_test() {
  let answering = udp_echo.start()
  let #(relaying, sending) = pair()

  let assert Ok(Nil) =
    udp_client.send(sending, <<"hello":utf8>>, to: target_at(answering))

  assert udp_client.receive(sending, within: 2000)
    == Ok(#(target_at(answering), <<"hello":utf8>>))

  udp_client.close(sending)
  let assert Ok(Nil) = udp.stop(relaying)
}

pub fn every_packet_draws_a_new_salt_test() {
  // Repeating one repeats the subkey, and a repeated subkey under this
  // protocol's fixed nonce is a total break rather than a degradation. There
  // is no way to ask for anything else, so this asserts the bytes differ.
  let answering = udp_echo.start()
  let #(relaying, sending) = pair()

  let assert Ok(Nil) =
    udp_client.send(sending, <<"same":utf8>>, to: target_at(answering))
  let assert Ok(_) = udp_client.receive(sending, within: 2000)

  let assert Ok(Nil) =
    udp_client.send(sending, <<"same":utf8>>, to: target_at(answering))
  let assert Ok(_) = udp_client.receive(sending, within: 2000)

  // Two identical payloads went out; the relay took both, which a replayed
  // salt would not have been. (The relay here has a guard of its own.)
  assert udp.sessions(relaying, within: 1000) == Ok(1)

  udp_client.close(sending)
  let assert Ok(Nil) = udp.stop(relaying)
}

pub fn a_reply_says_which_address_answered_test() {
  // Not always the address that was asked for: a resolver behind a load
  // balancer answers from one of its own, and a caller talking to more than
  // one target needs to know which.
  let first = udp_echo.start()
  let second = udp_echo.start()
  let #(relaying, sending) = pair()

  let assert Ok(Nil) =
    udp_client.send(sending, <<"one":utf8>>, to: target_at(first))
  let assert Ok(#(from, _)) = udp_client.receive(sending, within: 2000)
  assert from == target_at(first)

  let assert Ok(Nil) =
    udp_client.send(sending, <<"two":utf8>>, to: target_at(second))
  let assert Ok(#(from, _)) = udp_client.receive(sending, within: 2000)
  assert from == target_at(second)

  udp_client.close(sending)
  let assert Ok(Nil) = udp.stop(relaying)
}

pub fn an_empty_payload_round_trips_test() {
  let answering = udp_echo.start()
  let #(relaying, sending) = pair()

  let assert Ok(Nil) = udp_client.send(sending, <<>>, to: target_at(answering))

  assert udp_client.receive(sending, within: 2000)
    == Ok(#(target_at(answering), <<>>))

  udp_client.close(sending)
  let assert Ok(Nil) = udp.stop(relaying)
}

pub fn a_large_payload_round_trips_test() {
  // Under the usual path MTU, since a datagram that does not fit is not this
  // module's problem to solve — it has no fragmentation and says so.
  let answering = udp_echo.start()
  let #(relaying, sending) = pair()
  let payload = filler(1200)

  let assert Ok(Nil) =
    udp_client.send(sending, payload, to: target_at(answering))

  assert udp_client.receive(sending, within: 2000)
    == Ok(#(target_at(answering), payload))

  udp_client.close(sending)
  let assert Ok(Nil) = udp.stop(relaying)
}

pub fn something_that_is_not_a_packet_is_refused_rather_than_returned_test() {
  // UDP sockets hear from anybody. What arrives is not necessarily from the
  // relay, and nothing that does not authenticate may reach the caller as
  // though it did.
  let #(relaying, sending) = pair()
  let assert Ok(port) = udp_client.port(sending)

  let assert Ok(stranger) = toss.open(toss.new(port: 0))
  let assert Ok(loopback) = glip.parse_ip("127.0.0.1")
  let assert Ok(Nil) = toss.send_to(stranger, loopback, port, <<"noise":utf8>>)

  let assert Error(udp_client.NotAuthentic(_)) =
    udp_client.receive(sending, within: 2000)

  toss.close(stranger)
  udp_client.close(sending)
  let assert Ok(Nil) = udp.stop(relaying)
}

pub fn a_reply_that_never_comes_is_a_timeout_rather_than_a_wait_test() {
  // UDP has no acknowledgement. A lost packet is lost and nothing will say so,
  // which is why every read here takes a budget.
  let #(relaying, sending) = pair()

  let assert Error(udp_client.ReceiveFailed(_)) =
    udp_client.receive(sending, within: 200)

  udp_client.close(sending)
  let assert Ok(Nil) = udp.stop(relaying)
}

pub fn every_refusal_has_a_sentence_of_its_own_test() {
  use reason <- list.each([
    udp_client.CouldNotOpen(toss.Eaddrinuse),
    udp_client.SendFailed(toss.Ehostunreach),
    udp_client.ReceiveFailed(toss.Timeout),
    udp_client.NotAuthentic(datagram.AuthenticationFailed),
  ])

  let sentence = udp_client.explain(reason)
  assert sentence != ""
  assert sentence != string.inspect(reason)
  assert string.contains(sentence, " ")
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
