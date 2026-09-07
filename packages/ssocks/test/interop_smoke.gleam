//// Talk to a real Shadowsocks server.
////
//// Every other test in this repository compares this implementation against
//// itself. That cannot distinguish "my decoder agrees with my encoder" from
//// "this is Shadowsocks": a reversed nonce or a flipped length byte order would
//// be applied consistently in both directions and pass everything.
////
//// This one puts shadowsocks-rust on the other end. The bytes leave here, are
//// decrypted by an implementation that had no part in writing them, are relayed
//// to an echo server, come back encrypted by that same implementation, and are
//// decrypted here. Nothing about that round trip can succeed by shared
//// misunderstanding.
////
//// It goes through `ssocks/client` rather than through the codec directly, so
//// the thing being checked against a real server is the thing a caller
//// actually uses — including the decision to hold the target address header
//// back until the first payload, which only a foreign server can confirm is
//// read the way this expects.
////
//// Driven by `scripts/interop.mjs`, which starts the echo server and the
//// Shadowsocks server and passes their ports in. Run it with `mise run interop`.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/bit_array
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import ssocks
import ssocks/address
import ssocks/client
import ssocks/method
import ssocks/url

pub fn main() -> Nil {
  case argv.load().arguments {
    [server_port, echo_port, method_name, password] -> {
      let assert Ok(server_port) = int.parse(server_port)
      let assert Ok(echo_port) = int.parse(echo_port)
      let assert Ok(chosen) = method.from_string(method_name)
      run(server_port, echo_port, chosen, password)
    }
    other -> {
      io.println(
        "interop_smoke: expected <server_port> <echo_port> <method> <password>, got "
        <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

fn run(
  server_port: Int,
  echo_port: Int,
  chosen: method.Method,
  password: String,
) -> Nil {
  let assert Ok(server) =
    address.parse("127.0.0.1:" <> int.to_string(server_port))
  let config = url.new(chosen, password, server)
  let target = "127.0.0.1:" <> int.to_string(echo_port)

  // Sizes chosen around the 16383 byte chunk limit. Anything above it must be
  // split by this encoder and reassembled by the other implementation, which is
  // the part of the framing an isolated round trip cannot check.
  let sizes = [1, 100, 16_382, 16_383, 16_384, 40_000]

  let failures =
    list.filter_map(sizes, fn(size) {
      case exchange(config, target, payload_of(size)) {
        Ok(_) -> {
          io.println(
            "  ok   "
            <> method.to_string(chosen)
            <> "  "
            <> int.to_string(size)
            <> " bytes",
          )
          Error(Nil)
        }
        Error(reason) -> {
          io.println(
            "  FAIL "
            <> method.to_string(chosen)
            <> "  "
            <> int.to_string(size)
            <> " bytes: "
            <> reason,
          )
          Ok(reason)
        }
      }
    })

  case failures {
    [] -> Nil
    _ -> halt(1)
  }
}

/// One request through the Shadowsocks server and back.
fn exchange(
  config: url.Config,
  target: String,
  payload: BitArray,
) -> Result(Nil, String) {
  use connection <- with_connection(config, target)

  use connection <- result.try(
    ssocks.send(connection, payload) |> result.map_error(client.explain),
  )

  use echoed <- result.try(collect(
    connection,
    <<>>,
    bit_array.byte_size(payload),
  ))

  case echoed == payload {
    True -> Ok(Nil)
    False ->
      Error(
        "the echo differed: sent "
        <> int.to_string(bit_array.byte_size(payload))
        <> " bytes, got back "
        <> int.to_string(bit_array.byte_size(echoed)),
      )
  }
}

/// `ssocks.with_connection` reports a failed connect in the outer `Result` and
/// whatever the body produced in the inner one. Both are failures here, so they
/// are flattened into one.
fn with_connection(
  config: url.Config,
  target: String,
  run: fn(client.Connection) -> Result(Nil, String),
) -> Result(Nil, String) {
  ssocks.with_connection(config, target, 5000, run)
  |> result.map_error(client.explain)
  |> result.flatten
}

/// Read until the expected number of plaintext bytes has arrived.
fn collect(
  connection: client.Connection,
  so_far: BitArray,
  wanted: Int,
) -> Result(BitArray, String) {
  case bit_array.byte_size(so_far) >= wanted {
    True -> Ok(so_far)
    False ->
      case ssocks.receive(connection, within: 5000) {
        Error(reason) ->
          Error(
            client.explain(reason)
            <> " (after "
            <> int.to_string(bit_array.byte_size(so_far))
            <> " of "
            <> int.to_string(wanted)
            <> " bytes, "
            <> int.to_string(client.chunks_read(connection))
            <> " chunks read)",
          )
        Ok(#(connection, more)) ->
          collect(connection, bit_array.append(so_far, more), wanted)
      }
  }
}

fn payload_of(size: Int) -> BitArray {
  // A repeating pattern rather than a constant byte, so a reordering or a
  // duplicated chunk shows up as a mismatch instead of cancelling out.
  <<0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x5a, 0xa5>>
  |> list.repeat(size / 8 + 1)
  |> bit_array.concat
  |> bit_array.slice(0, size)
  |> unwrap_bytes
}

fn unwrap_bytes(sliced: Result(BitArray, Nil)) -> BitArray {
  let assert Ok(bytes) = sliced
  bytes
}

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil
