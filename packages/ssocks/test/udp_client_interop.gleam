//// Send Shadowsocks UDP packets to somebody else's relay.
////
//// `udp_interop` covers the reading direction: a real `sslocal` writes packets
//// and this library's relay reads them. This is the writing direction, and it
//// is the half that had no foreign check at all — until this file, every
//// packet this library produced had only ever been read by the reader in the
//// same repository. A reversed field or a salt in the wrong place would be
//// written and read back the same way and pass everything, while nothing else
//// in the world could open one.
////
//// Usage:
//// `gleam run -m udp_client_interop -- <server_port> <echo_port> <method> <password>`
//// Exits 0 if every round trip matched.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/int
import gleam/io
import gleam/list
import ssocks/address
import ssocks/key
import ssocks/method
import ssocks/udp_client

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
        "udp_client_interop: expected <server_port> <echo_port> <method> "
        <> "<password>, got "
        <> int.to_string(list.length(other))
        <> " arguments. They are not quoted here: a usage error is "
        <> "exactly when the arguments are in the wrong places, and one of "
        <> "them is a password.",
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
  let assert Ok(relay) =
    address.parse("127.0.0.1:" <> int.to_string(server_port))
  let assert Ok(target) =
    address.parse("127.0.0.1:" <> int.to_string(echo_port))

  let assert Ok(sending) =
    udp_client.open(key.from_password(chosen, password), through: relay)

  // One datagram each, so the sizes stay under the usual path MTU and under
  // the relay's own read buffer. The protocol has no fragmentation.
  let sizes = [1, 100, 1200]

  let failures =
    list.filter_map(sizes, fn(size) {
      case attempt(sending, target, size) {
        Ok(Nil) -> {
          io.println("  ok   " <> int.to_string(size) <> " bytes")
          Error(Nil)
        }
        Error(reason) -> {
          io.println("  FAIL " <> int.to_string(size) <> " bytes: " <> reason)
          Ok(reason)
        }
      }
    })

  udp_client.close(sending)

  case failures {
    [] -> {
      io.println("udp_client_interop: a real relay can read these packets.")
      halt(0)
    }
    _ -> halt(1)
  }
}

fn attempt(
  sending: udp_client.Client,
  target: address.Address,
  size: Int,
) -> Result(Nil, String) {
  let payload = filler(size)

  case udp_client.send(sending, payload, to: target) {
    Error(reason) -> Error(udp_client.explain(reason))
    Ok(Nil) ->
      // Generous, because a datagram that is lost is simply lost and the only
      // way that shows here is as a timeout.
      case udp_client.receive(sending, within: 10_000) {
        Error(reason) -> Error(udp_client.explain(reason))
        Ok(#(from, back)) ->
          case back == payload, from == target {
            True, True -> Ok(Nil)
            False, _ ->
              Error("the echo differed at " <> int.to_string(size) <> " bytes")
            _, False ->
              Error(
                "the reply says it came from "
                <> address.to_string(from)
                <> " rather than "
                <> address.to_string(target),
              )
          }
      }
  }
}

/// A repeating pattern rather than a constant byte, so a duplicated or
/// reordered datagram shows up as a mismatch instead of cancelling out.
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

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil
