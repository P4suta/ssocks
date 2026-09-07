//// Stand up this library's UDP relay for a real client to talk to.
////
//// The TCP interop tests cover both directions of the stream framing. The UDP
//// packet format is different code with a different shape — one AEAD box under
//// an all-zero nonce, no counter, no framing — and its tests so far compare
//// this library with itself, which cannot tell a correct packet from one that
//// is consistently wrong in both directions.
////
//// So here the relay listens and `scripts/udp-interop.mjs` puts
//// `sslocal --protocol tunnel -u` in front of it, with a plain UDP echo behind.
//// The echo lives in the script rather than here: Erlang buffers stdout when it
//// is a pipe, so a port chosen over here could not be read from over there
//// until the process exited.
////
//// Usage: `gleam run -m udp_interop -- <relay_port> <method> <password>`
//// The process stays alive until it is killed.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/string
import ssocks/key
import ssocks/method
import ssocks/udp

pub fn main() -> Nil {
  case argv.load().arguments {
    [relay_port, method_name, password] -> {
      let assert Ok(relay_port) = int.parse(relay_port)
      let assert Ok(chosen) = method.from_string(method_name)
      run(relay_port, chosen, password)
    }
    other -> {
      io.println(
        "udp_interop: expected <relay_port> <method> <password>, got "
        <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

fn run(relay_port: Int, chosen: method.Method, password: String) -> Nil {
  let assert Ok(relaying) =
    udp.relay(key.from_password(chosen, password))
    |> udp.bind("127.0.0.1")
    |> udp.watching(fn(event) { io.println("event " <> describe(event)) })
    |> udp.start(relay_port)

  io.println("udp_interop: relaying on " <> int.to_string(udp.port(relaying)))
  process.sleep_forever()
}

fn describe(event: udp.Event) -> String {
  case event {
    udp.Forwarded(target, bytes) ->
      "forwarded " <> int.to_string(bytes) <> " to " <> string.inspect(target)
    udp.Returned(from, bytes) ->
      "returned " <> int.to_string(bytes) <> " from " <> string.inspect(from)
    udp.Rejected(reason) -> "rejected " <> string.inspect(reason)
    udp.SessionOpened(count) -> "opened, now " <> int.to_string(count)
    udp.SessionExpired(count) -> "expired, now " <> int.to_string(count)
    udp.SessionEvicted(count) -> "evicted, now " <> int.to_string(count)
  }
}

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil
