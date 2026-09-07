//// Stand up this library's server for a real client to talk to.
////
//// `interop_smoke` puts shadowsocks-rust on the far side of this library's
//// client. That validates the writing direction and the reading direction of
//// the codec, but it never asks the harder question about the server: can it
//// read a target address header that somebody else wrote, arriving at chunk
//// boundaries it did not choose?
////
//// Passing in the client direction makes it easy to assume both are covered.
//// They are not: the client always writes the header the same way, and the
//// server has, until this file, only ever read headers this library produced.
////
//// So here the server listens and `scripts/server-interop.mjs` puts
//// `sslocal --protocol tunnel` in front of it, with a plain TCP echo behind.
//// The echo lives in the script rather than here: Erlang buffers stdout when it
//// is a pipe, so anything this process prints is unreadable until it exits, and
//// a port the script chose needs no reading.
////
//// Usage: `gleam run -m server_interop -- <server_port> <method> <password>`
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
import ssocks/server

pub fn main() -> Nil {
  case argv.load().arguments {
    [server_port, method_name, password] -> {
      let assert Ok(server_port) = int.parse(server_port)
      let assert Ok(chosen) = method.from_string(method_name)
      run(server_port, chosen, password)
    }
    other -> {
      io.println(
        "server_interop: expected <server_port> <method> <password>, got "
        <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

fn run(server_port: Int, chosen: method.Method, password: String) -> Nil {
  let assert Ok(listening) =
    server.new(key.from_password(chosen, password))
    |> server.bind("127.0.0.1")
    |> server.watching(fn(event) { io.println("event " <> describe(event)) })
    |> server.start(server_port)

  io.println(
    "server_interop: listening on " <> int.to_string(server.port(listening)),
  )

  // Nothing else to do; the listener runs in its own supervision tree.
  process.sleep_forever()
}

fn describe(event: server.Event) -> String {
  case event {
    server.Accepted -> "accepted"
    server.Handshook(target) -> "handshook " <> string.inspect(target)
    server.Probed(probe) -> "probed " <> string.inspect(probe)
    server.TargetUnreachable(_) -> "unreachable"
    server.Finished -> "finished"
  }
}

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil
