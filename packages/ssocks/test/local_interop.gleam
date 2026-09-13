//// Stand up this library's SOCKS5 proxy for a real Shadowsocks server to sit
//// behind.
////
//// `scripts/socks5-interop.mjs` drives it with a SOCKS5 client written in the
//// script, points it at a real `ssserver`, and puts a plain TCP echo behind
//// that. What the round trip proves is that the SOCKS5 half and the
//// Shadowsocks half fit together with a foreign implementation in the middle.
////
//// Usage:
//// `gleam run -m local_interop -- <listen> <server_port> <method> <password>`
//// The process stays alive until it is killed.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/string
import ssocks/address
import ssocks/client
import ssocks/local
import ssocks/method
import ssocks/url

pub fn main() -> Nil {
  case argv.load().arguments {
    [listen, server_port, method_name, password] -> {
      let assert Ok(listen) = int.parse(listen)
      let assert Ok(server_port) = int.parse(server_port)
      let assert Ok(chosen) = method.from_string(method_name)
      run(listen, server_port, chosen, password)
    }
    other -> {
      io.println(
        "local_interop: expected <listen> <server_port> <method> <password>, "
        <> "got "
        <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

fn run(
  listen: Int,
  server_port: Int,
  chosen: method.Method,
  password: String,
) -> Nil {
  let assert Ok(where) =
    address.parse("127.0.0.1:" <> int.to_string(server_port))

  let assert Ok(proxy) =
    local.new(url.new(chosen, password, where))
    |> local.bind("127.0.0.1")
    |> local.watching(fn(event) { io.println("event " <> describe(event)) })
    |> local.start(listen)

  io.println("local_interop: listening on " <> int.to_string(local.port(proxy)))

  process.sleep_forever()
}

fn describe(event: local.Event) -> String {
  case event {
    local.Accepted -> "accepted"
    local.Requested(target) -> "requested " <> address.to_string(target)
    local.Associated(where) -> "associated " <> address.to_string(where)
    local.NotAssociated(reason) -> "not associated " <> string.inspect(reason)
    local.Dropped(reason) -> "dropped " <> string.inspect(reason)
    local.Declined(reply) -> "declined " <> string.inspect(reply)
    local.Malformed(reason) -> "malformed " <> string.inspect(reason)
    local.ServerUnreachable(_) -> "server unreachable"
    local.Broke(reason) -> "broke " <> client.explain(reason)
    local.Refused -> "refused"
    local.Idled -> "idled"
    local.Finished -> "finished"
  }
}

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil
