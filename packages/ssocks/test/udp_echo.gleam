//// A UDP echo, standing in for whatever a client actually wants to reach.
////
//// Answers every datagram with the same bytes, from the same port it was sent
//// to, so that anything different about what comes back through the relay is
//// the relay's doing.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process
import toss

/// Start on an ephemeral port and return it.
pub fn start() -> Int {
  let ready = process.new_subject()

  process.spawn(fn() {
    let assert Ok(socket) = toss.open(toss.new(port: 0))
    let assert Ok(port) = toss.local_port(socket)
    process.send(ready, port)
    loop(socket)
  })

  let assert Ok(port) = process.receive(ready, 2000)
  port
}

fn loop(socket: toss.Socket) -> Nil {
  case toss.receive_forever(socket, max_length: 65_535) {
    Error(_) -> Nil
    Ok(#(Error(_), _, _)) -> loop(socket)
    Ok(#(Ok(host), port, data)) -> {
      let _ = toss.send_to(socket, host, port, data)
      loop(socket)
    }
  }
}
