//// A Shadowsocks server that echoes instead of relaying.
////
//// The client tests need something on the other end that speaks the protocol.
//// Relaying to a real target is the server's job and is tested where the
//// server is; what a client test needs is a peer that reads a salt, reads the
//// target address header, and sends the rest back through the same framing.
////
//// So this is the server side of the codec with no sockets to anywhere else:
//// forty lines, no second process, and no NAT table. It also happens to be the
//// first thing in this repository that reads a target address header off a
//// wire rather than out of a test vector.
////
//// It is not a substitute for the interoperability tests. Both ends here were
//// written from the same understanding of the protocol; only shadowsocks-rust
//// can say whether that understanding is right.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/option.{type Option, None, Some}
import glisten
import ssocks/address
import ssocks/key
import ssocks/stream

pub type Observed {
  Target(address.Address)
  DecodeFailed(stream.StreamError)
}

type State {
  State(
    session: key.Key,
    decoder: stream.Decoder,
    encoder: Option(stream.Encoder),
    target: Option(address.Address),
    observed: Subject(Observed),
  )
}

/// Start on an ephemeral port. Returns the port and a subject that reports the
/// target address of each connection, so a test can check that the header the
/// client sent says what it should.
pub fn start(session: key.Key) -> #(Int, Subject(Observed)) {
  let name = process.new_name("ssocks_echo")
  let observed = process.new_subject()

  let assert Ok(_) =
    glisten.new(
      fn(_) {
        #(State(session, stream.decoder(session), None, None, observed), None)
      },
      loop,
    )
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  #(glisten.get_server_info(name, 1000).port, observed)
}

/// A server that authenticates nothing and answers with noise, for testing what
/// a client does when the other end is not what it claims to be.
pub fn start_garbage() -> Int {
  let name = process.new_name("ssocks_garbage")

  let assert Ok(_) =
    glisten.new(fn(_) { #(Nil, None) }, fn(state, message, connection) {
      case message {
        glisten.Packet(_) -> {
          let assert Ok(_) =
            glisten.send(
              connection,
              bytes_tree.from_bit_array(noise(300, <<>>)),
            )
          glisten.continue(state)
        }
        glisten.User(_) -> glisten.continue(state)
      }
    })
    |> glisten.with_listener_name(name)
    |> glisten.start(0)

  glisten.get_server_info(name, 1000).port
}

fn noise(count: Int, acc: BitArray) -> BitArray {
  case count {
    0 -> acc
    _ -> {
      let byte = count * 37 % 256
      noise(count - 1, bit_array.append(acc, <<byte:8>>))
    }
  }
}

fn loop(
  state: State,
  message: glisten.Message(Nil),
  connection: glisten.Connection(Nil),
) -> glisten.Next(State, glisten.Message(Nil)) {
  case message {
    glisten.User(_) -> glisten.continue(state)
    glisten.Packet(bytes) ->
      case stream.decode(state.decoder, bytes) {
        Error(reason) -> {
          process.send(state.observed, DecodeFailed(reason))
          glisten.stop()
        }
        Ok(#(decoder, chunks)) -> {
          let state = State(..state, decoder:)
          let plaintext = bit_array.concat(chunks)
          case take_target(state, plaintext) {
            Error(_) -> glisten.stop()
            Ok(#(state, payload)) -> {
              case bit_array.byte_size(payload) {
                0 -> glisten.continue(state)
                _ -> reply(state, connection, payload)
              }
            }
          }
        }
      }
  }
}

/// The first plaintext bytes of a Shadowsocks stream are the target address.
/// Everything after them, in that same chunk, is payload.
fn take_target(
  state: State,
  plaintext: BitArray,
) -> Result(#(State, BitArray), Nil) {
  case state.target {
    Some(_) -> Ok(#(state, plaintext))
    None ->
      case address.decode(plaintext) {
        Ok(address.Complete(target, rest)) -> {
          process.send(state.observed, Target(target))
          Ok(#(State(..state, target: Some(target)), rest))
        }
        // A header split across reads would need buffering. The tests never
        // produce one, and a real server does buffer; see `server.gleam`.
        _ -> Error(Nil)
      }
  }
}

fn reply(
  state: State,
  connection: glisten.Connection(Nil),
  payload: BitArray,
) -> glisten.Next(State, glisten.Message(Nil)) {
  let #(encoder, prologue) = case state.encoder {
    Some(encoder) -> #(encoder, <<>>)
    None -> {
      // The reply direction has its own salt and its own counter.
      let #(encoder, salt) = stream.encoder(state.session)
      #(encoder, salt)
    }
  }

  let #(encoder, framed) = stream.encode(encoder, payload)
  let assert Ok(_) =
    glisten.send(
      connection,
      bytes_tree.from_bit_array(bit_array.concat([prologue, framed])),
    )

  glisten.continue(State(..state, encoder: Some(encoder)))
}

/// Wait for the next thing the server noticed, for a test to assert on.
pub fn next(observed: Subject(Observed), within: Int) -> Result(Observed, Nil) {
  process.receive(observed, within)
}

/// Drain anything already reported, so one test does not see another's.
pub fn drain(observed: Subject(Observed)) -> Nil {
  case process.receive(observed, 0) {
    Ok(_) -> drain(observed)
    Error(_) -> Nil
  }
}
