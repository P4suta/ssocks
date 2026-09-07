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
import mug
import ssocks/address
import ssocks/key
import ssocks/method
import ssocks/stream

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
  let session_key = key.from_password(chosen, password)
  let assert Ok(target) =
    address.parse("127.0.0.1:" <> int.to_string(echo_port))

  // Sizes chosen around the 16383 byte chunk limit. Anything above it must be
  // split by this encoder and reassembled by the other implementation, which is
  // the part of the framing an isolated round trip cannot check.
  let sizes = [1, 100, 16_382, 16_383, 16_384, 40_000]

  let failures =
    list.filter_map(sizes, fn(size) {
      case exchange(session_key, target, server_port, payload_of(size)) {
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
  session_key: key.Key,
  target: address.Address,
  server_port: Int,
  payload: BitArray,
) -> Result(Nil, String) {
  use socket <- result.try(
    mug.new("127.0.0.1", port: server_port)
    |> mug.timeout(milliseconds: 5000)
    |> mug.connect()
    |> result.map_error(fn(reason) {
      "could not reach the server: " <> string.inspect(reason)
    }),
  )

  // A Shadowsocks stream opens with the salt, then the target address followed
  // immediately by the payload, all inside the framing.
  let #(encoder, salt) = stream.encoder(session_key)
  let #(_, framed) =
    stream.encode(encoder, bit_array.concat([address.encode(target), payload]))

  use _ <- result.try(
    mug.send(socket, bit_array.concat([salt, framed]))
    |> result.map_error(fn(reason) { "send failed: " <> string.inspect(reason) }),
  )

  use echoed <- result.try(collect(
    socket,
    stream.decoder(session_key),
    <<>>,
    bit_array.byte_size(payload),
  ))

  let _ = mug.shutdown(socket)

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

/// Read and decode until the expected number of plaintext bytes has arrived.
fn collect(
  socket: mug.Socket,
  decoder: stream.Decoder,
  so_far: BitArray,
  wanted: Int,
) -> Result(BitArray, String) {
  case bit_array.byte_size(so_far) >= wanted {
    True -> Ok(so_far)
    False -> {
      use received <- result.try(
        mug.receive(socket, timeout_milliseconds: 5000)
        |> result.map_error(fn(reason) {
          "receive failed after "
          <> int.to_string(bit_array.byte_size(so_far))
          <> " of "
          <> int.to_string(wanted)
          <> " bytes: "
          <> string.inspect(reason)
        }),
      )

      use #(decoder, chunks) <- result.try(
        stream.decode(decoder, received)
        |> result.map_error(describe),
      )

      collect(
        socket,
        decoder,
        bit_array.concat([so_far, bit_array.concat(chunks)]),
        wanted,
      )
    }
  }
}

/// Turn a framing failure into the sentence that actually helps.
fn describe(failure: stream.StreamError) -> String {
  case failure {
    stream.AuthenticationFailed(stage:, chunk:, nonce:, buffered:) ->
      "the reply did not authenticate at "
      <> string.inspect(stage)
      <> ", chunk "
      <> int.to_string(chunk)
      <> ", nonce "
      <> string.inspect(nonce)
      <> ", "
      <> int.to_string(buffered)
      <> " bytes buffered. A failure on chunk 0 in the length header usually "
      <> "means the key or the salt handling disagrees; one further in means "
      <> "the framing drifted."
    other -> string.inspect(other)
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
