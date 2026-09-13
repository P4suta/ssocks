//// Point this library's SOCKS5 client at somebody else's SOCKS5 server.
////
//// `local_interop` covers the server half: a foreign client asking this
//// library's proxy for a target. This is the other half, and it earns its keep
//// separately. A proxy that only ever met greetings and requests this library
//// wrote would agree with itself about every byte, and a shared mistake — a
//// reserved byte in the wrong place, a length counted from the wrong offset —
//// would be just as agreed upon and just as unusable.
////
//// shadowsocks-rust's `sslocal` in its default mode is a SOCKS5 server, so it
//// is the foreign implementation this needs and it ships in the same release
//// as the `ssserver` the wire tests already use.
////
//// Usage: `gleam run -m socks5_client_interop -- <socks_port> <target_port>`
//// Exits 0 if the round trip matched, 1 if it did not.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/bit_array
import gleam/int
import gleam/io
import gleam/list
import gleam/string
import mug
import ssocks/address
import ssocks/socks5

pub fn main() -> Nil {
  case argv.load().arguments {
    [socks_port, target_port] -> {
      let assert Ok(socks_port) = int.parse(socks_port)
      let assert Ok(target_port) = int.parse(target_port)
      run(socks_port, target_port)
    }
    other -> {
      io.println(
        "socks5_client_interop: expected <socks_port> <target_port>, got "
        <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

fn run(socks_port: Int, target_port: Int) -> Nil {
  let assert Ok(target) =
    address.parse("127.0.0.1:" <> int.to_string(target_port))

  // Sizes around the Shadowsocks chunk limit, because the proxy this is
  // talking to is tunnelling them over one.
  let sizes = [1, 100, 16_383, 16_384, 40_000]

  let failures =
    list.filter_map(sizes, fn(size) {
      case attempt(socks_port, target, size) {
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

  case failures {
    [] -> {
      io.println("socks5_client_interop: this client can use a real sslocal.")
      halt(0)
    }
    _ -> halt(1)
  }
}

fn attempt(
  socks_port: Int,
  target: address.Address,
  size: Int,
) -> Result(Nil, String) {
  use socket <- try(
    mug.new("127.0.0.1", port: socks_port)
    |> mug.timeout(milliseconds: 5000)
    |> mug.connect()
    |> replace_error("could not reach the SOCKS5 port"),
  )

  let assert Ok(greeting) = socks5.encode_greeting([socks5.NoAuthentication])
  use _ <- try(
    mug.send(socket, greeting) |> replace_error("could not send the greeting"),
  )

  use #(chosen, _) <- try(read(socket, <<>>, socks5.decode_choice))
  use _ <- try(case chosen {
    socks5.NoAuthentication -> Ok(Nil)
    other -> Error("it chose " <> string.inspect(other))
  })

  use _ <- try(
    mug.send(socket, socks5.encode_request(socks5.Connect, target))
    |> replace_error("could not send the request"),
  )

  use #(#(outcome, _), rest) <- try(read(socket, <<>>, socks5.decode_reply))
  use _ <- try(case outcome {
    socks5.Succeeded -> Ok(Nil)
    other -> Error("it replied " <> string.inspect(other))
  })

  let payload = filler(size)
  use _ <- try(
    mug.send(socket, payload) |> replace_error("could not send the payload"),
  )

  use back <- try(gather(socket, rest, size))
  let _ = mug.shutdown(socket)

  case back == payload {
    True -> Ok(Nil)
    False -> Error("the echo differed at " <> int.to_string(size) <> " bytes")
  }
}

/// Read until `decode` has a whole message, the way a SOCKS5 client must: the
/// greeting's answer and the request's answer both arrive over TCP and a read
/// can stop anywhere inside one.
fn read(
  socket: mug.Socket,
  so_far: BitArray,
  decode: fn(BitArray) -> Result(socks5.Outcome(message), socks5.Socks5Error),
) -> Result(#(message, BitArray), String) {
  case decode(so_far) {
    Error(reason) -> Error(socks5.explain(reason))
    Ok(socks5.Complete(message, rest)) -> Ok(#(message, rest))
    Ok(socks5.NeedMoreBytes(_)) ->
      case mug.receive(socket, timeout_milliseconds: 5000) {
        Error(_) -> Error("nothing more arrived while reading a SOCKS5 message")
        Ok(more) -> read(socket, <<so_far:bits, more:bits>>, decode)
      }
  }
}

fn gather(
  socket: mug.Socket,
  so_far: BitArray,
  wanted: Int,
) -> Result(BitArray, String) {
  case bit_array.byte_size(so_far) >= wanted {
    True -> Ok(so_far)
    False ->
      case mug.receive(socket, timeout_milliseconds: 15_000) {
        Error(reason) ->
          Error(
            mug.describe_error(reason)
            <> " with "
            <> int.to_string(bit_array.byte_size(so_far))
            <> " of "
            <> int.to_string(wanted)
            <> " bytes back",
          )
        Ok(more) -> gather(socket, <<so_far:bits, more:bits>>, wanted)
      }
  }
}

/// A repeating pattern rather than a constant byte, so a reordering or a
/// duplicated chunk shows up as a mismatch instead of cancelling out.
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

fn try(
  result: Result(a, String),
  then: fn(a) -> Result(b, String),
) -> Result(b, String) {
  case result {
    Error(reason) -> Error(reason)
    Ok(value) -> then(value)
  }
}

fn replace_error(result: Result(a, b), reason: String) -> Result(a, String) {
  case result {
    Ok(value) -> Ok(value)
    Error(_) -> Error(reason)
  }
}

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil
