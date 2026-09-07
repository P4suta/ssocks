//// A Shadowsocks client over TCP.
////
//// One socket, one connection, and a codec on top of it. The salt, the nonce
//// counters and the chunk boundaries are not visible from out here; what a
//// caller sends is what the far end receives, in whatever pieces the network
//// decides.
////
//// ### The first write carries the header
////
//// A Shadowsocks stream opens with the target address, and this holds that
//// header back until the first `send` so that it travels with the payload. A
//// header sent on its own would work, but it puts a lone short packet at the
//// start of every connection, and a fixed-size first packet is a pattern
//// somebody watching the wire can count.
////
//// If a caller reads before writing — some protocols have the server speak
//// first — the header is flushed at that point instead, because the far end
//// cannot answer a request it has not been given.
////
//// ### Deadlines are deadlines
////
//// `receive` takes the time it may spend, not the time each read may spend.
//// One TCP read can return a fragment that completes no chunk, so a reply is
//// often several reads; if each of those got the full timeout, a peer sending
//// one byte per interval could hold a connection open indefinitely. The budget
//// is computed once and spent down.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import mug
import ssocks/address
import ssocks/internal/clock
import ssocks/stream
import ssocks/url

/// An open connection through a Shadowsocks server to one target.
pub opaque type Connection {
  Connection(
    socket: mug.Socket,
    encoder: stream.Encoder,
    decoder: stream.Decoder,
    /// The salt and the encoded target address, held until the first write.
    /// `None` once they have gone out.
    opening: Option(#(BitArray, BitArray)),
  )
}

/// Why a connection could not be made or used.
pub type ClientError {
  /// The text given as the target is not a host and a port.
  BadTarget(reason: address.AddressError)
  /// The Shadowsocks server itself could not be reached. Nothing has been sent,
  /// so nothing about the configuration has been tested yet.
  CouldNotReach(reason: mug.ConnectError)
  WriteFailed(reason: mug.Error)
  ReadFailed(reason: mug.Error)
  /// Bytes arrived and did not authenticate. On the first chunk this is almost
  /// always the password or the method; later it means the framing drifted.
  Framing(reason: stream.StreamError)
}

/// Open a connection through the configured server to `to`.
///
/// `within` bounds reaching the Shadowsocks server. It does not bound later
/// reads, which carry their own budget — a connect timeout that silently
/// governed every subsequent operation would be a surprise waiting to happen.
///
/// Nothing is written here. The server learns the target on the first `send`.
pub fn connect(
  config: url.Config,
  to target: String,
  within timeout: Int,
) -> Result(Connection, ClientError) {
  use where <- result.try(address.parse(target) |> result.map_error(BadTarget))
  connect_to(config, where, timeout)
}

/// As `connect`, for a target that has already been parsed.
pub fn connect_to(
  config: url.Config,
  target: address.Address,
  within timeout: Int,
) -> Result(Connection, ClientError) {
  let server = url.server(config)

  use socket <- result.try(
    mug.new(address.host(server), port: address.port(server))
    |> mug.timeout(milliseconds: timeout)
    |> mug.connect()
    |> result.map_error(CouldNotReach),
  )

  let session = url.key(config)
  let #(encoder, salt) = stream.encoder(session)

  Ok(Connection(
    socket:,
    encoder:,
    decoder: stream.decoder(session),
    opening: Some(#(salt, address.encode(target))),
  ))
}

/// Send bytes to the target.
///
/// Any length. Anything over the protocol's chunk limit is split, and the far
/// end puts it back together.
pub fn send(
  connection: Connection,
  payload: BitArray,
) -> Result(Connection, ClientError) {
  let #(prologue, header) = case connection.opening {
    Some(opening) -> opening
    None -> #(<<>>, <<>>)
  }

  let plaintext = bit_array.concat([header, payload])

  case bit_array.byte_size(plaintext) {
    // A zero length chunk is not a thing the protocol has, and writing one
    // would be a framing error at the far end rather than a no-op.
    0 -> Ok(connection)
    _ -> {
      let #(encoder, framed) = stream.encode(connection.encoder, plaintext)

      use _ <- result.try(
        mug.send(connection.socket, bit_array.concat([prologue, framed]))
        |> result.map_error(WriteFailed),
      )

      Ok(Connection(..connection, encoder:, opening: None))
    }
  }
}

/// Wait up to `within` milliseconds for the target to say something.
///
/// Returns as soon as at least one chunk has been decrypted, with everything
/// that completed. An empty return is not possible: either bytes arrived or
/// this is an error, so a caller cannot mistake "not yet" for "nothing more".
pub fn receive(
  connection: Connection,
  within timeout: Int,
) -> Result(#(Connection, BitArray), ClientError) {
  // A caller reading before writing still needs the far end to know what it
  // asked for.
  use connection <- result.try(case connection.opening {
    None -> Ok(connection)
    Some(_) -> send(connection, <<>>)
  })

  read_until_a_chunk_completes(connection, clock.now_ms() + timeout)
}

fn read_until_a_chunk_completes(
  connection: Connection,
  deadline: Int,
) -> Result(#(Connection, BitArray), ClientError) {
  case clock.remaining(deadline) {
    0 -> Error(ReadFailed(mug.Timeout))
    left -> {
      use arrived <- result.try(
        mug.receive(connection.socket, timeout_milliseconds: left)
        |> result.map_error(ReadFailed),
      )

      use #(decoder, chunks) <- result.try(
        stream.decode(connection.decoder, arrived)
        |> result.map_error(Framing),
      )

      let connection = Connection(..connection, decoder:)

      case chunks {
        // The read landed inside a frame. Ordinary, and not an error: keep
        // going on what is left of the budget.
        [] -> read_until_a_chunk_completes(connection, deadline)
        _ -> Ok(#(connection, bit_array.concat(chunks)))
      }
    }
  }
}

/// Close the connection. Safe to call more than once.
pub fn close(connection: Connection) -> Nil {
  let _ = mug.shutdown(connection.socket)
  Nil
}

/// How many whole chunks have been read on this connection.
///
/// Diagnostic. A connection that has read zero chunks and is failing to
/// authenticate is failing at the handshake; one that has read many and then
/// fails has drifted somewhere in the framing.
pub fn chunks_read(connection: Connection) -> Int {
  stream.chunks_read(connection.decoder)
}

/// A sentence for a person.
pub fn explain(reason: ClientError) -> String {
  case reason {
    BadTarget(reason) ->
      "the target is not a host and a port: " <> string.inspect(reason)
    CouldNotReach(reason) ->
      "the Shadowsocks server could not be reached: "
      <> string.inspect(reason)
      <> ". Nothing was sent, so this says nothing about the password."
    WriteFailed(reason) ->
      "writing to the server failed: " <> mug.describe_error(reason)
    ReadFailed(mug.Timeout) ->
      "nothing arrived before the deadline. If the target is slow, allow more "
      <> "time; if nothing ever arrives, the server may be dropping the "
      <> "connection without answering, which is what it does when it cannot "
      <> "authenticate what it was sent."
    ReadFailed(reason) ->
      "reading from the server failed: " <> mug.describe_error(reason)
    Framing(reason) ->
      "the reply did not authenticate: "
      <> string.inspect(reason)
      <> ". On chunk 0 this is the password or the method; later it means the "
      <> "framing drifted."
  }
}
