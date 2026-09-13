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
import gleam/erlang/process
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import mug
import ssocks/address
import ssocks/internal/clock
import ssocks/stream
import ssocks/url

/// An open connection through a Shadowsocks server to one target.
///
/// Advance it by using what `send` and `receive` hand back. A `Connection` is a
/// value, and encrypting twice from the same one repeats a nonce under the same
/// subkey — which is the catastrophic failure for AEAD, not a degradation.
/// Nothing here can stop that, because nothing can stop a value being used
/// twice; what the design does buy is that it takes deliberately holding on to
/// a superseded value rather than one wrong argument.
///
/// The same goes for the error path: a `send` that fails hands back an error
/// and not a connection, so the one the caller still holds has a counter that
/// has not moved. Retrying with it is correct. Retrying with it *and* keeping
/// the old one is not.
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
///
/// A far end that closes cleanly arrives as `ReadFailed(mug.Closed)`, which is
/// the end of the stream rather than a fault. The message-driven side says so
/// properly — `handle_message` answers `Ended` — and this one cannot without
/// changing what it returns.
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

// --- driving it from an event loop ------------------------------------------------

/// What a message from the connection turned out to be.
pub type Arrival {
  /// Plaintext that became complete. Possibly none of it: a read that lands
  /// inside a frame is the ordinary case, not an error.
  Chunks(chunks: List(BitArray))
  /// The far end closed cleanly. Nothing more is coming.
  Ended
}

/// Ask for the next packet to arrive as a message rather than a return value.
///
/// One message per call, which is what makes this usable for flow control: a
/// caller that has not finished with the last packet simply does not ask for
/// the next one.
///
/// Do not mix this with `receive` on the same connection. `receive` reads the
/// socket directly; once packets are being delivered as messages they are in a
/// mailbox instead, and a direct read would sit there waiting for bytes that
/// have already arrived somewhere else.
pub fn receive_next_message(connection: Connection) -> Nil {
  mug.receive_next_packet_as_message(connection.socket)
}

/// Add this kind of message to a selector.
///
/// The mapping function is what keeps a relay honest: `mug` and `glisten` both
/// select the raw `{tcp, Socket, Data}` record and neither says which socket it
/// came from, so a process holding two of them cannot tell them apart. One
/// socket per process, and this is how its messages get into that process's
/// selector alongside everything else it listens to.
pub fn select_messages(
  selector: process.Selector(message),
  mapper: fn(mug.TcpMessage) -> message,
) -> process.Selector(message) {
  mug.select_tcp_messages(selector, mapper)
}

/// Decode a message that arrived for this connection.
///
/// The nonce advances only for frames that authenticated, so a connection
/// handed back here is positioned exactly where the last complete chunk left
/// off — feeding it the next message continues the stream.
pub fn handle_message(
  connection: Connection,
  message: mug.TcpMessage,
) -> Result(#(Connection, Arrival), ClientError) {
  case message {
    mug.SocketClosed(_) -> Ok(#(connection, Ended))
    mug.TcpError(_, reason) -> Error(ReadFailed(reason))

    mug.Packet(_, bytes) ->
      case stream.decode(connection.decoder, bytes) {
        Error(reason) -> Error(Framing(reason))
        Ok(#(decoder, chunks)) ->
          Ok(#(Connection(..connection, decoder:), Chunks(chunks)))
      }
  }
}

/// How many bytes the decoder is holding for a frame that has not finished.
///
/// Diagnostic, and the other half of `chunks_read`: a connection that has read
/// no chunks and is holding bytes is mid-handshake rather than stuck.
pub fn buffered(connection: Connection) -> Int {
  stream.buffered(connection.decoder)
}

/// Close the connection, in both directions. Safe to call more than once.
///
/// There is no half-close. A caller that wants to signal "I have finished
/// sending" while still reading — which some target protocols wait for — cannot
/// say it here, because `mug.shutdown` takes no direction and this library does
/// not reach past it to the socket. `ssocks/server` inherits the same limit:
/// when either end goes, the whole relay goes.
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
