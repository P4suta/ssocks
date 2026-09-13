//// The client side of the Shadowsocks UDP relay.
////
//// ```gleam
//// let assert Ok(sending) = udp_client.open(session, through: relay)
//// let assert Ok(Nil) = udp_client.send(sending, payload, to: target)
//// let assert Ok(#(from, reply)) = udp_client.receive(sending, within: 2000)
//// ```
////
//// `ssocks/udp` is the other half — the relay a client sends these to.
//// Splitting them apart is not symmetry for its own sake: until this module
//// existed, the packets this library *writes* had only ever been read by the
//// reader in this same repository, which is exactly the blind spot the wire
//// interoperability tests exist to close. `scripts/udp-client-interop.mjs`
//// puts a real `ssserver` on the other end of this one.
////
//// ### Every packet stands alone
////
//// There is no session and no ordering here, because the protocol has neither.
//// Each `send` draws a fresh salt, derives a subkey that will never be used
//// again, and seals the target address and the payload under an all-zero
//// nonce; `ssocks/datagram` explains why a fixed nonce is safe when the salt
//// is not. What that means for a caller is that a lost packet is lost, a
//// duplicated one arrives twice, and nothing here will tell you which.
////
//// ### The reply says where it came from
////
//// A relay seals each reply with the address it actually came from, which is
//// not always the address you sent to — a DNS server behind a load balancer
//// will answer from one of its own. `receive` hands that address back rather
//// than discarding it, because for anything but a single fixed target the
//// caller needs it to make sense of the payload.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process
import ssocks/address.{type Address}
import ssocks/datagram
import ssocks/key.{type Key}
import toss

/// An open socket for talking to one relay under one key.
pub opaque type Client {
  Client(socket: toss.Socket, session: Key, relay: Address)
}

/// Why a datagram could not be sent, or what arrived could not be read.
pub type UdpClientError {
  /// No socket could be opened to send from.
  CouldNotOpen(reason: toss.Error)
  SendFailed(reason: toss.Error)
  ReceiveFailed(reason: toss.Error)
  /// Something arrived and was not a packet this key could open. On UDP that
  /// is as much the ordinary noise of the internet as it is an attack, and
  /// either way there is nothing to answer.
  NotAuthentic(reason: datagram.DatagramError)
}

/// The largest datagram this will read.
///
/// Comfortably above any path MTU, so a reply is never truncated by this number
/// rather than by the network. Chosen rather than unbounded because the figure
/// decides an allocation per read.
pub const max_datagram = 65_535

/// Open a socket for sending through `relay`.
///
/// The operating system chooses the port. Ask `port` for it if something needs
/// to know.
pub fn open(
  session: Key,
  through relay: Address,
) -> Result(Client, UdpClientError) {
  case toss.open(toss.new(port: 0)) {
    Error(reason) -> Error(CouldNotOpen(reason))
    Ok(socket) -> Ok(Client(socket:, session:, relay:))
  }
}

/// The local port datagrams are being sent from.
pub fn port(sending: Client) -> Result(Int, Nil) {
  toss.local_port(sending.socket)
}

/// Seal a payload for `target` and send it to the relay.
///
/// A fresh salt every time, and no way to ask for anything else: repeating one
/// repeats the subkey, and a repeated subkey under this protocol's fixed nonce
/// is a total break rather than a degradation.
pub fn send(
  sending: Client,
  payload: BitArray,
  to target: Address,
) -> Result(Nil, UdpClientError) {
  let packet = datagram.seal(sending.session, target, payload)

  case
    toss.send_to_host(
      sending.socket,
      address.host(sending.relay),
      address.port(sending.relay),
      packet,
    )
  {
    Error(reason) -> Error(SendFailed(reason))
    Ok(Nil) -> Ok(Nil)
  }
}

/// Wait for one reply, and say where it came from.
pub fn receive(
  sending: Client,
  within timeout: Int,
) -> Result(#(Address, BitArray), UdpClientError) {
  case
    toss.receive(
      sending.socket,
      max_length: max_datagram,
      timeout_milliseconds: timeout,
    )
  {
    Error(reason) -> Error(ReceiveFailed(reason))
    Ok(#(_, _, data)) -> open_packet(sending, data)
  }
}

/// Close the socket.
///
/// A `Client` is a value, so nothing stops one being used afterwards — and
/// `toss` raises rather than returning an error when it is, because its error
/// decoder has no case for a socket that is already closed. Treat a closed
/// client as spent.
pub fn close(sending: Client) -> Nil {
  toss.close(sending.socket)
}

// --- driving it from an event loop ------------------------------------------------

/// Ask for the next datagram to arrive as a message rather than a return value.
///
/// One message per call. Do not mix this with `receive` on the same client:
/// `receive` reads the socket directly, and once datagrams are being delivered
/// as messages they are in a mailbox instead.
pub fn receive_next_message(sending: Client) -> Result(Nil, UdpClientError) {
  case toss.receive_next_datagram_as_message(sending.socket) {
    Error(reason) -> Error(ReceiveFailed(reason))
    Ok(Nil) -> Ok(Nil)
  }
}

/// Add this kind of message to a selector.
///
/// Note what `toss` says about this: a selector takes messages from every UDP
/// socket the process owns, not from one. One socket per process, as everywhere
/// else here.
pub fn select_messages(
  selector: process.Selector(message),
  mapper: fn(toss.UdpMessage) -> message,
) -> process.Selector(message) {
  toss.select_udp_messages(selector, mapper)
}

/// Open a datagram that arrived as a message.
pub fn handle_message(
  sending: Client,
  message: toss.UdpMessage,
) -> Result(#(Address, BitArray), UdpClientError) {
  case message {
    toss.UdpError(_, reason) -> Error(ReceiveFailed(reason))
    toss.Datagram(_, _, _, data) -> open_packet(sending, data)
  }
}

fn open_packet(
  sending: Client,
  data: BitArray,
) -> Result(#(Address, BitArray), UdpClientError) {
  case datagram.open(sending.session, data) {
    Error(reason) -> Error(NotAuthentic(reason))
    Ok(#(from, payload)) -> Ok(#(from, payload))
  }
}

/// A sentence for a person.
///
/// Nothing here quotes a payload or a key. A relay's replies are the caller's
/// traffic, and an error that printed one would put it wherever the error goes.
pub fn explain(reason: UdpClientError) -> String {
  case reason {
    CouldNotOpen(reason) ->
      "no socket could be opened to send from: " <> toss.describe_error(reason)
    SendFailed(reason) ->
      "the datagram could not be sent: " <> toss.describe_error(reason)
    ReceiveFailed(reason) ->
      "nothing could be read: "
      <> toss.describe_error(reason)
      <> ". On UDP a timeout here may simply mean the reply was lost; the "
      <> "protocol has no acknowledgement and nothing will say so."
    NotAuthentic(reason) ->
      "something arrived that this key could not open: "
      <> datagram.explain(reason)
      <> " On UDP that is as much the ordinary noise of the internet as it is "
      <> "an attack."
  }
}
