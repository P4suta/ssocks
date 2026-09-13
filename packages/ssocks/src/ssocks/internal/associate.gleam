//// A SOCKS5 UDP association, and the process that owns its two sockets.
////
//// `UDP ASSOCIATE` asks the proxy for somewhere to send datagrams. What comes
//// back is a UDP socket of the proxy's own; the client wraps each payload in a
//// small header saying where it is for, and this unwraps it, seals it for the
//// Shadowsocks server through `ssocks/udp_client`, and does the reverse for
//// every reply.
////
//// ### One process, two sockets — and here that is allowed
////
//// `ssocks/internal/upstream` has to exist because glisten and mug both select
//// the raw `{tcp, Socket, Data}` record without saying which socket it came
//// from. UDP is not like that: `toss.Datagram` carries its socket, so one
//// process can own several and tell them apart. `ssocks/udp` already relies on
//// exactly this, and so does this module.
////
//// ### The client's address is learned, not declared
////
//// RFC 1928 lets a client state the address it will send datagrams from, and in
//// practice clients send `0.0.0.0:0` — they are behind their own NAT and do not
//// know. So the first datagram to arrive names the client, and replies go
//// there. Nothing else would work.
////
//// ### The TCP connection is the lifetime
////
//// The association lasts as long as the TCP connection that asked for it, which
//// is what RFC 1928 says and what makes the cleanup unambiguous: the handler is
//// monitored, and when it goes, so do these sockets.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/option.{type Option, None, Some}
import glip
import ssocks/address.{type Address}
import ssocks/socks5
import ssocks/udp_client
import ssocks/url
import toss

/// What the handler asks of the association.
pub type Command {
  Close
}

/// What the association tells the handler.
pub type Event {
  /// Datagrams for this association should be sent to `where`, and the
  /// association is ended by sending `Close` to `commands`.
  ///
  /// The subject comes back here rather than from `start` for the reason every
  /// other process in this package does it: a subject has to be created by the
  /// process that will receive on it.
  Bound(where: Address, commands: Subject(Command))
  /// Nothing could be opened, so there is nothing to tell the client.
  Failed(reason: Opening)
  /// A datagram was not relayed, and why. Reported rather than acted on: a
  /// single bad datagram does not end an association.
  Dropped(reason: Rejection)
}

/// Why an association could not be opened.
///
/// Four cases rather than one, because the first version of this reported two
/// of them as `toss.BadArgument` — a socket that would not say its own port,
/// and an interface that would not become an address — and neither is a bad
/// argument. Reporting the wrong reason is the thing this package spends most
/// of its error types avoiding.
pub type Opening {
  /// No socket could be opened for the client to send its datagrams to.
  NoSocket(reason: toss.Error)
  /// The socket opened and would not say which port it got.
  NoPort
  /// The interface this proxy listens on is not one an address can be built
  /// from, so there is nothing to tell the client to send to.
  NoAddress(interface: String)
  /// The tunnel to the Shadowsocks server could not be opened.
  NoTunnel(reason: udp_client.UdpClientError)
}

/// Why one datagram was not relayed.
pub type Rejection {
  /// The SOCKS5 header on it was not one.
  Malformed(reason: socks5.Socks5Error)
  /// It could not be sealed and sent on to the Shadowsocks server.
  Undeliverable(reason: udp_client.UdpClientError)
  /// Something came back from the server that this key could not open.
  NotAuthentic(reason: udp_client.UdpClientError)
  /// A reply arrived before any datagram had said where the client is.
  NoClientYet
}

type Inbox {
  FromHandler(Command)
  FromSocket(toss.UdpMessage)
}

type State {
  State(
    /// The socket the SOCKS5 client sends its datagrams to.
    facing: toss.Socket,
    /// The tunnel to the Shadowsocks server.
    sending: udp_client.Client,
    /// Where the client turned out to be. Learned from its first datagram.
    client: Option(#(glip.IpAddress, Int)),
    events: Subject(Event),
  )
}

/// Open an association and report where the client should send datagrams.
///
/// Returns immediately. `Bound` or `Failed` arrives on `events`.
pub fn start(
  config: url.Config,
  on interface: String,
  reporting events: Subject(Event),
) -> Nil {
  // Whoever is asking. Monitored below, because the association lasts exactly
  // as long as the TCP connection that asked for it and a handler can end
  // without saying so.
  let handler = process.self()

  process.spawn(fn() {
    case open(config, interface) {
      Error(reason) -> process.send(events, Failed(reason))

      Ok(#(facing, sending, where)) -> {
        // Created here so that orders land in this process's mailbox.
        let commands = process.new_subject()
        process.send(events, Bound(where, commands))

        let watching = process.monitor(handler)

        loop(
          State(facing:, sending:, client: None, events:),
          process.new_selector()
            |> process.select_map(commands, FromHandler)
            |> process.select_specific_monitor(watching, fn(_) {
              FromHandler(Close)
            })
            |> udp_client.select_messages(FromSocket),
        )
      }
    }
  })
  Nil
}

fn open(
  config: url.Config,
  interface: String,
) -> Result(#(toss.Socket, udp_client.Client, Address), Opening) {
  // `localhost` is what `local.bind` accepts and `glip.parse_ip` does not, and
  // falling through to "no interface" would put this socket on every one of
  // them — the same silent widening `udp.bind` used to do.
  let host = case interface {
    "localhost" -> "127.0.0.1"
    other -> other
  }

  case glip.parse_ip(host) {
    Error(Nil) -> Error(NoAddress(interface))
    Ok(ip) ->
      case toss.open(toss.using_interface(toss.new(port: 0), ip)) {
        Error(reason) -> Error(NoSocket(reason))
        Ok(facing) ->
          case toss.local_port(facing) {
            Error(Nil) -> {
              toss.close(facing)
              Error(NoPort)
            }
            Ok(port) ->
              case
                udp_client.open(url.key(config), through: url.server(config))
              {
                Error(reason) -> {
                  toss.close(facing)
                  Error(NoTunnel(reason))
                }
                Ok(sending) ->
                  case address.parse(host <> ":" <> int.to_string(port)) {
                    Error(_) -> {
                      toss.close(facing)
                      udp_client.close(sending)
                      Error(NoAddress(interface))
                    }
                    Ok(where) -> {
                      let _ = toss.receive_next_datagram_as_message(facing)
                      let _ = udp_client.receive_next_message(sending)
                      Ok(#(facing, sending, where))
                    }
                  }
              }
          }
      }
  }
}

fn loop(state: State, selector: process.Selector(Inbox)) -> Nil {
  case process.selector_receive_forever(selector) {
    FromHandler(Close) -> {
      toss.close(state.facing)
      udp_client.close(state.sending)
    }

    FromSocket(toss.UdpError(_, _)) -> loop(state, selector)

    FromSocket(toss.Datagram(socket, host, port, data) as message) -> {
      // Which socket it came from is the whole reason one process may own
      // both: `toss.Datagram` says, where the TCP equivalents do not.
      let state = case socket == state.facing {
        True -> from_client(state, host, port, data)
        False -> from_server(state, message)
      }

      // Active-once, on whichever socket this was.
      let _ = toss.receive_next_datagram_as_message(socket)
      loop(state, selector)
    }
  }
}

/// A datagram from the SOCKS5 client, wrapped in its little header.
fn from_client(
  state: State,
  host: Result(glip.IpAddress, Nil),
  port: Int,
  data: BitArray,
) -> State {
  case socks5.decode_datagram(data) {
    Error(reason) -> {
      process.send(state.events, Dropped(Malformed(reason)))
      state
    }

    Ok(#(target, payload)) -> {
      // Where the client is, learned rather than declared: RFC 1928 lets it
      // say, and in practice it says `0.0.0.0:0` because it is behind its own
      // NAT and does not know.
      let state = case host {
        Error(Nil) -> state
        Ok(host) -> State(..state, client: Some(#(host, port)))
      }

      case udp_client.send(state.sending, payload, to: target) {
        Error(reason) -> {
          process.send(state.events, Dropped(Undeliverable(reason)))
          state
        }
        Ok(Nil) -> state
      }
    }
  }
}

/// A reply from the Shadowsocks server, to be wrapped and handed back.
fn from_server(state: State, message: toss.UdpMessage) -> State {
  case udp_client.handle_message(state.sending, message) {
    Error(reason) -> {
      process.send(state.events, Dropped(NotAuthentic(reason)))
      state
    }

    Ok(#(from, payload)) ->
      case state.client {
        None -> {
          process.send(state.events, Dropped(NoClientYet))
          state
        }
        Some(#(host, port)) -> {
          let _ =
            toss.send_to(
              state.facing,
              host,
              port,
              socks5.encode_datagram(from, payload),
            )
          state
        }
      }
  }
}
