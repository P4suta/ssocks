//// A SOCKS5 proxy that goes out through Shadowsocks.
////
//// ```gleam
//// let assert Ok(config) = ssocks.from_uri("ss://…@example.com:8388")
//// let assert Ok(_) = local.new(config) |> local.start(1080)
//// ```
////
//// This is the half a browser can use. `ssocks/client` tunnels to one target
//// chosen in Gleam; this listens for SOCKS5 and tunnels to whatever each
//// request asks for, which is what a proxy setting in an application expects
//// to find.
////
//// ### It listens on loopback by default
////
//// `ssocks/server` defaults to every interface, because a Shadowsocks server is
//// meant to be reachable. This defaults to `127.0.0.1`, because it is not: a
//// SOCKS5 proxy with no authentication, reachable from the network, is an open
//// proxy, and an open proxy is somebody else's outbound traffic with your
//// address on it. `bind` will put it elsewhere, deliberately.
////
//// ### No authentication, and why that is not a gap
////
//// Only `NoAuthentication` is offered. The SOCKS5 username and password
//// exchange sends both in the clear, and the hop it would protect is the
//// loopback interface — where anyone able to read it can already read the
//// process's memory. Reaching for it here would buy nothing and imply
//// something.
////
//// ### One process per socket
////
//// A connection here owns two: the client's, from glisten, and the
//// Shadowsocks one, in `ssocks/internal/tunnel`. They cannot live in one
//// process, for the reason `ssocks/internal/upstream` sets out.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/atom
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/result
import glip
import glisten
import ssocks/address
import ssocks/client
import ssocks/internal/associate
import ssocks/internal/clock
import ssocks/internal/tally.{type Tally}
import ssocks/internal/tunnel
import ssocks/socks5
import ssocks/url

/// Five minutes of silence on an established connection, matching
/// `ssocks/server`.
pub const default_idle_timeout = 300_000

/// How long a client has to get through the greeting and the request.
pub const default_handshake_timeout = 30_000

/// Enough that a browser opening everything at once will not reach it.
pub const default_max_connections = 10_000

/// How much may be queued for the server before the client stops being read.
pub const default_max_outstanding_bytes = 262_144

/// Things worth knowing about, for logs and for tests.
///
/// The callback runs inside the connection's own process, so it should be
/// quick; anything slow belongs on the other end of a `Subject`.
pub type Event {
  Accepted
  /// A well-formed `CONNECT` for this target.
  Requested(target: address.Address)
  /// A `UDP ASSOCIATE`, served on this address.
  Associated(where: address.Address)
  /// An association could not be opened, and the client was told so.
  NotAssociated(reason: associate.Opening)
  /// One datagram in an association was not relayed. Reported rather than
  /// acted on: a single bad datagram does not end an association.
  Dropped(reason: associate.Rejection)
  /// A well-formed request this proxy will not serve, and the code it was
  /// answered with.
  Declined(reply: socks5.Reply)
  /// Bytes that are not SOCKS5. The connection is closed without an answer.
  Malformed(reason: socks5.Socks5Error)
  /// The Shadowsocks server could not be reached.
  ServerUnreachable(reason: client.ClientError)
  /// The tunnel stopped because something failed rather than because either
  /// end finished. A wrong password arrives here, as a framing failure on the
  /// first chunk: Shadowsocks says nothing on connect, so that is the earliest
  /// anything can be said about it.
  Broke(reason: client.ClientError)
  /// Turned away because `with_max_connections` was reached.
  Refused
  /// Closed for having said nothing for `with_idle_timeout`.
  Idled
  Finished
}

pub opaque type Builder {
  Builder(
    config: url.Config,
    interface: String,
    handshake_timeout: Int,
    connect_timeout: Int,
    idle_timeout: Int,
    max_connections: Int,
    max_outstanding_bytes: Int,
    /// Filled in by `start`; a builder never carries one.
    counting: Option(Tally),
    watching: fn(Event) -> Nil,
  )
}

pub opaque type Proxy {
  Proxy(port: Int, control: Subject(Command), counting: Tally)
}

/// What the process owning the listener accepts. Sent by `stop`.
pub opaque type Command {
  Stop
}

/// Why a proxy could not start.
pub type StartError {
  CouldNotListen(reason: actor.StartError)
  /// The connection counter would not start.
  CouldNotCount(reason: actor.StartError)
  /// `bind` was given something that is not an address this machine could
  /// listen on.
  BadInterface(interface: String)
  /// The listener did not report back in time.
  DidNotStart
}

/// A proxy for one Shadowsocks configuration, with the safe defaults.
pub fn new(config: url.Config) -> Builder {
  Builder(
    config:,
    interface: "127.0.0.1",
    handshake_timeout: default_handshake_timeout,
    connect_timeout: 10_000,
    idle_timeout: default_idle_timeout,
    max_connections: default_max_connections,
    max_outstanding_bytes: default_max_outstanding_bytes,
    counting: None,
    watching: fn(_) { Nil },
  )
}

/// Which interface to listen on. Defaults to loopback, and read the module
/// documentation before changing that.
pub fn bind(builder: Builder, interface: String) -> Builder {
  Builder(..builder, interface:)
}

/// How long a client has to complete the greeting and the request.
pub fn with_handshake_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, handshake_timeout: milliseconds)
}

/// How long reaching the Shadowsocks server may take.
pub fn with_connect_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, connect_timeout: milliseconds)
}

/// How long an established connection may say nothing. 0 allows silence for
/// ever.
pub fn with_idle_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, idle_timeout: milliseconds)
}

/// How many connections may be live at once.
pub fn with_max_connections(builder: Builder, connections: Int) -> Builder {
  Builder(..builder, max_connections: connections)
}

/// How much may be queued for the server before the client stops being read.
pub fn with_max_outstanding_bytes(builder: Builder, bytes: Int) -> Builder {
  Builder(..builder, max_outstanding_bytes: bytes)
}

/// Watch what the proxy is doing.
pub fn watching(builder: Builder, watcher: fn(Event) -> Nil) -> Builder {
  Builder(..builder, watching: watcher)
}

/// Listen. Pass 0 for a port the operating system chooses, then ask `port`.
pub fn start(builder: Builder, port: Int) -> Result(Proxy, StartError) {
  use settings <- result.try(resolve_interface(builder))

  use settings <- result.try(
    tally.start()
    |> result.map(fn(counting) { Builder(..settings, counting: Some(counting)) })
    |> result.map_error(CouldNotCount),
  )

  let ready = process.new_subject()
  process.spawn(fn() { own(settings, port, ready) })

  case process.receive(ready, start_timeout) {
    Ok(outcome) -> outcome
    Error(Nil) -> Error(DidNotStart)
  }
}

/// glisten panics on an interface it cannot parse, so it is checked here first.
fn resolve_interface(builder: Builder) -> Result(Builder, StartError) {
  case builder.interface {
    "0.0.0.0" | "localhost" | "127.0.0.1" -> Ok(builder)
    other ->
      case glip.parse_ip(other) {
        Ok(_) -> Ok(builder)
        Error(Nil) -> Error(BadInterface(other))
      }
  }
}

/// Hold the listener's supervisor, and take it down when told to. The same
/// arrangement, and for the same reasons, as `ssocks/server`.
fn own(
  settings: Builder,
  port: Int,
  ready: Subject(Result(Proxy, StartError)),
) -> Nil {
  let name = process.new_name("ssocks_local")
  let control = process.new_subject()

  case
    glisten.new(fn(_) { open(settings) }, loop)
    |> glisten.with_close(closed)
    |> glisten.bind(settings.interface)
    |> glisten.with_listener_name(name)
    |> glisten.start(port)
  {
    Error(reason) -> process.send(ready, Error(CouldNotListen(reason)))

    Ok(started) -> {
      let assert Some(counting) = settings.counting
      process.send(
        ready,
        Ok(Proxy(glisten.get_server_info(name, 5000).port, control, counting)),
      )

      let Stop = process.receive_forever(control)

      let watching = process.monitor(started.pid)
      process.unlink(started.pid)
      process.send_abnormal_exit(started.pid, atom.create("shutdown"))

      process.new_selector()
      |> process.select_specific_monitor(watching, fn(_) { Nil })
      |> process.selector_receive_forever

      let _ = tally.stop(counting)
      Nil
    }
  }
}

/// The port actually listened on.
pub fn port(proxy: Proxy) -> Int {
  proxy.port
}

/// How many connections are live right now.
pub fn connections(proxy: Proxy, within timeout: Int) -> Result(Int, Nil) {
  tally.count(proxy.counting, within: timeout)
}

/// Stop listening and drop every connection. Waits for the port to be free.
pub fn stop(proxy: Proxy) -> Result(Nil, Nil) {
  case process.subject_owner(proxy.control) {
    Error(Nil) -> Ok(Nil)
    Ok(running) -> {
      let watching = process.monitor(running)
      process.send(proxy.control, Stop)

      let stopped =
        process.new_selector()
        |> process.select_specific_monitor(watching, fn(_) { Nil })
        |> process.selector_receive(stop_timeout)

      process.demonitor_process(watching)
      stopped
    }
  }
}

const start_timeout = 5000

const stop_timeout = 5000

/// How long the handler will wait for the server to catch up. Generous: the
/// client is not being read meanwhile, so nothing accumulates while it waits.
const drain_timeout = 30_000

// --- one connection ---------------------------------------------------------------

/// Where a connection is in the SOCKS5 exchange.
type Stage {
  /// Reading the greeting.
  Greeting
  /// Greeted; reading the request.
  Awaiting
  /// Through, and moving bytes.
  Relaying
  /// Holding a UDP association open. Nothing more is expected on this
  /// connection: RFC 1928 keeps it open only to bound the association's life,
  /// and closing it is how a client ends one.
  Holding
}

type Notice {
  FromTunnel(tunnel.Event)
  FromAssociation(associate.Event)
  HandshakeOverdue
  IdleOverdue
}

type Session {
  Session(
    settings: Builder,
    stage: Stage,
    /// Bytes read from the client that are not yet a whole SOCKS5 message.
    pending: BitArray,
    notices: Subject(Notice),
    from_tunnel: Subject(tunnel.Event),
    from_association: Subject(associate.Event),
    tunnel: Option(Subject(tunnel.Command)),
    association: Option(Subject(associate.Command)),
    /// Payload waiting for the server to be reached, newest first.
    held: List(BitArray),
    outstanding: Int,
    last_activity: Int,
    accepted: Bool,
  )
}

fn open(settings: Builder) -> #(Session, Option(process.Selector(Notice))) {
  let notices = process.new_subject()
  let from_tunnel = process.new_subject()
  let from_association = process.new_subject()

  let accepted = case settings.counting {
    None -> True
    Some(counting) ->
      case tally.claim(counting, settings.max_connections, within: 5000) {
        Ok(_) -> True
        Error(Nil) -> False
      }
  }

  case accepted {
    True -> settings.watching(Accepted)
    False -> {
      settings.watching(Refused)
      process.send(notices, HandshakeOverdue)
    }
  }

  let _ =
    process.send_after(notices, settings.handshake_timeout, HandshakeOverdue)

  case settings.idle_timeout {
    0 -> Nil
    milliseconds -> {
      let _ = process.send_after(notices, milliseconds, IdleOverdue)
      Nil
    }
  }

  #(
    Session(
      settings:,
      stage: Greeting,
      pending: <<>>,
      notices:,
      from_tunnel:,
      from_association:,
      tunnel: None,
      association: None,
      held: [],
      outstanding: 0,
      last_activity: clock.now_ms(),
      accepted:,
    ),
    Some(
      process.new_selector()
      |> process.select(notices)
      |> process.select_map(from_tunnel, FromTunnel)
      |> process.select_map(from_association, FromAssociation),
    ),
  )
}

fn loop(
  state: Session,
  message: glisten.Message(Notice),
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case message {
    glisten.Packet(bytes) -> from_client(touch(state), bytes, connection)

    glisten.User(FromTunnel(event)) ->
      from_server(touch(state), event, connection)

    glisten.User(FromAssociation(event)) ->
      from_association(touch(state), event, connection)

    glisten.User(HandshakeOverdue) ->
      case state.stage {
        // Through the exchange already: the timer is stale.
        Relaying | Holding -> glisten.continue(state)
        _ -> finish(state)
      }

    glisten.User(IdleOverdue) -> idle(state)
  }
}

fn touch(state: Session) -> Session {
  Session(..state, last_activity: clock.now_ms())
}

fn idle(state: Session) -> glisten.Next(Session, glisten.Message(Notice)) {
  case state.settings.idle_timeout {
    0 -> glisten.continue(state)
    milliseconds -> {
      let quiet = clock.now_ms() - state.last_activity
      case quiet >= milliseconds {
        True -> {
          state.settings.watching(Idled)
          finish(state)
        }
        False -> {
          let _ =
            process.send_after(state.notices, milliseconds - quiet, IdleOverdue)
          glisten.continue(state)
        }
      }
    }
  }
}

fn from_client(
  state: Session,
  bytes: BitArray,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case state.stage {
    Relaying -> to_server(state, bytes)

    // RFC 1928 keeps this connection open to bound the association's life and
    // expects nothing more on it. Anything that does arrive is not part of the
    // protocol, so it is read and dropped rather than acted on.
    Holding -> glisten.continue(state)
    Greeting ->
      greet(Session(..state, pending: append(state.pending, bytes)), connection)
    Awaiting ->
      request(
        Session(..state, pending: append(state.pending, bytes)),
        connection,
      )
  }
}

/// Read the greeting, and answer with the method this proxy will use.
fn greet(
  state: Session,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case socks5.decode_greeting(state.pending) {
    Error(reason) -> malformed(state, reason)
    Ok(socks5.NeedMoreBytes(_)) -> glisten.continue(state)

    Ok(socks5.Complete(offered, rest)) ->
      case list.contains(offered, socks5.NoAuthentication) {
        False -> {
          // Answered rather than dropped: this is a local client that got the
          // configuration wrong, not a prober. Telling it why is the point.
          state.settings.watching(Declined(socks5.NotAllowed))
          let _ = say(connection, socks5.encode_choice(socks5.NoneAcceptable))
          finish(state)
        }

        True ->
          case say(connection, socks5.encode_choice(socks5.NoAuthentication)) {
            Error(Nil) -> finish(state)
            Ok(Nil) ->
              // Whatever followed the greeting is the start of the request,
              // and a client that writes both at once is ordinary.
              request(
                Session(..state, stage: Awaiting, pending: rest),
                connection,
              )
          }
      }
  }
}

/// Read the request, and start reaching for what it asks for.
fn request(
  state: Session,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case socks5.decode_request(state.pending) {
    Error(reason) -> malformed(state, reason)
    Ok(socks5.NeedMoreBytes(_)) -> glisten.continue(state)

    Ok(socks5.Complete(#(socks5.Connect, target), rest)) -> {
      state.settings.watching(Requested(target))

      tunnel.start(
        state.settings.config,
        target,
        within: state.settings.connect_timeout,
        reporting: state.from_tunnel,
      )

      // The reply waits for the tunnel: answering `Succeeded` before the
      // server has been reached would have the client send a request into a
      // connection that is about to fail.
      hold(Session(..state, stage: Relaying, pending: <<>>), rest)
    }

    Ok(socks5.Complete(#(socks5.Associate, _), _)) -> {
      // The address the client says it will send from is ignored on purpose:
      // clients send `0.0.0.0:0` because they are behind their own NAT and do
      // not know. The association learns it from the first datagram instead.
      associate.start(
        state.settings.config,
        on: state.settings.interface,
        reporting: state.from_association,
      )

      glisten.continue(Session(..state, stage: Holding, pending: <<>>))
    }

    Ok(socks5.Complete(#(socks5.Bind, _), _)) -> declined(state, connection)
  }
}

fn from_association(
  state: Session,
  event: associate.Event,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case event {
    associate.Bound(where, commands) -> {
      state.settings.watching(Associated(where))

      case say(connection, socks5.encode_reply(socks5.Succeeded, where)) {
        Error(Nil) -> finish(state)
        Ok(Nil) ->
          glisten.continue(Session(..state, association: Some(commands)))
      }
    }

    associate.Failed(reason) -> {
      state.settings.watching(NotAssociated(reason))
      let _ =
        say(
          connection,
          socks5.encode_reply(socks5.GeneralFailure, socks5.unspecified()),
        )
      finish(state)
    }

    associate.Dropped(reason) -> {
      state.settings.watching(Dropped(reason))
      glisten.continue(state)
    }
  }
}

fn declined(
  state: Session,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  state.settings.watching(Declined(socks5.CommandNotSupported))
  let _ =
    say(
      connection,
      socks5.encode_reply(socks5.CommandNotSupported, socks5.unspecified()),
    )
  finish(state)
}

/// Bytes that are not SOCKS5 at all. Closed without an answer.
fn malformed(
  state: Session,
  reason: socks5.Socks5Error,
) -> glisten.Next(Session, glisten.Message(Notice)) {
  state.settings.watching(Malformed(reason))
  finish(state)
}

fn from_server(
  state: Session,
  event: tunnel.Event,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case event {
    tunnel.Ready(commands) ->
      case
        say(
          connection,
          socks5.encode_reply(socks5.Succeeded, socks5.unspecified()),
        )
      {
        Error(Nil) -> finish(state)
        Ok(Nil) -> {
          tunnel.flush(commands, state.held)
          glisten.continue(
            Session(
              ..state,
              tunnel: Some(commands),
              held: [],
              outstanding: state.outstanding,
            ),
          )
        }
      }

    tunnel.Unreachable(reason) -> {
      state.settings.watching(ServerUnreachable(reason))
      let _ =
        say(
          connection,
          socks5.encode_reply(socks5.HostUnreachable, socks5.unspecified()),
        )
      finish(state)
    }

    tunnel.Arrived(bytes) ->
      case say(connection, bytes) {
        Error(Nil) -> finish(state)
        Ok(Nil) -> {
          case state.tunnel {
            Some(commands) -> process.send(commands, tunnel.More)
            None -> Nil
          }
          glisten.continue(state)
        }
      }

    tunnel.Gone(tunnel.Closed) -> finish(state)

    tunnel.Gone(tunnel.Failed(reason)) -> {
      state.settings.watching(Broke(reason))
      finish(state)
    }
  }
}

fn to_server(
  state: Session,
  payload: BitArray,
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case bit_array.byte_size(payload), state.tunnel {
    0, _ -> glisten.continue(state)

    size, Some(commands) -> {
      process.send(commands, tunnel.Write(payload))
      let outstanding = state.outstanding + size

      case outstanding >= state.settings.max_outstanding_bytes {
        False -> glisten.continue(Session(..state, outstanding:))
        True -> {
          tunnel.drain(commands, within: drain_timeout)
          glisten.continue(Session(..state, outstanding: 0))
        }
      }
    }

    _, None -> hold(state, payload)
  }
}

/// Keep what arrived before the server was reached. `Ready` flushes it.
fn hold(
  state: Session,
  payload: BitArray,
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case bit_array.byte_size(payload) {
    0 -> glisten.continue(state)
    size ->
      glisten.continue(
        Session(
          ..state,
          held: [payload, ..state.held],
          outstanding: state.outstanding + size,
        ),
      )
  }
}

fn finish(state: Session) -> glisten.Next(Session, glisten.Message(Notice)) {
  closed(state)
  glisten.stop()
}

/// The connection ended. Let go of the tunnel, and say so.
///
/// glisten calls this when the client's socket closes and then ends the handler
/// normally, which does not travel down the link to the tunnel process. Without
/// it the Shadowsocks connection would outlive the browser tab that asked for
/// it.
fn closed(state: Session) -> Nil {
  case state.tunnel {
    Some(commands) -> process.send(commands, tunnel.Close)
    None -> Nil
  }

  // The TCP connection is the association's lifetime, which is what RFC 1928
  // says and what makes this unambiguous.
  case state.association {
    Some(commands) -> process.send(commands, associate.Close)
    None -> Nil
  }

  case state.accepted, state.settings.counting {
    False, _ -> Nil
    True, counting -> {
      case counting {
        Some(counting) -> tally.release(counting)
        None -> Nil
      }
      state.settings.watching(Finished)
    }
  }
}

fn say(
  connection: glisten.Connection(Notice),
  bytes: BitArray,
) -> Result(Nil, Nil) {
  glisten.send(connection, bytes_tree.from_bit_array(bytes))
  |> result.replace_error(Nil)
  |> result.replace(Nil)
}

fn append(accumulated: BitArray, more: BitArray) -> BitArray {
  <<accumulated:bits, more:bits>>
}
