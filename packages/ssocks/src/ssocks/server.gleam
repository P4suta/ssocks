//// A Shadowsocks server.
////
//// ```gleam
//// let assert Ok(_) =
////   server.new(key.from_password(method.Aes256Gcm, "hunter2"))
////   |> server.start(8388)
//// ```
////
//// One process per connection, from `glisten`, and one more per connection for
//// the socket to the target — see `ssocks/internal/upstream` for why that
//// second process is not optional.
////
//// ### Not answering is the point
////
//// Active probing is how Shadowsocks servers have historically been found. A
//// prober opens a connection, sends something that is not a valid handshake,
//// and watches what happens. A server that closes immediately, or closes after
//// a distinctive delay, or answers at all, has told the prober what it is: a
//// port that behaves differently for garbage than an unused port does is a
//// port worth blocking.
////
//// So the default is `Drain`: keep the connection open, keep reading, say
//// nothing, and let the other end get bored. That is what a black hole looks
//// like, and it is what this port should look like to anyone who cannot
//// authenticate.
////
//// Three things trigger it, because a prober can produce any of them: bytes
//// that do not authenticate, bytes that authenticate but do not decrypt to a
//// target address, and a connection that opens and then says nothing. A policy
//// that covered only the first would still be distinguishable by the other two.
////
//// ### Replay
////
//// A salt is checked against `ssocks/replay_guard` before anything is relayed.
//// A server given no guard starts one of its own, which is right for one server
//// and wrong the moment there are two — see that module.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/result
import glisten
import mug
import ssocks/address
import ssocks/internal/upstream
import ssocks/key.{type Key}
import ssocks/replay
import ssocks/replay_guard.{type Guard}
import ssocks/stream

/// What to do with a connection that cannot be authenticated.
pub type OnProbe {
  /// Keep it open, keep reading, answer nothing. The default, because it is
  /// what an unused port looks like from the outside.
  Drain
  /// Keep it open for a while and then close. A middle ground for operators
  /// who do not want idle sockets held indefinitely; the delay is a signal, so
  /// prefer it long and prefer `Drain`.
  CloseAfter(milliseconds: Int)
  /// Close at once. Distinguishable, and therefore not the default. Useful
  /// when the port is not exposed to a hostile network and connections are
  /// worth more than concealment.
  CloseNow
}

/// Why a connection was treated as a probe.
pub type Probe {
  /// Bytes arrived that do not authenticate under this key. Almost always the
  /// password or the method, unless somebody is looking for a server.
  AuthenticationFailed(reason: stream.StreamError)
  /// They authenticated and did not decrypt to a target address. This means a
  /// peer holding the right key and speaking a different protocol.
  MalformedHeader
  /// This salt has been used before.
  Replayed(reason: replay.ReplayError)
  /// The connection opened and never completed a handshake.
  Silent
}

/// Things worth knowing about, for logs and for tests.
///
/// The callback runs inside the connection's own process, so it should be
/// quick; anything slow belongs on the other end of a `Subject`.
pub type Event {
  Accepted
  Handshook(target: address.Address)
  Probed(probe: Probe)
  TargetUnreachable(reason: mug.ConnectError)
  Finished
}

/// Which replay filter to use.
type Sharing {
  /// Start a guard for this server alone.
  OwnGuard
  /// Use one that already exists, so that several listeners under one key
  /// agree about what has been seen.
  SharedGuard(Guard)
  /// Do not check at all. Only reasonable when something else is.
  NoGuard
}

pub opaque type Builder {
  Builder(
    session: Key,
    on_probe: OnProbe,
    sharing: Sharing,
    handshake_timeout: Int,
    connect_timeout: Int,
    guard_timeout: Int,
    interface: String,
    watching: fn(Event) -> Nil,
  )
}

pub opaque type Server {
  Server(port: Int)
}

/// A server for one key, with the safe defaults.
pub fn new(session: Key) -> Builder {
  Builder(
    session:,
    on_probe: Drain,
    sharing: OwnGuard,
    // Long enough for a slow client on a bad link, short enough that an open
    // socket saying nothing does not sit there for the afternoon.
    handshake_timeout: 30_000,
    connect_timeout: 10_000,
    guard_timeout: 5000,
    interface: "0.0.0.0",
    watching: fn(_) { Nil },
  )
}

/// What to do with a connection that cannot be authenticated.
pub fn on_probe(builder: Builder, policy: OnProbe) -> Builder {
  Builder(..builder, on_probe: policy)
}

/// Share a replay filter with other listeners under the same key.
pub fn with_replay_guard(builder: Builder, guard: Guard) -> Builder {
  Builder(..builder, sharing: SharedGuard(guard))
}

/// Do not check salts against a replay filter.
///
/// The specification asks for the check, and skipping it lets a recorded
/// handshake be replayed. Reasonable only when another layer is doing it.
pub fn without_replay_guard(builder: Builder) -> Builder {
  Builder(..builder, sharing: NoGuard)
}

/// How long a connection may take to produce a valid target address header.
pub fn with_handshake_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, handshake_timeout: milliseconds)
}

/// How long reaching a target may take.
pub fn with_connect_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, connect_timeout: milliseconds)
}

/// Which interface to listen on. Defaults to all of them.
pub fn bind(builder: Builder, interface: String) -> Builder {
  Builder(..builder, interface:)
}

/// Watch what the server is doing.
pub fn watching(builder: Builder, watcher: fn(Event) -> Nil) -> Builder {
  Builder(..builder, watching: watcher)
}

/// Listen. Pass 0 for a port the operating system chooses, then ask `port`.
pub fn start(builder: Builder, port: Int) -> Result(Server, StartError) {
  use settings <- result.try(resolve_guard(builder))

  let name = process.new_name("ssocks_server")

  use _ <- result.try(
    glisten.new(fn(_) { open(settings) }, loop)
    |> glisten.bind(settings.interface)
    |> glisten.with_listener_name(name)
    |> glisten.start(port)
    |> result.map_error(CouldNotListen),
  )

  Ok(Server(glisten.get_server_info(name, 5000).port))
}

/// Why a server could not start.
///
/// Both cases come down to a process that would not start, but they are worth
/// telling apart: one is a port problem and the other is not.
pub type StartError {
  CouldNotListen(reason: actor.StartError)
  /// The replay filter would not start.
  CouldNotGuard(reason: actor.StartError)
}

fn resolve_guard(builder: Builder) -> Result(Builder, StartError) {
  case builder.sharing {
    SharedGuard(_) | NoGuard -> Ok(builder)
    OwnGuard ->
      replay_guard.start()
      |> result.map(fn(guard) {
        Builder(..builder, sharing: SharedGuard(guard))
      })
      |> result.map_error(CouldNotGuard)
  }
}

/// The port actually listened on, which is what was asked for unless that was
/// 0.
pub fn port(server: Server) -> Int {
  server.port
}

// --- one connection -----------------------------------------------------------

/// What a connection's process selects on besides its client socket.
type Notice {
  FromUpstream(upstream.Event)
  HandshakeOverdue
  CloseOverdue
}

type Session {
  Session(
    settings: Builder,
    decoder: stream.Decoder,
    encoder: Option(stream.Encoder),
    notices: Subject(Notice),
    from_upstream: Subject(upstream.Event),
    upstream: Option(Subject(upstream.Command)),
    /// Decrypted bytes that are not yet a whole target address header.
    pending: BitArray,
    /// Payload waiting for the target to be reached, newest first.
    held: List(BitArray),
    target: Option(address.Address),
    salt_checked: Bool,
    probing: Bool,
  )
}

fn open(settings: Builder) -> #(Session, Option(process.Selector(Notice))) {
  let notices = process.new_subject()
  let from_upstream = process.new_subject()

  settings.watching(Accepted)

  // A connection that opens and says nothing is one of the three things a
  // prober does, so it gets the same answer as the other two.
  let _ =
    process.send_after(notices, settings.handshake_timeout, HandshakeOverdue)

  #(
    Session(
      settings:,
      decoder: stream.decoder(settings.session),
      encoder: None,
      notices:,
      from_upstream:,
      upstream: None,
      pending: <<>>,
      held: [],
      target: None,
      salt_checked: False,
      probing: False,
    ),
    Some(
      process.new_selector()
      |> process.select(notices)
      |> process.select_map(from_upstream, FromUpstream),
    ),
  )
}

fn loop(
  state: Session,
  message: glisten.Message(Notice),
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case message {
    glisten.Packet(bytes) -> from_client(state, bytes)
    glisten.User(FromUpstream(event)) -> from_target(state, event, connection)

    glisten.User(HandshakeOverdue) ->
      case state.target, state.probing {
        // Already through, or already being drained: the timer is stale.
        Some(_), _ | _, True -> glisten.continue(state)
        None, False -> probed(state, Silent)
      }

    glisten.User(CloseOverdue) -> finish(state)
  }
}

fn from_client(
  state: Session,
  bytes: BitArray,
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case state.probing {
    // Draining. Read it, drop it, say nothing.
    True -> glisten.continue(state)
    False ->
      case stream.decode(state.decoder, bytes) {
        Error(reason) -> probed(state, AuthenticationFailed(reason))
        Ok(#(decoder, chunks)) -> {
          let state = Session(..state, decoder:)
          case check_salt(state) {
            Error(reason) -> probed(state, Replayed(reason))
            Ok(state) ->
              case state.target {
                Some(_) -> to_target(state, bit_array.concat(chunks))
                None -> handshake(state, bit_array.concat(chunks))
              }
          }
        }
      }
  }
}

/// The salt is known as soon as enough bytes have arrived for it, which is
/// before any chunk has been authenticated. Checking it here means a replayed
/// handshake is refused without the target ever being reached.
fn check_salt(state: Session) -> Result(Session, replay.ReplayError) {
  case state.salt_checked, state.settings.sharing, stream.salt(state.decoder) {
    True, _, _ | _, NoGuard, _ | _, _, None -> Ok(state)
    False, SharedGuard(guard), Some(salt) ->
      replay_guard.observe(guard, salt, within: state.settings.guard_timeout)
      |> result.map(fn(_) { Session(..state, salt_checked: True) })
    // Unreachable: `start` replaces OwnGuard with a real one before listening.
    False, OwnGuard, Some(_) -> Ok(state)
  }
}

/// The first plaintext bytes of a stream are the target address. They may
/// arrive in pieces, so they are buffered until they are whole.
fn handshake(
  state: Session,
  plaintext: BitArray,
) -> glisten.Next(Session, glisten.Message(Notice)) {
  let pending = bit_array.append(state.pending, plaintext)

  case address.decode(pending) {
    Error(_) -> probed(state, MalformedHeader)

    Ok(address.NeedMoreBytes(_)) -> glisten.continue(Session(..state, pending:))

    Ok(address.Complete(target, rest)) -> {
      state.settings.watching(Handshook(target))
      upstream.start(
        target,
        within: state.settings.connect_timeout,
        reporting: state.from_upstream,
      )

      let state =
        Session(..state, target: Some(target), pending: <<>>, held: [])

      to_target(state, rest)
    }
  }
}

fn to_target(
  state: Session,
  payload: BitArray,
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case bit_array.byte_size(payload), state.upstream {
    0, _ -> glisten.continue(state)
    _, Some(commands) -> {
      process.send(commands, upstream.Write(payload))
      glisten.continue(state)
    }
    // The target is still being reached. Hold it; `Ready` will flush.
    _, None -> glisten.continue(Session(..state, held: [payload, ..state.held]))
  }
}

fn from_target(
  state: Session,
  event: upstream.Event,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case event {
    upstream.Ready(commands) -> {
      upstream.flush(commands, state.held)
      glisten.continue(Session(..state, upstream: Some(commands), held: []))
    }

    upstream.Arrived(bytes) -> to_client(state, bytes, connection)

    upstream.Unreachable(reason) -> {
      state.settings.watching(TargetUnreachable(reason))
      finish(state)
    }

    upstream.Gone -> finish(state)
  }
}

fn to_client(
  state: Session,
  payload: BitArray,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  // The reply direction has its own salt and its own counter, sent once at the
  // head of the first reply.
  let #(encoder, prologue) = case state.encoder {
    Some(encoder) -> #(encoder, <<>>)
    None -> {
      let #(encoder, salt) = stream.encoder(state.settings.session)
      #(encoder, salt)
    }
  }

  let #(encoder, framed) = stream.encode(encoder, payload)

  case
    glisten.send(
      connection,
      bytes_tree.from_bit_array(bit_array.concat([prologue, framed])),
    )
  {
    Ok(_) -> glisten.continue(Session(..state, encoder: Some(encoder)))
    Error(_) -> finish(state)
  }
}

fn probed(
  state: Session,
  probe: Probe,
) -> glisten.Next(Session, glisten.Message(Notice)) {
  state.settings.watching(Probed(probe))

  case state.settings.on_probe {
    CloseNow -> finish(state)

    Drain -> glisten.continue(Session(..state, probing: True))

    CloseAfter(milliseconds) -> {
      let _ = process.send_after(state.notices, milliseconds, CloseOverdue)
      glisten.continue(Session(..state, probing: True))
    }
  }
}

fn finish(state: Session) -> glisten.Next(Session, glisten.Message(Notice)) {
  case state.upstream {
    Some(commands) -> process.send(commands, upstream.Close)
    None -> Nil
  }
  state.settings.watching(Finished)
  glisten.stop()
}
