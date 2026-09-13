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
import gleam/erlang/atom
import gleam/erlang/process.{type Subject}
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/result
import glip
import glisten
import glisten/socket
import mug
import ssocks/address
import ssocks/internal/clock
import ssocks/internal/tally.{type Tally}
import ssocks/internal/upstream
import ssocks/key.{type Key}
import ssocks/replay
import ssocks/replay_guard.{type Guard}
import ssocks/stream

/// Five minutes of silence on an established connection, matching the figure
/// `ssocks/udp` uses for an association and the one most Shadowsocks servers
/// ship with.
///
/// Before this existed, only the handshake was bounded: once a peer had
/// authenticated it could hold a glisten process, an upstream process and two
/// sockets for as long as it liked by saying nothing at all.
pub const default_idle_timeout = 300_000

/// Enough that honest traffic on one listener will not reach it.
///
/// A ceiling is visible from the outside — a port that refuses at a threshold
/// behaves differently from one that does not — so it trades a little of what
/// `Drain` buys back for a bound on how many sockets an unauthenticated peer
/// can hold open at once. Prefer it high.
pub const default_max_connections = 10_000

/// How much a connection may send before its target has been reached.
///
/// The target is reached inside `with_connect_timeout`, so without a bound
/// this is "as much as the peer can push in ten seconds", held in one process's
/// memory. 256 KiB is far more than any first request and far less than that.
pub const default_max_pending_bytes = 262_144

/// How much may be queued for the target before the client stops being read.
///
/// Writes to the upstream process are asynchronous, so a client faster than the
/// target it is talking to grows that process's mailbox without limit. At this
/// mark the handler waits for the target to catch up, which — because glisten
/// re-arms a socket when its handler returns — is what stops the client.
pub const default_max_outstanding_bytes = 262_144

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
  /// The replay filter could not answer, so nothing was relayed.
  ///
  /// Not a prober — this one is the server's own fault. It is a `Probe` rather
  /// than its own kind of event because the connection is treated exactly like
  /// one: a guard that cannot answer has not said yes, and relaying anyway
  /// would drop the guarantee precisely when it is least able to be checked.
  GuardUnavailable
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
  /// Turned away because `with_max_connections` was reached. The only event
  /// such a connection produces: there is no `Accepted` and no `Finished` for
  /// it, so the two still balance.
  Refused
  /// Closed for sending more before its target was reached than
  /// `with_max_pending_bytes` allows.
  Overflowed(held: Int)
  /// Closed for having said nothing for `with_idle_timeout`.
  Idled
  /// The relay stopped because something on a socket failed, rather than
  /// because either end finished.
  ///
  /// `Finished` follows, as it does for every other ending. This is here
  /// because a relay that reports only "finished" cannot tell an operator the
  /// difference between a client that hung up and a target that reset, and
  /// those have different causes.
  Broke(reason: Fault)
  Finished
}

/// What failed on a connection that broke.
pub type Fault {
  /// A read or a write on the socket to the target.
  Target(reason: mug.Error)
  /// A write to the client.
  Client(reason: socket.SocketReason)
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
    idle_timeout: Int,
    max_connections: Int,
    max_pending_bytes: Int,
    max_outstanding_bytes: Int,
    /// Filled in by `start`; a builder never carries one.
    counting: Option(Tally),
    interface: String,
    watching: fn(Event) -> Nil,
  )
}

pub opaque type Server {
  Server(port: Int, control: Subject(Command), counting: Tally)
}

/// What the process owning the listener accepts. Sent by `stop`.
pub opaque type Command {
  Stop
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
    idle_timeout: default_idle_timeout,
    max_connections: default_max_connections,
    max_pending_bytes: default_max_pending_bytes,
    max_outstanding_bytes: default_max_outstanding_bytes,
    counting: None,
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

/// How long an established connection may say nothing before it is closed.
///
/// Pass 0 to allow silence for ever, which is what this did before the option
/// existed. Only the handshake was bounded then, so an authenticated peer could
/// hold two processes and two sockets indefinitely by going quiet.
pub fn with_idle_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, idle_timeout: milliseconds)
}

/// How many connections may be live at once.
///
/// At the ceiling, new connections are closed at once and `Refused` is
/// reported. That is visible from the outside in a way `Drain` is not, so it
/// is a bound on resource exhaustion bought with a little concealment; prefer
/// it high rather than tight.
pub fn with_max_connections(builder: Builder, connections: Int) -> Builder {
  Builder(..builder, max_connections: connections)
}

/// How much a connection may send before its target has been reached.
pub fn with_max_pending_bytes(builder: Builder, bytes: Int) -> Builder {
  Builder(..builder, max_pending_bytes: bytes)
}

/// How much may be queued for the target before the client stops being read.
pub fn with_max_outstanding_bytes(builder: Builder, bytes: Int) -> Builder {
  Builder(..builder, max_outstanding_bytes: bytes)
}

/// How long a connection may wait for the replay filter to answer.
///
/// The filter is one process shared by every connection and, when it is shared
/// with a UDP relay, by every datagram too. A busy one is the reason this is
/// not the same number as every other timeout here.
pub fn with_guard_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, guard_timeout: milliseconds)
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
  use settings <- result.try(resolve_interface(builder))
  use settings <- result.try(resolve_guard(settings))

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

/// Hold the listener's supervisor, and take it down when told to.
///
/// `glisten.start` links its supervisor to whoever calls it, so without this
/// process that would be the caller of `start` — and `stop` would then have to
/// reach into another process's links to take it down, which is only safe when
/// `stop` happens to be called from the same process as `start`. Owning it here
/// makes the two independent. It is also the shape `ssocks/udp` already uses.
fn own(
  settings: Builder,
  port: Int,
  ready: Subject(Result(Server, StartError)),
) -> Nil {
  let name = process.new_name("ssocks_server")
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
        Ok(Server(glisten.get_server_info(name, 5000).port, control, counting)),
      )

      let Stop = process.receive_forever(control)

      // `shutdown` rather than a kill. This process is the one that called
      // `glisten.start`, so it is the supervisor's parent, and OTP reads a
      // `shutdown` exit from a parent as an orderly stop: children are
      // terminated in turn and nothing is written to the log. A kill also
      // works and is two lines shorter, but it makes every `stop` print a
      // supervisor crash report, which trains an operator to ignore them.
      //
      // Unlinked first so this process's own exit stays normal and whoever
      // called `start` is not taken down with it.
      let watching = process.monitor(started.pid)
      process.unlink(started.pid)
      process.send_abnormal_exit(started.pid, atom.create("shutdown"))

      // The listening socket is closed by the runtime as its owner ends, so
      // waiting here is what makes `stop`'s promise about the port true:
      // without it this process could return while the port was still held.
      process.new_selector()
      |> process.select_specific_monitor(watching, fn(_) { Nil })
      |> process.selector_receive_forever

      // The counter is linked to this process, which is about to end normally
      // — and a normal exit does not travel down a link. Nothing would ever
      // collect it otherwise.
      let assert Some(counting) = settings.counting
      let _ = tally.stop(counting)
      Nil
    }
  }
}

/// Why a server could not start.
///
/// Both cases come down to a process that would not start, but they are worth
/// telling apart: one is a port problem and the other is not.
pub type StartError {
  CouldNotListen(reason: actor.StartError)
  /// The replay filter would not start.
  CouldNotGuard(reason: actor.StartError)
  /// `bind` was given something that is not an address this machine could
  /// listen on. Refused rather than ignored: the fallback would be every
  /// interface, and a typo would publish a server the operator meant to keep
  /// on one address.
  BadInterface(interface: String)
  /// The listener did not report back in time.
  DidNotStart
  /// The connection counter would not start.
  CouldNotCount(reason: actor.StartError)
}

/// glisten panics on an interface it cannot parse, so it is checked here first.
///
/// The three names it special-cases are accepted verbatim; anything else has to
/// be an address `glip` can read, which is the same question glisten's own
/// parser asks.
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

/// Long enough for a listener on a slow machine, short enough that a caller is
/// not left waiting on a process that is never going to answer.
const start_timeout = 5000

/// Long enough for a full pool of connections to end, short enough that a
/// listener which is never going to answer does not hold up the caller.
const stop_timeout = 5000

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

/// How many connections are live right now.
///
/// `Error(Nil)` means there was nobody to answer: the server was stopped, or it
/// went down, or it did not reply inside the timeout. Asking is the sort of
/// thing a caller does on a timer to draw a graph, and a caller on a timer
/// should not be brought down by the server it is watching going away.
pub fn connections(server: Server, within timeout: Int) -> Result(Int, Nil) {
  tally.count(server.counting, within: timeout)
}

/// Stop listening and drop every connection.
///
/// Waits for the listener to be gone before returning. A listening socket is
/// closed by the runtime as its owner ends, so a `stop` that returned first
/// would leave a window in which the port is still taken by a server that has
/// been told to stop — which is exactly when a caller rebinds it.
///
/// `Error(Nil)` means that did not happen inside `stop_timeout` and the server
/// is still there, holding its port. The waiting is the whole point of this
/// function, so returning `Ok` when the wait ran out would be a promise about
/// the port that it cannot keep.
///
/// Connections are dropped rather than drained, and `on_close` does not run for
/// them. A server told to stop is one whose port somebody wants back.
///
/// glisten may log a failed accept while this happens: an acceptor blocked on a
/// socket that is being closed under it loses the race and says so. Harmless,
/// and not something this side can order differently — the listening socket and
/// the acceptors are children of the same supervisor.
pub fn stop(server: Server) -> Result(Nil, Nil) {
  case process.subject_owner(server.control) {
    // Nothing to wait for; being gone is what was asked for.
    Error(Nil) -> Ok(Nil)
    Ok(running) -> {
      let watching = process.monitor(running)
      process.send(server.control, Stop)

      let stopped =
        process.new_selector()
        |> process.select_specific_monitor(watching, fn(_) { Nil })
        |> process.selector_receive(stop_timeout)

      process.demonitor_process(watching)
      stopped
    }
  }
}

// --- one connection -----------------------------------------------------------

/// What a connection's process selects on besides its client socket.
type Notice {
  FromUpstream(upstream.Event)
  HandshakeOverdue
  CloseOverdue
  IdleOverdue
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
    /// How much `held` adds up to, so the cap costs no walking of the list.
    held_bytes: Int,
    /// Bytes queued for the upstream since it last said it had caught up.
    outstanding: Int,
    /// When something last went either way, for the idle timeout. Monotonic,
    /// so a clock correction cannot move the deadline.
    last_activity: Int,
    /// Whether a place was taken in the connection count. A connection turned
    /// away at the ceiling never took one, and must not give one back.
    accepted: Bool,
    target: Option(address.Address),
    salt_checked: Bool,
    probing: Bool,
  )
}

fn open(settings: Builder) -> #(Session, Option(process.Selector(Notice))) {
  let notices = process.new_subject()
  let from_upstream = process.new_subject()

  // Claiming and counting are one message, so two connections cannot both read
  // one place left and both take it.
  let accepted = case settings.counting {
    None -> True
    Some(counting) ->
      case
        tally.claim(
          counting,
          settings.max_connections,
          within: settings.guard_timeout,
        )
      {
        Ok(_) -> True
        Error(Nil) -> False
      }
  }

  case accepted {
    True -> settings.watching(Accepted)
    False -> {
      settings.watching(Refused)
      // Already in this process's mailbox, so the handler stops the moment it
      // starts selecting. There is nothing to drain: at the ceiling there is
      // no room to hold the socket open either.
      process.send(notices, CloseOverdue)
    }
  }

  // A connection that opens and says nothing is one of the three things a
  // prober does, so it gets the same answer as the other two.
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
      decoder: stream.decoder(settings.session),
      encoder: None,
      notices:,
      from_upstream:,
      upstream: None,
      pending: <<>>,
      held: [],
      held_bytes: 0,
      outstanding: 0,
      last_activity: clock.now_ms(),
      accepted:,
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
    glisten.Packet(bytes) -> from_client(touch(state), bytes)
    glisten.User(FromUpstream(event)) ->
      from_target(touch(state), event, connection)

    glisten.User(IdleOverdue) -> idle(state)

    glisten.User(HandshakeOverdue) ->
      case state.target, state.probing {
        // Already through, or already being drained: the timer is stale.
        Some(_), _ | _, True -> glisten.continue(state)
        None, False -> probed(state, Silent)
      }

    glisten.User(CloseOverdue) -> finish(state)
  }
}

/// Something went either way, so the connection is not idle.
///
/// A timestamp rather than a timer: re-arming one per packet would leave a
/// pending timer per packet until each fired, which on a busy connection is
/// hundreds of thousands of them. `idle` re-arms once per quiet period instead.
fn touch(state: Session) -> Session {
  Session(..state, last_activity: clock.now_ms())
}

/// The idle timer fired. Close, or set it again for the time that is left.
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
            Error(probe) -> probed(state, probe)
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

/// Record the salt once, after the first chunk has authenticated and before
/// anything is relayed.
///
/// Waiting for the authentication matters. The salt is readable from the first
/// 32 bytes, long before any chunk has been checked, and recording it there
/// would let anyone who can open a socket put an entry in the filter by sending
/// 32 bytes of noise. The filter is bounded (`replay.default_capacity`) and is
/// meant to be shared with the UDP relay, so that is a way to fill it from the
/// outside and have it start refusing honest traffic on both transports.
///
/// Nothing is lost by waiting: reaching the target needs the address header,
/// the address header is inside the first chunk, and the first chunk has to
/// authenticate before it can be read. A replayed handshake is still a valid
/// stream, so it still authenticates, and it is still refused here — before
/// `handshake` runs.
fn check_salt(state: Session) -> Result(Session, Probe) {
  case
    state.salt_checked,
    state.settings.sharing,
    stream.salt(state.decoder),
    stream.chunks_read(state.decoder)
  {
    // Already recorded, nothing to record it in, no salt yet, or nothing has
    // authenticated yet.
    True, _, _, _ | _, NoGuard, _, _ | _, _, None, _ | _, _, _, 0 -> Ok(state)

    False, SharedGuard(guard), Some(salt), _ ->
      case
        replay_guard.observe(guard, salt, within: state.settings.guard_timeout)
      {
        Ok(Nil) -> Ok(Session(..state, salt_checked: True))
        Error(replay_guard.Refused(reason)) -> Error(Replayed(reason))
        Error(replay_guard.Unavailable) -> Error(GuardUnavailable)
      }

    // Unreachable: `start` replaces OwnGuard with a real one before listening.
    False, OwnGuard, Some(_), _ -> Ok(state)
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
        Session(
          ..state,
          target: Some(target),
          pending: <<>>,
          held: [],
          held_bytes: 0,
        )

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

    size, Some(commands) -> {
      process.send(commands, upstream.Write(payload))
      let outstanding = state.outstanding + size

      case outstanding >= state.settings.max_outstanding_bytes {
        False -> glisten.continue(Session(..state, outstanding:))

        // Enough is queued for the target; wait for it to catch up before
        // reading the client again. glisten re-arms this connection's socket
        // when the handler returns, so not returning yet is the flow control.
        True -> {
          upstream.drain(commands, within: drain_timeout)
          glisten.continue(Session(..state, outstanding: 0))
        }
      }
    }

    // The target is still being reached. Hold it; `Ready` will flush.
    size, None -> {
      let held_bytes = state.held_bytes + size

      case held_bytes > state.settings.max_pending_bytes {
        True -> {
          state.settings.watching(Overflowed(held_bytes))
          finish(state)
        }
        False ->
          glisten.continue(
            Session(..state, held: [payload, ..state.held], held_bytes:),
          )
      }
    }
  }
}

/// How long the handler will wait for a target to catch up before giving up on
/// the connection. Generous: a slow target is not a broken one, and the client
/// is not being read meanwhile, so nothing is accumulating while it waits.
const drain_timeout = 30_000

fn from_target(
  state: Session,
  event: upstream.Event,
  connection: glisten.Connection(Notice),
) -> glisten.Next(Session, glisten.Message(Notice)) {
  case event {
    upstream.Ready(commands) -> {
      upstream.flush(commands, state.held)
      glisten.continue(
        Session(
          ..state,
          upstream: Some(commands),
          held: [],
          held_bytes: 0,
          outstanding: state.held_bytes,
        ),
      )
    }

    upstream.Arrived(bytes) -> to_client(state, bytes, connection)

    upstream.Unreachable(reason) -> {
      state.settings.watching(TargetUnreachable(reason))
      finish(state)
    }

    upstream.Gone(upstream.Closed) -> finish(state)

    upstream.Gone(upstream.Failed(reason)) -> {
      state.settings.watching(Broke(Target(reason)))
      finish(state)
    }
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
    Ok(_) -> {
      // The target is not read again until this is sent, so a target faster
      // than the client cannot fill this process's mailbox with replies.
      case state.upstream {
        Some(commands) -> process.send(commands, upstream.More)
        None -> Nil
      }
      glisten.continue(Session(..state, encoder: Some(encoder)))
    }
    Error(reason) -> {
      state.settings.watching(Broke(Client(reason)))
      finish(state)
    }
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
  closed(state)
  glisten.stop()
}

/// The connection ended. Let go of the target, and say so.
///
/// glisten calls this when the client's socket closes, and then ends the
/// handler process normally. A normal exit does not travel down the link to the
/// upstream process, so without this the socket to the target — and the process
/// holding it — would outlive the client, parked on a selector waiting for a
/// message that is never coming. That is one leaked process and one leaked file
/// descriptor for every client that hangs up, which is every client.
///
/// `Finished` belongs here for the same reason: without it `Accepted` and
/// `Finished` do not balance, and a caller counting live connections from
/// `watching` climbs for ever.
///
/// `finish` calls it too, and the two cannot both fire: glisten runs `on_close`
/// for a closed socket, not for a handler that chose to stop.
fn closed(state: Session) -> Nil {
  case state.upstream {
    Some(commands) -> process.send(commands, upstream.Close)
    None -> Nil
  }

  // A connection turned away at the ceiling never took a place in the count and
  // never reported `Accepted`, so it gives nothing back and reports no
  // `Finished` either. The two stay balanced.
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
