//// The UDP relay.
////
//// ```gleam
//// let assert Ok(relaying) =
////   udp.relay(key.from_password(method.Aes256Gcm, "hunter2"))
////   |> udp.start(8388)
//// ```
////
//// A Shadowsocks UDP packet stands alone: salt, then one AEAD box holding the
//// target address and the payload, under an all-zero nonce. There is no
//// framing, no ordering and no counter, because there is no stream — every
//// packet is its own session. `ssocks/datagram` does that part, and it has no
//// sockets in it.
////
//// What is left is the association, and it is the whole of the work here.
////
//// ### The table
////
//// UDP has no connections, so a relay has to invent them. Each client address
//// gets a socket of its own to the outside, and replies arriving on that
//// socket are sent back to that client. Without the table the relay would not
//// know who to answer; with it, the relay is a NAT, and inherits every NAT's
//// problem: the entries have to go away by themselves, because nothing will
//// ever tell it that a client has finished.
////
//// Two limits, for two different failure modes. An idle timeout drops what has
//// gone quiet, five minutes by default, which is the conventional figure. A
//// ceiling on the number of entries bounds memory against a flood — and UDP
//// source addresses are trivially forged, so a flood costs an attacker nothing.
//// At the ceiling the least recently used entry is evicted rather than the new
//// packet refused: both are a denial of service against somebody, and evicting
//// keeps recent traffic working.
////
//// ### One process
////
//// Every socket here belongs to this relay, and `toss.Datagram` carries the
//// socket it arrived on, so one process can own all of them and tell them
//// apart. That is not true of the TCP server, where `glisten` owns one socket
//// and cannot be asked which one a raw `{tcp, ...}` message came from — see
//// `ssocks/internal/upstream`.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import glip
import ssocks/address.{type Address}
import ssocks/datagram
import ssocks/internal/clock
import ssocks/key.{type Key}
import ssocks/replay
import ssocks/replay_guard.{type Guard}
import toss

/// Five minutes, the conventional NAT figure for UDP.
pub const default_session_timeout = 300_000

/// How often idle entries are looked for.
pub const default_sweep_interval = 30_000

/// Enough that honest traffic will not reach it on one relay.
pub const default_max_sessions = 10_000

/// Why a packet was not relayed.
pub type Rejection {
  /// It did not authenticate under this key. On UDP this is the ordinary sound
  /// of the internet as much as it is a probe, so nothing is sent back either
  /// way: an answer would say a Shadowsocks relay is here.
  NotAuthentic(reason: datagram.DatagramError)
  Replayed(reason: replay.ReplayError)
  /// The target could not be written to.
  Undeliverable
}

/// Things worth knowing about, for logs and for tests.
///
/// The callback runs inside the relay's own process, so it should be quick.
pub type Event {
  Forwarded(target: Address, bytes: Int)
  Returned(from: Address, bytes: Int)
  Rejected(reason: Rejection)
  /// A client that had no entry now has one.
  SessionOpened(sessions: Int)
  /// Dropped for having gone quiet.
  SessionExpired(sessions: Int)
  /// Dropped to make room, which means the ceiling has been reached and
  /// somebody is probably forging source addresses.
  SessionEvicted(sessions: Int)
}

type Sharing {
  OwnGuard
  SharedGuard(Guard)
  NoGuard
}

pub opaque type Builder {
  Builder(
    session: Key,
    sharing: Sharing,
    session_timeout: Int,
    sweep_interval: Int,
    max_sessions: Int,
    guard_timeout: Int,
    interface: Option(String),
    watching: fn(Event) -> Nil,
  )
}

pub opaque type Relay {
  Relay(port: Int, control: Subject(Message))
}

/// Why a relay could not start.
pub type StartError {
  CouldNotBind(reason: toss.Error)
  /// The replay filter would not start.
  CouldNotGuard
  /// The relay process did not report back in time.
  DidNotStart
}

/// A relay for one key, with the safe defaults.
pub fn relay(session: Key) -> Builder {
  Builder(
    session:,
    sharing: OwnGuard,
    session_timeout: default_session_timeout,
    sweep_interval: default_sweep_interval,
    max_sessions: default_max_sessions,
    guard_timeout: 5000,
    interface: None,
    watching: fn(_) { Nil },
  )
}

/// Share a replay filter with the TCP server under the same key.
///
/// The specification asks that a salt be unique for the lifetime of a master
/// key, and a UDP packet carries a salt. Two filters would let a salt seen over
/// TCP be replayed over UDP.
pub fn with_replay_guard(builder: Builder, guard: Guard) -> Builder {
  Builder(..builder, sharing: SharedGuard(guard))
}

pub fn without_replay_guard(builder: Builder) -> Builder {
  Builder(..builder, sharing: NoGuard)
}

/// How long an association survives without traffic.
pub fn with_session_timeout(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, session_timeout: milliseconds)
}

/// How often to look for associations that have gone quiet.
pub fn with_sweep_interval(builder: Builder, milliseconds: Int) -> Builder {
  Builder(..builder, sweep_interval: milliseconds)
}

/// How many associations may exist at once.
pub fn with_max_sessions(builder: Builder, sessions: Int) -> Builder {
  Builder(..builder, max_sessions: sessions)
}

/// Which interface to listen on. Defaults to all of them.
pub fn bind(builder: Builder, interface: String) -> Builder {
  Builder(..builder, interface: Some(interface))
}

/// Watch what the relay is doing.
pub fn watching(builder: Builder, watcher: fn(Event) -> Nil) -> Builder {
  Builder(..builder, watching: watcher)
}

/// Listen. Pass 0 for a port the operating system chooses, then ask `port`.
pub fn start(builder: Builder, port: Int) -> Result(Relay, StartError) {
  case resolve_guard(builder) {
    Error(reason) -> Error(reason)
    Ok(settings) -> {
      let ready = process.new_subject()
      process.spawn(fn() { boot(settings, port, ready) })

      case process.receive(ready, 5000) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(DidNotStart)
      }
    }
  }
}

fn resolve_guard(builder: Builder) -> Result(Builder, StartError) {
  case builder.sharing {
    SharedGuard(_) | NoGuard -> Ok(builder)
    OwnGuard ->
      case replay_guard.start() {
        Error(_) -> Error(CouldNotGuard)
        Ok(guard) -> Ok(Builder(..builder, sharing: SharedGuard(guard)))
      }
  }
}

/// The port actually listened on.
pub fn port(relaying: Relay) -> Int {
  relaying.port
}

/// How many client associations exist right now.
pub fn sessions(relaying: Relay, within timeout: Int) -> Int {
  process.call(relaying.control, timeout, Sessions)
}

/// Stop listening and drop every association.
pub fn stop(relaying: Relay) -> Nil {
  process.send(relaying.control, Stop)
}

// --- the relay process --------------------------------------------------------

pub opaque type Message {
  Sweep
  Sessions(reply: Subject(Int))
  Stop
}

type Inbox {
  FromCaller(Message)
  FromSocket(toss.UdpMessage)
}

/// One client, and the socket the outside world sees it as.
type Session {
  Session(socket: toss.Socket, host: glip.IpAddress, port: Int, used: Int)
}

type State {
  State(
    settings: Builder,
    listening: toss.Socket,
    /// Keyed by the client's address as text, because a `glip.IpAddress` on
    /// Erlang may keep the string it was parsed from and two spellings of one
    /// address would then be two entries.
    sessions: Dict(String, Session),
    /// Which client a reply socket belongs to.
    owners: Dict(toss.Socket, String),
  )
}

fn boot(
  settings: Builder,
  port: Int,
  ready: Subject(Result(Relay, StartError)),
) -> Nil {
  let options = case settings.interface {
    None -> toss.new(port: port)
    Some(interface) ->
      case glip.parse_ip(interface) {
        Ok(ip) -> toss.using_interface(toss.new(port: port), ip)
        Error(Nil) -> toss.new(port: port)
      }
  }

  case toss.open(options) {
    Error(reason) -> process.send(ready, Error(CouldNotBind(reason)))
    Ok(listening) -> {
      let assert Ok(bound) = toss.local_port(listening)
      let control = process.new_subject()

      process.send(ready, Ok(Relay(bound, control)))
      let _ = toss.receive_next_datagram_as_message(listening)
      let _ = process.send_after(control, settings.sweep_interval, Sweep)

      loop(
        State(settings, listening, dict.new(), dict.new()),
        process.new_selector()
          |> process.select_map(control, FromCaller)
          |> toss.select_udp_messages(FromSocket),
        control,
      )
    }
  }
}

fn loop(
  state: State,
  selector: process.Selector(Inbox),
  control: Subject(Message),
) -> Nil {
  case process.selector_receive_forever(selector) {
    FromCaller(Stop) -> shut_down(state)

    FromCaller(Sessions(reply)) -> {
      process.send(reply, dict.size(state.sessions))
      loop(state, selector, control)
    }

    FromCaller(Sweep) -> {
      let _ = process.send_after(control, state.settings.sweep_interval, Sweep)
      loop(sweep(state), selector, control)
    }

    FromSocket(toss.UdpError(socket, _)) -> {
      // A socket that has errored is no use to the client it belonged to.
      loop(forget(state, socket), selector, control)
    }

    FromSocket(toss.Datagram(socket, host, peer_port, data)) -> {
      let state = case host {
        Error(Nil) -> state
        Ok(host) ->
          case socket == state.listening {
            True -> from_client(state, host, peer_port, data)
            False -> from_target(state, socket, host, peer_port, data)
          }
      }

      // Active-once, on whichever socket this was.
      let _ = toss.receive_next_datagram_as_message(socket)
      loop(state, selector, control)
    }
  }
}

// --- outbound -----------------------------------------------------------------

fn from_client(
  state: State,
  host: glip.IpAddress,
  port: Int,
  data: BitArray,
) -> State {
  case datagram.open(state.settings.session, data) {
    Error(reason) -> {
      state.settings.watching(Rejected(NotAuthentic(reason)))
      state
    }

    Ok(#(target, payload)) ->
      case check_replay(state, data) {
        Error(reason) -> {
          state.settings.watching(Rejected(Replayed(reason)))
          state
        }

        Ok(Nil) -> {
          let #(state, session) = session_for(state, host, port)

          case
            toss.send_to_host(
              session.socket,
              address.host(target),
              address.port(target),
              payload,
            )
          {
            Error(_) -> {
              state.settings.watching(Rejected(Undeliverable))
              state
            }
            Ok(Nil) -> {
              state.settings.watching(Forwarded(
                target,
                bit_array.byte_size(payload),
              ))
              state
            }
          }
        }
      }
  }
}

fn check_replay(
  state: State,
  packet: BitArray,
) -> Result(Nil, replay.ReplayError) {
  case
    state.settings.sharing,
    datagram.salt_of(state.settings.session, packet)
  {
    NoGuard, _ | _, Error(_) -> Ok(Nil)
    SharedGuard(guard), Ok(salt) ->
      replay_guard.observe(guard, salt, within: state.settings.guard_timeout)
    // Unreachable: `start` replaces OwnGuard before the process is spawned.
    OwnGuard, Ok(_) -> Ok(Nil)
  }
}

/// The association for this client, opening one if there is none.
fn session_for(
  state: State,
  host: glip.IpAddress,
  port: Int,
) -> #(State, Session) {
  let name = client_key(host, port)

  case dict.get(state.sessions, name) {
    Ok(session) -> {
      let refreshed = Session(..session, used: clock.now_ms())
      #(
        State(..state, sessions: dict.insert(state.sessions, name, refreshed)),
        refreshed,
      )
    }

    Error(Nil) -> {
      let state = make_room(state)
      let assert Ok(socket) = toss.open(toss.new(port: 0))
      let _ = toss.receive_next_datagram_as_message(socket)

      let session = Session(socket, host, port, clock.now_ms())
      let state =
        State(
          ..state,
          sessions: dict.insert(state.sessions, name, session),
          owners: dict.insert(state.owners, socket, name),
        )

      state.settings.watching(SessionOpened(dict.size(state.sessions)))
      #(state, session)
    }
  }
}

/// At the ceiling, drop the least recently used.
///
/// Refusing the new packet instead would also be a denial of service, against
/// whoever arrived last rather than whoever has been quiet longest, and it
/// would leave a full table permanently full. UDP source addresses are forged
/// for free, so neither answer is good; this one keeps recent traffic working.
fn make_room(state: State) -> State {
  case dict.size(state.sessions) < state.settings.max_sessions {
    True -> state
    False ->
      case oldest(dict.to_list(state.sessions), None) {
        None -> state
        Some(#(name, session)) -> {
          toss.close(session.socket)
          let state =
            State(
              ..state,
              sessions: dict.delete(state.sessions, name),
              owners: dict.delete(state.owners, session.socket),
            )
          state.settings.watching(SessionEvicted(dict.size(state.sessions)))
          state
        }
      }
  }
}

fn oldest(
  entries: List(#(String, Session)),
  best: Option(#(String, Session)),
) -> Option(#(String, Session)) {
  case entries, best {
    [], _ -> best
    [first, ..rest], None -> oldest(rest, Some(first))
    [#(name, session), ..rest], Some(#(_, held)) ->
      case session.used < held.used {
        True -> oldest(rest, Some(#(name, session)))
        False -> oldest(rest, best)
      }
  }
}

// --- inbound ------------------------------------------------------------------

fn from_target(
  state: State,
  socket: toss.Socket,
  host: glip.IpAddress,
  port: Int,
  data: BitArray,
) -> State {
  case dict.get(state.owners, socket) {
    Error(Nil) -> state
    Ok(name) ->
      case dict.get(state.sessions, name), source_address(host, port) {
        Error(Nil), _ | _, Error(Nil) -> state
        Ok(session), Ok(source) -> {
          // Every reply carries its own salt, and the source address of the
          // reply is what the client is told the packet came from.
          let packet = datagram.seal(state.settings.session, source, data)
          let _ =
            toss.send_to(state.listening, session.host, session.port, packet)

          state.settings.watching(Returned(source, bit_array.byte_size(data)))

          State(
            ..state,
            sessions: dict.insert(
              state.sessions,
              name,
              Session(..session, used: clock.now_ms()),
            ),
          )
        }
      }
  }
}

fn source_address(host: glip.IpAddress, port: Int) -> Result(Address, Nil) {
  let text = glip.ip_to_string(host)
  let bracketed = case string.contains(text, ":") {
    True -> "[" <> text <> "]"
    False -> text
  }

  case address.parse(bracketed <> ":" <> int.to_string(port)) {
    Ok(built) -> Ok(built)
    Error(_) -> Error(Nil)
  }
}

// --- housekeeping -------------------------------------------------------------

fn sweep(state: State) -> State {
  let now = clock.now_ms()

  let expired =
    dict.to_list(state.sessions)
    |> list.filter(fn(entry) {
      now - { entry.1 }.used >= state.settings.session_timeout
    })

  case expired {
    [] -> state
    _ -> {
      let state =
        list.fold(expired, state, fn(state, entry) {
          let #(name, session) = entry
          toss.close(session.socket)
          State(
            ..state,
            sessions: dict.delete(state.sessions, name),
            owners: dict.delete(state.owners, session.socket),
          )
        })

      state.settings.watching(SessionExpired(dict.size(state.sessions)))
      state
    }
  }
}

fn forget(state: State, socket: toss.Socket) -> State {
  case dict.get(state.owners, socket) {
    Error(Nil) -> state
    Ok(name) -> {
      toss.close(socket)
      State(
        ..state,
        sessions: dict.delete(state.sessions, name),
        owners: dict.delete(state.owners, socket),
      )
    }
  }
}

fn shut_down(state: State) -> Nil {
  list.each(dict.to_list(state.sessions), fn(entry) {
    toss.close({ entry.1 }.socket)
  })
  toss.close(state.listening)
}

fn client_key(host: glip.IpAddress, port: Int) -> String {
  glip.ip_to_string(host) <> ":" <> int.to_string(port)
}
