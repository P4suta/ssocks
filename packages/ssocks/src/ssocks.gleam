//// Shadowsocks, from the outside.
////
//// Paste the URL a provider gave you and connect:
////
//// ```gleam
//// import ssocks
////
//// pub fn main() {
////   let assert Ok(config) = ssocks.from_uri("ss://…@example.com:8388#Tokyo")
////   use connection <- ssocks.with_connection(config, "example.org:443", 5000)
////   let assert Ok(connection) = ssocks.send(connection, <<"GET / HTTP/1.1\r\n\r\n":utf8>>)
////   ssocks.receive(connection, within: 5000)
//// }
//// ```
////
//// That is the whole client. The salt, the key derivation, the nonce counters,
//// the chunk boundaries and the target address header are all below this line.
////
//// This module is a façade and holds no logic of its own. Everything here is
//// `ssocks/url` and `ssocks/client`, and either can be used directly when the
//// shorter path does not fit — a caller running its own event loop wants
//// `ssocks/client`, and a caller that only reads configuration wants
//// `ssocks/url` from `ssocks_codec`, which has no sockets in it at all.
////
//// ### The other four roles are not here
////
//// This covers one of them: a client, opening one connection to one target.
//// The rest have modules of their own, because each has a builder's worth of
//// decisions that do not belong behind a one-line façade:
////
//// - `ssocks/local` — a SOCKS5 proxy a browser can be pointed at
//// - `ssocks/server` — the server side, with the anti-probing policy
//// - `ssocks/udp` — the UDP relay, with its NAT table
//// - `ssocks/udp_client` — the client side of that

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import ssocks/client
import ssocks/url

/// A configuration: which server, which cipher, which password.
pub type Config =
  url.Config

/// An open connection through a server to one target.
pub type Connection =
  client.Connection

/// Why an `ss://` URL could not be read. `explain_config` puts it in words.
pub type ConfigError =
  url.UrlError

/// Why a connection could not be made or used. `explain` puts it in words.
pub type Error =
  client.ClientError

/// Read an `ss://` URL.
///
/// All three forms in circulation are accepted. See `ssocks/url` for what a
/// refusal means and for building a configuration without a URL.
pub fn from_uri(text: String) -> Result(Config, ConfigError) {
  url.parse(text)
}

/// Open a connection through the server to `target`, given as `host:port`.
///
/// `within` bounds reaching the Shadowsocks server, not later reads.
pub fn connect(
  config: Config,
  to target: String,
  within timeout: Int,
) -> Result(Connection, Error) {
  client.connect(config, to: target, within: timeout)
}

/// Open a connection, hand it to `run`, and close it however that ends.
///
/// Written for `use`:
///
/// ```gleam
/// use connection <- ssocks.with_connection(config, "example.org:443", 5000)
/// ```
pub fn with_connection(
  config: Config,
  target: String,
  timeout: Int,
  run: fn(Connection) -> a,
) -> Result(a, Error) {
  case client.connect(config, to: target, within: timeout) {
    Error(reason) -> Error(reason)
    Ok(connection) -> {
      let produced = run(connection)
      client.close(connection)
      Ok(produced)
    }
  }
}

/// Send bytes to the target. Any length; the chunking is handled below.
pub fn send(
  connection: Connection,
  payload: BitArray,
) -> Result(Connection, Error) {
  client.send(connection, payload)
}

/// Wait up to `within` milliseconds for the target to say something.
pub fn receive(
  connection: Connection,
  within timeout: Int,
) -> Result(#(Connection, BitArray), Error) {
  client.receive(connection, within: timeout)
}

/// How many whole chunks have been read on this connection.
///
/// Diagnostic, and the first thing `docs/debugging.md` asks for: zero chunks
/// and a framing failure is the password or the method, and any other number is
/// the framing having drifted.
pub fn chunks_read(connection: Connection) -> Int {
  client.chunks_read(connection)
}

pub fn close(connection: Connection) -> Nil {
  client.close(connection)
}

/// A sentence for a person, for anything a connection can fail with.
pub fn explain(reason: Error) -> String {
  client.explain(reason)
}

/// A sentence for a person, for a URL that could not be read.
///
/// Separate from `explain` because the two are different types, and having only
/// the first would leave the single-import path unable to explain its own first
/// failure. Neither quotes the URL: a parse failure is exactly when a caller
/// reaches for the text to print it, and the text is a credential.
pub fn explain_config(reason: ConfigError) -> String {
  url.explain(reason)
}
