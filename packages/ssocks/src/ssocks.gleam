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

pub type ConfigError =
  url.UrlError

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

pub fn close(connection: Connection) -> Nil {
  client.close(connection)
}

/// A sentence for a person, for anything this module can fail with.
pub fn explain(reason: Error) -> String {
  client.explain(reason)
}
