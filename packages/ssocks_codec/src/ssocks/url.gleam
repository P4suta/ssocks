//// The `ss://` URL a provider hands out.
////
//// This is usually the first thing a user of this library touches, and often
//// the only configuration they have: a single line, pasted from a web page or
//// scanned from a QR code. Three forms of it are in circulation and all three
//// are accepted here, because a library that reads two of them is a library
//// that fails for a third of its users.
////
//// ### The three forms
////
//// - SIP002 with base64 credentials, `ss://<base64 of method:password>@host:port`
//// - SIP002 written out, `ss://method:percent-encoded-password@host:port`
//// - the pre-SIP002 form, where everything after `ss://` is one base64 blob
////   that contains the `@` and the host as well
////
//// A `?plugin=` query and a `#tag` fragment are kept in all three. Dropping a
//// plugin quietly would produce a configuration that connects to a server
//// expecting an obfuscation layer that is not there, and fails in a way that
//// looks like a wrong password.
////
//// ### Why this does not use `gleam/uri`
////
//// It was tried first, and it silently produces wrong answers here. The legacy
//// form's payload is base64, the standard alphabet contains `/`, and a `/` in
//// an authority is the start of a path — so `uri.parse` returns `Ok` with the
//// blob truncated at that byte and the remainder filed under `path`. The same
//// happens to a standard-alphabet userinfo, where the `userinfo` field comes
//// back empty and the host is a fragment of the credentials.
////
//// Splitting an `ss://` URL is a handful of unambiguous cuts, so those are made
//// here. The genuinely fiddly parts — percent coding, base64, and reading a
//// host and port — are still stdlib and `ssocks/address`.
////
//// ### What an error may say
////
//// A parse failure is the moment a caller most wants to print the input, and
//// the input is a credential. So no error in this module repeats text that
//// could be part of a password. They name the shape of the problem and the
//// field it was in.
////
//// Two things are named, and the line between them is structural rather than a
//// judgement call. The scheme and the method are said out loud: a scheme ends
//// at the first `://` and a method ends at the first `:` of the credentials,
//// and a password begins after that colon, so neither can be password text.
//// What follows the last `@` is not said, because it is the authority only if
//// that `@` was the separator — for a password containing one, with the host
//// left out, the text there is the tail of the password, and that is exactly
//// the case where reading it fails and an error is produced.
////
//// The same applies to a `Config` that parsed: `echo` and `string.inspect`
//// reach inside opaque types, so use `redacted` where one has to be printed.
//// `to_string` is the exception, and returns a credential by design — it is
//// how a configuration is handed to somebody else.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import ssocks/address.{type Address}
import ssocks/key.{type Key}
import ssocks/method.{type Method}

/// Everything an `ss://` URL says.
pub opaque type Config {
  Config(
    method: Method,
    password: String,
    server: Address,
    tag: Option(String),
    plugin: Option(Plugin),
  )
}

/// A SIP003 plugin, named and configured but not run.
///
/// Executing one is out of scope here; this module reads and writes the field
/// so that a URL survives a round trip through it unchanged.
pub type Plugin {
  Plugin(name: String, arguments: Option(String))
}

/// Which part of a URL an escape was wrong in.
///
/// Named rather than quoted: the contents of these fields are exactly what
/// must not appear in an error.
pub type UrlField {
  Password
  Tag
  PluginArguments
}

/// Why some text could not be a Shadowsocks URL.
pub type UrlError {
  /// Not a URL at all, or a URL of some other scheme. The scheme is named when
  /// there was one, since a scheme is not a secret and is usually the mistake.
  NotShadowsocks(scheme: Option(String))
  /// The `ss://` was there and nothing followed it.
  MissingCredentials
  /// Credentials that are neither `method:password` nor base64 of it.
  MalformedCredentials
  /// A method this library will not use. Carries the reason, and so the method
  /// name, so the caller can say which cipher and why rather than "invalid
  /// URL". Safe because a method is structurally the text before the first
  /// colon and a password is the text after it.
  UnsupportedMethod(reason: method.UnsupportedMethod)
  /// The host and port could not be read as a server address. Names the kind
  /// of problem and never the text; see `ServerProblem`.
  BadServer(problem: ServerProblem)
  /// A percent escape that is not one, in the named field.
  MalformedEscape(field: UrlField)
}

/// What was wrong with the part that should have been a host and a port.
///
/// Deliberately without the text, which is the one error here that cannot
/// quote its input. The authority is whatever follows the last `@`, which is
/// right whenever there is a host and wrong when the password contains an `@`
/// and the host was left out — and that second case is precisely the one where
/// the authority fails to parse, so it is the case that produces this error.
/// From inside there is no way to tell them apart, so nothing is repeated.
pub type ServerProblem {
  /// Shadowsocks has no default port, so one has to be written.
  NoPort
  PortNotANumber
  PortOutOfRange
  NoHost
  HostTooLong
  MalformedIpv6
  MalformedHost
}

// --- reading ------------------------------------------------------------------

/// Read a URL a provider handed out.
pub fn parse(text: String) -> Result(Config, UrlError) {
  use body <- result.try(after_scheme(text))

  // The fragment comes off first, because it is everything after the first
  // `#`. A tag may legally contain an `@` or a `?`, and cutting the authority
  // before the fragment would read one of those as a separator.
  let #(body, fragment) = split_first(body, "#")
  let #(body, query) = split_first(body, "?")
  let body = drop_trailing_slash(body)

  use #(name, password, authority) <- result.try(credentials_and_authority(body))
  use chosen <- result.try(
    method.from_string(name) |> result.map_error(UnsupportedMethod),
  )
  use where <- result.try(
    address.parse(authority)
    |> result.map_error(fn(reason) { BadServer(server_problem(reason)) }),
  )
  use tag <- result.try(percent_decoded(fragment, Tag))
  use plugin <- result.try(plugin_of(query))

  Ok(Config(chosen, password, where, tag, plugin))
}

/// Keep the kind and drop the text.
///
/// `address.AddressError` quotes what it was given, which is right for a module
/// whose input is an address. Here the same string may be the tail of a
/// password, so only the shape of the problem survives the crossing.
fn server_problem(reason: address.AddressError) -> ServerProblem {
  case reason {
    address.MissingPort(_) -> NoPort
    address.MalformedPort(_) -> PortNotANumber
    address.PortOutOfRange(_) -> PortOutOfRange
    address.EmptyDomain -> NoHost
    address.DomainTooLong(_) -> HostTooLong
    address.MalformedIpv6(_) -> MalformedIpv6
    address.OctetOutOfRange(_) -> MalformedHost
    address.GroupOutOfRange(_) -> MalformedHost
    address.WrongGroupCount(_) -> MalformedHost
  }
}

fn after_scheme(text: String) -> Result(String, UrlError) {
  case string.split_once(text, "://") {
    Error(Nil) -> Error(NotShadowsocks(None))
    Ok(#(scheme, rest)) ->
      case string.lowercase(scheme) {
        "ss" -> Ok(rest)
        _ -> Error(NotShadowsocks(Some(scheme)))
      }
  }
}

/// Separate the credentials from the host, whichever form they arrived in.
///
/// An `@` in what is left after the fragment and query decides it: neither
/// base64 alphabet contains one, so the legacy form — which hides its `@`
/// inside the blob — is exactly the case where there is none.
fn credentials_and_authority(
  body: String,
) -> Result(#(String, String, String), UrlError) {
  case split_last(body, "@") {
    Some(#(userinfo, authority)) -> {
      use #(name, password) <- result.try(userinfo_credentials(userinfo))
      Ok(#(name, password, authority))
    }
    None -> legacy_credentials(body)
  }
}

fn userinfo_credentials(
  userinfo: String,
) -> Result(#(String, String), UrlError) {
  case userinfo {
    "" -> Error(MissingCredentials)
    _ ->
      case string.split_once(userinfo, ":") {
        // Written out. Neither base64 alphabet contains a colon, so a colon
        // here is the plaintext form, where the password is percent-encoded.
        Ok(#(name, encoded)) -> {
          use password <- result.try(
            uri.percent_decode(encoded)
            |> result.replace_error(MalformedEscape(Password)),
          )
          Ok(#(name, password))
        }
        // Otherwise base64 of `method:password`, verbatim and not escaped.
        Error(Nil) ->
          decode_base64_text(userinfo) |> result.try(method_and_password)
      }
  }
}

fn legacy_credentials(
  body: String,
) -> Result(#(String, String, String), UrlError) {
  case body {
    "" -> Error(MissingCredentials)
    _ -> {
      use decoded <- result.try(decode_base64_text(body))
      case split_last(decoded, "@") {
        None -> Error(MalformedCredentials)
        Some(#(credentials, authority)) -> {
          use #(name, password) <- result.try(method_and_password(credentials))
          Ok(#(name, password, authority))
        }
      }
    }
  }
}

/// Split at the first colon only. A password may contain colons; a method name
/// may not, so the first one is the separator and the rest is the password.
fn method_and_password(text: String) -> Result(#(String, String), UrlError) {
  string.split_once(text, ":") |> result.replace_error(MalformedCredentials)
}

/// Decode either alphabet.
///
/// SIP002 asks for the websafe one, but standard-alphabet URLs are handed out
/// in the wild and refusing one helps nobody. The two alphabets differ in two
/// characters, so a string valid in one is almost never valid in the other.
fn decode_base64_text(encoded: String) -> Result(String, UrlError) {
  let bytes = case bit_array.base64_url_decode(encoded) {
    Ok(bytes) -> Ok(bytes)
    Error(Nil) -> bit_array.base64_decode(encoded)
  }

  bytes
  |> result.try(bit_array.to_string)
  |> result.replace_error(MalformedCredentials)
}

fn percent_decoded(
  value: Option(String),
  field: UrlField,
) -> Result(Option(String), UrlError) {
  case value {
    None -> Ok(None)
    Some(text) ->
      uri.percent_decode(text)
      |> result.map(Some)
      |> result.replace_error(MalformedEscape(field))
  }
}

fn plugin_of(query: Option(String)) -> Result(Option(Plugin), UrlError) {
  case query {
    None -> Ok(None)
    Some(text) ->
      case plugin_parameter(string.split(text, "&")) {
        None -> Ok(None)
        Some(raw) -> {
          use decoded <- result.try(
            uri.percent_decode(raw)
            |> result.replace_error(MalformedEscape(PluginArguments)),
          )
          // SIP003 packs the name and its options into one value, separated by
          // a semicolon; options may contain further semicolons of their own.
          case string.split_once(decoded, ";") {
            Ok(#(name, arguments)) -> Ok(Some(Plugin(name, Some(arguments))))
            Error(Nil) -> Ok(Some(Plugin(decoded, None)))
          }
        }
      }
  }
}

fn plugin_parameter(pairs: List(String)) -> Option(String) {
  case pairs {
    [] -> None
    [first, ..rest] ->
      case string.split_once(first, "=") {
        Ok(#("plugin", value)) -> Some(value)
        _ -> plugin_parameter(rest)
      }
  }
}

// --- building -----------------------------------------------------------------

/// A configuration for a server, without a tag or a plugin.
pub fn new(chosen: Method, password: String, where: Address) -> Config {
  Config(chosen, password, where, None, None)
}

/// Name this configuration. The tag is a label for humans and carries no
/// protocol meaning.
pub fn with_tag(config: Config, tag: String) -> Config {
  Config(..config, tag: Some(tag))
}

pub fn without_tag(config: Config) -> Config {
  Config(..config, tag: None)
}

pub fn with_plugin(config: Config, plugin: Plugin) -> Config {
  Config(..config, plugin: Some(plugin))
}

pub fn without_plugin(config: Config) -> Config {
  Config(..config, plugin: None)
}

// --- reading one back out -----------------------------------------------------

pub fn method(config: Config) -> Method {
  config.method
}

pub fn server(config: Config) -> Address {
  config.server
}

pub fn tag(config: Config) -> Option(String) {
  config.tag
}

pub fn plugin(config: Config) -> Option(Plugin) {
  config.plugin
}

/// The master key this URL describes.
///
/// Derived on each call rather than stored, so a `Config` holds a password and
/// a `Key` holds key material and neither one is quietly both.
pub fn key(config: Config) -> Key {
  key.from_password(config.method, config.password)
}

/// Write the URL back out, in the SIP002 base64 form.
///
/// **This returns a credential.** Anyone holding the result can connect as the
/// user it describes, so it belongs in a config file or a QR code and not in a
/// log line. Use `redacted` for the latter.
///
/// The output is canonical rather than a copy of whatever was parsed: the
/// written-out and legacy forms both come back as SIP002 base64, and escapes
/// are normalised. `parse` of the result is equal to the configuration it came
/// from, which is the direction that has to hold.
pub fn to_string(config: Config) -> String {
  let credentials = method.to_string(config.method) <> ":" <> config.password

  "ss://"
  <> bit_array.base64_url_encode(<<credentials:utf8>>, False)
  <> "@"
  <> address.to_string(config.server)
  <> plugin_query(config.plugin)
  <> tag_fragment(config.tag)
}

/// How to render a configuration where one must be rendered.
///
/// Everything except the password, which is replaced by a fixed marker. Two
/// configurations differing only in their password render identically, on
/// purpose: a rendering that varied with the secret would be a distinguisher.
pub fn redacted(config: Config) -> String {
  "ss://"
  <> method.to_string(config.method)
  <> ":<redacted>@"
  <> address.to_string(config.server)
  <> plugin_query(config.plugin)
  <> tag_fragment(config.tag)
}

fn plugin_query(plugin: Option(Plugin)) -> String {
  case plugin {
    None -> ""
    Some(Plugin(name, arguments)) -> {
      let value = case arguments {
        None -> name
        Some(arguments) -> name <> ";" <> arguments
      }
      "?plugin=" <> uri.percent_encode(value)
    }
  }
}

fn tag_fragment(tag: Option(String)) -> String {
  case tag {
    None -> ""
    Some(text) -> "#" <> uri.percent_encode(text)
  }
}

/// A sentence for a person, for the errors this module returns.
pub fn explain(reason: UrlError) -> String {
  case reason {
    NotShadowsocks(None) ->
      "this is not a URL: a Shadowsocks URL starts with ss:// ."
    NotShadowsocks(Some(scheme)) ->
      "this is a "
      <> scheme
      <> ":// URL, and a Shadowsocks URL starts with ss:// ."
    MissingCredentials ->
      "the URL has an ss:// and nothing after it. It should carry a method and "
      <> "a password, either base64 encoded or written as method:password ."
    MalformedCredentials ->
      "the credentials could not be read. They should be method:password, "
      <> "either written out or base64 encoded; the base64 here either does "
      <> "not decode, is not text, or has no colon in it."
    UnsupportedMethod(reason) -> method.explain(reason)
    BadServer(problem) ->
      "the part after the @ could not be read as a host and port: "
      <> case problem {
        NoPort ->
          "there is no port. Shadowsocks has no default port, so one has to "
          <> "be written. If the password contains an @, note that the host "
          <> "is read from after the last one."
        PortNotANumber -> "the port is not a number."
        PortOutOfRange -> "the port is not in 0-65535."
        NoHost -> "there is no host."
        HostTooLong ->
          "the host name is longer than the 255 bytes that fit in the protocol."
        MalformedIpv6 -> "the bracketed IPv6 address is not well formed."
        MalformedHost -> "the host is not well formed."
      }
    MalformedEscape(Password) ->
      "the password contains a percent escape that is not valid."
    MalformedEscape(Tag) ->
      "the tag after the # contains a percent escape that is not valid."
    MalformedEscape(PluginArguments) ->
      "the plugin= value contains a percent escape that is not valid."
  }
}

// --- text ---------------------------------------------------------------------

fn split_first(text: String, on: String) -> #(String, Option(String)) {
  case string.split_once(text, on) {
    Ok(#(before, after)) -> #(before, Some(after))
    Error(Nil) -> #(text, None)
  }
}

/// Split at the last occurrence, so that a userinfo which somehow contains an
/// unescaped `@` still separates from the host at the right one.
fn split_last(text: String, on: String) -> Option(#(String, String)) {
  case list.reverse(string.split(text, on)) {
    [] | [_] -> None
    [last, ..before] -> Some(#(string.join(list.reverse(before), on), last))
  }
}

fn drop_trailing_slash(text: String) -> String {
  case string.ends_with(text, "/") {
    True -> string.drop_end(text, 1)
    False -> text
  }
}
