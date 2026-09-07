//// Put a real implementation on the other side of `ss://`.
////
//// `url_test.gleam` compares this module's parser with this module's writer,
//// which cannot tell a correct SIP002 implementation from one that is
//// consistently wrong in both directions. A base64 alphabet mixed up, or a
//// fragment escaped where it should not be, would be produced and consumed
//// the same way here and pass everything while nobody else could read a URL
//// this library writes.
////
//// So `scripts/url-interop.mjs` puts shadowsocks-rust's own `ssurl` on the
//// other end, in both directions: it decodes what this writes, and this parses
//// what it encodes.
////
//// Two modes:
////
////   - `write` prints one tab-separated case per line, for the harness to feed
////     to `ssurl --decode` and check field by field
////   - `read <url> <password>` parses a URL that `ssurl --encode` produced and
////     prints what it found
////
//// The password is never printed. `read` is told what to expect and answers
//// whether the derived key matches, which is the thing that actually has to
//// agree — two implementations that disagree about the password text but
//// derive the same key would still interoperate, and two that agree on the
//// text and derive different keys would not.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import argv
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import ssocks/address
import ssocks/key
import ssocks/method
import ssocks/url

pub fn main() -> Nil {
  case argv.load().arguments {
    ["write"] -> list.each(cases(), write_case)
    ["read", text, password] -> read_case(text, password)
    other -> {
      io.println(
        "url_interop: expected `write` or `read <url> <password>`, got "
        <> string.join(other, " "),
      )
      halt(2)
    }
  }
}

type Case {
  Case(
    name: String,
    chosen: method.Method,
    password: String,
    host: String,
    port: Int,
    tag: Option(String),
    plugin: Option(url.Plugin),
  )
}

/// Passwords and tags here contain no double quote and no backslash, because
/// the harness reads `ssurl`'s output with a regular expression rather than a
/// JSON parser — its output is not quite JSON.
fn cases() -> List(Case) {
  [
    Case("plain", method.Aes256Gcm, "passwd", "example.com", 8388, None, None),
    Case(
      "tagged",
      method.Aes128Gcm,
      "hunter2",
      "192.168.100.1",
      8888,
      Some("Tokyo"),
      None,
    ),
    Case(
      "unicode",
      method.ChaCha20Poly1305,
      "パスワード",
      "example.org",
      443,
      Some("東京 タグ"),
      None,
    ),
    Case(
      "symbols",
      method.Aes256Gcm,
      "p@ss:w#rd?&=/ %+",
      "example.net",
      1080,
      Some("a/b?c#d"),
      None,
    ),
    Case("ipv6", method.Aes256Gcm, "passwd", "[2001:db8::1]", 8388, None, None),
    Case(
      "plugin",
      method.Aes256Gcm,
      "passwd",
      "example.com",
      8388,
      None,
      Some(url.Plugin("v2ray-plugin", Some("mode=quic"))),
    ),
  ]
}

fn write_case(one: Case) -> Nil {
  let assert Ok(where) =
    address.parse(one.host <> ":" <> int.to_string(one.port))

  let config =
    url.new(one.chosen, one.password, where)
    |> apply_tag(one.tag)
    |> apply_plugin(one.plugin)

  // The host as `ssurl` will report it, which is without the brackets an IPv6
  // literal wears inside a URL.
  fields([
    one.name,
    url.to_string(config),
    address.host(where),
    int.to_string(one.port),
    one.password,
    method.to_string(one.chosen),
    or_empty(one.tag),
    plugin_text(one.plugin),
  ])
}

fn read_case(text: String, password: String) -> Nil {
  case url.parse(text) {
    Error(reason) -> {
      io.println("error\t" <> url.explain(reason))
      halt(1)
    }
    Ok(config) ->
      fields([
        address.host(url.server(config)),
        int.to_string(address.port(url.server(config))),
        method.to_string(url.method(config)),
        or_empty(url.tag(config)),
        plugin_text(url.plugin(config)),
        case
          url.key(config) == key.from_password(url.method(config), password)
        {
          True -> "key-matches"
          False -> "key-differs"
        },
      ])
  }
}

fn fields(values: List(String)) -> Nil {
  io.println(string.join(values, "\t"))
}

fn or_empty(value: Option(String)) -> String {
  case value {
    None -> ""
    Some(text) -> text
  }
}

fn plugin_text(plugin: Option(url.Plugin)) -> String {
  case plugin {
    None -> ""
    Some(url.Plugin(name, None)) -> name
    Some(url.Plugin(name, Some(arguments))) -> name <> ";" <> arguments
  }
}

fn apply_tag(config: url.Config, tag: Option(String)) -> url.Config {
  case tag {
    None -> config
    Some(text) -> url.with_tag(config, text)
  }
}

fn apply_plugin(config: url.Config, plugin: Option(url.Plugin)) -> url.Config {
  case plugin {
    None -> config
    Some(chosen) -> url.with_plugin(config, chosen)
  }
}

@external(erlang, "erlang", "halt")
@external(javascript, "./property_smoke_ffi.mjs", "halt")
fn halt(code: Int) -> Nil
