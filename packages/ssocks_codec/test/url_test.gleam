// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/option.{None, Some}
import gleam/string
import ssocks/address
import ssocks/key
import ssocks/method
import ssocks/url

fn server(text: String) -> address.Address {
  let assert Ok(parsed) = address.parse(text)
  parsed
}

/// A URL in the SIP002 base64 form, built rather than pasted, so a test reads
/// as its inputs instead of as an opaque blob.
fn sip002(credentials: String, rest: String) -> String {
  "ss://" <> bit_array.base64_url_encode(<<credentials:utf8>>, False) <> rest
}

// --- the three forms a provider might hand over ------------------------------

pub fn a_url_with_base64_credentials_parses_test() {
  let assert Ok(config) =
    url.parse("ss://YWVzLTI1Ni1nY206cGFzc3dk@example.com:8388")

  assert url.method(config) == method.Aes256Gcm
  assert url.server(config) == server("example.com:8388")
  assert url.tag(config) == None
  assert url.plugin(config) == None
}

pub fn a_url_with_plaintext_credentials_parses_test() {
  // SIP002 allows the userinfo to be written out, which is what a human
  // editing a config file by hand will do.
  let assert Ok(config) = url.parse("ss://aes-128-gcm:hunter2@example.com:8388")

  assert url.method(config) == method.Aes128Gcm
  assert url.key(config) == key.from_password(method.Aes128Gcm, "hunter2")
}

pub fn a_legacy_whole_authority_base64_url_parses_test() {
  // The pre-SIP002 form: everything after ss:// is one base64 blob, including
  // the at sign and the host.
  let blob =
    bit_array.base64_url_encode(
      <<"aes-256-gcm:passwd@192.168.100.1:8888":utf8>>,
      False,
    )
  let assert Ok(config) = url.parse("ss://" <> blob <> "#Home")

  assert url.method(config) == method.Aes256Gcm
  assert url.server(config) == server("192.168.100.1:8888")
  assert url.tag(config) == Some("Home")
  assert url.key(config) == key.from_password(method.Aes256Gcm, "passwd")
}

// --- the parts ---------------------------------------------------------------

pub fn a_tag_is_percent_decoded_test() {
  let assert Ok(config) =
    url.parse(sip002("aes-256-gcm:p", "@h.example:1#My%20Tag"))
  assert url.tag(config) == Some("My Tag")
}

pub fn a_tag_may_contain_characters_that_look_like_syntax_test() {
  // The fragment is everything after the first hash, so an at sign or a
  // question mark in a tag is ordinary text. Splitting the authority before
  // the fragment would read this one as a second credential separator.
  let assert Ok(config) =
    url.parse(sip002("aes-256-gcm:p", "@h.example:1#tokyo@home?yes"))
  assert url.tag(config) == Some("tokyo@home?yes")
}

pub fn a_non_ascii_tag_survives_test() {
  let assert Ok(config) =
    url.parse(sip002("aes-256-gcm:p", "@h.example:1#%E6%9D%B1%E4%BA%AC"))
  assert url.tag(config) == Some("東京")
}

pub fn a_plugin_and_its_arguments_are_kept_test() {
  // Dropping the plugin silently would produce a config that connects to a
  // server expecting an obfuscation layer that is not there.
  let assert Ok(config) =
    url.parse(sip002(
      "aes-256-gcm:p",
      "@h.example:1/?plugin=obfs-local%3Bobfs%3Dhttp#Example",
    ))

  assert url.plugin(config) == Some(url.Plugin("obfs-local", Some("obfs=http")))
  assert url.tag(config) == Some("Example")
}

pub fn a_plugin_without_arguments_parses_test() {
  let assert Ok(config) =
    url.parse(sip002("aes-256-gcm:p", "@h.example:1?plugin=v2ray-plugin"))
  assert url.plugin(config) == Some(url.Plugin("v2ray-plugin", None))
}

pub fn an_ipv6_server_parses_test() {
  let assert Ok(config) =
    url.parse(sip002("aes-256-gcm:p", "@[2001:db8::1]:8388"))
  assert url.server(config) == server("[2001:db8::1]:8388")
}

pub fn a_trailing_slash_is_tolerated_test() {
  let assert Ok(config) = url.parse(sip002("aes-256-gcm:p", "@h.example:1/"))
  assert url.server(config) == server("h.example:1")
}

pub fn both_base64_alphabets_are_accepted_test() {
  // SIP002 says websafe, but standard-alphabet URLs are handed out in the
  // wild, and refusing one is a worse outcome than accepting both.
  let credentials = <<"aes-256-gcm:ab~cd?ef":utf8>>
  let websafe = bit_array.base64_url_encode(credentials, False)
  let standard = bit_array.base64_encode(credentials, True)

  assert websafe != standard
  let assert Ok(from_websafe) = url.parse("ss://" <> websafe <> "@h.example:1")
  let assert Ok(from_standard) =
    url.parse("ss://" <> standard <> "@h.example:1")
  assert from_websafe == from_standard
}

pub fn credentials_split_at_the_first_colon_only_test() {
  // A password containing a colon is legal and common. Splitting at the last
  // one would take part of the password for the method name.
  let assert Ok(config) =
    url.parse(sip002("aes-256-gcm:p@ss:word", "@h.example:1"))

  assert url.method(config) == method.Aes256Gcm
  assert url.key(config) == key.from_password(method.Aes256Gcm, "p@ss:word")
}

pub fn a_percent_encoded_plaintext_password_is_decoded_test() {
  let assert Ok(config) =
    url.parse("ss://aes-256-gcm:p%40ss%3Aword@h.example:1")
  assert url.key(config) == key.from_password(method.Aes256Gcm, "p@ss:word")
}

pub fn the_scheme_is_case_insensitive_test() {
  let assert Ok(config) = url.parse("SS://YWVzLTI1Ni1nY206cA@h.example:1")
  assert url.method(config) == method.Aes256Gcm
}

// --- refusals ----------------------------------------------------------------

pub fn a_url_of_another_scheme_is_refused_test() {
  assert url.parse("https://example.com:8388")
    == Error(url.NotShadowsocks(Some("https")))
}

pub fn text_that_is_not_a_url_is_refused_test() {
  assert url.parse("example.com:8388") == Error(url.NotShadowsocks(None))
}

pub fn a_stream_cipher_url_is_refused_with_its_reason_test() {
  // This is the SIP002 specification's own second example. Both of its
  // examples use ciphers without authentication, which this library will not
  // use, and saying which is the difference between a user changing one field
  // and a user filing a bug.
  let assert Error(url.UnsupportedMethod(reason)) =
    url.parse(
      "ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local#Example2",
    )

  assert string.contains(method.explain(reason), "rc4-md5")
}

pub fn a_url_without_a_port_is_refused_test() {
  let assert Error(url.BadServer(reason)) =
    url.parse(sip002("aes-256-gcm:p", "@h.example"))
  assert reason == address.MissingPort("h.example")
}

pub fn a_url_with_an_unreadable_port_is_refused_test() {
  let assert Error(url.BadServer(address.MalformedPort(text))) =
    url.parse(sip002("aes-256-gcm:p", "@h.example:not-a-port"))
  assert text == "not-a-port"
}

pub fn credentials_with_no_separator_are_refused_test() {
  assert url.parse(sip002("no-colon-here", "@h.example:1"))
    == Error(url.MalformedCredentials)
}

pub fn a_url_with_no_credentials_at_all_is_refused_test() {
  assert url.parse("ss://@h.example:1") == Error(url.MissingCredentials)
}

pub fn a_bare_scheme_is_refused_test() {
  assert url.parse("ss://") == Error(url.MissingCredentials)
}

pub fn a_broken_percent_escape_in_a_tag_is_refused_test() {
  assert url.parse(sip002("aes-256-gcm:p", "@h.example:1#%zz"))
    == Error(url.MalformedEscape(url.Tag))
}

// --- what an error is allowed to say -----------------------------------------

pub fn an_error_never_carries_the_password_test() {
  // A parse failure is exactly when a caller reaches for the input to print
  // it, and the input is a credential. Every error this module returns must
  // therefore be safe to log. `string.inspect` sees through opaque types, so
  // this is what a crash report would actually show.
  let secret = "correct-horse-battery-staple"

  let refusals = [
    // an unsupported method, seen only after the password is in hand
    url.parse(sip002("rc4-md5:" <> secret, "@h.example:1")),
    // a bad port, seen after the credentials parsed cleanly
    url.parse(sip002("aes-256-gcm:" <> secret, "@h.example:nope")),
    // a bad escape in the tag
    url.parse(sip002("aes-256-gcm:" <> secret, "@h.example:1#%zz")),
    // plaintext credentials, where the password is not even encoded
    url.parse("ss://rc4-md5:" <> secret <> "@h.example:1"),
  ]

  assert all_free_of(refusals, secret)
}

pub fn redacted_does_not_carry_the_password_test() {
  let secret = "correct-horse-battery-staple"
  let assert Ok(config) =
    url.parse(sip002("aes-256-gcm:" <> secret, "@h.example:1"))

  let described = url.redacted(config)
  assert !string.contains(described, secret)
  // Still has to be useful: the server is not the secret.
  assert string.contains(described, "h.example")
  assert string.contains(described, "aes-256-gcm")
}

fn all_free_of(
  results: List(Result(url.Config, url.UrlError)),
  secret: String,
) -> Bool {
  case results {
    [] -> True
    [first, ..rest] ->
      case first {
        Ok(_) -> False
        Error(reason) ->
          !string.contains(string.inspect(reason), secret)
          && !string.contains(url.explain(reason), secret)
          && all_free_of(rest, secret)
      }
  }
}

// --- writing one back out ----------------------------------------------------

pub fn to_string_produces_the_canonical_sip002_form_test() {
  let config =
    url.new(method.Aes256Gcm, "passwd", server("example.com:8388"))
    |> url.with_tag("Tokyo")

  assert url.to_string(config)
    == "ss://YWVzLTI1Ni1nY206cGFzc3dk@example.com:8388#Tokyo"
}

pub fn to_string_brackets_an_ipv6_server_test() {
  let config = url.new(method.Aes256Gcm, "p", server("[2001:db8::1]:8388"))
  assert string.contains(url.to_string(config), "@[2001:db8::1]:8388")
}

pub fn to_string_writes_the_plugin_back_test() {
  let config =
    url.new(method.Aes256Gcm, "p", server("h.example:1"))
    |> url.with_plugin(url.Plugin("obfs-local", Some("obfs=http")))

  assert string.contains(
    url.to_string(config),
    "?plugin=obfs-local%3Bobfs%3Dhttp",
  )
}

pub fn a_config_round_trips_through_its_url_test() {
  let config =
    url.new(method.ChaCha20Poly1305, "s3cr3t", server("example.com:8388"))
    |> url.with_tag("Tokyo")
    |> url.with_plugin(url.Plugin("v2ray-plugin", Some("mode=quic")))

  assert url.parse(url.to_string(config)) == Ok(config)
}

pub fn a_password_full_of_url_syntax_round_trips_test() {
  // Every character that means something in a URL, in the one field where a
  // provider is most likely to put one.
  let config =
    url.new(method.Aes256Gcm, "p@ss:w#rd?&=/ %+é", server("example.com:8388"))
    |> url.with_tag("東京 / #1")

  assert url.parse(url.to_string(config)) == Ok(config)
}
