<!--
SPDX-FileCopyrightText: 2026 ssocks contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ssocks

Shadowsocks for Gleam. There was no Shadowsocks in the Gleam ecosystem, and no
SOCKS either; this is the first.

Two packages, because they can't be one:

- **`ssocks_codec`** is the protocol with no sockets in it. Ciphers, key
  derivation, the target address header, the TCP framing and the UDP packet, as
  pure functions over bytes. Runs on Erlang and on Node, Deno and Bun.
- **`ssocks`** is the part that touches the network, on Erlang. In progress.

The split is forced rather than stylistic. `glisten`, `mug` and `toss` are built
on `gleam_erlang` with no JavaScript implementations, and Gleam refuses to
compile a call to a function that has no implementation for the current target,
so a single package containing the IO layer could not build for JavaScript at
all.

## Status

**Alpha, and the cryptography has not been audited.** The wire format is
verified against a real implementation (see [Interoperability](#interoperability))
and against the published vectors of every specification it implements, but
"passes its tests" is not "reviewed by cryptographers". Judge accordingly.

What works today:

| | |
| --- | --- |
| Methods | `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` |
| TCP | framing, in both directions, incremental |
| UDP | packet format |
| Addresses | IPv4, IPv6 and domain names, wire and text |
| URLs | `ss://` in all three forms, read and written |
| Not yet | the client, the server, the UDP relay |

## The URL your provider gave you

Configuration usually arrives as one line, pasted from a web page or scanned
from a QR code. Three forms of that line are in circulation and all three are
read here, because a library that handles two of them fails for a third of its
users:

```gleam
import ssocks/url

let assert Ok(config) =
  url.parse("ss://YWVzLTI1Ni1nY206cGFzc3dk@example.com:8388#Tokyo")

url.method(config)  // Aes256Gcm
url.server(config)  // example.com:8388
url.tag(config)     // Some("Tokyo")
url.key(config)     // ready for stream.encoder
```

`?plugin=` and `#tag` are kept, so a URL survives a round trip through this
module rather than losing a field somebody downstream needs. Refusals name what
was wrong — an unauthenticated cipher says which cipher and why, rather than
"invalid URL".

None of those refusals quote the input. A parse failure is exactly when a
caller reaches for the text to print it, and the text is a credential; use
`url.redacted` to print a configuration, and `url.to_string` only where a
credential is what you meant.

## The incremental decoder

This is the part worth having.

TCP hands you a stream in whatever pieces it feels like. A read can stop in the
middle of the salt, between a chunk's length and that length's authentication
tag, or halfway through a payload. Handling that is where hand-written
Shadowsocks implementations break, and the failure is silent: the connection
simply stops working.

So feed `decode` whatever arrived, in whatever grouping, and take back the
plaintext chunks that became complete:

```gleam
import ssocks/key
import ssocks/method
import ssocks/stream

let session = key.from_password(method.Aes256Gcm, "hunter2")

// Writing: the salt goes first, then framed payloads of any size.
let #(encoder, salt) = stream.encoder(session)
let #(encoder, bytes) = stream.encode(encoder, <<"anything, any length":utf8>>)

// Reading: hand it what arrived; an empty list means "not yet", not "broken".
let assert Ok(#(decoder, chunks)) = stream.decode(stream.decoder(session), bytes)
```

The rule that makes it work is that the nonce advances only when an AEAD
operation succeeds. A length that decrypts without its payload holds the counter
still, so the next call starts where the last one stopped rather than one step
past it.

## Nonce reuse is unsayable

Reusing a nonce under one key is the catastrophic failure for AEAD: it leaks the
keystream, and for Poly1305 it leaks the authentication key outright.

Here it is not discouraged, it is impossible to write. The counter lives inside
the encoder, advances on its own, and is never accepted as an argument. There is
no function anywhere that takes a nonce from a caller.

The master key is treated the same way. A `Key` has no accessor for its bytes;
the only thing it will hand over is a session subkey for a given salt, which is
useless without that salt. Key material therefore has no route into a log line
or an error message. Use `key.redacted` where a key has to be printed — it
renders identically for every key of a method, so what does get printed is not a
distinguisher.

## Supported environments

| Runtime | AES-GCM | ChaCha20-Poly1305 |
| --- | --- | --- |
| Erlang / OTP 27+ | platform | platform |
| Node | platform | platform |
| Deno | platform | platform |
| Bun | platform | **this library's own** |

Bun ships no ChaCha20 at all, so `ssocks_codec` carries a ChaCha20-Poly1305
written in Gleam and uses it where the platform has none. Run `mise run
backends` to see which one a runtime actually selects.

That implementation turned out to be worth more than Bun support. Where a
runtime has both, the two are handed identical inputs and required to produce
identical bytes, which is a far stronger check than any published vector: a bug
subtle enough to survive the specifications would have to occur identically in
two independent implementations.

Browsers are out of scope. The Web Crypto AEAD interface is asynchronous and
cannot back a synchronous `BitArray -> BitArray` codec.

## Deliberately not supported

- **Stream ciphers** (`aes-256-cfb`, `chacha20`, `rc4-md5` and the rest). They
  carry no authentication, so anyone on the network path can alter traffic
  undetected, and they are what active probing has historically used to identify
  servers. `method.from_string` refuses them by name and says why rather than
  reporting them as unknown.
- **Shadowsocks 2022 (SIP022)**, for now. It derives session keys with BLAKE3,
  which the Erlang crypto application does not provide.

## Interoperability

Every test in this repository except one compares this implementation with
itself, and that cannot distinguish a correct codec from one that is
consistently wrong in both directions. A reversed nonce counter would be applied
the same way when writing and when reading, and everything would pass while the
library talked to nothing in the world.

So there are two tests that put [shadowsocks-rust][ssrust] on the other end.

For the wire format, a plain TCP echo server sits behind a real `ssserver`, and
the client asks that server to reach it. All three methods pass at 1, 100,
16382, 16383, 16384 and 40000 bytes; the last two are the first sizes that force
a payload across chunk boundaries.

For `ss://`, its `ssurl` decodes URLs written here and this parses URLs written
by it, field by field, including a Japanese password, a tag full of URL syntax
and an IPv6 server. The second direction earns its keep on its own: `ssurl`
escapes more than it has to — it writes `v2ray-plugin` as `v2ray%2Dplugin` — and
a parser that only ever saw its own minimal output would never meet that.

```sh
SSOCKS_SSRUST_DIR=/path/to/shadowsocks-rust mise run interop
```

Nothing is downloaded by the build. The binaries stay outside the repository.

[ssrust]: https://github.com/shadowsocks/shadowsocks-rust/releases

## Development

Everything runs through [mise][mise], so what CI runs and what you run cannot
drift apart.

```sh
mise run bootstrap
```

```sh
mise run check
```

`check` is fmt, both builds with warnings denied, the test suite on all four
runtimes, the long property run, the fuzz run, the cross-runtime vector
comparison, the docs and the linters.

Individually:

| Task | What it does |
| --- | --- |
| `mise run test` | the unit suite, on Erlang and all three JavaScript runtimes |
| `mise run test-property` | 6 properties, 10000 cases each, fixed seed |
| `mise run test-fuzz` | 150000 hostile inputs; a decoder may error but not crash |
| `mise run test-cross` | every runtime must compute byte-identical output |
| `mise run interop` | round trip through a real shadowsocks-rust server |
| `mise run backends` | which cipher backend each runtime selects |

Several of those exist because of gaps rather than preference.

`gleam build --warnings-as-errors` only covers `src/`, so a warning in a test is
printed and ignored; `scripts/no-warnings.mjs` closes that, after an integer
literal above 2^53 silently turned a Poly1305 assertion into a comparison of two
zeroes.

`gleam test` exits 0 when gleeunit finds no tests at all — it prints
`No tests found!` and reports success — so a package can pass CI while asserting
nothing. `scripts/gleam-test.mjs` runs each leg and requires a positive test
count, which is also where the Deno leg lives: `gleam test --runtime deno`
cannot pass Deno the read permission gleeunit needs, so that one is built and
invoked directly rather than left to quietly not run.

[mise]: https://mise.jdx.dev

## Licence

MIT or Apache-2.0, at your option.
