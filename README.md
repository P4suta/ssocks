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
- **`ssocks`** is the part that touches the network, on Erlang: the client, the
  server, and the UDP relay.

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
| TCP framing | in both directions, incremental |
| UDP packets | seal and open |
| Addresses | IPv4, IPv6 and domain names, wire and text |
| URLs | `ss://` in all three forms, read and written |
| Client | TCP, over `mug` |
| Server | TCP, over `glisten`, with replay and anti-probing |
| UDP relay | a NAT table with two limits, over `toss` |

## Three lines

```gleam
import ssocks

pub fn main() {
  let assert Ok(config) = ssocks.from_uri("ss://YWVzLTI1Ni1nY206cGFzc3dk@example.com:8388#Tokyo")
  use connection <- ssocks.with_connection(config, "example.org:443", 5000)
  let assert Ok(connection) = ssocks.send(connection, <<"GET / HTTP/1.1\r\n\r\n":utf8>>)
  ssocks.receive(connection, within: 5000)
}
```

The salt, the key derivation, the nonce counters, the chunk boundaries and the
target address header are all below that line.

Two details are worth knowing because they are decisions rather than defaults.
The target address header is held back until the first `send`, so it travels
with the payload instead of putting a lone short packet at the start of every
connection — a fixed-size first packet is a pattern somebody watching can count.
And `receive` takes the time it may spend in total, not per read: one TCP read
often completes no chunk, and a per-read timeout would let a peer sending one
byte at a time hold the connection open indefinitely.

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

## The server, and not answering

```gleam
import ssocks/server

let assert Ok(listening) =
  server.new(key.from_password(method.Aes256Gcm, "hunter2"))
  |> server.start(8388)
```

Active probing is how Shadowsocks servers have historically been found. A prober
opens a connection, sends something that is not a valid handshake, and watches.
A server that closes immediately, or closes after a distinctive delay, or answers
at all, has told the prober what it is: a port that behaves differently for
garbage than an unused port does is a port worth blocking.

So the default is `Drain` — keep the connection open, keep reading, say nothing.
Three things trigger it, because a prober can produce any of them:

| | |
| --- | --- |
| `AuthenticationFailed` | bytes that do not authenticate under this key |
| `MalformedHeader` | bytes that authenticate and are not a target address |
| `Silent` | a connection that opens and never handshakes |

A policy covering only the first would still be distinguishable by the other two.
`server.on_probe` can choose `CloseAfter` or `CloseNow` where concealment
matters less than idle sockets.

Salts are checked against a replay filter before anything is relayed. The
specification asks that a salt be unique for the lifetime of a master key, not of
a transport, so `ssocks/replay_guard` is shareable: one guard across several
listeners and, later, across UDP. Most implementations skip this — it costs
memory and does nothing visible when it works.

## UDP

```gleam
import ssocks/udp

let assert Ok(guard) = replay_guard.start()

let assert Ok(_) =
  server.new(session) |> server.with_replay_guard(guard) |> server.start(8388)
let assert Ok(_) =
  udp.relay(session) |> udp.with_replay_guard(guard) |> udp.start(8388)
```

A Shadowsocks UDP packet stands alone: salt, one AEAD box holding the target
address and the payload, an all-zero nonce. No framing, no ordering, no counter.
`ssocks/datagram` does that part and has no sockets in it.

What is left is the association, and it is the whole of the work. UDP has no
connections, so the relay invents them: each client address gets a socket of its
own to the outside, and replies on that socket go back to that client. That
makes it a NAT, and it inherits the problem every NAT has — nothing will ever
say that a client has finished, so entries have to leave on their own. An idle
timeout drops what has gone quiet; a ceiling bounds memory against a flood, and
since UDP source addresses are forged for free, that flood costs an attacker
nothing.

The guard is shared on purpose. The specification asks that a salt be unique for
the lifetime of a master key, not of a transport, and a UDP packet carries a
salt — two filters would let a salt seen over TCP be replayed over UDP.

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

## Diagnosis

Protocol bugs are silent: one symptom, many causes, none distinguishable from
the outside. [docs/debugging.md](docs/debugging.md) is the order to look in.

`ssocks/inspect` walks a stream the way the decoder does and prints every field
with its offset, its length and the nonce it was decrypted under, so that a
mismatch with another implementation is a minute of reading two dumps rather
than a day of guessing.

`ssocks/testing` is public on purpose. The hard part of an incremental decoder
is not the decoder, it is the loop around it, and that code lives in the caller
and breaks only against real networks. The generators this library tests itself
with — every split, one byte at a time, every corruption, every truncation —
are exported so a caller can point them at their own loop.

## Interoperability

Almost every test in this repository compares this implementation with itself,
and that cannot distinguish a correct codec from one that is consistently wrong
in both directions. A reversed nonce counter would be applied the same way when
writing and when reading, and everything would pass while the library talked to
nothing in the world.

So four of them put [shadowsocks-rust][ssrust] on the other end.

For the client, a plain TCP echo server sits behind a real `ssserver`, and this
library's client asks that server to reach it. All three methods pass at 1, 100,
16382, 16383, 16384 and 40000 bytes; the last two are the first sizes that force
a payload across chunk boundaries.

For the server, the arrangement is reversed: a real `sslocal --protocol tunnel`
sits in front of this library's server. That direction is not implied by the
first. The client always writes the target address header the same way, so until
this test existed the server had only ever read headers this library produced —
never one somebody else wrote, arriving at chunk boundaries it did not choose.

For UDP, the packet format is different code with a different shape, and gets
its own test: `sslocal --protocol tunnel -u` in front of this relay, with a
plain UDP echo behind it.

For `ss://`, its `ssurl` decodes URLs written here and this parses URLs written
by it, field by field, on both targets, including a Japanese password, a tag
full of URL syntax and an IPv6 server. The second direction earns its keep on
its own: `ssurl` escapes more than it has to — it writes `v2ray-plugin` as
`v2ray%2Dplugin` — and a parser that only ever saw its own minimal output would
never meet that.

Both targets, because this is the only check that says the output is *right*
rather than merely agreed upon. The cross-runtime comparison already proves
every runtime computes the same URL bytes, but a shared mistake in percent
coding would be just as agreed upon and just as unusable.

These four need a real shadowsocks-rust, so they are not part of `mise run
check` and they need one command first:

```sh
mise run interop-fetch
```

```sh
mise run interop
```

`interop-fetch` is the only task in this repository that uses the network. It
downloads the pinned release, checks it against a SHA-256 recorded per platform
in `scripts/ssrust.mjs`, and unpacks it into a per-user cache directory —
outside the checkout, so a third-party binary cannot arrive in a copy or an
archive of this repository by accident. Nothing else downloads anything: not the
build, not the tests, and not `mise run interop`, which says to run the fetch
rather than quietly running it for you.

Already have a copy? Point `SSOCKS_SSRUST_DIR` at it and skip the fetch.

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
| `mise run interop` | four round trips against real shadowsocks-rust |
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
