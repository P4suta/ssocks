<!--
SPDX-FileCopyrightText: 2026 ssocks contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# When it does not connect

Shadowsocks bugs are silent. There is one symptom — nothing gets through — and
the causes are not distinguishable from the outside. A wrong password, a nonce
advanced once too often, a length field read the wrong way round, and a server
that is not running all look identical from a client.

This is the order to look in, from cheapest to most work. Each step rules
something out; none of them requires guessing.

## 1. Say what failed, not that something did

Every error type here has an `explain`, and none of them quote your
credentials. That was not always true — `client.explain` used to fall through to
`string.inspect` for two of its five cases, printing a variant name where a
sentence was promised.

```gleam
case ssocks.send(connection, request) {
  Ok(connection) -> …
  Error(reason) -> io.println(ssocks.explain(reason))
}
```

The distinctions worth having up front:

| What you see | What it rules out |
| --- | --- |
| `CouldNotReach` | Nothing was sent. This says nothing about the password. |
| `ReadFailed(Timeout)` | Bytes went out. Either the far end is slow, or it is dropping you silently — which is what a server does when it cannot authenticate. |
| `Framing` on chunk 0 | The password, the method, or the salt. |
| `Framing` further in | Not the password. Something about the framing drifted. |

`client.chunks_read` says which of the last two you are in.

## 2. Read the bytes

`ssocks/inspect` walks a stream the way the decoder does and prints every field
with its offset, its length and the nonce it was decrypted under.

```gleam
io.println(inspect.stream(session, whatever_arrived))
```

```text
0000  951a5b9c74…(32)     salt (32 bytes)
0020  9ea9                chunk 0 length, sealed
0022  94763c645f…(16)     tag, nonce 000000000000000000000000
                        -> length 20
0032  87f87234a2…(20)     chunk 0 payload, sealed
0046  2d89c1b026…(16)     tag, nonce 010000000000000000000000
                        -> 20 bytes: example.org:443 then 5 bytes of payload
```

Three things to read off it:

- **The nonce.** It advances once per authenticated operation, twice per chunk,
  in little-endian. `01 00 00 …` is one, not `… 00 01`. If your dump and
  another implementation's differ here, that is the bug.
- **The length.** Two bytes, big-endian, at most `3fff`. The asymmetry with the
  nonce is real and is in the protocol.
- **The first plaintext.** In a stream from a client it is the target address,
  and `inspect` names the host. If it says a host you did not ask for, the
  header is being built wrong; if it says "not an address header", you are
  reading a server's stream as though it were a client's.

`inspect.packet` does the same for UDP, `inspect.header` for an address on its
own.

## 3. Check the two ends against each other, not against themselves

A codec that is consistently wrong in both directions passes every test it has.
The only test that can say "this is Shadowsocks" puts another implementation on
the other end.

```sh
mise run interop-fetch
```

```sh
mise run interop
```

The first is needed once. It downloads the pinned shadowsocks-rust, checks its
SHA-256, and puts it outside the repository; `SSOCKS_SSRUST_DIR` points at a
copy you already have instead. The second downloads nothing.

Six suites run: this client against a real `ssserver`, a real `sslocal` against
this server, a real `sslocal -u` against this UDP relay, this UDP client against
a real `ssserver -U`, SOCKS5 in both directions, and `ssurl` reading and writing
`ss://` both ways. If your change broke a wire format, one of them says so and
says which layer.

## 4. Feed the loop badly on purpose

Most integration bugs are not in the decoder. They are in the loop around it:
the buffer a caller keeps, the decision about when to read again, the place a
partial frame waits. That code breaks only when a read stops in the middle of a
field, which on a real network is roughly never and then suddenly.

`ssocks/testing` is public for this.

```gleam
use pieces <- list.each(testing.every_split(whole_stream))
assert my_loop(pieces) == expected
```

| | |
| --- | --- |
| `every_split` | every two-way cut, exhaustively |
| `single_bytes` | one byte per call, the worst case |
| `random_splits` | arbitrary groupings, reproducible from a seed |
| `corruptions` | one byte changed, at every position — all must be refused |
| `truncations` | every prefix — all must wait, none may fail |

The last two are where assumptions hide. A prefix of a valid stream is a valid
stream that has not finished, and treating one as an error closes connections
that were merely slow.

## 5. Check the runtime, not the code

On JavaScript, which backend is in use is not obvious and matters:

```sh
mise run backends
```

Bun ships no ChaCha20, so `ssocks_codec` uses its own implementation there.
If Erlang and a JavaScript runtime disagree about the same input, that is what
`mise run test-cross` is for — it runs the same vectors on all four runtimes and
names the first layer that differs.

## The five mistakes, and how each one looks

| Mistake | How it shows |
| --- | --- |
| Nonce advanced on a failed authentication | Works for one chunk, then never again. Dump shows the nonce ahead of the far end's. |
| Nonce in the wrong byte order | Fails at chunk 1, never at chunk 0 — the first nonce is all zeroes either way. |
| Length read little-endian | Chunk 0's length authenticates and then the payload length is absurd. |
| Tag length left to a default | AES-GCM appears to work and produces bytes nobody else accepts. Only `test-cross` and `interop` catch it. |
| Target header sent as its own chunk | Works, and puts a fixed-size packet at the head of every connection for anyone counting. |

The fourth is the reason this repository compares runtimes against each other
rather than only against published vectors: a wrong tag length is not wrong
against itself.

## When a server seems to ignore you

That is the default and it is deliberate. `server.on_probe` is `Drain`: a
connection that cannot be authenticated is held open, read, and never answered,
because a port that behaves differently for garbage than an unused port does is
a port worth blocking.

While developing against your own server, `server.watching` says what it
decided:

```gleam
server.new(session)
|> server.watching(fn(event) { io.println(string.inspect(event)) })
```

`Probed(AuthenticationFailed(_))` is a wrong password. `Probed(MalformedHeader)`
means the password is right and the first plaintext is not an address — check
step 2. `Probed(Silent)` means nothing arrived at all before the handshake
timeout. `Probed(Replayed(_))` means this salt has been seen before, which for
one client usually means a recorded connection being sent again.

`Probed(GuardUnavailable)` is the odd one out: it is not a prober at all, it is
the replay filter failing to answer, and it drains because a guard that cannot
answer has not said yes. If every connection reports it, the guard process has
gone — `replay_guard.size` returns `Error(Nil)` rather than raising, so a
supervisor can see that without being taken down by it.

`Broke(Target(_))` and `Broke(Client(_))` say which socket failed on a relay
that was working, and `Finished` follows either. Without them an ending is an
ending: a client that hung up and a target that reset look the same in the
event stream, and they have different causes.

## When the proxy does not proxy

`ssocks/local` has three places to stop, and they look different from each
other. `local.watching` says which one you are in:

| What you see | Where it stopped |
| --- | --- |
| nothing at all | The client never reached the port. Check the address: this listens on `127.0.0.1` by default, not on every interface. |
| `Malformed(WrongVersion(_))` | Whatever connected is not speaking SOCKS5. A browser configured for an HTTP proxy rather than a SOCKS one arrives exactly like this. |
| `Declined(NotAllowed)` | The client offered no authentication method this serves. Only `NO AUTHENTICATION` is offered, and it is the only one anything normally asks for. |
| `Declined(CommandNotSupported)` | `BIND`, which is not implemented. |
| `Requested(_)` and then nothing | SOCKS5 is fine and the Shadowsocks side is not. Go to step 1 with `ssocks/client`. |
| `ServerUnreachable(_)` | The Shadowsocks server could not be reached at all. Nothing was sent, so this says nothing about the password. |
| `Broke(_)` | The far end answered with something that is not a stream. Carries the `client.ClientError`, so `client.explain` says which. |

A wrong password is the case worth naming, because it does not appear here. The
proxy answers `Succeeded` as soon as the tunnel's socket is open, and
Shadowsocks says nothing on connect — a server that cannot authenticate you
simply never replies. So the symptom is a client that connects, sends, and waits:
`Requested(_)` with no `Finished` until the idle timeout. That is
`Framing` on chunk 0 wearing a different hat.

For an association, `Dropped(_)` is per datagram and does not end anything:
`Malformed(_)` is a client wrapping its payloads wrongly, `NotAuthentic(_)` is
something arriving on the relay socket that this key cannot open — which on UDP
is as much the ordinary noise of the internet as it is an attack — and
`NoClientYet` means a reply arrived before any datagram had said where the
client is.
