//// Print every layer's output for a fixed set of inputs.
////
//// Run on each target and compared byte for byte by
//// `scripts/cross-target-vectors.mjs`. Nothing here is random: given the same
//// source, every runtime must print exactly the same text.
////
//// This is the check that catches an FFI that is subtly different rather than
//// absent. A missing cipher fails loudly at the first call; a ChaCha20 fed its
//// nonce in the wrong order, or an AES-GCM built without an explicit tag
//// length, produces plausible bytes that differ from the other runtimes and
//// from the rest of the world. Only a comparison across runtimes sees that.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/io
import gleam/list
import gleam/option.{Some}
import ssocks/address
import ssocks/cipher/chacha20
import ssocks/cipher/poly1305
import ssocks/datagram
import ssocks/internal/aead
import ssocks/internal/hex
import ssocks/internal/kdf
import ssocks/key
import ssocks/method
import ssocks/nonce
import ssocks/stream
import ssocks/url

pub fn main() -> Nil {
  let key32 =
    bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  let key16 = bytes("000102030405060708090a0b0c0d0e0f")
  let nonce12 = bytes("070000004041424344454647")
  let salt32 =
    bytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
  let salt16 = bytes("0102030405060708090a0b0c0d0e0f10")

  urls(salt32)

  line("kdf.extract", kdf.extract(salt32, key32))
  line("kdf.expand", kdf.expand(key32, <<"ss-subkey":utf8>>, 32))
  line("kdf.session_subkey.32", kdf.session_subkey(key32, salt32, 32))
  line("kdf.session_subkey.16", kdf.session_subkey(key16, salt16, 16))
  line("kdf.evp.ascii", kdf.evp_bytes_to_key("hunter2", 32))
  line("kdf.evp.utf8", kdf.evp_bytes_to_key("パスワード", 32))

  line("chacha20.block.0", chacha20.block(key32, 0, nonce12))
  line("chacha20.block.1", chacha20.block(key32, 1, nonce12))
  line("chacha20.encrypt.65", chacha20.encrypt(key32, 1, nonce12, filler(65)))
  line("poly1305.mac.empty", poly1305.mac(key32, <<>>))
  line("poly1305.mac.127", poly1305.mac(key32, filler(127)))

  use chosen <- list.each([
    method.Aes128Gcm,
    method.Aes256Gcm,
    method.ChaCha20Poly1305,
  ])
  let name = method.to_string(chosen)
  let material = case method.key_size(chosen) {
    16 -> key16
    _ -> key32
  }
  let salt = case method.salt_size(chosen) {
    16 -> salt16
    _ -> salt32
  }
  let assert Ok(session) = key.from_bytes(chosen, material)
  let assert Ok(target) = address.parse("example.com:443")

  let #(ciphertext, tag) =
    aead.seal(chosen, material, nonce12, <<"aad":utf8>>, filler(40))
  line(name <> ".aead.ciphertext", ciphertext)
  line(name <> ".aead.tag", tag)

  line(name <> ".subkey", key.derive_subkey(session, salt))
  line(name <> ".address", address.encode(target))

  let assert Ok(#(encoder, _)) = stream.encoder_with_salt(session, salt)
  let #(_, framed) =
    stream.encode(
      encoder,
      bit_array.concat([address.encode(target), filler(17_000)]),
    )
  line(name <> ".stream", framed)

  let assert Ok(packet) =
    datagram.seal_with_salt(session, salt, target, filler(100))
  line(name <> ".datagram", packet)

  line(name <> ".nonce.257", advance(nonce.zero(), 257) |> nonce.to_bytes)
}

/// The `ss://` layer, which is the only one here made of text.
///
/// Everything above this point is bytes in and bytes out, where the targets
/// agree because they are told to. Percent coding, base64 and UTF-8 are where
/// a runtime gets to have an opinion, so the results are printed as the hex of
/// their UTF-8 bytes: two runtimes that disagree about how a codepoint is
/// spelled disagree here, visibly, rather than in a URL that one of them hands
/// to a server which then refuses it.
fn urls(salt: BitArray) -> Nil {
  let assert Ok(parsed) =
    url.parse("ss://YWVzLTI1Ni1nY206cGFzc3dk@example.com:8388#Tokyo")
  line("url.parsed.server", address.encode(url.server(parsed)))
  line("url.parsed.subkey", key.derive_subkey(url.key(parsed), salt))

  let assert Ok(legacy) =
    url.parse(
      "ss://"
      <> bit_array.base64_url_encode(
        <<"chacha20-ietf-poly1305:passwd@[2001:db8::1]:8388":utf8>>,
        False,
      ),
    )
  line("url.legacy.server", address.encode(url.server(legacy)))
  line("url.legacy.subkey", key.derive_subkey(url.key(legacy), salt))

  let assert Ok(where) = address.parse("example.com:8388")
  let built =
    url.new(method.ChaCha20Poly1305, "p@ss:w#rd?&=/ %+é パスワード", where)
    |> url.with_tag("東京 / #1")
    |> url.with_plugin(url.Plugin("v2ray-plugin", Some("mode=quic;host=a.b")))

  text("url.to_string", url.to_string(built))
  text("url.redacted", url.redacted(built))

  let assert Ok(again) = url.parse(url.to_string(built))
  text("url.round_trip", url.to_string(again))
}

fn text(label: String, value: String) -> Nil {
  line(label, <<value:utf8>>)
}

fn line(label: String, value: BitArray) -> Nil {
  io.println(label <> " " <> hex.encode(value))
}

fn bytes(text: String) -> BitArray {
  let assert Ok(decoded) = hex.decode(text)
  decoded
}

fn filler(size: Int) -> BitArray {
  <<0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x5a, 0xa5>>
  |> list.repeat(size / 8 + 1)
  |> bit_array.concat
  |> take(size)
}

fn take(value: BitArray, size: Int) -> BitArray {
  let assert Ok(sliced) = bit_array.slice(value, 0, size)
  sliced
}

fn advance(from: nonce.Nonce, steps: Int) -> nonce.Nonce {
  case steps {
    0 -> from
    _ -> advance(nonce.next(from), steps - 1)
  }
}
