//// The codec, reached from the package that owns the sockets.
////
//// `ssocks` and `ssocks_codec` are two packages because they have to be: the
//// IO layer is built on `gleam_erlang`, and Gleam refuses to compile a call to
//// a function with no implementation for the current target, so a single
//// package containing `mug` or `glisten` could never build for JavaScript.
//// That split is the most load-bearing structural decision in the repository
//// and it is held together by one path dependency.
////
//// A path dependency is exactly the kind of thing that works on the machine
//// where it was written and breaks somewhere else — a rename, a publish, a
//// version bound that stops resolving. So the wire format is exercised here,
//// from this side of the split, rather than assumed to have arrived.
////
//// These are not a second copy of the codec's own tests. They ask one
//// question: does the protocol still work when called from here?

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import ssocks/address
import ssocks/key
import ssocks/method
import ssocks/stream

fn session_key() -> key.Key {
  key.from_password(method.Aes256Gcm, "a secret shared with the tests")
}

pub fn the_codec_package_is_reachable_across_the_path_dependency_test() {
  assert method.to_string(method.ChaCha20Poly1305) == "chacha20-ietf-poly1305"
}

pub fn a_stream_encoded_here_decodes_here_test() {
  let payload = <<"a request that will cross a socket one day":utf8>>

  let #(encoder, salt) = stream.encoder(session_key())
  let #(_, framed) = stream.encode(encoder, payload)

  let assert Ok(#(_, chunks)) =
    stream.decode(
      stream.decoder(session_key()),
      bit_array.concat([salt, framed]),
    )

  assert bit_array.concat(chunks) == payload
}

pub fn a_target_address_survives_the_round_trip_test() {
  // The header a client writes before its first byte of payload. If this were
  // to break, every connection would open onto the wrong host.
  let assert Ok(target) = address.parse("example.org:443")

  assert address.decode(address.encode(target))
    == Ok(address.Complete(target, <<>>))
}

pub fn the_incremental_decoder_survives_a_split_arriving_from_a_socket_test() {
  // TCP will hand the IO layer whatever it feels like. The codec's own suite
  // covers every byte boundary; this checks that the same behaviour is what
  // reaches this package, since this is where real fragments will arrive.
  let payload = <<"split me anywhere at all":utf8>>

  let #(encoder, salt) = stream.encoder(session_key())
  let #(_, framed) = stream.encode(encoder, payload)
  let whole = bit_array.concat([salt, framed])

  let assert Ok(head) = bit_array.slice(whole, 0, 40)
  let assert Ok(tail) =
    bit_array.slice(whole, 40, bit_array.byte_size(whole) - 40)

  let assert Ok(#(decoder, first)) =
    stream.decode(stream.decoder(session_key()), head)
  let assert Ok(#(_, second)) = stream.decode(decoder, tail)

  assert bit_array.concat([bit_array.concat(first), bit_array.concat(second)])
    == payload
}
