// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// JavaScript side of the AEAD funnel, for the Node-family runtimes.
//
// Availability is decided by trying to construct the cipher rather than by
// reading `getCiphers()`. The list is not equally trustworthy across runtimes,
// and the question that actually matters is whether a cipher can be built, not
// whether it is advertised. Bun, for instance, ships no ChaCha20 at all, which
// is what the portable Gleam implementation exists to cover.
//
// `open` catches everything for the same reason the Erlang side does: a failed
// tag and a malformed one both have to read as "did not authenticate".

import { Buffer } from "node:buffer";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { BitArray, Result$Ok, Result$Error } from "../../gleam.mjs";

const TAG_LENGTH = 16;
const NONCE_LENGTH = 12;

function raw(bitArray) {
  return bitArray.rawBuffer;
}

function wrap(buffer) {
  return new BitArray(new Uint8Array(buffer));
}

export function available(name, keySize) {
  try {
    createCipheriv(name, new Uint8Array(keySize), new Uint8Array(NONCE_LENGTH), {
      authTagLength: TAG_LENGTH,
    });
    return true;
  } catch {
    return false;
  }
}

export function seal(name, key, nonce, aad, plaintext) {
  const cipher = createCipheriv(name, raw(key), raw(nonce), {
    authTagLength: TAG_LENGTH,
  });

  const associated = raw(aad);
  if (associated.length > 0) {
    cipher.setAAD(associated);
  }

  const ciphertext = Buffer.concat([cipher.update(raw(plaintext)), cipher.final()]);

  // Gleam tuples are plain arrays on this target.
  return [wrap(ciphertext), wrap(cipher.getAuthTag())];
}

export function open(name, key, nonce, aad, ciphertext, tag) {
  try {
    const decipher = createDecipheriv(name, raw(key), raw(nonce), {
      authTagLength: TAG_LENGTH,
    });

    const associated = raw(aad);
    if (associated.length > 0) {
      decipher.setAAD(associated);
    }

    decipher.setAuthTag(raw(tag));

    return Result$Ok(
      wrap(Buffer.concat([decipher.update(raw(ciphertext)), decipher.final()])),
    );
  } catch {
    return Result$Error(undefined);
  }
}
