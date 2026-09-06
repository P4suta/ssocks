//// Shared helper for tests that carry published protocol vectors.
////
//// Vectors are pasted in the wrapped, indented shape the specifications print
//// them in. Keeping them byte-identical to the source document is what makes a
//// failure trustworthy: if a test disagrees with the RFC, the implementation is
//// wrong, not the transcription.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import ssocks/internal/hex

/// Decode a hex vector, failing loudly if the text is not valid hex.
///
/// A malformed vector is a mistake in the test, not a property of the code
/// under test, so it should stop the run rather than quietly compare wrong.
pub fn bytes(text: String) -> BitArray {
  let assert Ok(decoded) = hex.decode(text)
  decoded
}
