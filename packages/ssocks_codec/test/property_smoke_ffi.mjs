// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Erlang has halt/1 in the standard library; the JavaScript runtimes need a
// one line shim so the smoke modules can fail a CI job.

export function halt(code) {
  // Deno, Node and Bun all expose this.
  globalThis.process?.exit?.(code) ?? globalThis.Deno?.exit?.(code);
}
