// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// One command line, quoted once.
//
// Windows needs a shell to find the mise-installed `gleam`, `deno` and `bun`
// shims, and Node deprecates passing an argument array alongside `shell: true`
// because it concatenates the arguments rather than escaping them. Every token
// these scripts pass is a literal written in this repository, so nothing is
// actually at risk, but a deprecation warning printed on every run trains the
// eye to skim past warnings — and this project's warning gate exists precisely
// because a skimmed-past warning once made a test assert nothing.
//
// So the arguments are joined here, quoted where they need it, and the callers
// pass a single string.

/// A command and its arguments as one shell-safe string.
export function quoted(command, args = []) {
  return [command, ...args].map(quoteToken).join(" ");
}

function quoteToken(token) {
  const text = String(token);
  return /[\s"'`$&|;<>(){}[\]*?!#~]/.test(text) ? JSON.stringify(text) : text;
}
