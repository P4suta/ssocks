// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Every runtime must compute the same bytes.
//
// The test suite runs on Erlang, Node, Deno and Bun and passes on all four, but
// passing separately is a weaker claim than agreeing. A cipher fed its nonce in
// the wrong order, or an AES-GCM built without an explicit tag length, produces
// plausible bytes that are simply different, and a suite that only checks
// round trips within one runtime never notices.
//
// So `vector_dump` prints every layer's output for fixed inputs, it is run on
// each runtime, and the results are compared line by line. The first
// disagreement is reported by name, which says which layer diverged rather than
// only that something did.

import { spawnSync } from "node:child_process";
import { quoted } from "./shell.mjs";

const RUNTIMES = [
  { name: "erlang", args: ["--target", "erlang"] },
  { name: "node", args: ["--target", "javascript", "--runtime", "node"] },
  { name: "deno", args: ["--target", "javascript", "--runtime", "deno"] },
  { name: "bun", args: ["--target", "javascript", "--runtime", "bun"] },
];

/// Keep only the "label hex" lines, discarding whatever the build printed.
function vectorsFrom(output) {
  const vectors = new Map();
  for (const line of output.split(/\r?\n/)) {
    const match = /^([A-Za-z0-9_.\-]+) ([0-9a-f]*)$/.exec(line.trim());
    if (match) vectors.set(match[1], match[2]);
  }
  return vectors;
}

function dump(runtime) {
  const result = spawnSync(
    quoted("gleam", ["run", "-m", "vector_dump", ...runtime.args]),
    {
      cwd: "packages/ssocks_codec",
      encoding: "utf8",
      shell: true,
      maxBuffer: 64 * 1024 * 1024,
    },
  );

  if (result.status !== 0) {
    console.error(`cross-target: ${runtime.name} failed to run vector_dump`);
    console.error(result.stdout ?? "");
    console.error(result.stderr ?? "");
    process.exit(1);
  }

  const vectors = vectorsFrom(result.stdout ?? "");
  if (vectors.size === 0) {
    console.error(`cross-target: ${runtime.name} produced no vectors`);
    process.exit(1);
  }
  return vectors;
}

const [reference, ...others] = RUNTIMES;
const expected = dump(reference);
console.log(`cross-target: ${expected.size} vectors from ${reference.name}`);

let failed = false;

for (const runtime of others) {
  const actual = dump(runtime);
  const differences = [];

  for (const [label, value] of expected) {
    if (!actual.has(label)) {
      differences.push(`${label}: missing on ${runtime.name}`);
    } else if (actual.get(label) !== value) {
      differences.push(
        `${label}:\n    ${reference.name}: ${abbreviate(value)}\n    ${runtime.name}: ${abbreviate(actual.get(label))}`,
      );
    }
  }

  for (const label of actual.keys()) {
    if (!expected.has(label)) {
      differences.push(`${label}: only on ${runtime.name}`);
    }
  }

  if (differences.length === 0) {
    console.log(`cross-target: ${runtime.name} agrees on all ${actual.size}`);
  } else {
    failed = true;
    console.error(
      `cross-target: ${runtime.name} disagrees on ${differences.length} of ${expected.size}:`,
    );
    // Only the first few, because once one layer diverges everything built on
    // it diverges too and the rest is noise.
    for (const difference of differences.slice(0, 5)) {
      console.error(`  ${difference}`);
    }
    if (differences.length > 5) {
      console.error(`  ... and ${differences.length - 5} more`);
    }
  }
}

function abbreviate(hex) {
  return hex.length > 96 ? `${hex.slice(0, 96)}... (${hex.length / 2} bytes)` : hex;
}

if (failed) {
  console.error("\ncross-target: the runtimes do not agree.");
  process.exit(1);
}

console.log("\ncross-target: every runtime computes identical bytes.");
