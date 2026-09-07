// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// `gleam build --warnings-as-errors` only covers src/. Test modules are compiled
// by `gleam test`, which has no such flag, so a warning there is printed and
// ignored.
//
// That gap is not cosmetic. An integer literal above 2^53 is only a warning, but
// on the JavaScript target it collapses to a different value, which once turned
// a Poly1305 test into a comparison of two identical zeroes that passed. This
// gate exists so that cannot happen quietly again.
//
// `gleam check` type-checks src/ and test/ together, so running it per target
// and refusing any warning covers what the build flag cannot.

import { spawnSync } from "node:child_process";
import { quoted } from "./shell.mjs";

const targets = process.argv.slice(2);
if (targets.length === 0) {
  console.error("no-warnings: pass one or more targets, e.g. erlang javascript");
  process.exit(1);
}

let failed = false;

for (const target of targets) {
  const result = spawnSync(quoted("gleam", ["check", "--target", target]), {
    encoding: "utf8",
    shell: true,
  });

  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  if (result.status !== 0) {
    console.error(`no-warnings: gleam check --target ${target} failed`);
    console.error(output);
    failed = true;
    continue;
  }

  // Strip ANSI colouring before looking for the marker.
  const plain = output.replace(/\u001b\[[0-9;]*m/g, "");
  const warnings = plain.split(/\n(?=warning:)/).filter((b) => b.startsWith("warning:"));

  if (warnings.length > 0) {
    console.error(
      `no-warnings: ${warnings.length} warning(s) on the ${target} target, which this project treats as errors:\n`,
    );
    console.error(plain.trimEnd());
    failed = true;
  } else {
    console.log(`no-warnings: ${target} clean`);
  }
}

process.exit(failed ? 1 : 0);
