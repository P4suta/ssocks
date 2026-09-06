// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// `gleam test --runtime deno` cannot pass Deno permission flags, and gleeunit
// reads gleam.toml to discover test modules, so the run dies on a permission
// error before a single test executes. Build first, then invoke Deno directly
// with the one permission gleeunit needs.
//
// The generated entrypoint carries the Gleam version in its filename, so it is
// discovered rather than hardcoded; a compiler upgrade must not silently skip
// the Deno leg of the matrix.

import { readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const packageName = readFileSync("gleam.toml", "utf8").match(
  /^name\s*=\s*"([^"]+)"/m,
)?.[1];

if (!packageName) {
  console.error("deno-test: no `name` in ./gleam.toml; run this from a package root");
  process.exit(1);
}

const outputDirectory = join("build", "dev", "javascript", packageName);

let entrypoints;
try {
  entrypoints = readdirSync(outputDirectory).filter(
    (name) => name.startsWith("gleam@@private_main") && name.endsWith(".mjs"),
  );
} catch {
  console.error(
    `deno-test: ${outputDirectory} does not exist. Run \`gleam build --target javascript\` first.`,
  );
  process.exit(1);
}

if (entrypoints.length !== 1) {
  console.error(
    `deno-test: expected exactly one generated entrypoint in ${outputDirectory}, found ${entrypoints.length}: ${entrypoints.join(", ")}`,
  );
  process.exit(1);
}

const result = spawnSync(
  "deno",
  ["run", "--allow-read", join(outputDirectory, entrypoints[0])],
  { stdio: "inherit", shell: process.platform === "win32" },
);

process.exit(result.status ?? 1);
