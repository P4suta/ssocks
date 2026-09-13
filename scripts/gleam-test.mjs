// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Run one leg of the test matrix and require that it actually ran something.
//
// `gleam test` exits 0 when gleeunit finds no tests at all. It prints
// "No tests found!" and reports success, so a package whose test directory has
// only a `main` in it — or whose test module stopped being discovered after a
// rename — passes CI while asserting nothing. That is worse than a missing
// gate, because the green tick claims coverage that does not exist.
//
// So the summary line is parsed and a count is demanded. A positive one is not
// enough on its own: a module that stops being discovered takes its tests with
// it and the rest still report success, which is the same green tick claiming
// the same coverage that is not there. Each package therefore states a floor,
// and a leg that falls below it fails here.
//
// The floor is a minimum rather than an exact number, so adding a test does not
// break the build; raising it when tests are added is the deliberate part.
//
// Deno needs a different invocation entirely: `gleam test --runtime deno`
// cannot pass Deno permission flags, and gleeunit reads gleam.toml to discover
// test modules, so the run dies on a permission error before a single test
// executes. Build first, then invoke Deno directly with the one permission it
// needs. The generated entrypoint carries the Gleam version in its filename, so
// it is discovered rather than hardcoded; a compiler upgrade must not silently
// skip this leg.

import { readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { quoted } from "./shell.mjs";

const runtime = process.argv[2];
const RUNTIMES = ["erlang", "node", "deno", "bun"];

// The exact number of tests each package runs, treated as a floor.
//
// Exact rather than a round number underneath: a margin is a number of tests
// that can go missing without anybody hearing about it, which is the failure
// this gate exists for. Raise these in the commit that adds tests; never lower
// one to make a red build green.
const FLOORS = { ssocks_codec: 323, ssocks: 94 };

if (!RUNTIMES.includes(runtime)) {
  console.error(`gleam-test: expected one of ${RUNTIMES.join(", ")}, got ${runtime ?? "nothing"}`);
  process.exit(2);
}

function packageName() {
  const name = readFileSync("gleam.toml", "utf8").match(/^name\s*=\s*"([^"]+)"/m)?.[1];
  if (!name) {
    console.error("gleam-test: no `name` in ./gleam.toml; run this from a package root");
    process.exit(2);
  }
  return name;
}

/// Deno cannot go through `gleam test`, so build and run the entrypoint.
function denoCommand() {
  const built = spawnSync(quoted("gleam", ["build", "--target", "javascript"]), {
    stdio: "inherit",
    shell: true,
  });
  if (built.status !== 0) process.exit(built.status ?? 1);

  const directory = join("build", "dev", "javascript", packageName());
  let entrypoints;
  try {
    entrypoints = readdirSync(directory).filter(
      (name) => name.startsWith("gleam@@private_main") && name.endsWith(".mjs"),
    );
  } catch {
    console.error(`gleam-test: ${directory} does not exist after a successful build`);
    process.exit(1);
  }
  if (entrypoints.length !== 1) {
    console.error(
      `gleam-test: expected exactly one generated entrypoint in ${directory}, found ${entrypoints.length}: ${entrypoints.join(", ")}`,
    );
    process.exit(1);
  }
  return ["deno", ["run", "--allow-read", join(directory, entrypoints[0])]];
}

const COMMANDS = {
  erlang: ["gleam", ["test", "--target", "erlang"]],
  node: ["gleam", ["test", "--target", "javascript", "--runtime", "node"]],
  bun: ["gleam", ["test", "--target", "javascript", "--runtime", "bun"]],
};

const [command, args] = runtime === "deno" ? denoCommand() : COMMANDS[runtime];

const result = spawnSync(quoted(command, args), {
  encoding: "utf8",
  shell: true,
  maxBuffer: 64 * 1024 * 1024,
});

const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
process.stdout.write(output);

if (result.status !== 0) process.exit(result.status ?? 1);

// gleeunit's summary, on both targets: "209 passed, no failures".
const passed = Number(/(\d+) passed, no failures/.exec(output)?.[1] ?? "0");

if (passed === 0) {
  console.error(
    `\ngleam-test: ${runtime} reported success without running a test.\n` +
      "  gleeunit exits 0 when it finds nothing, so this leg was asserting nothing at all.\n" +
      "  Check that the package has a test module ending in `_test.gleam` with `pub fn`\n" +
      "  names ending in `_test`, and that its gleeunit main is being reached.",
  );
  process.exit(1);
}

const name = packageName();
const floor = FLOORS[name];

if (floor === undefined) {
  console.error(
    `\ngleam-test: no test-count floor is recorded for \`${name}\`.\n` +
      "  Add one to FLOORS in scripts/gleam-test.mjs, or a package could lose\n" +
      "  every test it has and still report success.",
  );
  process.exit(1);
}

if (passed < floor) {
  console.error(
    `\ngleam-test: ${runtime} ran ${passed} tests and \`${name}\` has a floor of ${floor}.\n` +
      "  Tests have gone missing rather than failed — a module that stops being\n" +
      "  discovered takes its tests with it and the rest still report success.\n" +
      "  Check for a renamed file, a `pub fn` that lost its `_test` suffix, or a\n" +
      "  module that no longer compiles into the test build.\n" +
      "  If tests were deliberately removed, lower the floor in the same commit.",
  );
  process.exit(1);
}

console.log(`gleam-test: ${runtime} ran ${passed} tests (floor ${floor})`);
