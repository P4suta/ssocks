// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Check `ss://` against shadowsocks-rust's own `ssurl`, in both directions and
// on both targets.
//
// The URL tests in this repository compare this library's parser with this
// library's writer. That cannot distinguish a correct SIP002 implementation
// from one that is consistently wrong: a base64 alphabet mixed up, or a
// fragment escaped where it should not be, would be written and read back the
// same way and pass everything, while nobody else could read a URL this
// library produces.
//
// So both directions are checked here. `ssurl --decode` reads what this writes,
// and this reads what `ssurl --encode` writes. The second direction matters on
// its own: `ssurl` percent-encodes more than it has to — it writes `v2ray-plugin`
// as `v2ray%2Dplugin` — and a parser that only ever sees its own minimal output
// would never meet that.
//
// Both targets, because this is the only check that says the output is *right*
// rather than merely agreed upon. `scripts/cross-target-vectors.mjs` already
// proves every runtime computes the same URL bytes, but a shared mistake in
// percent coding or base64 would be just as agreed upon and just as unusable.
// Only an implementation that had no part in writing this can tell those apart,
// and it should see what each target actually produces.
//
// `mise run interop-fetch` puts a SHA-256 pinned shadowsocks-rust outside the
// repository and this finds it there; SSOCKS_SSRUST_DIR overrides where it
// looks. Nothing is downloaded from here.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { quoted } from "./shell.mjs";
import { locate } from "./ssrust.mjs";

const TARGETS = [
  { name: "erlang", flags: ["--target", "erlang"] },
  { name: "node", flags: ["--target", "javascript", "--runtime", "node"] },
];

function fail(message) {
  console.error(`url-interop: ${message}`);
  process.exit(1);
}

function urlTool() {
  return locate("ssurl", fail);
}

const SSURL = urlTool();

function ssurl(args) {
  const result = spawnSync(quoted(SSURL, args), {
    encoding: "utf8",
    shell: true,
  });
  if (result.status !== 0) {
    fail(
      `ssurl ${args.join(" ")} failed:\n${result.stdout ?? ""}${result.stderr ?? ""}`,
    );
  }
  return (result.stdout ?? "").trim();
}

function gleam(target, args) {
  const result = spawnSync(
    quoted("gleam", [
      "run",
      "-m",
      "url_interop",
      ...target.flags,
      "--",
      ...args,
    ]),
    { cwd: "packages/ssocks_codec", encoding: "utf8", shell: true },
  );
  const output = `${result.stdout ?? ""}`;
  if (result.status !== 0) {
    fail(`url_interop ${args[0]} on ${target.name} failed:\n${output}${result.stderr ?? ""}`);
  }
  // Only the tab-separated lines; the compiler prints its own progress.
  //
  // Not trimmed. An absent tag or plugin is an empty trailing field, and
  // trimming the line deletes it, which reads downstream as `undefined` and
  // looks exactly like a field the two implementations disagree about.
  return output
    .split(/\r?\n/)
    .filter((line) => line.includes("\t"))
    .map((line) => line.split("\t"));
}

/// `ssurl --decode` prints something close to JSON but not close enough to
/// parse: unquoted keys and trailing commas. The fields wanted here are all
/// simple, so they are picked out by name.
function field(text, name) {
  const quotedValue = new RegExp(`\\b${name}:\\s*"((?:[^"\\\\]|\\\\.)*)"`).exec(text);
  if (quotedValue) return JSON.parse(`"${quotedValue[1]}"`);
  const bareValue = new RegExp(`\\b${name}:\\s*([^,\\s]+)`).exec(text);
  return bareValue ? bareValue[1] : "";
}

let failures = 0;

function check(label, ours, theirs) {
  if (ours === theirs) return true;
  failures += 1;
  console.error(
    `  FAIL ${label}\n    ours:  ${JSON.stringify(ours)}\n    ssurl: ${JSON.stringify(theirs)}`,
  );
  return false;
}

// --- the cases, and what ssurl makes of the same inputs ----------------------

// Written once on the reference target, purely to drive `ssurl --encode`; the
// per-target checks below re-read the cases from each target in turn.
const reference = gleam(TARGETS[0], ["write"]);
if (reference.length === 0) fail("url_interop write produced no cases");

const scratch = mkdtempSync(join(tmpdir(), "ssocks-url-"));

/// One URL per case, written by ssurl rather than by us.
const theirUrls = new Map();

for (const [name, , host, port, password, method, , plugin] of reference) {
  const config = { server: host, server_port: Number(port), password, method };
  if (plugin) {
    const [pluginName, ...rest] = plugin.split(";");
    config.plugin = pluginName;
    if (rest.length > 0) config.plugin_opts = rest.join(";");
  }

  const path = join(scratch, `${name}.json`);
  writeFileSync(path, JSON.stringify(config), "utf8");
  theirUrls.set(name, ssurl(["--encode", path]));
}

// --- both directions, on every target ----------------------------------------

for (const target of TARGETS) {
  console.log(`\nurl-interop: ${target.name}`);

  const cases = target === TARGETS[0] ? reference : gleam(target, ["write"]);

  for (const [name, ours, host, port, password, method, tag, plugin] of cases) {
    // Theirs reading ours.
    const decoded = ssurl(["--decode", ours]);
    const written = [
      check(`${name} host`, host, field(decoded, "server")),
      check(`${name} port`, port, field(decoded, "server_port")),
      check(`${name} password`, password, field(decoded, "password")),
      check(`${name} method`, method, field(decoded, "method")),
      // ssurl omits remarks entirely when there is no tag.
      check(`${name} tag`, tag, field(decoded, "remarks")),
    ].every(Boolean);

    // Ours reading theirs.
    const theirs = theirUrls.get(name);
    const [parsed] = gleam(target, ["read", theirs, password]);

    if (!parsed) {
      failures += 1;
      console.error(`  FAIL ${name}: nothing parsed from ${theirs}`);
      continue;
    }

    const [gotHost, gotPort, gotMethod, , gotPlugin, keys] = parsed;
    const read = [
      check(`${name} host (theirs)`, gotHost, host),
      check(`${name} port (theirs)`, gotPort, port),
      check(`${name} method (theirs)`, gotMethod, method),
      check(`${name} plugin (theirs)`, gotPlugin, plugin),
      // ssurl drops remarks when encoding, so a tag is not expected back.
      check(`${name} key (theirs)`, keys, "key-matches"),
    ].every(Boolean);

    if (written && read) console.log(`  ok   ${name}`);
  }
}

if (failures > 0) {
  console.error(`\nurl-interop: ${failures} field(s) did not agree with ssurl.`);
  process.exit(1);
}

console.log("\nurl-interop: ssurl and this library read each other's URLs.");
