// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Check `ss://` against shadowsocks-rust's own `ssurl`, in both directions.
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
// Point SSOCKS_SSRUST_DIR at a directory holding ssurl. Nothing is downloaded
// here; the binaries stay outside the repository.

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { quoted } from "./shell.mjs";

const WINDOWS = process.platform === "win32";

function fail(message) {
  console.error(`url-interop: ${message}`);
  process.exit(1);
}

function urlTool() {
  const directory = process.env.SSOCKS_SSRUST_DIR;
  if (!directory) {
    fail(
      "SSOCKS_SSRUST_DIR is not set. Point it at a directory containing ssurl\n" +
        "from https://github.com/shadowsocks/shadowsocks-rust/releases .",
    );
  }
  const binary = join(directory, WINDOWS ? "ssurl.exe" : "ssurl");
  if (!existsSync(binary)) fail(`no ssurl at ${binary}`);
  return binary;
}

const SSURL = urlTool();

function ssurl(args) {
  const result = spawnSync(quoted(SSURL, args), {
    encoding: "utf8",
    shell: true,
  });
  if (result.status !== 0) {
    fail(`ssurl ${args.join(" ")} failed:\n${result.stdout ?? ""}${result.stderr ?? ""}`);
  }
  return (result.stdout ?? "").trim();
}

function gleam(args) {
  const result = spawnSync(
    quoted("gleam", ["run", "-m", "url_interop", "--target", "erlang", "--", ...args]),
    { cwd: "packages/ssocks_codec", encoding: "utf8", shell: true },
  );
  const output = `${result.stdout ?? ""}`;
  if (result.status !== 0) {
    fail(`url_interop ${args[0]} failed:\n${output}${result.stderr ?? ""}`);
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

function check(label, actual, expected) {
  if (actual === expected) return true;
  failures += 1;
  console.error(`  FAIL ${label}\n    ours:  ${JSON.stringify(expected)}\n    ssurl: ${JSON.stringify(actual)}`);
  return false;
}

// --- direction one: ssurl reads what we write --------------------------------

const cases = gleam(["write"]);
if (cases.length === 0) fail("url_interop write produced no cases");

console.log("url-interop: ssurl decoding URLs written here");

for (const [name, url, host, port, password, method, tag] of cases) {
  const decoded = ssurl(["--decode", url]);
  const ok =
    [
      check(`${name} host`, field(decoded, "server"), host),
      check(`${name} port`, field(decoded, "server_port"), port),
      check(`${name} password`, field(decoded, "password"), password),
      check(`${name} method`, field(decoded, "method"), method),
      // ssurl omits remarks entirely when there is no tag.
      check(`${name} tag`, field(decoded, "remarks"), tag),
    ].every(Boolean);
  if (ok) console.log(`  ok   ${name}`);
}

// --- direction two: we read what ssurl writes --------------------------------

console.log("\nurl-interop: parsing URLs written by ssurl");

const scratch = mkdtempSync(join(tmpdir(), "ssocks-url-"));

for (const [name, , host, port, password, method, , plugin] of cases) {
  const config = { server: host, server_port: Number(port), password, method };
  if (plugin) {
    const [pluginName, ...rest] = plugin.split(";");
    config.plugin = pluginName;
    if (rest.length > 0) config.plugin_opts = rest.join(";");
  }

  const path = join(scratch, `${name}.json`);
  writeFileSync(path, JSON.stringify(config), "utf8");

  const theirs = ssurl(["--encode", path]);
  const [parsed] = gleam(["read", theirs, password]);

  if (!parsed) {
    failures += 1;
    console.error(`  FAIL ${name}: nothing parsed from ${theirs}`);
    continue;
  }

  const [gotHost, gotPort, gotMethod, , gotPlugin, keys] = parsed;
  const ok =
    [
      check(`${name} host (theirs)`, gotHost, host),
      check(`${name} port (theirs)`, gotPort, port),
      check(`${name} method (theirs)`, gotMethod, method),
      check(`${name} plugin (theirs)`, gotPlugin, plugin),
      // ssurl drops remarks when encoding, so a tag is not expected back.
      check(`${name} key (theirs)`, keys, "key-matches"),
    ].every(Boolean);
  if (ok) console.log(`  ok   ${name}`);
}

if (failures > 0) {
  console.error(`\nurl-interop: ${failures} field(s) did not agree with ssurl.`);
  process.exit(1);
}

console.log("\nurl-interop: ssurl and this library read each other's URLs.");
