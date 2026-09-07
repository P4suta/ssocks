// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Fetch the shadowsocks-rust that the interoperability tests run against.
//
// This is the one place in the repository that touches the network, and it runs
// only when a person types `mise run interop-fetch`. Building does not call it,
// testing does not call it, and `mise run interop` does not call it either — it
// says to run this instead. A test suite that downloads a binary the moment it
// is short of one is a test suite that can be made to download something else.
//
// The bytes are checked against a hash pinned in `ssrust.mjs` before anything is
// unpacked, so this either produces the exact release this repository was tested
// against or produces nothing.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  RELEASE,
  TOOLS,
  VERSION,
  WINDOWS,
  asset,
  directory,
  knownPlatforms,
  pathTo,
} from "./ssrust.mjs";

function fail(message) {
  console.error(`interop-fetch: ${message}`);
  process.exit(1);
}

function say(message) {
  console.log(`interop-fetch: ${message}`);
}

const wanted = asset();
if (!wanted) {
  fail(
    `no pinned build for ${process.platform}-${process.arch}.\n` +
      `Pinned: ${knownPlatforms().join(", ")}.\n` +
      `Fetch shadowsocks-rust ${VERSION} yourself from\n` +
      `${RELEASE}\nand point SSOCKS_SSRUST_DIR at the unpacked directory.`,
  );
}

const where = directory();

// Honest about what this branch did and did not check. The archive is deleted
// after unpacking, so there is nothing left to re-verify the binaries against,
// and printing "verified" here for a check that did not run would make the word
// worthless in the line above it.
const present = TOOLS.filter((tool) => existsSync(pathTo(tool)));
if (present.length === TOOLS.length) {
  say(`${where} already holds ${TOOLS.join(", ")}. Nothing fetched, nothing re-checked.`);
  say("Delete that directory and run this again to fetch and verify from scratch.");
  process.exit(0);
}

const url = `${RELEASE}/${wanted.name}`;
say(`fetching ${url}`);

const response = await fetch(url, { redirect: "follow" });
if (!response.ok) {
  fail(`${url} answered ${response.status} ${response.statusText}`);
}

const archive = Buffer.from(await response.arrayBuffer());
say(`${archive.length} bytes`);

const digest = createHash("sha256").update(archive).digest("hex");

// Both sides lower-cased. The release publishes its digests in upper case and
// comparing them raw against a lower-case hash reports a mismatch for two
// identical files, which looks exactly like a tampered download.
if (digest.toLowerCase() !== wanted.sha256.toLowerCase()) {
  fail(
    `SHA-256 mismatch for ${wanted.name}.\n` +
      `  expected ${wanted.sha256.toLowerCase()}\n` +
      `  received ${digest.toLowerCase()}\n` +
      "Nothing was written. Do not unpack this file.",
  );
}
say(`SHA-256 ${digest} matches the pin`);

mkdirSync(where, { recursive: true });
const downloaded = join(where, wanted.name);
writeFileSync(downloaded, archive);

unpack(downloaded, where);
rmSync(downloaded, { force: true });

const missing = TOOLS.filter((tool) => !existsSync(pathTo(tool)));
if (missing.length > 0) {
  fail(
    `unpacked ${wanted.name} but ${missing.join(", ")} did not appear in ${where}.\n` +
      `That directory now holds: ${readdirSync(where).join(", ") || "nothing"}.`,
  );
}

say(`ready in ${where}`);
say("`mise run interop` will find it there; SSOCKS_SSRUST_DIR overrides.");

/// Windows ships the release as a zip and everything else as a tar.xz, so the
/// two platforms need different tools rather than one with a flag.
///
/// The PowerShell command is a constant, and the two paths reach it through the
/// environment. Interpolating them into the command text instead would break on
/// any path holding a single quote — `C:\Users\O'Brien\...` is an ordinary
/// Windows path — and what follows a quote that closes a string early is not a
/// broken path but a second PowerShell statement.
function unpack(archivePath, into) {
  const run = WINDOWS
    ? spawnSync(
        "powershell",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Expand-Archive -LiteralPath $env:SSOCKS_ARCHIVE" +
            " -DestinationPath $env:SSOCKS_INTO -Force",
        ],
        {
          stdio: "inherit",
          env: { ...process.env, SSOCKS_ARCHIVE: archivePath, SSOCKS_INTO: into },
        },
      )
    : spawnSync("tar", ["-xJf", archivePath, "-C", into], { stdio: "inherit" });

  if (run.error) fail(`could not unpack: ${run.error.message}`);
  if (run.status !== 0) fail(`unpacking ${wanted.name} exited ${run.status}`);
}
