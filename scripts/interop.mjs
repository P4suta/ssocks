// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Run this implementation against shadowsocks-rust.
//
// Everything else in this repository checks the codec against itself, which
// cannot tell a correct implementation from one that is consistently wrong in
// both directions. Here the bytes are decrypted by software that had no part in
// writing them.
//
// The shape is: a plain TCP echo server, a real ssserver in front of it, and the
// Gleam client asking that server to reach the echo. A payload that survives the
// trip was encrypted, framed, chunked, unchunked and decrypted correctly by two
// independent implementations.
//
// Point SSOCKS_SSRUST_DIR at a directory holding ssserver from
// https://github.com/shadowsocks/shadowsocks-rust/releases. Nothing is
// downloaded here; the binaries stay outside the repository.

import { createServer, Socket } from "node:net";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

const METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
// No spaces: the child is spawned through a shell on Windows, which would
// split a quoted password into separate arguments. Passwords containing spaces
// are covered by the unit tests instead.
const PASSWORD = "interop-password-1";
const WINDOWS = process.platform === "win32";

function fail(message) {
  console.error(`interop: ${message}`);
  process.exit(1);
}

function serverBinary() {
  const directory = process.env.SSOCKS_SSRUST_DIR;
  if (!directory) {
    fail(
      "SSOCKS_SSRUST_DIR is not set. Point it at a directory containing ssserver\n" +
        "from https://github.com/shadowsocks/shadowsocks-rust/releases .",
    );
  }
  const binary = join(directory, WINDOWS ? "ssserver.exe" : "ssserver");
  if (!existsSync(binary)) fail(`no ssserver at ${binary}`);
  return binary;
}

/// A TCP echo server. Whatever the Shadowsocks server relays to it comes back
/// unchanged, so any difference at the client is the codec's doing.
function startEcho() {
  return new Promise((resolve) => {
    const server = createServer((socket) => {
      socket.on("error", () => {});
      socket.pipe(socket);
    });
    server.on("error", (error) => fail(`echo server: ${error.message}`));
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: server.address().port });
    });
  });
}

function freePort() {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function startShadowsocks(binary, port, method) {
  const child = spawn(
    binary,
    ["-s", `127.0.0.1:${port}`, "-m", method, "-k", PASSWORD],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  const log = [];
  child.stdout.on("data", (d) => log.push(d.toString()));
  child.stderr.on("data", (d) => log.push(d.toString()));
  child.on("error", (error) => fail(`could not start ssserver: ${error.message}`));

  // Wait for the port to accept a connection rather than sleeping a guess.
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (await accepts(port)) return { child, log };
    if (child.exitCode !== null) {
      fail(`ssserver exited with ${child.exitCode}:\n${log.join("")}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill();
  fail(`ssserver did not start listening on ${port}:\n${log.join("")}`);
}

function accepts(port) {
  return new Promise((resolve) => {
    const socket = new Socket();
    socket.setTimeout(300);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, "127.0.0.1");
  });
}

const binary = serverBinary();
const echo = await startEcho();
let failed = false;

console.log(`interop: echo server on 127.0.0.1:${echo.port}`);

for (const method of METHODS) {
  const port = await freePort();
  const { child, log } = await startShadowsocks(binary, port, method);
  console.log(`\ninterop: ${method} against ssserver on 127.0.0.1:${port}`);

  // Spawned asynchronously, not with spawnSync. The echo server lives in this
  // same process, and spawnSync blocks the event loop, so a synchronous child
  // would leave every relayed connection unanswered and the client would time
  // out against a bug in the harness rather than in the codec.
  const status = await new Promise((resolve) => {
    const run = spawn(
      "gleam",
      [
        "run",
        "-m",
        "interop_smoke",
        "--target",
        "erlang",
        "--",
        String(port),
        String(echo.port),
        method,
        PASSWORD,
      ],
      { cwd: "packages/ssocks", stdio: "inherit", shell: WINDOWS },
    );
    run.on("error", (error) => fail(`could not run the client: ${error.message}`));
    run.on("close", resolve);
  });

  child.kill();

  if (status !== 0) {
    failed = true;
    console.error(`interop: ${method} failed. ssserver said:\n${log.join("")}`);
  }
}

echo.server.close();

if (failed) {
  console.error("\ninterop: at least one method did not interoperate.");
  process.exit(1);
}

console.log("\ninterop: every method round-tripped through shadowsocks-rust.");
