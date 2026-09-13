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
// `mise run interop-fetch` puts a SHA-256 pinned shadowsocks-rust outside the
// repository and this finds it there; SSOCKS_SSRUST_DIR overrides where it
// looks. Nothing is downloaded from here.

import { createServer, Socket } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { quoted } from "./shell.mjs";
import { locate } from "./ssrust.mjs";

const METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
const WINDOWS = process.platform === "win32";
// Reaches the client through a shell, so it is quoted rather than restricted.
// An earlier version of this file relied on the value having no spaces, and
// when that assumption was first broken the password arrived split across two
// arguments and every method failed to authenticate — which is indistinguishable
// from a broken key derivation until you print the command line.
const PASSWORD = "interop-password-1";

/// Everything that has to be let go of, whatever happens.
///
/// `fail` calls `process.exit(1)`, which runs no `finally` and no `exit`
/// handler that was not registered for it — so a child spawned before the
/// failure would outlive this script. That mattered more once these spawns
/// became `detached`: the child is its own process group leader now, so it is
/// not even taken down with the shell.
const cleanups = [];

function cleanUp() {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()();
    } catch {
      // Already gone, which is the outcome this is asking for.
    }
  }
}

function fail(message) {
  cleanUp();
  console.error(`interop: ${message}`);
  process.exit(1);
}

function serverBinary() {
  return locate("ssserver", fail);
}

/// Kill a child and everything it started.
///
/// The other two harnesses have had this since a Windows run passed every test
/// and then hung for ever: killing a shell-spawned child there kills cmd.exe
/// and orphans its grandchild, which keeps its pipes open and keeps this
/// process alive. This one was spawning children the same way with a bare
/// `child.kill()`.
///
/// On POSIX it needs `detached: true` on the spawn to work at all: without it
/// the child shares this process's group, so `-child.pid` names no group of its
/// own and the negative kill throws.
function killTree(child) {
  if (child.pid === undefined) return;
  if (WINDOWS) {
    spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
      stdio: "ignore",
    });
  } else {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  }
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
    { stdio: ["ignore", "pipe", "pipe"], detached: !WINDOWS },
  );

  const log = [];
  child.stdout.on("data", (d) => log.push(d.toString()));
  child.stderr.on("data", (d) => log.push(d.toString()));
  cleanups.push(() => killTree(child));
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
  killTree(child);
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
cleanups.push(() => echo.server.close());
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
    // Quoted rather than passed as an array: Windows needs a shell to find the
    // mise-installed `gleam`, and a shell concatenates an argument array
    // instead of escaping it. That is how the password once arrived at the
    // client split across two arguments, which looked exactly like a codec
    // fault until the command line was printed.
    const run = spawn(
      quoted("gleam", [
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
      ]),
      { cwd: "packages/ssocks", stdio: "inherit", shell: true, detached: !WINDOWS },
    );
    run.on("error", (error) => fail(`could not run the client: ${error.message}`));
    run.on("close", resolve);
  });

  killTree(child);

  if (status !== 0) {
    failed = true;
    console.error(`interop: ${method} failed. ssserver said:\n${log.join("")}`);
  }
}

cleanUp();

if (failed) {
  console.error("\ninterop: at least one method did not interoperate.");
  process.exit(1);
}

console.log("\ninterop: every method round-tripped through shadowsocks-rust.");

// Explicit, because the work is finished and the children this script started
// keep the event loop open until every pipe is collected. A task that passes
// and then never returns is a hung build, which is worse than a failing one —
// the other harnesses have said so for a while and this one did not do it.
process.exit(0);
