// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Put a real client in front of this library's server.
//
// scripts/interop.mjs checks the other direction: this library's client against
// a real ssserver. That validates the codec both ways, but it never asks the
// harder question about the server — can it read a target address header that
// somebody else wrote, split at boundaries it did not choose?
//
// Passing in the client direction makes it easy to assume both are covered.
// They are not. The client always writes the header the same way; until this
// script existed, the server had only ever read headers this library produced.
//
// The shape is: a plain TCP echo here, this library's server in an Erlang node
// pointed at it, `sslocal --protocol tunnel` in front of that, and a plain TCP
// client here again. A payload that survives the trip was framed by
// shadowsocks-rust and unframed by this library, which is the direction
// interop.mjs cannot reach.
//
// Point SSOCKS_SSRUST_DIR at a directory holding sslocal. Nothing is downloaded
// here; the binaries stay outside the repository.

import { createServer, Socket } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { quoted } from "./shell.mjs";

const METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
const PASSWORD = "server-interop-password-1";
const SIZES = [1, 100, 16_383, 16_384, 40_000];
const WINDOWS = process.platform === "win32";

function fail(message) {
  console.error(`server-interop: ${message}`);
  process.exit(1);
}

function localBinary() {
  const directory = process.env.SSOCKS_SSRUST_DIR;
  if (!directory) {
    fail(
      "SSOCKS_SSRUST_DIR is not set. Point it at a directory containing sslocal\n" +
        "from https://github.com/shadowsocks/shadowsocks-rust/releases .",
    );
  }
  const binary = join(directory, WINDOWS ? "sslocal.exe" : "sslocal");
  if (!existsSync(binary)) fail(`no sslocal at ${binary}`);
  return binary;
}

/// Kill a child and everything it started.
///
/// The Gleam server is spawned through a shell so that Windows can find the
/// mise shim, which means the child is cmd.exe and the Erlang node is its
/// grandchild. Killing the shell leaves the node running with its pipes open,
/// and this script then finishes its work and never exits — a CI task that
/// hangs after passing.
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

function freePort() {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
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

async function waitFor(port, what, log, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (await accepts(port)) return;
    if (child.exitCode !== null) {
      fail(`${what} exited with ${child.exitCode}:\n${log.join("")}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  killTree(child);
  fail(`${what} never listened on ${port}:\n${log.join("")}`);
}

/// A plain TCP echo, the target the tunnel is pointed at.
///
/// It lives here rather than in the Erlang node because Erlang buffers stdout
/// when it is a pipe, so a port chosen over there could not be read from here
/// until the process exited.
function startEcho() {
  return new Promise((resolve) => {
    const server = createServer((socket) => {
      socket.on("error", () => {});
      socket.pipe(socket);
    });
    server.on("error", (error) => fail(`echo server: ${error.message}`));
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: server.address().port }),
    );
  });
}

async function startServer(port, method) {
  const log = [];
  const child = spawn(
    quoted("gleam", [
      "run",
      "-m",
      "server_interop",
      "--target",
      "erlang",
      "--",
      String(port),
      method,
      PASSWORD,
    ]),
    { cwd: "packages/ssocks", stdio: ["ignore", "pipe", "pipe"], shell: true },
  );

  child.stdout.on("data", (d) => log.push(d.toString()));
  child.stderr.on("data", (d) => log.push(d.toString()));
  child.on("error", (error) => fail(`could not start the server: ${error.message}`));

  await waitFor(port, "the Gleam server", log, child);
  return { child, log };
}

async function startLocal(binary, localPort, serverPort, echoPort, method) {
  const log = [];
  const child = spawn(
    binary,
    [
      "--protocol",
      "tunnel",
      "-b",
      `127.0.0.1:${localPort}`,
      "-f",
      `127.0.0.1:${echoPort}`,
      "-s",
      `127.0.0.1:${serverPort}`,
      "-m",
      method,
      "-k",
      PASSWORD,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  child.stdout.on("data", (d) => log.push(d.toString()));
  child.stderr.on("data", (d) => log.push(d.toString()));
  child.on("error", (error) => fail(`could not start sslocal: ${error.message}`));

  await waitFor(localPort, "sslocal", log, child);
  return { child, log };
}

/// A repeating pattern rather than a constant byte, so a reordering or a
/// duplicated chunk shows up as a mismatch instead of cancelling out.
function payloadOf(size) {
  const unit = Buffer.from([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x5a, 0xa5]);
  return Buffer.concat(Array(Math.ceil(size / 8)).fill(unit)).subarray(0, size);
}

function exchange(port, payload) {
  return new Promise((resolve) => {
    const socket = new Socket();
    const received = [];
    let total = 0;

    const finish = (outcome) => {
      socket.destroy();
      resolve(outcome);
    };

    socket.setTimeout(15_000);
    socket.once("timeout", () =>
      finish(`timed out with ${total} of ${payload.length} bytes back`),
    );
    socket.once("error", (error) => finish(error.message));

    socket.on("data", (chunk) => {
      received.push(chunk);
      total += chunk.length;
      if (total >= payload.length) {
        const back = Buffer.concat(received);
        finish(back.equals(payload) ? null : `the echo differed at ${payload.length} bytes`);
      }
    });

    socket.connect(port, "127.0.0.1", () => socket.write(payload));
  });
}

const binary = localBinary();
const echo = await startEcho();
let failed = false;

console.log(`server-interop: echo on 127.0.0.1:${echo.port}`);

for (const method of METHODS) {
  const serverPort = await freePort();
  const localPort = await freePort();

  const server = await startServer(serverPort, method);
  const local = await startLocal(binary, localPort, serverPort, echo.port, method);

  console.log(`\nserver-interop: ${method}, sslocal -> this server -> echo`);

  for (const size of SIZES) {
    const problem = await exchange(localPort, payloadOf(size));
    if (problem) {
      failed = true;
      console.error(`  FAIL ${method}  ${size} bytes: ${problem}`);
      console.error(`    server said:\n${server.log.join("")}`);
      console.error(`    sslocal said:\n${local.log.join("")}`);
    } else {
      console.log(`  ok   ${method}  ${size} bytes`);
    }
  }

  killTree(local.child);
  killTree(server.child);
}

echo.server.close();

if (failed) {
  console.error("\nserver-interop: a real client could not use this server.");
  process.exit(1);
}

console.log("\nserver-interop: shadowsocks-rust can use this server.");

// Explicit, because the work is finished and the children this script started
// keep the event loop open until every pipe is collected. A task that passes
// and then never returns is a hung build, which is worse than a failing one.
process.exit(0);
