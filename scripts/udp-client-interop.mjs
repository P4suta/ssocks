// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Send UDP packets this library wrote to a relay that did not write them.
//
// `scripts/udp-interop.mjs` covers the reading direction: a real `sslocal -u`
// writes packets and this library's relay reads them. This is the other half,
// and it is the one that had no foreign check at all — until it existed, every
// UDP packet this library produced had only ever been read by the reader in the
// same repository. A field in the wrong order would be written and read back
// the same way, pass everything, and be unusable by anybody else.
//
// The shape is: a plain UDP echo here, a real `ssserver` with UDP enabled in
// front of it, and this library's `ssocks/udp_client` sending through that.
//
// `mise run interop-fetch` puts a SHA-256 pinned shadowsocks-rust outside the
// repository and this finds it there; SSOCKS_SSRUST_DIR overrides where it
// looks. Nothing is downloaded from here.

import { createSocket } from "node:dgram";
import { createServer, Socket } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { quoted } from "./shell.mjs";
import { locate } from "./ssrust.mjs";

const METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
const PASSWORD = "udp-client-interop-password-1";
const WINDOWS = process.platform === "win32";

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
  console.error(`udp-client-interop: ${message}`);
  process.exit(1);
}

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

/// A plain UDP echo. Whatever the relay forwards comes back unchanged.
function startEcho() {
  return new Promise((resolve) => {
    const socket = createSocket("udp4");
    socket.on("error", (error) => fail(`udp echo: ${error.message}`));
    socket.on("message", (data, from) =>
      socket.send(data, from.port, from.address),
    );
    socket.bind(0, "127.0.0.1", () => resolve({ socket, port: socket.address().port }));
  });
}

/// A real `ssserver` carrying both transports.
///
/// `-U` is TCP_AND_UDP and `-u` is UDP only — the letters are the other way
/// round from the guess. TCP is not used by this test, but keeping it is what
/// makes readiness a connect rather than a sleep: UDP has nothing to connect
/// to, and a sleep long enough for a slow machine is a race on a slower one.
async function startServer(binary, port, method) {
  const log = [];
  const child = spawn(
    binary,
    ["-s", `127.0.0.1:${port}`, "-m", method, "-k", PASSWORD, "-U"],
    { stdio: ["ignore", "pipe", "pipe"], detached: !WINDOWS },
  );

  child.stdout.on("data", (d) => log.push(d.toString()));
  child.stderr.on("data", (d) => log.push(d.toString()));
  cleanups.push(() => killTree(child));
  child.on("error", (error) => fail(`could not start ssserver: ${error.message}`));

  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (await accepts(port)) return { child, log };
    if (child.exitCode !== null) {
      fail(`ssserver exited with ${child.exitCode}:\n${log.join("")}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  killTree(child);
  fail(`ssserver never listened on ${port}:\n${log.join("")}`);
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

const binary = locate("ssserver", fail);
const echo = await startEcho();
cleanups.push(() => echo.socket.close());
let failed = false;

console.log(`udp-client-interop: udp echo on 127.0.0.1:${echo.port}`);

for (const method of METHODS) {
  const serverPort = await freePort();
  const server = await startServer(binary, serverPort, method);

  console.log(`\nudp-client-interop: ${method}, this client -> ssserver -U -> echo`);

  // `spawn`, never `spawnSync`: the echo lives in this process and a
  // synchronous child blocks the event loop it answers on.
  const status = await new Promise((resolve) => {
    const run = spawn(
      quoted("gleam", [
        "run",
        "-m",
        "udp_client_interop",
        "--target",
        "erlang",
        "--",
        String(serverPort),
        String(echo.port),
        method,
        PASSWORD,
      ]),
      { cwd: "packages/ssocks", stdio: "inherit", shell: true },
    );
    run.on("error", (error) => fail(`could not run the client: ${error.message}`));
    run.on("close", resolve);
  });

  if (status !== 0) {
    failed = true;
    console.error(`  FAIL ${method}: a real relay could not read these packets`);
    console.error(`    ssserver said:\n${server.log.join("")}`);
  }

  killTree(server.child);
}

cleanUp();

if (failed) {
  console.error("\nudp-client-interop: these packets are not Shadowsocks UDP.");
  process.exit(1);
}

console.log("\nudp-client-interop: shadowsocks-rust can read packets this client writes.");

// Explicit, because the work is finished and the children this script started
// keep the event loop open until every pipe is collected.
process.exit(0);
