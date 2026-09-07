// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Put a real client in front of this library's UDP relay.
//
// The TCP interop scripts cover the stream framing in both directions. The UDP
// packet format is different code with a different shape — one AEAD box under
// an all-zero nonce, no counter, no framing — and every other test of it
// compares this library with itself, which cannot tell a correct packet from
// one that is consistently wrong in both directions.
//
// The shape is: a plain UDP echo here, this library's relay pointed at it,
// `sslocal --protocol tunnel -u` in front of that, and a plain UDP client here
// again. A payload that survives the trip was sealed by shadowsocks-rust and
// opened by this library, and the reply sealed here and opened there.
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
const PASSWORD = "udp-interop-password-1";
// One datagram each, so the sizes stay under the usual path MTU and under the
// 64 KiB a UDP payload can hold at all.
const SIZES = [1, 100, 1200];
const WINDOWS = process.platform === "win32";

function fail(message) {
  console.error(`udp-interop: ${message}`);
  process.exit(1);
}

function localBinary() {
  return locate("sslocal", fail);
}

/// Kill a child and everything it started.
///
/// The Gleam relay is spawned through a shell so that Windows can find the mise
/// shim, which makes the child cmd.exe and the Erlang node its grandchild.
/// Killing only the shell leaves the node running with its pipes open, and this
/// script then finishes its work and never exits.
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

/// A plain UDP echo, the target the tunnel is pointed at.
function startEcho() {
  return new Promise((resolve) => {
    const socket = createSocket("udp4");
    socket.on("message", (data, from) =>
      socket.send(data, from.port, from.address),
    );
    socket.on("error", (error) => fail(`echo: ${error.message}`));
    socket.bind(0, "127.0.0.1", () => resolve({ socket, port: socket.address().port }));
  });
}

/// UDP has nothing to connect to, so there is no way to ask whether the relay
/// is listening. Its stdout would say so, but Erlang buffers that until the
/// process exits, and the relay never does.
///
/// So readiness is the thing itself: keep trying a one byte round trip until it
/// works. A fixed sleep would have to be long enough for the slowest Gleam
/// build on the slowest machine, and would still be a race on a slower one.
async function waitUntilRelaying(port, deadlineMs, children) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    for (const child of children) {
      if (child.exitCode !== null) return `a child exited with ${child.exitCode}`;
    }
    if ((await exchange(port, payloadOf(1), 1000)) === null) return null;
  }
  return "the relay never answered";
}

function startRelay(port, method) {
  const log = [];
  const child = spawn(
    quoted("gleam", [
      "run",
      "-m",
      "udp_interop",
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
  child.on("error", (error) => fail(`could not start the relay: ${error.message}`));

  return { child, log };
}

function startLocal(binary, localPort, relayPort, echoPort, method) {
  const log = [];
  const child = spawn(
    binary,
    [
      "--protocol",
      "tunnel",
      "-u",
      "-b",
      `127.0.0.1:${localPort}`,
      "-f",
      `127.0.0.1:${echoPort}`,
      "-s",
      `127.0.0.1:${relayPort}`,
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

  return { child, log };
}

/// A repeating pattern rather than a constant byte, so a truncation or a
/// duplicated packet shows up as a mismatch instead of cancelling out.
function payloadOf(size) {
  const unit = Buffer.from([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x5a, 0xa5]);
  return Buffer.concat(Array(Math.ceil(size / 8) + 1).fill(unit)).subarray(0, size);
}

function exchange(port, payload, timeoutMs = 10_000) {
  return new Promise((resolve) => {
    const socket = createSocket("udp4");
    const timer = setTimeout(() => {
      socket.close();
      resolve("nothing came back");
    }, timeoutMs);

    socket.on("message", (data) => {
      clearTimeout(timer);
      socket.close();
      resolve(data.equals(payload) ? null : `the echo differed at ${payload.length} bytes`);
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      socket.close();
      resolve(error.message);
    });

    socket.send(payload, port, "127.0.0.1");
  });
}

const binary = localBinary();
const echo = await startEcho();
let failed = false;

console.log(`udp-interop: echo on 127.0.0.1:${echo.port}`);

for (const method of METHODS) {
  const relayPort = await freePort();
  const localPort = await freePort();

  const relay = startRelay(relayPort, method);
  const local = startLocal(binary, localPort, relayPort, echo.port, method);

  const notReady = await waitUntilRelaying(localPort, 90_000, [
    relay.child,
    local.child,
  ]);
  if (notReady) {
    console.error(`udp-interop: ${method}: ${notReady}`);
    console.error(`    relay said:\n${relay.log.join("")}`);
    console.error(`    sslocal said:\n${local.log.join("")}`);
    killTree(local.child);
    killTree(relay.child);
    failed = true;
    continue;
  }

  console.log(`\nudp-interop: ${method}, sslocal -> this relay -> echo`);

  for (const size of SIZES) {
    const problem = await exchange(localPort, payloadOf(size));
    if (problem) {
      failed = true;
      console.error(`  FAIL ${method}  ${size} bytes: ${problem}`);
      console.error(`    relay said:\n${relay.log.join("")}`);
      console.error(`    sslocal said:\n${local.log.join("")}`);
    } else {
      console.log(`  ok   ${method}  ${size} bytes`);
    }
  }

  killTree(local.child);
  killTree(relay.child);
}

echo.socket.close();

if (failed) {
  console.error("\nudp-interop: a real client could not use this relay.");
  process.exit(1);
}

console.log("\nudp-interop: shadowsocks-rust can use this relay.");

// Explicit, because the work is finished and the children this script started
// keep the event loop open until every pipe is collected.
process.exit(0);
