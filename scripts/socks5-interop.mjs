// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// SOCKS5, both ways, with a real implementation on the other end.
//
// The other four interoperability tests are about the Shadowsocks wire format.
// This one is about the protocol in front of it — the one a browser speaks —
// and it needs the same discipline for the same reason: a SOCKS5 codec checked
// only against its own output agrees with itself about every byte, and a shared
// mistake would be just as agreed upon and just as unusable.
//
// Direction 1, the server half: a SOCKS5 client written here drives this
// library's `ssocks/local`, which tunnels through a real `ssserver` to a plain
// TCP echo. The client is written out below rather than taken from a package so
// that what checks this library's proxy is not a sibling of what wrote it.
//
// Direction 2, the client half: this library's SOCKS5 client codec is pointed
// at a real `sslocal`, which in its default mode is a SOCKS5 server. That is the
// only direction that can say the bytes are right rather than merely agreed
// upon, and it is where over-strictness shows up — `ssurl` over-escaping is the
// same lesson from the URL tests.
//
// `mise run interop-fetch` puts a SHA-256 pinned shadowsocks-rust outside the
// repository and this finds it there; SSOCKS_SSRUST_DIR overrides where it
// looks. Nothing is downloaded from here.

import { createServer, Socket } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { quoted } from "./shell.mjs";
import { locate } from "./ssrust.mjs";

const METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
const PASSWORD = "socks5-interop-password-1";
const SIZES = [1, 100, 16_383, 16_384, 40_000];
const WINDOWS = process.platform === "win32";

function fail(message) {
  console.error(`socks5-interop: ${message}`);
  process.exit(1);
}

/// Kill a child and everything it started.
///
/// The Gleam proxy is spawned through a shell so that Windows can find the mise
/// shim, which means the child is cmd.exe and the Erlang node is its grandchild.
/// Killing the shell leaves the node running with its pipes open, and this
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

/// A plain TCP echo, the target every request is pointed at.
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

function watch(child, log) {
  child.stdout.on("data", (d) => log.push(d.toString()));
  child.stderr.on("data", (d) => log.push(d.toString()));
}

async function startGleam(module, args, port, what) {
  const log = [];
  const child = spawn(
    quoted("gleam", ["run", "-m", module, "--target", "erlang", "--", ...args]),
    {
      cwd: "packages/ssocks",
      stdio: ["ignore", "pipe", "pipe"],
      shell: true,
      detached: !WINDOWS,
    },
  );

  watch(child, log);
  child.on("error", (error) => fail(`could not start ${what}: ${error.message}`));

  await waitFor(port, what, log, child);
  return { child, log };
}

async function startServer(binary, port, method) {
  const log = [];
  const child = spawn(
    binary,
    ["-s", `127.0.0.1:${port}`, "-m", method, "-k", PASSWORD],
    { stdio: ["ignore", "pipe", "pipe"], detached: !WINDOWS },
  );

  watch(child, log);
  child.on("error", (error) => fail(`could not start ssserver: ${error.message}`));

  await waitFor(port, "ssserver", log, child);
  return { child, log };
}

/// A real `sslocal` in its default mode, which is a SOCKS5 server.
async function startSocksLocal(binary, localPort, serverPort, method) {
  const log = [];
  const child = spawn(
    binary,
    [
      // SOCKS5 is sslocal's default, and naming it keeps this readable next to
      // `--protocol tunnel` in the other two harnesses.
      "--protocol",
      "socks",
      "-b",
      `127.0.0.1:${localPort}`,
      "-s",
      `127.0.0.1:${serverPort}`,
      "-m",
      method,
      "-k",
      PASSWORD,
    ],
    { stdio: ["ignore", "pipe", "pipe"], detached: !WINDOWS },
  );

  watch(child, log);
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

// --- a SOCKS5 client, written out ---------------------------------------------

/// RFC 1928 in about forty lines: greet, read the chosen method, ask for the
/// target, read the reply, and then the socket is a plain pipe.
function socks5Exchange(port, targetPort, payload) {
  return new Promise((resolve) => {
    const socket = new Socket();
    let stage = "greeting";
    let buffered = Buffer.alloc(0);
    let echoed = Buffer.alloc(0);

    const finish = (outcome) => {
      socket.destroy();
      resolve(outcome);
    };

    socket.setTimeout(20_000);
    socket.once("timeout", () =>
      finish(`timed out during ${stage} with ${echoed.length} of ${payload.length} bytes back`),
    );
    socket.once("error", (error) => finish(error.message));

    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);

      if (stage === "greeting") {
        if (buffered.length < 2) return;
        if (buffered[0] !== 0x05) return finish(`the choice began with ${buffered[0]}, not 5`);
        if (buffered[1] !== 0x00) return finish(`it chose method ${buffered[1]}, not 0`);
        buffered = buffered.subarray(2);
        stage = "request";

        // CONNECT to 127.0.0.1:targetPort, as an IPv4 address.
        const request = Buffer.from([
          0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
          (targetPort >> 8) & 0xff, targetPort & 0xff,
        ]);
        socket.write(request);
      }

      if (stage === "request") {
        // VER REP RSV ATYP, then an address whose length the type decides.
        if (buffered.length < 4) return;
        if (buffered[0] !== 0x05) return finish(`the reply began with ${buffered[0]}, not 5`);
        if (buffered[1] !== 0x00) return finish(`it replied ${buffered[1]}, not 0`);
        if (buffered[2] !== 0x00) return finish(`the reserved byte was ${buffered[2]}, not 0`);

        const type = buffered[3];
        const bound =
          type === 0x01 ? 4 : type === 0x04 ? 16 : type === 0x03 ? 1 + buffered[4] : null;
        if (bound === null) return finish(`the reply's address type was ${type}`);
        const total = 4 + bound + 2;
        if (buffered.length < total) return;

        buffered = buffered.subarray(total);
        stage = "relaying";
        socket.write(payload);
      }

      if (stage === "relaying") {
        echoed = Buffer.concat([echoed, buffered]);
        buffered = Buffer.alloc(0);
        if (echoed.length >= payload.length) {
          finish(echoed.equals(payload) ? null : `the echo differed at ${payload.length} bytes`);
        }
      }
    });

    socket.connect(port, "127.0.0.1", () =>
      // VER, one method, NO AUTHENTICATION.
      socket.write(Buffer.from([0x05, 0x01, 0x00])),
    );
  });
}

// --- the two directions ---------------------------------------------------------

const binary = locate("sslocal", fail);
const serverBinary = locate("ssserver", fail);
const echo = await startEcho();
let failed = false;

console.log(`socks5-interop: echo on 127.0.0.1:${echo.port}`);

for (const method of METHODS) {
  // Direction 1: a SOCKS5 client here -> this proxy -> a real ssserver -> echo.
  {
    const serverPort = await freePort();
    const proxyPort = await freePort();

    const server = await startServer(serverBinary, serverPort, method);
    const proxy = await startGleam(
      "local_interop",
      [String(proxyPort), String(serverPort), method, PASSWORD],
      proxyPort,
      "the Gleam proxy",
    );

    console.log(`\nsocks5-interop: ${method}, socks5 client -> this proxy -> ssserver -> echo`);

    for (const size of SIZES) {
      const problem = await socks5Exchange(proxyPort, echo.port, payloadOf(size));
      if (problem) {
        failed = true;
        console.error(`  FAIL ${method}  ${size} bytes: ${problem}`);
        console.error(`    proxy said:\n${proxy.log.join("")}`);
        console.error(`    ssserver said:\n${server.log.join("")}`);
      } else {
        console.log(`  ok   ${method}  ${size} bytes`);
      }
    }

    killTree(proxy.child);
    killTree(server.child);
  }

  // Direction 2: this library's SOCKS5 client -> a real sslocal -> ssserver -> echo.
  {
    const serverPort = await freePort();
    const localPort = await freePort();

    const server = await startServer(serverBinary, serverPort, method);
    const local = await startSocksLocal(binary, localPort, serverPort, method);

    console.log(`\nsocks5-interop: ${method}, this client -> real sslocal -> ssserver -> echo`);

    // `spawn`, never `spawnSync`. The echo this client is asking for lives in
    // this process, and a synchronous child blocks the event loop it needs to
    // answer on — so the round trip times out and the failure looks like a
    // codec fault. It cost an afternoon once already.
    const status = await new Promise((resolve) => {
      const run = spawn(
        quoted("gleam", [
          "run",
          "-m",
          "socks5_client_interop",
          "--target",
          "erlang",
          "--",
          String(localPort),
          String(echo.port),
        ]),
        { cwd: "packages/ssocks", stdio: "inherit", shell: true },
      );
      run.on("error", (error) => fail(`could not run the client: ${error.message}`));
      run.on("close", resolve);
    });

    if (status !== 0) {
      failed = true;
      console.error(`  FAIL ${method}: the client could not use a real sslocal`);
      console.error(`    sslocal said:\n${local.log.join("")}`);
    }

    killTree(local.child);
    killTree(server.child);
  }
}

echo.server.close();

if (failed) {
  console.error("\nsocks5-interop: this SOCKS5 does not interoperate.");
  process.exit(1);
}

console.log("\nsocks5-interop: SOCKS5 works in both directions against shadowsocks-rust.");

// Explicit, because the work is finished and the children this script started
// keep the event loop open until every pipe is collected.
process.exit(0);
