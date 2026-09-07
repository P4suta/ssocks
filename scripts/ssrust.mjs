// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Where shadowsocks-rust is, and which shadowsocks-rust it is.
//
// The interoperability tests are the only ones in this repository that can say
// this library speaks Shadowsocks rather than merely agreeing with itself, so
// they need a real implementation on the other end. That implementation is a
// third-party binary, and this file is the whole of the policy about it:
//
//   - It never lives inside the repository and is never committed. The default
//     location is a per-user cache directory; SSOCKS_SSRUST_DIR overrides it.
//   - Nothing downloads it as a side effect of building or testing. One task
//     does, `mise run interop-fetch`, and only when it is asked to.
//   - Its hash is pinned below, per platform, so a fetch either produces the
//     bytes this repository was tested against or fails saying so.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const VERSION = "1.25.0";

export const WINDOWS = process.platform === "win32";

/// The three binaries the four interoperability tests use between them.
export const TOOLS = ["ssserver", "sslocal", "ssurl"];

// Taken from the release's own `.sha256` files, which are published in upper
// case. That once produced a false mismatch against a lower-case digest and
// cost an afternoon, so every comparison in this repository lower-cases both
// sides rather than trusting the case of either.
const ASSETS = {
  "win32-x64": {
    name: `shadowsocks-v${VERSION}.x86_64-pc-windows-msvc.zip`,
    sha256: "882151ea5c52941d4a3360ebd12c74c6d6bd1b599596089ef1811b379c705666",
  },
  "linux-x64": {
    name: `shadowsocks-v${VERSION}.x86_64-unknown-linux-gnu.tar.xz`,
    sha256: "874f817fcf3e6d7681ec715a1c13c686c6eaae936524d102639b38364f3966ae",
  },
  "linux-arm64": {
    name: `shadowsocks-v${VERSION}.aarch64-unknown-linux-gnu.tar.xz`,
    sha256: "9c3b7fd2df1b7fd12cd80bb3b57d9de98a0fb526921669c3ac40587b88be3009",
  },
  "darwin-x64": {
    name: `shadowsocks-v${VERSION}.x86_64-apple-darwin.tar.xz`,
    sha256: "f4d7e8d9e3fe905c5c4a28e05593f2bcbd247e1618454c7996b81d951556282a",
  },
  "darwin-arm64": {
    name: `shadowsocks-v${VERSION}.aarch64-apple-darwin.tar.xz`,
    sha256: "58e0caf0cc9266c4ea226f38aa20fb28c1be12efc87a73cf5903197867555208",
  },
};

export const RELEASE =
  "https://github.com/shadowsocks/shadowsocks-rust/releases/download/" +
  `v${VERSION}`;

/// The asset for the machine this is running on, or undefined.
export function asset() {
  return ASSETS[`${process.platform}-${process.arch}`];
}

/// Every platform this repository has a pinned hash for, for error messages.
export function knownPlatforms() {
  return Object.keys(ASSETS);
}

/// The directory the binaries are expected in.
///
/// Outside the repository in both branches. A checkout is a thing that gets
/// archived, copied and published, and a 40 MB third-party binary that arrived
/// by accident is not something it should be possible to do any of that to.
export function directory() {
  const chosen = process.env.SSOCKS_SSRUST_DIR;
  return chosen ?? join(cacheRoot(), "ssocks", `shadowsocks-rust-${VERSION}`);
}

function cacheRoot() {
  if (WINDOWS) {
    return process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local");
  }
  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Caches");
  }
  return process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache");
}

/// Where one binary would be, whether or not it is there.
export function pathTo(tool) {
  return join(directory(), WINDOWS ? `${tool}.exe` : tool);
}

/// The path to one binary, or an explanation of how to get it.
///
/// The explanation matters more than it looks. Without it the first thing a
/// reader following the README meets is a missing file, and the difference
/// between "you have not fetched this yet" and "your build is broken" is not
/// visible from the error alone.
export function locate(tool, fail) {
  const path = pathTo(tool);
  if (existsSync(path)) return path;

  if (process.env.SSOCKS_SSRUST_DIR) {
    fail(
      `no ${tool} at ${path}.\n` +
        "SSOCKS_SSRUST_DIR points at that directory. Either unpack a\n" +
        `shadowsocks-rust release into it, or unset it and run \`mise run interop-fetch\`.`,
    );
  }

  fail(
    `no ${tool} at ${path}.\n` +
      `Run \`mise run interop-fetch\` to download shadowsocks-rust ${VERSION} there\n` +
      "(pinned by SHA-256, outside the repository), or point SSOCKS_SSRUST_DIR at a\n" +
      "copy you already have.",
  );
}
