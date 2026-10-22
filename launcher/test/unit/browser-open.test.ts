/**
 * browser-open.test — which program opens a URL in the person's browser
 * (launcher/src/browser-open.ts, for `mandu scan --open`;
 * confidentiality-plan-17-past-sessions-scan.md §3 item 12): BROWSER first,
 * macOS `open`, WSL `wslview` or `cmd.exe /c start "" <url>`, `xdg-open`
 * with a display, and none with no display or a Mac over SSH; then the real
 * spawn, detached, of a recorder script and of a program that is not there.
 * No protection axis is involved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { browserCommand, cmdStartArgs, onPath, openUrl, overSsh } from "../../src/browser-open.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no axis is read: opening a page is no part of protection

const URL_ = "http://127.0.0.1:40123/scan";

test("browserCommand: macOS open; Linux xdg-open with a display (X or Wayland); none without one, saying whether over SSH", () => {
  assert.deepEqual(browserCommand("darwin", {}, URL_), { kind: "spawn", cmd: "open", args: [URL_] });
  assert.deepEqual(browserCommand("linux", { DISPLAY: ":0" }, URL_), { kind: "spawn", cmd: "xdg-open", args: [URL_] });
  assert.deepEqual(browserCommand("linux", { WAYLAND_DISPLAY: "wayland-0" }, URL_), { kind: "spawn", cmd: "xdg-open", args: [URL_] });
  assert.deepEqual(browserCommand("freebsd", { DISPLAY: ":0" }, URL_), { kind: "spawn", cmd: "xdg-open", args: [URL_] });
  assert.deepEqual(browserCommand("linux", {}, URL_), { kind: "none", ssh: false }, "headless: nothing tried");
  assert.deepEqual(browserCommand("linux", { DISPLAY: "" }, URL_), { kind: "none", ssh: false });
  assert.deepEqual(browserCommand("linux", { SSH_CONNECTION: "10.0.0.2 51000 10.0.0.1 22" }, URL_), { kind: "none", ssh: true });
  // An X forwarded over SSH is a display: the page opens at the far end.
  assert.deepEqual(browserCommand("linux", { SSH_CONNECTION: "x", DISPLAY: "localhost:10.0" }, URL_), { kind: "spawn", cmd: "xdg-open", args: [URL_] });
  // A Mac over SSH: `open` would show it on the Mac's own screen.
  assert.deepEqual(browserCommand("darwin", { SSH_CONNECTION: "x" }, URL_), { kind: "none", ssh: true });
  assert.equal(overSsh({ SSH_CLIENT: "10.0.0.2 51000 22" }), true);
  assert.equal(overSsh({}), false);
});

test("browserCommand: BROWSER first, as a command (the URL appended, or in place of %s), its first entry, with no display too", () => {
  assert.deepEqual(browserCommand("linux", { BROWSER: "firefox", DISPLAY: ":0" }, URL_), { kind: "spawn", cmd: "firefox", args: [URL_] });
  assert.deepEqual(browserCommand("linux", { BROWSER: "chromium --new-window %s" }, URL_), { kind: "spawn", cmd: "chromium", args: ["--new-window", URL_] });
  assert.deepEqual(browserCommand("linux", { BROWSER: "x --at=%s" }, URL_), { kind: "spawn", cmd: "x", args: [`--at=${URL_}`] });
  assert.deepEqual(browserCommand("linux", { BROWSER: "w3m:lynx" }, URL_), { kind: "spawn", cmd: "w3m", args: [URL_] }, "the first of a list");
  assert.deepEqual(browserCommand("linux", { BROWSER: "b --pct=100%% %s" }, URL_), { kind: "spawn", cmd: "b", args: ["--pct=100%", URL_] });
  // The person's choice holds over SSH, with no display, and on macOS.
  assert.deepEqual(browserCommand("linux", { BROWSER: "/usr/bin/w3m", SSH_CONNECTION: "x" }, URL_), { kind: "spawn", cmd: "/usr/bin/w3m", args: [URL_] });
  assert.deepEqual(browserCommand("darwin", { BROWSER: "lynx" }, URL_), { kind: "spawn", cmd: "lynx", args: [URL_] });
  // An empty or blank one is no choice.
  assert.deepEqual(browserCommand("linux", { BROWSER: "  : " }, URL_), { kind: "none", ssh: false });
  assert.deepEqual(browserCommand("darwin", { BROWSER: "" }, URL_), { kind: "spawn", cmd: "open", args: [URL_] });
});

test("browserCommand: WSL opens the Windows browser, wslview when present, else cmd.exe /c start with an empty title and cmd's metacharacters escaped", () => {
  const has = (names: string[]) => (c: string): boolean => names.includes(c);
  assert.deepEqual(browserCommand("linux", {}, URL_, { wsl: true, onPath: has(["wslview"]) }), { kind: "spawn", cmd: "wslview", args: [URL_] });
  assert.deepEqual(browserCommand("linux", {}, URL_, { wsl: true, onPath: has([]) }), { kind: "spawn", cmd: "cmd.exe", args: ["/c", "start", "", URL_] });
  // WSL_DISTRO_NAME alone says WSL; WSLg's DISPLAY does not send it to xdg-open.
  assert.deepEqual(browserCommand("linux", { WSL_DISTRO_NAME: "Ubuntu", DISPLAY: ":0" }, URL_), { kind: "spawn", cmd: "cmd.exe", args: ["/c", "start", "", URL_] });
  assert.deepEqual(browserCommand("win32", {}, URL_), { kind: "spawn", cmd: "cmd.exe", args: ["/c", "start", "", URL_] });
  assert.deepEqual(cmdStartArgs("http://h/a?x=1&y=(2)|<3>^"), ["/c", "start", "", "http://h/a?x=1^&y=^(2^)^|^<3^>^^"]);
  // What cmd could still read as more than a URL is not handed to it.
  for (const bad of ["http://h/a b", "http://h/\"x", "http://h/%PATH%", "http://h/!x!"]) {
    assert.equal(cmdStartArgs(bad), null, bad);
    assert.deepEqual(browserCommand("linux", {}, bad, { wsl: true }), { kind: "none", ssh: false }, bad);
  }
  // BROWSER still first under WSL.
  assert.deepEqual(browserCommand("linux", { BROWSER: "wslview" }, URL_, { wsl: true }), { kind: "spawn", cmd: "wslview", args: [URL_] });
});

test("openUrl: the program started detached with the URL as its own argument; one that is not there is a failure, never a throw; no browser, nothing started", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-browser-"));
  try {
    const rec = join(dir, "rec.txt");
    const script = join(dir, "browser.sh");
    writeFileSync(script, `#!/bin/sh\nprintf '%s\\n' "$@" > "${rec}.tmp" && mv "${rec}.tmp" "${rec}"\n`);
    chmodSync(script, 0o755);
    const tricky = "http://127.0.0.1:1/scan?a=$(touch x)&b=`y`";
    const ok = await openUrl(tricky, { PATH: process.env["PATH"], BROWSER: script }, "linux", {});
    assert.deepEqual(ok, { kind: "opened", cmd: script });
    for (let i = 0; i < 100 && !existsSync(rec); i++) await new Promise((r) => setTimeout(r, 20));
    assert.equal(readFileSync(rec, "utf8"), `${tricky}\n`, "one argument, no shell read it");
    assert.ok(!existsSync(join(dir, "x")));

    const missing = await openUrl(URL_, { PATH: dir, BROWSER: join(dir, "no-such-browser") }, "linux", {});
    assert.equal(missing.kind, "failed");
    assert.match((missing as { why: string }).why, /ENOENT/);

    assert.deepEqual(await openUrl(URL_, { PATH: dir }, "linux", {}), { kind: "no-browser", ssh: false });
    assert.equal(onPath("browser.sh", { PATH: `/nonexistent:${dir}` }), true);
    assert.equal(onPath("rec.txt", { PATH: dir }), false, "not executable");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
