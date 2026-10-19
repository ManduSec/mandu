/**
 * pty-relay.test — unit tests for the PTY relay backend helpers
 * (src/pty-relay.ts): platform → flavor mapping, the per-flavor argv
 * construction (util-linux `script -qefc` vs BSD `script -q /dev/null …`), the
 * POSIX quoting that survives util-linux's `sh -c` layer, the probe argv, the
 * BSD stdin check, and the availability probe on the host + unsupported
 * platforms.
 *
 * The pure pieces (flavor, argv, probe argv, stdin check) fully specify the
 * darwin backend off-platform; the host-keyed probe test proves the BSD
 * ok-path when the suite runs on a Mac (measured on macOS 26.5.1,
 * docs/design/agents/pty-relay.md), and test/component/bsd-relay.test.ts drives it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  BSD_SCRIPT,
  shellQuote,
  buildPtyArgv,
  ptyFlavor,
  ptyProbeArgv,
  ptyRelayAvailable,
  ptyRelayEnv,
  PTY_RELAY_SHELL,
  ptyScriptPath,
  ptyStdinProblem,
  stdinFacts,
} from "../../src/pty-relay.js";

test("ptyFlavor maps each platform to its script(1) dialect", () => {
  assert.equal(ptyFlavor("linux"), "util-linux");
  assert.equal(ptyFlavor("darwin"), "bsd");
  assert.equal(ptyFlavor("win32"), null);
  assert.equal(ptyFlavor("freebsd"), null);
});

test("buildPtyArgv (util-linux) wraps the command in script -qefc … /dev/null, handing the agent the user's SHELL back", () => {
  const argv = buildPtyArgv(["claude", "--resume", "abc"], "util-linux", "/usr/bin/zsh");
  assert.deepEqual(argv, ["script", "-qefc", "exec env SHELL='/usr/bin/zsh' 'claude' '--resume' 'abc'", "/dev/null"]);
  // no SHELL in the caller's env: the agent gets none either (not /bin/sh)
  assert.deepEqual(buildPtyArgv(["claude"], "util-linux", null), ["script", "-qefc", "exec env -u SHELL 'claude'", "/dev/null"]);
  assert.deepEqual(buildPtyArgv(["claude"], "util-linux", "it's"), ["script", "-qefc", "exec env SHELL='it'\\''s' 'claude'", "/dev/null"]);
});

test("ptyRelayEnv runs script's -c string with /bin/sh, not the user's shell", () => {
  assert.equal(PTY_RELAY_SHELL, "/bin/sh");
  assert.deepEqual(ptyRelayEnv({ SHELL: "/bin/bash", HOME: "/h" }), { SHELL: "/bin/sh", HOME: "/h" });
  assert.deepEqual(ptyRelayEnv({}), { SHELL: "/bin/sh" });
});

test("buildPtyArgv (bsd) passes the command straight to /usr/bin/script -q /dev/null — no quoting", () => {
  const argv = buildPtyArgv(["claude", "--resume", "abc"], "bsd");
  assert.deepEqual(argv, ["/usr/bin/script", "-q", "/dev/null", "claude", "--resume", "abc"]);
});

test("the script(1) binary: BSD by absolute path (a PATH entry cannot stand in for it), util-linux on PATH as before", () => {
  assert.equal(BSD_SCRIPT, "/usr/bin/script");
  assert.equal(ptyScriptPath("bsd"), "/usr/bin/script");
  assert.equal(ptyScriptPath("util-linux"), "script");
  assert.equal(buildPtyArgv(["x"], "bsd")[0], "/usr/bin/script");
  assert.equal(buildPtyArgv(["x"], "util-linux")[0], "script", "Linux unchanged");
});

test("buildPtyArgv (bsd) keeps hostile args verbatim (BSD execs, no sh -c)", () => {
  // BSD script execvp's the trailing argv directly, so a space/quote/metachar
  // in an arg is passed as one literal argv element — no shell to re-split it.
  const cmd = ["claude", "sym $MDU:Read[9b0a]", "a b;c && $(x)"];
  const argv = buildPtyArgv(cmd, "bsd");
  assert.deepEqual(argv, ["/usr/bin/script", "-q", "/dev/null", ...cmd]);
});

test("ptyProbeArgv is the version check on util-linux and the real relay shape on bsd", () => {
  assert.deepEqual(ptyProbeArgv("util-linux"), ["--version"]);
  assert.deepEqual(ptyProbeArgv("bsd"), ["-q", "/dev/null", "/usr/bin/true"], "true by path too: BSD script execvp's it outside the profile");
});

test("shellQuote survives sh -c round-trips for hostile words", () => {
  const hostile = [
    "plain",
    "two words",
    "sym $MDU:Read[9b0a] token",
    'double "quoted"',
    "single 'quoted'",
    "back\\slash",
    "semi;colon && $(sub) `tick` *glob* \n newline",
  ];
  for (const word of hostile) {
    const r = spawnSync("sh", ["-c", `printf '%s' ${shellQuote(word)}`], { encoding: "utf8" });
    assert.equal(r.status, 0);
    assert.equal(r.stdout, word, `round-trip failed for ${JSON.stringify(word)}`);
  }
});

test("ptyRelayAvailable reports not-ok on a platform with no vetted backend", () => {
  const r = ptyRelayAvailable("win32");
  assert.equal(r.ok, false);
  assert.match(r.why, /win32/);
  assert.match(r.why, /Linux util-linux \/ macOS BSD script only/);
});

test("ptyStdinProblem: BSD script cannot start on a socket or a named FIFO; everything else passes", () => {
  // The fstat shapes measured on macOS 26.5.1 (pty-relay.md §3.1).
  const devNull = { socket: false, fifo: false, dev: 2010156706, nlink: 1 };
  const pipe2 = { socket: false, fifo: true, dev: 0, nlink: 0 };
  const namedFifo = { socket: false, fifo: true, dev: 16777232, nlink: 1 };
  const socketpair = { socket: true, fifo: false, dev: 1, nlink: 0 };
  assert.equal(ptyStdinProblem("bsd", devNull), null);
  assert.equal(ptyStdinProblem("bsd", pipe2), null, "an anonymous pipe works");
  assert.match(ptyStdinProblem("bsd", namedFifo) ?? "", /named FIFO/);
  assert.match(ptyStdinProblem("bsd", socketpair) ?? "", /socket/);
  // An unlinked FIFO still sits on a device.
  assert.match(ptyStdinProblem("bsd", { ...namedFifo, nlink: 0 }) ?? "", /named FIFO/);
  // util-linux script takes any stdin; an unreadable stdin is not guessed at.
  assert.equal(ptyStdinProblem("util-linux", socketpair), null);
  assert.equal(ptyStdinProblem(null, socketpair), null);
  assert.equal(ptyStdinProblem("bsd", null), null);
});

test("stdinFacts reads this process's stdin (and a bad fd reads null)", () => {
  const s = stdinFacts(0);
  assert.ok(s !== null);
  assert.equal(typeof s.socket, "boolean");
  assert.equal(stdinFacts(987654), null);
});

test("ptyRelayAvailable finds the host's script(1) backend", () => {
  // Keyed off the ACTUAL host so the SAME assertion proves the ok-path on
  // whichever platform runs it: util-linux script on the Linux CI host, and —
  // when this suite runs on a Mac (packaging.md §6, by hand) — the BSD
  // script ok-path that no Linux box can reach. Skipped on any other platform.
  if (process.platform !== "linux" && process.platform !== "darwin") return;
  const r = ptyRelayAvailable(process.platform);
  assert.equal(r.ok, true, r.why);
});

test("util-linux relay: a user $SHELL that swallows every -c command does not stop the agent, and the agent keeps that SHELL", { skip: process.platform !== "linux" || !ptyRelayAvailable("linux").ok ? "needs util-linux script" : false }, () => {
  // 2026-09-30: under a tmux server started from an ssh login, Ubuntu's bash
  // read a ~/.bashrc for `bash -c` that `exec zsh`s on a terminal, so the
  // relayed agent never ran. Stand-in: a SHELL that ignores its arguments.
  const dir = mkdtempSync(join(tmpdir(), "pty-relay-shell-"));
  try {
    const swallow = join(dir, "swallow");
    writeFileSync(swallow, "#!/bin/sh\necho SWALLOWED\n", { mode: 0o755 });
    const env = { ...process.env, SHELL: swallow };
    const argv = buildPtyArgv(["sh", "-c", "echo RAN SHELL=$SHELL"], "util-linux", env.SHELL);
    const r = spawnSync(argv[0]!, argv.slice(1), { env: ptyRelayEnv(env), encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "pipe"] });
    assert.match(r.stdout, new RegExp(`RAN SHELL=${swallow}`), `stdout: ${r.stdout} stderr: ${r.stderr}`);
    assert.doesNotMatch(r.stdout, /SWALLOWED/);
    // the old shape (script under the user's SHELL) is what swallowed it
    const old = spawnSync("script", ["-qefc", "exec sh -c 'echo RAN'", "/dev/null"], { env, encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "pipe"] });
    assert.match(old.stdout, /SWALLOWED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the macOS probe never runs a `script` or `true` planted first on PATH (review 2026-09-29, docs-tests-11)", () => {
  // The relay runs outside the Seatbelt profile with the agent's PATH, whose
  // user directories the profile does not write-protect. The probe is run
  // on every host with the darwin flavor: on Linux /usr/bin/script is
  // util-linux (or absent) and the probe's answer does not matter here, only
  // that neither planted program runs.
  const dir = mkdtempSync(join(tmpdir(), "mandu-ptypath-"));
  const marker = join(dir, "planted-ran");
  for (const name of ["script", "true"]) {
    writeFileSync(join(dir, name), `#!/bin/sh\necho ${name} >> '${marker}'\nexit 0\n`, { mode: 0o755 });
  }
  const prev = process.env["PATH"];
  process.env["PATH"] = `${dir}:${prev ?? "/usr/bin:/bin"}`;
  try {
    ptyRelayAvailable("darwin");
  } finally {
    if (prev === undefined) delete process.env["PATH"]; else process.env["PATH"] = prev;
  }
  try {
    assert.equal(existsSync(marker), false, "a planted script/true ran");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
