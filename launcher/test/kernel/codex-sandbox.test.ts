/**
 * codex-sandbox e2e — through the real CLI entry (main) with the REAL host
 * probes: a stand-in `codex` on PATH and the system `bwrap` hidden from PATH
 * (a symlink farm of each PATH dir minus bwrap), which is what a stock Ubuntu
 * cloud image looks like to Codex (os-test-matrix.md §10.14.1 item 4,
 * src/codex-sandbox.ts). `mandu doctor` names the fix, a `mandu codex` launch
 * prints ONE WARNING line and still starts the agent; with bwrap visible the
 * answer follows Codex's own probe on this host.
 *
 * The expected row depends on this host: where `mandu setup` installed
 * Mandu's own bubblewrap, Codex uses it under mandu (✓, no warning, whatever
 * PATH shows); otherwise, with the AppArmor restriction on, Codex's bundled
 * bwrap cannot run (✗ + `apt install bubblewrap`), and with it off the
 * bundled copy runs (✓). Each is asserted where it holds.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { spawnSync } from "node:child_process";
import { createServer, type Server } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { runCli } from "../lib/run-cli.js";
import { CODEX_BWRAP_PROBE_ARGV } from "../../src/codex-sandbox.js";
import { APPARMOR_USERNS_SYSCTL } from "../../src/userns.js";
import { manduBwrapInForceHere, resolveWrapBwrap } from "../../src/bwrap-grant.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

// Axes: stated per launch (MANDU_MODE: "off"); this check is axis-independent.

const knob = ((): string | null => { try { return readFileSync(APPARMOR_USERNS_SYSCTL, "utf8").trim(); } catch { return null; } })();
const restricted = knob === "1";
// `mandu setup` ran here: Codex runs Mandu's own bubblewrap under mandu.
const manduBwrap = manduBwrapInForceHere();
// The bwrap a launch really runs (Mandu's copy where it is in force).
const BWRAP = resolveWrapBwrap() ?? "bwrap";

/** PATH with every directory that holds a `bwrap` replaced by a farm of its
 *  entries minus bwrap, and a dir with the stand-in `codex` first. */
function pathWithoutBwrap(root: string, codexDir: string): string {
  const out = [codexDir];
  let i = 0;
  for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
    if (d === "" || !existsSync(join(d, "bwrap"))) { out.push(d); continue; }
    const farm = join(root, `farm-${i++}`);
    mkdirSync(farm);
    for (const e of readdirSync(d)) if (e !== "bwrap") symlinkSync(join(d, e), join(farm, e));
    out.push(farm);
  }
  return out.join(delimiter);
}

async function withHost(hideBwrap: boolean, fn: (dir: string, sock: string, ran: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-codexbox-e2e-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const codexDir = join(dir, "codexbin");
  mkdirSync(codexDir);
  const ran = join(dir, "ran");
  writeFileSync(join(codexDir, "codex"),
    `#!/bin/sh\nif [ "$1" = --version ]; then echo 'codex-cli 0.154.0'; exit 0; fi\ntouch '${ran}'\n`, { mode: 0o755 });
  const origPath = process.env["PATH"];
  // The host probes (commandExists, the bwrap probe) read the process PATH.
  process.env["PATH"] = hideBwrap ? pathWithoutBwrap(dir, codexDir) : `${codexDir}${delimiter}${origPath}`;
  try { await fn(dir, sock, ran); } finally {
    process.env["PATH"] = origPath;
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

const env = (dir: string, sock: string) => ({
  HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir,
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", OPENAI_API_KEY: "sk-e2e-unused",
});

async function doctorOut(e: Record<string, string | undefined>): Promise<string> {
  const r = await runCli(["doctor"], e);
  assert.equal(r.code, 0, r.stderr);
  return r.stdout;
}

async function launch(argv: string[], e: Record<string, string | undefined>): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try { return { code: await main(argv, e), lines }; } finally { console.error = orig; }
}

const BOX_LINE = /Codex's own sandbox cannot run commands/;

test(`doctor, codex on PATH and bwrap hidden (AppArmor restriction ${restricted ? "ON" : "off"}${manduBwrap ? ", Mandu's bwrap installed" : ""}): the Codex sandbox row`, async () => {
  await withHost(true, async (dir, sock) => {
    assert.equal(spawnSync("bash", ["-c", "command -v bwrap"]).status !== 0, true, "bwrap is hidden");
    const out = await doctorOut(env(dir, sock));
    assert.match(out, /✓ Codex is installed \(codex\)/);
    if (manduBwrap) {
      assert.match(out, /✓ Codex can run commands in its own sandbox \(bubblewrap\)/, "Mandu's own bubblewrap serves Codex under mandu");
    } else if (restricted) {
      assert.match(out, /✗ Codex cannot run any command here, with or without Mandu: bubblewrap is not installed.*; fix: sudo apt install bubblewrap, then mandu setup/);
    } else {
      assert.match(out, /✓ Codex can run commands in its own sandbox \(bubblewrap\)/, "the bundled copy runs without the restriction");
    }
  });
});

test("doctor, bwrap visible: the row follows Codex's own probe on this host", async (t) => {
  if (spawnSync("bash", ["-c", "command -v bwrap"]).status !== 0) { t.skip("no bwrap on this host"); return; }
  const probeOk = spawnSync(BWRAP, CODEX_BWRAP_PROBE_ARGV, { stdio: "ignore" }).status === 0;
  await withHost(false, async (dir, sock) => {
    const out = await doctorOut(env(dir, sock));
    if (probeOk) assert.match(out, /✓ Codex can run commands in its own sandbox/);
    else assert.match(out, /✗ Codex cannot run any command here/);
  });
});

test("mandu codex with bwrap hidden: ONE warning line with the fix (restricted host), the agent still starts", async () => {
  await withHost(true, async (dir, sock, ran) => {
    const r = await launch(["--no-scope", "--no-reply-filter", "codex", "exec", "hi"], env(dir, sock));
    assert.equal(r.code, 0, "a warning, never a refusal");
    assert.ok(existsSync(ran), "the stand-in codex ran");
    const notes = r.lines.filter((l) => BOX_LINE.test(l));
    if (restricted && !manduBwrap) {
      assert.equal(notes.length, 1, JSON.stringify(r.lines));
      // A launch prints each notice on one line, `mandu: WARNING: …`, cut
      // short with "(more: `mandu log`)" where the log holds the rest, the
      // fix included (only a restricted host reaches this branch: the OS test
      // matrix's 26.04 guest, 2026-10-23; CI's guest lifts the restriction).
      assert.match(notes[0]!, /^mandu: WARNING( —|:) Codex's own sandbox cannot run commands/);
      assert.match(notes[0]!, /fix: sudo apt install bubblewrap, then mandu setup|\(more: `mandu log`\)$/);
    } else {
      assert.equal(notes.length, 0, JSON.stringify(notes));
    }
  });
});

test("mandu codex where Codex's probe passes: no sandbox line", async (t) => {
  if (spawnSync("bash", ["-c", "command -v bwrap"]).status !== 0 ||
      spawnSync(BWRAP, CODEX_BWRAP_PROBE_ARGV, { stdio: "ignore" }).status !== 0) {
    t.skip("Codex's bwrap probe does not pass on this host");
    return;
  }
  await withHost(false, async (dir, sock, ran) => {
    const r = await launch(["--no-scope", "--no-reply-filter", "codex", "exec", "hi"], env(dir, sock));
    assert.equal(r.code, 0);
    assert.ok(existsSync(ran));
    assert.equal(r.lines.filter((l) => BOX_LINE.test(l)).length, 0, JSON.stringify(r.lines));
  });
});
