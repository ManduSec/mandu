/**
 * instance-planted-paths.test — the REAL daemon entrypoint against a runtime
 * dir someone else prepared (runtime-instances.md §2, planted paths,
 * 2026-09-30).
 *
 * The arbiter runs outside the agent's confinement, while whoever can write
 * the runtime base (the agent on macOS, whose Seatbelt profile keeps the base
 * writable and denies only the registries; any same-uid process on Linux)
 * knows the names it is about to use. So:
 *
 *   - a normal start makes its instance dir 0700 and writes a whole manifest
 *     (the temp file created exclusively, then renamed);
 *   - `instances/` swapped for a link to someone's files: the start-up sweep
 *     never walks through it (each old entry there would read as an abandoned
 *     instance and be removed), and the daemon refuses to start instead of
 *     binding its socket wherever the link points.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { INSTANCES_DIR, readManifest } from "../../ipc/instance.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the daemon's registry does not depend on the axes; secrets is the default mode

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");

interface Stack { root: string; base: string; home: string; cleanup: () => void }

function tmpStack(): Stack {
  const root = mkdtempSync(join(tmpdir(), "mdu-"));
  return { root, base: join(root, "mandu"), home: join(root, "home"), cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** server-main in instance mode on an isolated base (`node --import tsx`, so
 *  the signalled process is the daemon: instance-mode.test.ts). */
function spawnArbiter(s: Stack): { child: ChildProcess; stderr: () => string } {
  const child = spawn(process.execPath, ["--import", "tsx", SERVER_MAIN, "--symbol-db", join(s.root, "symbols.db"), "--event-dir", join(s.root, "events")], {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_RUNTIME_DIR: s.base, MANDU_HOME: s.home, MANDU_ARBITER_SOCK: "" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = "";
  child.stderr!.setEncoding("utf8").on("data", (d: string) => { err += d; });
  return { child, stderr: () => err };
}

async function waitFor(pred: () => boolean, what: string, ms = 90_000): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => { child.kill("SIGKILL"); }, 60_000);
    kill.unref();
    child.once("exit", () => { clearTimeout(kill); resolve(); });
    child.kill("SIGTERM");
  });
}

test("a normal start: the instance dir is 0700 and holds a whole manifest, no temp file", async () => {
  const s = tmpStack();
  const { child } = spawnArbiter(s);
  try {
    const ids = (): string[] => { try { return readdirSync(join(s.base, INSTANCES_DIR)); } catch { return []; } };
    await waitFor(() => ids().length === 1 && readManifest(join(s.base, INSTANCES_DIR, ids()[0]!)) !== null, "the instance and its manifest");
    const dir = join(s.base, INSTANCES_DIR, ids()[0]!);
    assert.equal(statSync(dir).mode & 0o777, 0o700, "only this account can enter it");
    assert.equal(readManifest(dir)!.pid, child.pid);
    assert.deepEqual(readdirSync(dir).filter((n) => n.endsWith(".tmp")), [], "no temp file left behind");
  } finally {
    await stop(child);
    s.cleanup();
  }
});

test("instances/ swapped for a link to someone's files: nothing there is swept, and the daemon refuses to start", async () => {
  const s = tmpStack();
  const victim = join(s.root, "victim");
  mkdirSync(join(victim, "project"), { recursive: true });
  writeFileSync(join(victim, "notes.txt"), "keep me\n");
  // Old enough that a sweep walking through the link would take each for an
  // abandoned manifest-less instance (the grace is 60 s).
  const past = new Date(Date.now() - 3_600_000);
  for (const p of [join(victim, "project"), join(victim, "notes.txt")]) utimesSync(p, past, past);
  mkdirSync(s.base, { recursive: true, mode: 0o700 });
  symlinkSync(victim, join(s.base, INSTANCES_DIR));
  const { child, stderr } = spawnArbiter(s);
  try {
    // A deadline, not a delay: a daemon that started through the link would
    // serve on, and the test must fail rather than wait for it forever.
    const code = await new Promise<number | null | "running">((resolve) => {
      const t = setTimeout(() => resolve("running"), 90_000);
      child.once("exit", (c) => { clearTimeout(t); resolve(c); });
    });
    assert.equal(code, 1, `the start is refused:\n${stderr()}`);
    assert.match(stderr(), /instance registry .* is not a real directory .* refusing to start/, stderr());
    assert.deepEqual(readdirSync(victim).sort(), ["notes.txt", "project"], "the link's target is untouched");
    assert.equal(readFileSync(join(victim, "notes.txt"), "utf8"), "keep me\n");
    assert.ok(!existsSync(join(victim, "arbiter.sock")), "no socket was bound through the link");
  } finally {
    await stop(child);
    s.cleanup();
  }
});
