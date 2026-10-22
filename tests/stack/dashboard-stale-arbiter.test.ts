/**
 * dashboard-stale-arbiter.test.ts — the dashboard supervisor never keeps a
 * stale arbiter as the stack's when nothing uses it (runtime-instances.md
 * §4.1b; the 2026-10-21 incident: the service's dashboard re-adopted, on
 * every restart, an arbiter another dashboard had started four days and two
 * releases before, and every launch refused it).
 *
 * A REAL arbiter that says it is an older release (tests/fixtures/
 * older-arbiter.fixture.ts: titled `mandu-arbiter`, bound in its instance
 * dir, promoted to `current`) holds the stack; the real Supervisor starts in
 * instance mode on that stack, with the real session scan
 * (stack-sessions.ts) and the real /proc command-line check:
 *
 *   1. no `mandu` session on the stack: the old arbiter is SIGTERMed (its
 *      instance dir goes with it) and the supervisor's own arbiter, this
 *      release, answers at `current`;
 *   2. a `mandu` session on the stack (a process titled `mandu` whose env
 *      selects it): the old arbiter is adopted, flagged STALE, and left
 *      running, the log naming the session.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Supervisor, type ServiceDefinition } from "../../dashboard/src/supervisor/supervisor.js";
import { sweepRuntimeProcesses } from "../../launcher/test/lib/runtime-sweep.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { launcherVersion } from "../../launcher/src/update-check.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // the supervisor's adoption rule is axis-independent

const HERE = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(HERE, "..");
const REPO = join(TESTS_DIR, "..");
const FIXTURE = join(TESTS_DIR, "fixtures", "older-arbiter.fixture.ts");
const OURS = launcherVersion();
const LINUX = process.platform === "linux" || "the session scan and the command-line check read /proc";

function shortTmp(tag: string): string {
  return realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : TESTS_DIR, `mdu-${tag}-`)));
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

/** The fixture arbiter of `version` on `base`, resolved once promoted. */
async function startFixture(base: string, version: string, stateDir: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, ["--import", "tsx", FIXTURE, base, version, stateDir], {
    cwd: TESTS_DIR, detached: true, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, MANDU_RUNTIME_DIR: base, MANDU_HOME: join(stateDir, "home") },
  });
  let out = "";
  let err = "";
  child.stdout!.on("data", (c) => { out += c; });
  child.stderr!.on("data", (c) => { err += c; });
  const deadline = Date.now() + 60_000;
  while (!out.includes("ready ")) {
    if (child.exitCode !== null || Date.now() > deadline) throw new Error(`fixture arbiter did not start: ${err}`);
    await new Promise((r) => setTimeout(r, 50));
  }
  return child;
}

/** The supervisor of the stack at `base`; its own arbiter is the fixture at this release. */
function supervisorOn(base: string, tmp: string, logs: string[]): Supervisor {
  const current = join(base, "current", "arbiter.sock");
  const own: ServiceDefinition = {
    label: "Arbiter", command: process.execPath, args: ["--import", "tsx", FIXTURE, base, OURS, join(tmp, "own")], cwd: TESTS_DIR,
    env: { MANDU_RUNTIME_DIR: base }, ready: { kind: "socket", path: current }, endpoint: current,
  };
  mkdirSync(join(tmp, "own"), { recursive: true });
  return new Supervisor({
    repoRoot: REPO, arbiterSock: current, arbiterInstanceBase: base, logDir: join(tmp, "dash-logs"),
    eventDir: join(tmp, "older-events"), // the fixture's: this stack's, not FOREIGN
    ownArbiterBuild: () => ({ version: OURS, bundle: null, installed: false }),
    startTimeoutMs: 60_000, stopGraceMs: 5_000, definitions: { arbiter: own }, log: (m) => logs.push(m),
  });
}

test("no mandu session on the stack: the stale arbiter is replaced by the supervisor's own", { skip: LINUX === true ? false : LINUX, timeout: 180_000 }, async () => {
  const tmp = shortTmp("dsa");
  const base = join(tmp, "mandu");
  mkdirSync(base, { recursive: true });
  const old = await startFixture(base, "0.1.0", tmp);
  const logs: string[] = [];
  const sup = supervisorOn(base, tmp, logs);
  try {
    await sup.start("arbiter");
    assert.equal(alive(old.pid!), false, `the stale arbiter is gone (log: ${logs.join("\n")})`);
    const row = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(row.adopted, false, "the supervisor's own arbiter runs");
    const hello = await ndjsonCall<Record<string, unknown>>(join(base, "current", "arbiter.sock"), "hello", {}, 5_000);
    assert.equal(hello["version"], OURS, "current answers as this release");
    assert.equal(hello["pid"], row.pid);
    assert.equal(readdirSync(join(base, "instances")).length, 1, "the old instance dir went with it");
    assert.ok(logs.some((l) => /NOT adopting .*STALE — it runs Mandu 0\.1\.0; .*No mandu session uses this stack/.test(l)), logs.join("\n"));
  } finally {
    await sup.shutdownAll();
    try { process.kill(-old.pid!, "SIGKILL"); } catch { /* gone */ }
    await sweepRuntimeProcesses(base);
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a mandu session on the stack: the stale arbiter is adopted, flagged, left running", { skip: LINUX === true ? false : LINUX, timeout: 180_000 }, async () => {
  const tmp = shortTmp("dsb");
  const base = join(tmp, "mandu");
  mkdirSync(base, { recursive: true });
  const old = await startFixture(base, "0.1.0", tmp);
  const peer = spawn(process.execPath, ["-e", "process.title = 'mandu'; setInterval(() => {}, 1 << 30);"], {
    detached: true, stdio: "ignore", env: { ...process.env, MANDU_RUNTIME_DIR: base },
  });
  const logs: string[] = [];
  const sup = supervisorOn(base, tmp, logs);
  try {
    await new Promise((r) => setTimeout(r, 300)); // the title is set
    await sup.start("arbiter");
    const row = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(row.adopted, true);
    assert.equal(row.stale, true);
    assert.ok(alive(old.pid!), "left running for the session");
    assert.ok(logs.some((l) => new RegExp(`STALE — it runs Mandu 0\\.1\\.0; .*\\(not replaced: mandu session pid ${peer.pid} uses it\\)`).test(l)), logs.join("\n"));
  } finally {
    await sup.shutdownAll();
    try { process.kill(-peer.pid!, "SIGKILL"); } catch { /* gone */ }
    try { process.kill(-old.pid!, "SIGTERM"); } catch { /* gone */ }
    await sweepRuntimeProcesses(base);
    rmSync(tmp, { recursive: true, force: true });
  }
});
