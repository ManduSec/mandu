/**
 * test-owner-exit.test (e2e) — the REAL arbiter daemon a test started exits
 * when that test's process is killed outright (ipc/test-owner.ts,
 * runtime-instances.md §8a; the 2026-10-21 incident: twelve test arbiters
 * from 2026-10-17/18 still serving).
 *
 * A stand-in "test file" process (NODE_TEST_CONTEXT set, as node's test
 * runner sets it) is started through an intermediate that exits at once, so
 * its parent is no longer this test (whose own process carries the context
 * too and would otherwise be the topmost owner). It spawns the real
 * server-main the way the launcher does — detached, no lifeline, its own
 * MANDU_RUNTIME_DIR — and is then SIGKILLed: no `finally` runs. The arbiter
 * must name the stand-in as its owner, run its graceful shutdown (exit 0,
 * instance dir removed) and leave no process behind. Without the context the
 * same daemon survives its spawner's death (the resident stack's semantics).
 *
 * Run: npm run test:component
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); the lifetime rule it proves is axis-independent

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const LINUX = process.platform === "linux" || "the owner walk reads /proc";
// Deadlines, not durations (see lifeline.test.ts): a cold tsx start under a
// loaded CI guest can take tens of seconds.
const START_DEADLINE_MS = 90_000;
const EXIT_DEADLINE_MS = 30_000;

/** The stand-in test file: spawn the daemon detached, write its pid, wait. */
const STAND_IN = String.raw`
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const [, , out, log, cwd, main, sock] = process.argv;
const firstParent = Number(process.env.STAND_IN_PARENT);
(async () => {
  // Wait until the intermediate has exited and this process was reparented.
  while (process.ppid === firstParent) await new Promise((r) => setTimeout(r, 20));
  const fd = fs.openSync(log, "a");
  const d = spawn(process.execPath, ["--import", "tsx", main, sock], { cwd, detached: true, stdio: ["ignore", fd, fd], env: process.env });
  d.unref();
  fs.writeFileSync(out, String(d.pid));
  setInterval(() => {}, 1e9);
})();
`;

/** Intermediate: start the stand-in, print its pid, exit. */
const INTERMEDIATE = String.raw`
const { spawn } = require("node:child_process");
const c = spawn(process.execPath, process.argv.slice(1), { detached: true, stdio: "ignore", env: { ...process.env, STAND_IN_PARENT: String(process.pid) } });
c.unref();
process.stdout.write(String(c.pid));
`;

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function pollUntil(check: () => boolean, deadlineMs: number): Promise<boolean> {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return check();
}

/** Start the stand-in (through the intermediate) with `env`; resolve its pid. */
async function startStandIn(dir: string, env: NodeJS.ProcessEnv): Promise<{ standIn: number; daemon: () => number | null; log: () => string }> {
  const script = join(dir, "stand-in.cjs");
  writeFileSync(script, STAND_IN);
  const out = join(dir, "daemon.pid");
  const log = join(dir, "arbiter.log");
  const mid = spawn(process.execPath, ["-e", INTERMEDIATE, script, out, log, ARBITER_DIR, SERVER_MAIN, join(dir, "arbiter.sock")], {
    stdio: ["ignore", "pipe", "inherit"], env,
  });
  let pid = "";
  mid.stdout!.on("data", (b) => { pid += String(b); });
  await new Promise<void>((r) => mid.once("exit", () => r()));
  const standIn = Number(pid);
  assert.ok(Number.isInteger(standIn) && standIn > 1, `the intermediate named the stand-in (${pid})`);
  return {
    standIn,
    daemon: () => { try { return Number(readFileSync(out, "utf8")) || null; } catch { return null; } },
    log: () => { try { return readFileSync(log, "utf8"); } catch { return ""; } },
  };
}

function daemonEnv(dir: string, extra: Record<string, string | undefined>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    MANDU_HOME: join(dir, "home"),
    MANDU_RUNTIME_DIR: join(dir, "rt"),
    MANDU_ARBITER_SOCK: undefined,
    MANDU_LIFELINE: undefined,
    MANDU_TEST_OWNER_PID: undefined,
    MANDU_TENANT: "",
    ...extra,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  return env;
}

test("a test process killed outright takes the arbiter it started with it: graceful exit, instance dir gone", { skip: LINUX === true ? false : LINUX, timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-owner-"));
  let daemonPid: number | null = null;
  let standIn = 0;
  try {
    const s = await startStandIn(dir, daemonEnv(dir, { NODE_TEST_CONTEXT: "child-v8" }));
    standIn = s.standIn;
    assert.ok(await pollUntil(() => new RegExp(`test owner pid ${standIn}:`).test(s.log()), START_DEADLINE_MS),
      `the arbiter named the stand-in as its owner (log: ${s.log()})`);
    daemonPid = s.daemon();
    assert.ok(daemonPid !== null && alive(daemonPid), "the arbiter is up");
    assert.ok(await pollUntil(() => existsSync(join(dir, "rt", "instances")) && readdirSync(join(dir, "rt", "instances")).length === 1, START_DEADLINE_MS), "it registered its instance dir");

    process.kill(standIn, "SIGKILL"); // the test dies: no finally, no cleanup
    assert.ok(await pollUntil(() => !alive(daemonPid!), EXIT_DEADLINE_MS), `the arbiter exited after its test owner died (log: ${s.log()})`);
    assert.match(s.log(), new RegExp(`received test owner pid ${standIn} gone, shutting down`), "through the graceful shutdown");
    assert.deepEqual(readdirSync(join(dir, "rt", "instances")), [], "which removed its instance dir");
  } finally {
    if (standIn && alive(standIn)) process.kill(standIn, "SIGKILL");
    if (daemonPid !== null && alive(daemonPid)) process.kill(daemonPid, "SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("without a test context the same arbiter outlives its spawner (the resident stack's semantics)", { skip: LINUX === true ? false : LINUX, timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-owner-"));
  let daemonPid: number | null = null;
  let standIn = 0;
  try {
    const s = await startStandIn(dir, daemonEnv(dir, { NODE_TEST_CONTEXT: undefined }));
    standIn = s.standIn;
    assert.ok(await pollUntil(() => existsSync(join(dir, "rt", "current")) || /instance \S+ /.test(s.log()), START_DEADLINE_MS),
      `the arbiter came up (log: ${s.log()})`);
    daemonPid = s.daemon();
    assert.ok(daemonPid !== null && alive(daemonPid));
    assert.doesNotMatch(s.log(), /test owner pid/, "no owner outside a test");
    process.kill(standIn, "SIGKILL");
    await new Promise((r) => setTimeout(r, 2_500));
    assert.ok(alive(daemonPid), "it still runs after its spawner died");
  } finally {
    if (standIn && alive(standIn)) process.kill(standIn, "SIGKILL");
    if (daemonPid !== null && alive(daemonPid)) {
      process.kill(daemonPid, "SIGTERM");
      await pollUntil(() => !alive(daemonPid!), 20_000);
      if (alive(daemonPid)) process.kill(daemonPid, "SIGKILL");
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
