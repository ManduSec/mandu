/**
 * test-owner-cleanup.test — E2E, the 2026-10-21 incident's shape: a test that
 * runs a launch in-process (`main()`, as runtime-fallback.test.ts,
 * runtime-dir-mode.test.ts and claude-env-key.test.ts do) autostarts the
 * resident stack, the supervisor dashboard and its arbiter, which by design
 * have no owner and no lifeline (runtime-instances.md §8, §10). When that
 * test's process is killed outright, before its `finally`, the stack must
 * not outlive it: both daemons name the test as their owner and shut down
 * (runtime-instances.md §8a; dashboard/src/test-owner.ts and
 * arbiter/ipc/test-owner.ts). Twelve arbiters and three dashboards of such
 * tests were found still serving after four days.
 *
 * The stand-in test file is started through an intermediate that exits at
 * once (this file's own process carries NODE_TEST_CONTEXT too and would
 * otherwise be the topmost owner), runs the real launch with an agent that
 * sleeps, and is SIGKILLed once the stack is up.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // the daemons' npm cache and the agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { stateAxes } from "../axes.js";
import { sweepRuntimeProcesses } from "../lib/runtime-sweep.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); the lifetime rule it proves is axis-independent

const HERE = dirname(fileURLToPath(import.meta.url));
const LAUNCHER_DIR = join(HERE, "..", "..");
const LINUX = process.platform === "linux" || "the owner walk reads /proc";

/** The stand-in test file: wait to be reparented, then launch for real. */
function standInScript(base: string, tmp: string, home: string): string {
  const lib = (f: string): string => JSON.stringify(pathToFileURL(join(LAUNCHER_DIR, "test", "lib", f)).href);
  return `
import ${lib("private-home.ts")};
import { main } from ${lib("launch-in-dir.ts")};
const firstParent = Number(process.env.STAND_IN_PARENT);
while (process.ppid === firstParent) await new Promise((r) => setTimeout(r, 20));
process.env.MANDU_HOME = ${JSON.stringify(home)};
delete process.env.MANDU_ARBITER_SOCK;
await main(["--target", "claude", "--no-scope", "--", "bash", "-c", "sleep 120"], {
  HOME: process.env.HOME, PWD: ${JSON.stringify(tmp)}, PATH: process.env.PATH,
  MANDU_HOME: ${JSON.stringify(home)}, MANDU_NO_CONTEXT_PROXY: "1",
  MANDU_RUNTIME_DIR: ${JSON.stringify(base)}, TMPDIR: ${JSON.stringify(tmp)},
});
`;
}

const INTERMEDIATE = String.raw`
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const fd = fs.openSync(process.argv[2], "a");
const c = spawn(process.execPath, ["--import", "tsx", process.argv[1]], { detached: true, stdio: ["ignore", fd, fd], env: { ...process.env, STAND_IN_PARENT: String(process.pid) } });
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

/** Pids named by the registry entries under `base` (dashboards/*.json, instances/*\/manifest.json). */
function registeredPids(base: string, kind: "dashboards" | "instances"): number[] {
  const dir = join(base, kind);
  if (!existsSync(dir)) return [];
  const out: number[] = [];
  for (const n of readdirSync(dir)) {
    const f = kind === "dashboards" ? join(dir, n) : join(dir, n, "manifest.json");
    try {
      const m = JSON.parse(readFileSync(f, "utf8")) as { pid?: unknown };
      if (typeof m.pid === "number") out.push(m.pid);
    } catch { /* torn, or not a manifest */ }
  }
  return out;
}

/** This user's mandu-arbiter / mandu-dashboard processes whose env names `base`. */
function residentDaemonsOn(base: string): number[] {
  const want = `MANDU_RUNTIME_DIR=${base}`;
  const out: number[] = [];
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const argv0 = readFileSync(`/proc/${name}/cmdline`, "latin1").split("\0")[0] ?? "";
      if (argv0 !== "mandu-arbiter" && argv0 !== "mandu-dashboard") continue;
      if (readFileSync(`/proc/${name}/environ`, "latin1").split("\0").includes(want)) out.push(Number(name));
    } catch { /* gone, or not ours */ }
  }
  return out;
}

/** This user's processes whose env has `TMPDIR=<tmp>`: every process of the
 *  stand-in's launch, the per-session services included, which carry no
 *  MANDU_RUNTIME_DIR (the net proxy, an exec shim) and so escape the sweep. */
function launchProcessesUnder(tmp: string): number[] {
  const want = `TMPDIR=${tmp}`;
  const out: number[] = [];
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name) || Number(name) === process.pid) continue;
    try {
      if (readFileSync(`/proc/${name}/environ`, "latin1").split("\0").includes(want)) out.push(Number(name));
    } catch { /* gone, or not ours */ }
  }
  return out;
}

/** Remove `dir` while a late writer may still add to it: each pass walks the
 *  tree again. (rmSync's own `maxRetries` retries only the failed rmdir, never
 *  the walk, so an entry created after the walk fails every retry: CI job
 *  18368 slept 47 s in those retries and still failed ENOTEMPTY.) */
async function removeTree(dir: string): Promise<void> {
  for (let pass = 1; ; pass++) {
    try { rmSync(dir, { recursive: true, force: true }); return; } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOTEMPTY" || pass >= 20) throw e;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}

test("a test killed mid-launch leaves no dashboard or arbiter of the stack its launch autostarted", { skip: LINUX === true ? false : LINUX, timeout: 300_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-to-")));
  const base = join(tmp, "mandu");
  const log = join(tmp, "stand-in.log");
  const script = join(tmp, "stand-in.mts");
  writeFileSync(script, standInScript(base, tmp, join(tmp, "mandu-home")));
  let standIn = 0;
  try {
    // TMPDIR: the stand-in's private home (private-home.ts) is removed by its
    // exit hook, which a SIGKILL skips; under `tmp` it goes with the rest.
    const mid = spawn(process.execPath, ["-e", INTERMEDIATE, script, log], {
      cwd: LAUNCHER_DIR, stdio: ["ignore", "pipe", "inherit"], env: { ...process.env, TMPDIR: tmp },
    });
    let out = "";
    mid.stdout!.on("data", (b) => { out += String(b); });
    await new Promise<void>((r) => mid.once("exit", () => r()));
    standIn = Number(out);
    assert.ok(Number.isInteger(standIn) && standIn > 1, `the intermediate named the stand-in (${out})`);

    const autostartLog = (): string => { try { return readFileSync(join(base, "logs", "arbiter-autostart.log"), "utf8"); } catch { return ""; } };
    // The supervised arbiter logs to the dashboard's per-module log file.
    const arbiterLog = (): string => { try { return readFileSync(join(base, "logs", "arbiter.log"), "utf8"); } catch { return ""; } };
    const standInLog = (): string => { try { return readFileSync(log, "utf8"); } catch { return ""; } };
    const up = await pollUntil(
      () => registeredPids(base, "dashboards").length > 0 && registeredPids(base, "instances").length > 0
        && existsSync(join(base, "current", "arbiter.sock")),
      240_000,
    );
    assert.ok(up, `the launch autostarted the stack (stand-in: ${standInLog()}\nautostart: ${autostartLog()})`);
    const daemons = [...registeredPids(base, "dashboards"), ...registeredPids(base, "instances")];
    assert.match(autostartLog(), new RegExp(`\\[dashboard\\] test owner pid ${standIn}:`), "the dashboard names the test as its owner");
    assert.ok(await pollUntil(() => new RegExp(`\\[arbiter\\] test owner pid ${standIn}:`).test(arbiterLog()), 10_000),
      `and so does the arbiter it started (its log: ${arbiterLog()})`);
    assert.ok(daemons.every(alive), "both are up");

    process.kill(standIn, "SIGKILL"); // the test dies: no finally, no cleanup
    const gone = await pollUntil(() => daemons.every((p) => !alive(p)) && residentDaemonsOn(base).length === 0, 60_000);
    assert.ok(gone, `the stack is gone after its test died (still running: ${residentDaemonsOn(base).join(", ")}; autostart: ${autostartLog()})`);
    assert.deepEqual(registeredPids(base, "dashboards"), [], "the dashboard removed its registry entry on the way out");
    assert.deepEqual(registeredPids(base, "instances"), [], "the arbiter removed its instance dir");
  } finally {
    if (standIn && alive(standIn)) process.kill(standIn, "SIGKILL");
    await sweepRuntimeProcesses(base);
    // The launch was killed mid-way: a per-session service it had just
    // spawned (the net proxy, the exec shim of a probe) may still be loading
    // through tsx, writing its cache under TMPDIR (`<tmp>/tsx-<uid>`), and
    // sees its cut lifeline only once loaded (seconds on a loaded host;
    // CI jobs 18107 and 18368: ENOTEMPTY). Wait for every process of the
    // launch to end before the removal, then stop what has not.
    if (!(await pollUntil(() => launchProcessesUnder(tmp).length === 0, 60_000))) {
      const left = launchProcessesUnder(tmp);
      console.error(`# the killed launch's processes ${left.join(", ")} still ran 60 s on: SIGKILL`);
      for (const p of left) { try { process.kill(p, "SIGKILL"); } catch { /* gone */ } }
      await pollUntil(() => launchProcessesUnder(tmp).length === 0, 10_000);
    }
    await removeTree(tmp);
  }
});
