/**
 * reap-abandoned.test — `mandu reap` and another stack's services whose code
 * folder is gone (abandoned-stacks.ts, runtime-instances.md §10.5; found
 * 2026-10-21: a dashboard and arbiter of /run/user/1007/mrel-npmtest, started
 * from a scratch npm install deleted since, ownerless, serving).
 *
 * The rule over a fake process table (which daemons count), then runReap:
 * `--dry-run` lists them, a plain run only says how many and how to stop
 * them, `--other-stacks` stops each after checking it again. The real CLI
 * against a real stand-in is test/component/reap-abandoned-real.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findAbandonedDaemons, folderGone, stillAbandoned, type ProcFacts } from "../../src/abandoned-stacks.js";
import { runReap, type ReapDeps } from "../../src/reap.js";

const WALKED = "/run/user/1007/mandu";
const OTHER = "/run/user/1007/mrel-npmtest";
const GONE = "/tmp/scratch/npmpfx/lib/node_modules/@mandusec/mandu (deleted)";

function proc(pid: number, over: Partial<ProcFacts> = {}): ProcFacts {
  return { pid, title: "mandu-dashboard", stack: OTHER, owner: "none", ppid: 1, cwd: GONE, container: false, ...over };
}

const alive = (live: number[]) => (pid: number) => live.includes(pid);

test("the incident's stack: an ownerless dashboard and its arbiter in a deleted folder, on another stack, nobody on it", () => {
  const procs = [proc(336108), proc(336184, { title: "mandu-arbiter", ppid: 336108, owner: "none" })];
  const got = findAbandonedDaemons(WALKED, { procs: () => procs, pidAlive: alive([336108, 336184]) });
  assert.deepEqual(got.map((d) => [d.pid, d.title, d.stack, d.cwd]), [
    [336108, "mandu-dashboard", OTHER, "/tmp/scratch/npmpfx/lib/node_modules/@mandusec/mandu"],
    [336184, "mandu-arbiter", OTHER, "/tmp/scratch/npmpfx/lib/node_modules/@mandusec/mandu"],
  ]);
});

test("not abandoned: the walked stack's own, a folder that exists, a live owner, a session on the stack, a container's, a non-daemon", () => {
  const live = alive([10, 11, 12, 13, 14, 15, 16, 900]);
  const one = (p: ProcFacts, extra: ProcFacts[] = []) => findAbandonedDaemons(WALKED, { procs: () => [p, ...extra], pidAlive: live });
  assert.deepEqual(one(proc(10, { stack: WALKED })), [], "the walked stack's registry judges its own (an upgrade leaves them in a deleted folder for a while)");
  assert.deepEqual(one(proc(11, { cwd: "/home/u/mandu/dashboard" })), [], "its install is still there");
  assert.deepEqual(one(proc(12, { owner: "900" })), [], "a live owner");
  assert.deepEqual(one(proc(13), [proc(900, { title: "mandu", owner: undefined })]), [], "a mandu session on that stack");
  assert.deepEqual(one(proc(14, { container: true })), [], "a container's stack");
  assert.deepEqual(one(proc(15, { title: "mandu-inspect-mcp" })), [], "a per-session helper, not a resident daemon");
  assert.deepEqual(one(proc(16, { owner: undefined, ppid: 900 }), [proc(900, { title: "bash", stack: null })]), [], "no owner set, its parent alive and not a daemon");
});

test("abandoned owners: none or 0, a dead pid, unset with the parent gone or another daemon of that stack", () => {
  const live = alive([20, 21, 22, 23, 24]);
  for (const p of [proc(20, { owner: "0" }), proc(21, { owner: "777" }), proc(22, { owner: undefined, ppid: 1 }), proc(23, { owner: "", ppid: 4444 })]) {
    assert.equal(findAbandonedDaemons(WALKED, { procs: () => [p], pidAlive: live }).length, 1, JSON.stringify(p));
  }
  const parent = proc(24);
  const child = proc(25, { title: "mandu-arbiter", owner: undefined, ppid: 24 });
  assert.deepEqual(findAbandonedDaemons(WALKED, { procs: () => [parent, child], pidAlive: alive([24, 25]) }).map((d) => d.pid), [24, 25]);
});

test("folderGone and the re-check before the signal", () => {
  assert.equal(folderGone(GONE), true);
  assert.equal(folderGone("/home/u"), false);
  assert.equal(folderGone(null), false);
  const d = { pid: 5, title: "mandu-arbiter" };
  assert.equal(stillAbandoned(d, () => proc(5, { title: "mandu-arbiter" })), true);
  assert.equal(stillAbandoned(d, () => proc(5, { title: "vim" })), false, "a reused pid");
  assert.equal(stillAbandoned(d, () => proc(5, { title: "mandu-arbiter", cwd: "/home/u" })), false);
  assert.equal(stillAbandoned(d, () => null), false, "gone");
});

async function reap(args: string[], deps: ReapDeps, base: string): Promise<{ code: number; out: string }> {
  const lines: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  (process.stdout as unknown as { write: (s: string) => boolean }).write = (s: string) => { lines.push(String(s)); return true; };
  try {
    const code = await runReap(args, { MANDU_RUNTIME_DIR: base }, deps);
    return { code, out: lines.join("") };
  } finally {
    (process.stdout as unknown as { write: typeof orig }).write = orig;
  }
}

test("runReap: --dry-run lists them, a plain run only says so, --other-stacks stops each after checking it again", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-reap-ab-"));
  const base = join(dir, "mandu");
  const killed: number[] = [];
  const procs = [proc(336108), proc(336184, { title: "mandu-arbiter", ppid: 336108 })];
  const deps: ReapDeps = {
    pidAlive: alive([336108, 336184]),
    cmdlineOf: () => null,
    kill: (pid) => { killed.push(pid); },
    socketLive: async () => false,
    now: () => Date.now(),
    abandoned: { procs: () => procs, pidAlive: alive([336108, 336184]) },
    procFacts: (pid) => (pid === 336184 ? { ...procs[1]!, title: "vim" } : procs.find((p) => p.pid === pid) ?? null),
  };
  try {
    const dry = await reap(["--dry-run"], deps, base);
    assert.match(dry.out, /would stop \(with --other-stacks\) pid 336108 mandu-dashboard of the stack at \/run\/user\/1007\/mrel-npmtest: its code folder \/tmp\/scratch\/npmpfx\/lib\/node_modules\/@mandusec\/mandu is gone, nobody owns it and no mandu session uses it/);
    assert.match(dry.out, /would stop \(with --other-stacks\) pid 336184 mandu-arbiter/);
    assert.deepEqual(killed, []);

    const plain = await reap([], deps, base);
    assert.match(plain.out, /2 daemons of other stacks are abandoned \(their code folder is gone\): `mandu reap --dry-run` lists them, `mandu reap --other-stacks` stops them/);
    assert.deepEqual(killed, [], "a plain reap never stops another stack's services");

    const stop = await reap(["--other-stacks"], deps, base);
    assert.deepEqual(killed, [336108], "the dashboard stopped; the arbiter's pid now names another program, so it is skipped");
    assert.match(stop.out, /stopped pid 336108 mandu-dashboard/);
    assert.match(stop.out, /\(skipped\) pid 336184 mandu-arbiter .* it changed since/);
    assert.equal(stop.code, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runReap: deps without the scan (a test's) look for none", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-reap-ab-"));
  try {
    const r = await reap(["--dry-run"], { pidAlive: () => false, cmdlineOf: () => null, kill: () => {}, socketLive: async () => false, now: () => 0 }, join(dir, "mandu"));
    assert.doesNotMatch(r.out, /other-stacks/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
