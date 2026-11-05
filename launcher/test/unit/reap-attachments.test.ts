/**
 * reap-attachments — `mandu reap` and the service's attachment directories
 * (docs/design/agents/openclaw-plugin.md §3.2, "Reap"; runtime-instances.md
 * §10): a live service's proxies and port files are never touched; once its
 * pool (the dashboard its record names) is gone, a proxy still running there
 * is stopped only after its title confirms it, and the directory and the
 * pool's record go. A recycled pid is never signalled.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { planReap, runReap, type ReapDeps } from "../../src/reap.js";
import { tmpDir } from "../lib/tmp-dir.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // runtime-dir housekeeping: axis-independent

function fakeDeps(world: Record<number, string>, killed: Array<[number, string]> = []): ReapDeps {
  return {
    pidAlive: (pid) => pid in world,
    cmdlineOf: (pid) => world[pid] ?? null,
    kill: (pid, sig) => { killed.push([pid, sig]); },
    socketLive: async () => false,
    now: () => Date.now(),
  };
}

function seed(base: string, session: string, rec: object | null): string {
  const dir = join(base, "attachments", session);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, "anthropic-proxy.port"), "41234\n", { mode: 0o600 });
  if (rec) writeFileSync(join(dir, "pool.json"), JSON.stringify(rec));
  return dir;
}

test("a live service's attachment is left alone; a dead pool's goes, its proxy stopped first when one still runs", async () => {
  const base = join(tmpDir("mandu-reap-att-"), "mandu");
  mkdirSync(base, { recursive: true });
  const live = seed(base, "openclaw:main", { pid: 100, proxyPid: 101, session: "openclaw:main" });
  const orphan = seed(base, "openclaw:ops", { pid: 200, proxyPid: 201, session: "openclaw:ops" });
  const gone = seed(base, "openclaw:old", { pid: 300, proxyPid: 301, session: "openclaw:old" });
  const recycled = seed(base, "openclaw:rec", { pid: 400, proxyPid: 401, session: "openclaw:rec" });
  writeFileSync(join(base, "attachments", "pool.json"), JSON.stringify({ pid: 100 }));
  const killed: Array<[number, string]> = [];
  const deps = fakeDeps({ 100: "mandu-dashboard", 101: "mandu-anthropic-proxy", 201: "mandu-anthropic-proxy", 400: "vim notes", 401: "bash" }, killed);

  const actions = await planReap(base, deps);
  const by = Object.fromEntries(actions.map((a) => [a.path.split("/").pop(), a.kind]));
  assert.deepEqual(by, {
    "openclaw:ops": "kill-orphan-attachment-proxy",
    "openclaw:old": "rm-stale-attachment",
    "openclaw:rec": "rm-stale-attachment",
  }, JSON.stringify(actions, null, 2));
  assert.ok(!actions.some((a) => a.path === live), "the live service's session is never planned");

  assert.equal(await runReap([], { MANDU_RUNTIME_DIR: base }, deps), 0);
  assert.deepEqual(killed, [[201, "SIGTERM"]], "only the confirmed orphan proxy is signalled; a recycled pid never");
  assert.ok(existsSync(live) && existsSync(join(live, "anthropic-proxy.port")), "the live port file stays");
  assert.ok(existsSync(orphan), "the orphan's directory stays until its proxy is gone");
  assert.ok(!existsSync(gone) && !existsSync(recycled));
  assert.ok(existsSync(join(base, "attachments", "pool.json")), "the live pool's record stays");

  // The service is gone: its record and everything left go.
  const after = fakeDeps({}, killed);
  assert.equal(await runReap([], { MANDU_RUNTIME_DIR: base }, after), 0);
  assert.ok(!existsSync(live) && !existsSync(orphan));
  assert.ok(!existsSync(join(base, "attachments", "pool.json")));
});

test("a directory with no record is kept while fresh (a pool writing it), and a link is refused, never followed", async () => {
  const base = join(tmpDir("mandu-reap-att2-"), "mandu");
  mkdirSync(base, { recursive: true });
  seed(base, "openclaw:new", null);
  const actions = await planReap(base, fakeDeps({}));
  assert.deepEqual(actions, []);
  const notes: string[] = [];
  const { symlinkSync } = await import("node:fs");
  symlinkSync("/etc", join(base, "attachments", "openclaw:evil"));
  assert.deepEqual(await planReap(base, fakeDeps({}), notes), []);
  assert.ok(notes.some((n) => /attachments\/openclaw:evil skipped: a symbolic link/.test(n)), notes.join("\n"));
});
