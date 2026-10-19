/**
 * autostart-supervisor-stall.test — E2E with real processes: the instance
 * autostart never leaves TWO resident arbiters (runtime-instances.md §8,
 * 2026-09-29).
 *
 * Found live: a 3-hour `npm run serve` → tsx → mandu-arbiter orphan of
 * instance-autostart.test.ts. On a loaded host the supervisor dashboard
 * missed the launcher's 6 s wait while it was still starting its own
 * arbiter; the launcher started the bare fallback arbiter BESIDE it (ownerless
 * and lifeline-free by design), the test stopped the dashboard and the one
 * manifest it saw, and the fallback came up after the temp dir was wiped.
 *
 * Here the real spawner (the dev layout's `node --import tsx <entry>` in a
 * fake checkout, detached) runs two stand-ins: a "dashboard" that promotes `current` after a
 * delay or never, and an "arbiter" that records whether the dashboard was
 * still alive when it started. The first wait is cut from 6 s to 1 s.
 *   - slow supervisor: it promotes inside the grace window → the fallback
 *     arbiter never starts (the pre-fix launcher started it at 1 s);
 *   - stalled supervisor: never promotes → its WHOLE process group (the
 *     dashboard and a grandchild) is gone before the fallback starts.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // the children's caches go to temp, not the real HOME (test-organization.md §8.4)
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, existsSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startArbiterInstance, pollSocket } from "../../src/arbiter.js";
import { Layout } from "../../src/services/layout.js";
import { stateAxes } from "../axes.js";
import { standInService } from "../lib/stand-in-service.js";
import { sweepRuntimeProcesses, runtimeProcessGroups } from "../lib/runtime-sweep.js";

stateAxes("off"); // process lifecycle only: no arbiter decides anything here

const linux = process.platform === "linux"; // the group checks read /proc

const DASHBOARD = `
import { mkdirSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";
const dir = process.env.FAKE_DIR, base = process.env.MANDU_RUNTIME_DIR;
// A grandchild in the same group, as the real dashboard's supervised arbiter is.
const kid = spawn(process.execPath, ["-e", "setInterval(() => {}, 1e6)"], { stdio: "ignore" });
writeFileSync(join(dir, "dashboard.json"), JSON.stringify({ pid: process.pid, kid: kid.pid }));
const delay = Number(process.env.FAKE_PROMOTE_MS);
if (delay >= 0) setTimeout(() => {
  mkdirSync(join(base, "current"), { recursive: true });
  writeFileSync(join(base, "current", "arbiter.sock"), "");
}, delay);
setInterval(() => {}, 1e6);
`;

const ARBITER = `
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const dir = process.env.FAKE_DIR;
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
let dash = null;
try { dash = JSON.parse(readFileSync(join(dir, "dashboard.json"), "utf8")); } catch {}
writeFileSync(join(dir, "arbiter.json"), JSON.stringify({
  pid: process.pid,
  dashboardAlive: dash ? alive(dash.pid) || alive(dash.kid) : null,
}));
setInterval(() => {}, 1e6);
`;

function fakeRepo(root: string): void {
  standInService(root, "dashboard", "dashboard", DASHBOARD);
  standInService(root, "arbiter", "arbiter", ARBITER);
}

const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };

async function run(promoteMs: number, graceMs: number) {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-stall-")));
  const repo = join(tmp, "repo");
  const base = join(tmp, "mandu");
  const fake = join(tmp, "fake");
  mkdirSync(fake, { recursive: true });
  fakeRepo(repo);
  const logs: string[] = [];
  const start = startArbiterInstance(Layout.dev(repo), base, join(base, "logs", "arbiter-autostart.log"), {}, {
    env: { ...process.env, FAKE_DIR: fake, FAKE_PROMOTE_MS: String(promoteMs) },
    account: null,
    // The launcher's first wait is 60 × 100 ms; 10 × 100 ms here.
    waitForSocket: (s, tries, delay) => pollSocket(s, Math.min(tries, 10), delay),
    supervisorGraceMs: graceMs,
    log: (m) => { logs.push(m); },
    info: () => {},
  });
  return { tmp, base, fake, logs, start };
}

test("a SLOW supervisor (promotes after the first wait) is waited for: no second, bare arbiter starts", { skip: !linux, timeout: 60_000 }, async () => {
  const r = await run(2_500, 15_000);
  try {
    await r.start();
    assert.ok(existsSync(join(r.base, "current", "arbiter.sock")), "the supervisor promoted");
    // Give a fallback that WAS spawned time to start and record itself.
    await new Promise((res) => setTimeout(res, 2_000));
    assert.ok(!existsSync(join(r.fake, "arbiter.json")), "no bare arbiter beside the supervisor's own");
    const dash = JSON.parse(readFileSync(join(r.fake, "dashboard.json"), "utf8")) as { pid: number };
    assert.ok(alive(dash.pid), "the supervisor keeps running");
    assert.equal(r.logs.length, 0, JSON.stringify(r.logs));
  } finally {
    await sweepRuntimeProcesses(r.base);
    assert.deepEqual(runtimeProcessGroups(r.base), [], "the sweep leaves nothing under the base");
    rmSync(r.tmp, { recursive: true, force: true });
  }
});

test("a STALLED supervisor (never promotes) is stopped, whole group, BEFORE the bare arbiter starts", { skip: !linux, timeout: 60_000 }, async () => {
  const r = await run(-1, 3_000);
  try {
    await r.start();
    const dash = JSON.parse(readFileSync(join(r.fake, "dashboard.json"), "utf8")) as { pid: number; kid: number };
    assert.ok(!alive(dash.pid) && !alive(dash.kid), "the dashboard and its grandchild are gone");
    // The fallback records itself once it has started.
    for (let i = 0; i < 100 && !existsSync(join(r.fake, "arbiter.json")); i++) await new Promise((res) => setTimeout(res, 100));
    const arb = JSON.parse(readFileSync(join(r.fake, "arbiter.json"), "utf8")) as { dashboardAlive: boolean | null };
    assert.equal(arb.dashboardAlive, false, "the bare arbiter never ran beside the supervisor");
    assert.ok(r.logs.some((l) => /the dashboard did not start \(it was still starting after \d+ s, so it was stopped\)/.test(l)), JSON.stringify(r.logs));
  } finally {
    await sweepRuntimeProcesses(r.base);
    assert.deepEqual(runtimeProcessGroups(r.base), [], "the sweep leaves nothing under the base");
    rmSync(r.tmp, { recursive: true, force: true });
  }
});
