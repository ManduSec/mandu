/**
 * registry.test — the dashboard's runtime-registry entry (registry.ts):
 * id scheme + owner semantics (mirrors of arbiter/ipc/instance.ts), atomic
 * register/unregister, and the boot-time dead-pid sweep that keeps the
 * `dashboards/` dir from accumulating SIGKILLed entries.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

import {
  dashboardId,
  registerDashboard,
  resolveOwnerPid,
  sweepDeadDashboards,
  unregisterDashboard,
  type DashboardManifest,
} from "../../src/registry.js";
import { tmpDir } from "./tmp-dir.js";

function withBase(fn: (base: string) => void): void {
  const base = tmpDir("mandu-dashreg-");
  try {
    fn(base);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

function manifest(over: Partial<DashboardManifest> = {}): DashboardManifest {
  return {
    pid: 4242, port: 4500, host: "127.0.0.1", startedAt: "2026-07-19T00:00:00.000Z",
    gitRev: "8b5a345", ownerPid: null, repoRoot: "/repo", ...over,
  };
}

test("dashboardId mirrors the arbiter id scheme: utc stamp + rev + pid", () => {
  const id = dashboardId(new Date(Date.UTC(2026, 6, 19, 4, 22)), "8b5a345", 4242);
  assert.equal(id, "20260719-0422-8b5a345-p4242");
  // A hostile/empty rev degrades the same way the arbiter's does.
  assert.match(dashboardId(new Date(Date.UTC(2026, 6, 19, 4, 22)), "", 1), /-nogit-p1$/);
});

test("resolveOwnerPid: explicit wins, 0/none = ownerless, default = parent pid — the arbiter's exact rule", () => {
  assert.equal(resolveOwnerPid({ MANDU_OWNER_PID: "123" }, 999), 123);
  assert.equal(resolveOwnerPid({ MANDU_OWNER_PID: "0" }, 999), null);
  assert.equal(resolveOwnerPid({ MANDU_OWNER_PID: "none" }, 999), null);
  assert.equal(resolveOwnerPid({}, 999), 999);
  assert.equal(resolveOwnerPid({ MANDU_OWNER_PID: "garbage" }, 999), 999);
});

test("registerDashboard writes dashboards/<id>.json atomically; unregister removes exactly it", () => {
  withBase((base) => {
    const m = manifest({ signInSock: join(base, "human", "dashboard-4242.sock") });
    const { id, path } = registerDashboard(base, m, new Date(Date.UTC(2026, 6, 19, 4, 22)));
    assert.equal(id, "20260719-0422-8b5a345-p4242");
    assert.equal(path, join(base, "dashboards", `${id}.json`));
    const onDisk = JSON.parse(readFileSync(path, "utf8")) as DashboardManifest;
    assert.deepEqual(onDisk, m, "the manifest round-trips verbatim");
    assert.ok(!existsSync(`${path}.tmp`), "no tmp litter — the write is tmp+rename");

    unregisterDashboard(path);
    assert.ok(!existsSync(path), "unregister removes the entry");
    unregisterDashboard(path); // idempotent — a raced double-exit must not throw
  });
});

test("sweepDeadDashboards removes dead-pid + corrupt entries, keeps live ones, ignores .tmp files", () => {
  withBase((base) => {
    const dir = join(base, "dashboards");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "a-p100.json"), JSON.stringify(manifest({ pid: 100 }))); // dead
    writeFileSync(join(dir, "b-p200.json"), JSON.stringify(manifest({ pid: 200 }))); // live
    writeFileSync(join(dir, "c-bad.json"), "{not json");                             // corrupt → dead
    writeFileSync(join(dir, "d-p300.json.tmp"), "half-written");                     // mid-write → untouched

    const removed = sweepDeadDashboards(base, (pid) => pid === 200);
    assert.deepEqual(removed.sort(), ["a-p100", "c-bad"]);
    assert.deepEqual(readdirSync(dir).sort(), ["b-p200.json", "d-p300.json.tmp"],
      "the live entry and the mid-write tmp survive");
  });
});

test("sweepDeadDashboards on a base with no registry is a quiet no-op", () => {
  withBase((base) => {
    assert.deepEqual(sweepDeadDashboards(base, () => true), []);
  });
});

// ── planted paths (runtime-instances.md §2, 2026-09-30) ──────────────────────
// Whoever can write the runtime base (any same-uid process on Linux; on macOS
// the agent's Seatbelt profile write-denies dashboards/) knows these names,
// and the dashboard runs outside the agent's confinement.

test("a dashboards/ that is a link to someone's folder: the sweep deletes NOTHING there, and no entry is written through it", () => {
  withBase((base) => {
    const project = join(base, "project");
    mkdirSync(project);
    writeFileSync(join(project, "package.json"), '{"name":"mine"}\n');
    writeFileSync(join(project, "tsconfig.json"), "{}\n");
    symlinkSync(project, join(base, "dashboards"));
    // Neither names a live pid: through the link both would read as dead entries.
    assert.deepEqual(sweepDeadDashboards(base, () => false), []);
    assert.deepEqual(readdirSync(project).sort(), ["package.json", "tsconfig.json"], "every file is still there");
    assert.throws(() => registerDashboard(base, manifest()), /dashboard registry .* is not a real directory/);
    assert.deepEqual(readdirSync(project).sort(), ["package.json", "tsconfig.json"], "no entry landed in the linked folder");
    // A file squatting the name: the same.
    rmSync(join(base, "dashboards"));
    writeFileSync(join(base, "dashboards"), "");
    assert.deepEqual(sweepDeadDashboards(base, () => false), []);
    assert.throws(() => registerDashboard(base, manifest()));
  });
});

test("registerDashboard: a link planted at the entry's temp name is removed, never written through", () => {
  withBase((base) => {
    const now = new Date(Date.UTC(2026, 8, 30, 12, 0));
    const victim = join(base, "victim.rc");
    writeFileSync(victim, "# rc\n");
    mkdirSync(join(base, "dashboards"));
    const id = dashboardId(now, "8b5a345", 4242);
    symlinkSync(victim, join(base, "dashboards", `${id}.json.tmp`));
    const { path } = registerDashboard(base, manifest(), now);
    assert.equal(readFileSync(victim, "utf8"), "# rc\n", "the link's target is untouched");
    assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), manifest());
    assert.ok(!lstatSync(path).isSymbolicLink());
    assert.deepEqual(readdirSync(join(base, "dashboards")), [`${id}.json`], "no temp file or link left");
  });
});
