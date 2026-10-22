/**
 * stack-sessions.test — which `mandu` sessions use a stack
 * (src/supervisor/stack-sessions.ts), the scan that decides whether the
 * supervisor may replace a stale arbiter (runtime-instances.md §4.1b). It
 * mirrors the launcher's liveLaunchersOn: the `mandu` title, the stack read
 * from the process's environment by the runtime-base rule, else its scope
 * dir in the stack's registry; a container's process is another stack's.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { isContainerCgroup, liveSessionsOn, realSessionScanDeps, type SessionScanDeps } from "../../../src/supervisor/stack-sessions.js";

const BASE = "/run/user/1007/mandu";

interface P { title: string; env?: Record<string, string> | null; cgroup?: string }

function deps(procs: Record<number, P>, scopeDirs: string[] = []): SessionScanDeps {
  return {
    listPids: () => Object.keys(procs).map(Number),
    titleOf: (pid) => procs[pid]?.title ?? null,
    environOf: (pid) => (procs[pid]?.env === undefined ? null : procs[pid]!.env!),
    cgroupOf: (pid) => procs[pid]?.cgroup ?? "0::/user.slice/user-1007.slice/user@1007.service/app.slice/x.scope",
    entriesOf: (dir) => (dir === BASE ? scopeDirs : []),
  };
}

test("a mandu launcher whose env selects this stack is a session; another stack's, a daemon or a container's is not", () => {
  const procs: Record<number, P> = {
    10: { title: "mandu", env: { XDG_RUNTIME_DIR: "/run/user/1007", HOME: "/home/u" } },
    11: { title: "mandu", env: { MANDU_RUNTIME_DIR: BASE + "/" } },
    12: { title: "mandu", env: { MANDU_RUNTIME_DIR: "/tmp/mdu-x/rt" } },
    13: { title: "mandu-arbiter", env: { MANDU_RUNTIME_DIR: BASE } },
    14: { title: "mandu", env: { MANDU_RUNTIME_DIR: BASE }, cgroup: "0::/system.slice/docker-abc.scope" },
    15: { title: "node", env: { MANDU_RUNTIME_DIR: BASE } },
  };
  assert.deepEqual(liveSessionsOn(BASE, deps(procs)), [10, 11]);
});

test("an unreadable environment falls back to the stack's scope dirs", () => {
  const procs: Record<number, P> = { 20: { title: "mandu", env: null }, 21: { title: "mandu", env: null } };
  assert.deepEqual(liveSessionsOn(BASE, deps(procs, ["1792536308-20", "dashboards", "instances", "demo-1-21x"])), [20]);
});

test("no process table: null, which the supervisor counts as in use", () => {
  assert.equal(liveSessionsOn(BASE, { ...deps({}), listPids: () => null }), null);
});

test("container cgroups", () => {
  for (const cg of ["0::/system.slice/docker-1.scope", "0::/machine.slice/libpod-2.scope", "0::/kubepods/burstable/pod3", "0::/lxc.payload.c1"]) {
    assert.equal(isContainerCgroup(cg), true, cg);
  }
  assert.equal(isContainerCgroup("0::/user.slice/user-1007.slice/user@1007.service/app.slice/mandu-dashboard.service"), false);
});

test("the real scan runs, and never counts this process", { skip: process.platform !== "linux" && "reads /proc" }, () => {
  const got = liveSessionsOn("/nonexistent/mandu-test-stack", realSessionScanDeps);
  assert.ok(Array.isArray(got));
  assert.ok(!got.includes(process.pid));
});
