/**
 * test-owner.test — who owns a daemon a test started, and the watch that
 * shuts it down when that process is gone (ipc/test-owner.ts,
 * runtime-instances.md §8a). Pure: the process table is a fake. The real
 * daemon dying with a SIGKILLed test process is
 * test/component/test-owner-exit.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { armTestOwnerWatch, realTestOwnerDeps, resolveTestOwner, type TestOwnerDeps } from "../../ipc/test-owner.js";

interface Proc { ppid: number; env: string[]; start: string }

/** A process table: pid → parent, environment, start time. */
function table(procs: Record<number, Proc>, self = 100): TestOwnerDeps & { procs: Record<number, Proc> } {
  return {
    procs,
    selfPid: self,
    parentOf: (pid) => procs[pid]?.ppid ?? null,
    environOf: (pid) => procs[pid]?.env ?? null,
    startTimeOf: (pid) => procs[pid]?.start ?? null,
    alive: (pid) => procs[pid] !== undefined,
  };
}

const CTX = "NODE_TEST_CONTEXT=child-v8";

/** runner 10 (no context) → test file 20 → launcher CLI 30 → dashboard 40 → this arbiter 100. */
function chain(): Record<number, Proc> {
  return {
    10: { ppid: 1, env: ["PATH=/bin"], start: "a" },
    20: { ppid: 10, env: [CTX, "PATH=/bin"], start: "b" },
    30: { ppid: 20, env: [CTX], start: "c" },
    40: { ppid: 30, env: [CTX], start: "d" },
    100: { ppid: 40, env: [CTX], start: "e" },
  };
}

test("no MANDU_TEST_OWNER_PID and no NODE_TEST_CONTEXT: no owner (every production start)", () => {
  assert.equal(resolveTestOwner({}, table(chain())), null);
  assert.equal(resolveTestOwner({ NODE_TEST_CONTEXT: "" }, table(chain())), null);
});

test("under node's test runner the owner is the TOPMOST ancestor with the context: the test file, not the CLI or dashboard between", () => {
  assert.equal(resolveTestOwner({ NODE_TEST_CONTEXT: "child-v8" }, table(chain())), 20);
});

test("the walk stops at a parent without the context, an unreadable one, or init", () => {
  const procs = chain();
  procs[30]!.env = ["PATH=/bin"]; // the CLI was started without it
  assert.equal(resolveTestOwner({ NODE_TEST_CONTEXT: "child-v8" }, table(procs)), 40);
  const unreadable = chain();
  delete unreadable[40]; // the parent is gone (reparented chain): nothing above can be read
  assert.equal(resolveTestOwner({ NODE_TEST_CONTEXT: "child-v8" }, table(unreadable)), null);
  const orphan = { 100: { ppid: 1, env: [CTX], start: "e" } };
  assert.equal(resolveTestOwner({ NODE_TEST_CONTEXT: "child-v8" }, table(orphan)), null, "a daemon already reparented to init has no test owner");
  const empty = chain();
  empty[20]!.env = ["NODE_TEST_CONTEXT="]; // an empty value is not the context
  assert.equal(resolveTestOwner({ NODE_TEST_CONTEXT: "child-v8" }, table(empty)), 30);
});

test("MANDU_TEST_OWNER_PID wins over the walk; 0, none, garbage or this pid name no owner", () => {
  const t = table(chain());
  assert.equal(resolveTestOwner({ MANDU_TEST_OWNER_PID: "30", NODE_TEST_CONTEXT: "child-v8" }, t), 30);
  assert.equal(resolveTestOwner({ MANDU_TEST_OWNER_PID: " 4242 " }, t), 4242);
  for (const v of ["0", "none", "NONE", "x", "1", "-5", "100"]) {
    assert.equal(resolveTestOwner({ MANDU_TEST_OWNER_PID: v, NODE_TEST_CONTEXT: "child-v8" }, t), null, v);
  }
});

test("the watch writes the owner back into the env, fires once when the owner dies, and never without one", async () => {
  const t = table(chain());
  const env: Record<string, string | undefined> = { NODE_TEST_CONTEXT: "child-v8" };
  const fired: number[] = [];
  const w = armTestOwnerWatch((o) => fired.push(o), env, t, 10);
  assert.ok(w);
  assert.equal(w.owner, 20);
  assert.equal(env["MANDU_TEST_OWNER_PID"], "20", "children inherit the owner even once the chain of parents is broken");
  await new Promise((r) => setTimeout(r, 40));
  assert.deepEqual(fired, [], "a live owner: nothing happens");
  delete t.procs[20];
  await new Promise((r) => setTimeout(r, 40));
  assert.deepEqual(fired, [20], "the owner is gone: fired once");
  await new Promise((r) => setTimeout(r, 40));
  assert.deepEqual(fired, [20], "and only once");
  w.stop();

  assert.equal(armTestOwnerWatch(() => { throw new Error("never"); }, {}, t, 10), null, "no owner, no watch");
});

test("a reused pid is not the owner: a changed start time fires the watch", async () => {
  const t = table(chain());
  const fired: number[] = [];
  const w = armTestOwnerWatch((o) => fired.push(o), { MANDU_TEST_OWNER_PID: "20" }, t, 10)!;
  t.procs[20] = { ppid: 1, env: [], start: "someone-else" };
  await new Promise((r) => setTimeout(r, 40));
  assert.deepEqual(fired, [20]);
  w.stop();
});

test("an owner already gone when the daemon starts fires on the first check", async () => {
  const t = table(chain());
  const fired: number[] = [];
  const w = armTestOwnerWatch((o) => fired.push(o), { MANDU_TEST_OWNER_PID: "777" }, t, 10)!;
  await new Promise((r) => setTimeout(r, 40));
  assert.deepEqual(fired, [777]);
  w.stop();
});

test("the real process table: this test file is its own topmost test process, and reads its own start time", { skip: process.platform !== "linux" && "reads /proc" }, () => {
  // Under node's test runner this file's process carries the context; a
  // daemon it spawned would resolve to it. From this process the walk starts
  // at the parent (the runner), which does not carry it unless this run is
  // itself nested in a test, whose process is then the owner of both.
  const fromHere = resolveTestOwner({ NODE_TEST_CONTEXT: process.env["NODE_TEST_CONTEXT"] }, realTestOwnerDeps);
  const asChild = resolveTestOwner({ NODE_TEST_CONTEXT: "child-v8" }, { ...realTestOwnerDeps, selfPid: -1, parentOf: (pid) => (pid === -1 ? process.pid : realTestOwnerDeps.parentOf(pid)) });
  if (process.env["NODE_TEST_CONTEXT"]) assert.equal(asChild, fromHere ?? process.pid, "a child of this file resolves to this file (or the test above it)");
  assert.equal(realTestOwnerDeps.parentOf(process.pid), process.ppid);
  assert.match(realTestOwnerDeps.startTimeOf(process.pid) ?? "", /^\d+$/);
  assert.equal(realTestOwnerDeps.alive(process.pid), true);
});
