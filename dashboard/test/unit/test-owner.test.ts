/**
 * test-owner.test — the dashboard's copy of the test-owner rule
 * (src/test-owner.ts, runtime-instances.md §8a): a dashboard a test started
 * exits when that test's process is gone, and hands the owner to the arbiter
 * it supervises through its env. The rule's cases are proven on the arbiter's
 * copy (arbiter/test/unit/test-owner.test.ts); this proves the copy here is
 * the same code and that it resolves and watches. The real stack dying with
 * a SIGKILLed test is launcher/test/component/test-owner-cleanup.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { armTestOwnerWatch, resolveTestOwner, type TestOwnerDeps } from "../../src/test-owner.js";

const HERE = dirname(fileURLToPath(import.meta.url));

test("the copy matches arbiter/ipc/test-owner.ts but for the provenance line", () => {
  const strip = (s: string): string => s.split("\n").filter((l) => !/^ \* verbatim (in|from) /.test(l)).join("\n");
  const ours = readFileSync(join(HERE, "..", "..", "src", "test-owner.ts"), "utf8");
  const theirs = readFileSync(join(HERE, "..", "..", "..", "arbiter", "ipc", "test-owner.ts"), "utf8");
  assert.equal(strip(ours), strip(theirs), "keep the two copies in sync");
});

test("the topmost test process owns the dashboard; the watch hands it on and fires when it dies", async () => {
  const procs: Record<number, { ppid: number; env: string[] }> = {
    10: { ppid: 1, env: [] },
    20: { ppid: 10, env: ["NODE_TEST_CONTEXT=child-v8"] },
    30: { ppid: 20, env: ["NODE_TEST_CONTEXT=child-v8"] },
  };
  const deps: TestOwnerDeps = {
    selfPid: 40,
    parentOf: (pid) => (pid === 40 ? 30 : procs[pid]?.ppid ?? null),
    environOf: (pid) => procs[pid]?.env ?? null,
    startTimeOf: () => null,
    alive: (pid) => procs[pid] !== undefined,
  };
  assert.equal(resolveTestOwner({}, deps), null, "no test context: no owner");
  const env: Record<string, string | undefined> = { NODE_TEST_CONTEXT: "child-v8" };
  const fired: number[] = [];
  const w = armTestOwnerWatch((o) => fired.push(o), env, deps, 10);
  assert.equal(w?.owner, 20);
  assert.equal(env["MANDU_TEST_OWNER_PID"], "20", "the supervised arbiter inherits it");
  delete procs[20];
  await new Promise((r) => setTimeout(r, 40));
  assert.deepEqual(fired, [20]);
  w!.stop();
});
