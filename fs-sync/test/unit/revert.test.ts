/**
 * Unit: revert (full-state filesystem rollback over the Mandu commit history).
 *
 * REAL git temp repo + MOCK arbiter. We perform several agent writes (each
 * producing a T/U commit pair via syncToHuman), then assert listWriteCycles /
 * planRevert / revertToWriteCycle restore the HumanView to an earlier state and
 * keep the AgentView (mdu-trusted) consistent.
 */

import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { ViewSync } from "../../src/view-sync.js";
import { listWriteCycles, planRevert, revertToWriteCycle } from "../../src/revert.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { makeTempRepo } from "../helpers/temp-repo.js";

async function seedThreeWrites() {
  const repo = makeTempRepo();
  const arbiter = new MockArbiter();
  const dv = new ViewSync({
    workspacePath: repo.workspacePath,
    arbiter,
    stateBase: repo.stateBase,
  });
  await dv.initialize();

  // Three agent writes; each is trusted content (agent-authored), so the
  // HumanView ends up with the literal text. captureAgentWrite + syncToHuman.
  dv.captureAgentWrite("a.md", "alpha\n");
  await dv.syncToHuman({ toolName: "Write", callId: "c1" });

  dv.captureAgentWrite("b.md", "bravo\n");
  await dv.syncToHuman({ toolName: "Write", callId: "c2" });

  dv.captureAgentWrite("c.md", "charlie\n");
  await dv.syncToHuman({ toolName: "Write", callId: "c3" });

  return { repo, arbiter, dv };
}

test("listWriteCycles enumerates each agent write oldest-first", async () => {
  const { repo, dv } = await seedThreeWrites();
  try {
    const cycles = listWriteCycles(dv.layout);
    assert.equal(cycles.length, 3);
    assert.deepEqual(
      cycles.map((c) => c.number),
      [1, 2, 3],
    );
    // files= metadata carried through.
    assert.ok(cycles[0]!.files.includes("a.md"));
    assert.ok(cycles[2]!.files.includes("c.md"));
  } finally {
    repo.cleanup();
  }
});

test("planRevert reports files kept vs removed for a target cycle", async () => {
  const { repo, dv } = await seedThreeWrites();
  try {
    const plan = planRevert(dv.layout, 1);
    assert.equal(plan.abandonedCount, 2);
    assert.ok(plan.filesKept.includes("a.md"));
    assert.ok(plan.filesRemoved.includes("b.md"));
    assert.ok(plan.filesRemoved.includes("c.md"));
  } finally {
    repo.cleanup();
  }
});

test("revertToWriteCycle restores the HumanView to the target state", async () => {
  const { repo, dv } = await seedThreeWrites();
  try {
    assert.ok(existsSync(join(repo.workspacePath, "c.md")), "c.md exists before revert");

    revertToWriteCycle(dv.layout, 1);

    assert.ok(existsSync(join(repo.workspacePath, "a.md")), "a.md kept");
    assert.equal(readFileSync(join(repo.workspacePath, "a.md"), "utf8"), "alpha\n");
    assert.ok(!existsSync(join(repo.workspacePath, "b.md")), "b.md removed");
    assert.ok(!existsSync(join(repo.workspacePath, "c.md")), "c.md removed");
  } finally {
    repo.cleanup();
  }
});
