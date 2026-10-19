/**
 * home-rule-changes.test — `buildHome` (GET /api/home) counts the rule
 * changes waiting through its narrow `proposals` dep (dashboard.md §4.25,
 * the verdict ladder's `waiting`).
 *
 * Pins:
 * - it reads the PENDING proposals and passes only their number to the
 *   view model: no proposal's pattern, file or reason reaches the payload;
 * - a read that throws, an op that is absent, a dep that is absent, or an
 *   answer that is not a list is none: the hero is today's, and buildHome
 *   never throws for it.
 *
 * Axes: the arbiter's posture is the snapshot's own, `secrets` (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildHome, HomeFacts, type HomeDeps } from "../../../src/server/home-routes.js";
import type { EventSource } from "../../../src/event-source.js";
import type { PolicySnapshot } from "../../../src/policy-model.js";
import type { PolicyProposalRow } from "../../../src/view-model/policy-proposals.js";

const SECRETS_SNAPSHOT = {
  specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
  posture: { integrity: false, confidentiality: true }, // the `secrets` axes, stated
  usage: { rules: [], sensitivePaths: [] },
  verdicts: [],
} as unknown as PolicySnapshot;

const PATTERN = "homeRuleChangeCanaryPattern";
const FILE = "/home/u/proj/rule-change-canary.txt";

function proposal(id: string, status: PolicyProposalRow["status"] = "pending"): PolicyProposalRow {
  return {
    id, status, requestedBy: "agent", reason: `widen for ${PATTERN}`,
    edits: [{ op: "add", path: ["paths"], value: { path: FILE, pattern: PATTERN } }],
  } as unknown as PolicyProposalRow;
}

function deps(proposals: HomeDeps["proposals"], mandu: string): HomeDeps {
  const source = {
    listSessions: async () => [],
    policySnapshot: async () => SECRETS_SNAPSHOT,
  } as unknown as EventSource;
  return {
    source,
    facts: new HomeFacts(source, "/home/u"),
    approvals: undefined,
    ...(proposals ? { proposals } : {}),
    testRuns: [],
    watchRuns: [],
    env: { MANDU_HOME: mandu },
    home: "/home/u",
  };
}

test("buildHome counts the pending rule changes, and only their number reaches the hero", async () => {
  const mandu = mkdtempSync(join(tmpdir(), "mandu-home-rules-"));
  try {
    const asked: unknown[] = [];
    const one = await buildHome(deps({ policyProposals: async (status) => { asked.push(status); return { proposals: [proposal("pp-000001")] }; } }, mandu));
    assert.deepEqual(asked, ["pending"], "it asks for the pending ones");
    assert.equal(one.protection.level, "secrets");
    assert.equal(one.verdict, "waiting");
    assert.equal(one.headline, "A rule change is waiting for you.");
    assert.equal(one.sentence, "Your rules stay as they are until you answer. Untrusted content is not masked in this mode.");
    assert.equal(one.ruleChangesWaiting, 1);
    const body = JSON.stringify(one);
    assert.ok(!body.includes(PATTERN) && !body.includes(FILE) && !body.includes("pp-000001"), "no proposal's words, file or id is in /api/home");

    // A row an older arbiter returns that is not pending is not counted.
    const two = await buildHome(deps({ policyProposals: async () => ({ proposals: [proposal("pp-000002"), proposal("pp-000003"), proposal("pp-000004", "approved")] }) }, mandu));
    assert.equal(two.headline, "2 rule changes are waiting for you.");
  } finally {
    rmSync(mandu, { recursive: true, force: true });
  }
});

test("a proposals read that fails, is absent or answers no list: none counted, today's hero", async () => {
  const mandu = mkdtempSync(join(tmpdir(), "mandu-home-rules-"));
  try {
    const cases: Array<[string, HomeDeps["proposals"]]> = [
      ["no dep", undefined],
      ["no op (an older arbiter)", {}],
      ["a read that throws", { policyProposals: async () => { throw new Error("arbiter went away"); } }],
      ["an answer with no list", { policyProposals: async () => ({}) as { proposals: PolicyProposalRow[] } }],
    ];
    for (const [what, p] of cases) {
      const vm = await buildHome(deps(p, mandu));
      assert.equal(vm.verdict, "secrets-only", what);
      assert.equal(vm.headline, "Your secrets are guarded.", what);
      assert.equal(vm.ruleChangesWaiting, 0, what);
    }
  } finally {
    rmSync(mandu, { recursive: true, force: true });
  }
});
