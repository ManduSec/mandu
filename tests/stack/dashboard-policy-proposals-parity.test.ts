/**
 * dashboard-policy-proposals-parity — the PRODUCTION wiring of the dashboard's
 * rule-change request surface (policy-surface.md §8.4.2, §8.6):
 * `makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }))`, exactly
 * as dashboard/src/server-main.ts builds it, over a real ArbiterServer, with
 * NO test bridge in between (CONTRIBUTING.md "Conventions in the code": an
 * adapter ships a parity test; the 2026-09-24 `callTaint` lesson).
 *
 * Each of the four forwarded ops is called through the returned `policyDoc`
 * surface and must be ANSWERED by the arbiter: the reads over the data
 * socket, approve and undo over the admin channel (the data socket would
 * refuse them as admin-only, so a write routed to the wrong door fails here).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("makeApprovalsArbiter over the REAL arbiter: list, approve, history and undo are each answered (full axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dash-proposals-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const server = new ArbiterServer({
    socketPath: dataSock,
    adminSocketPath: adminSock,
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    policyPath,
    policyPollMs: 0,
    integrity: true,
    confidentiality: true,
    log: () => {},
  });
  await server.listen();
  const agent = new ArbiterClient(dataSock);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  try {
    await agent.connect();
    assert.ok(wired?.policyDoc, "the production wiring exposes the policy surface");
    const doc = wired.policyDoc;
    assert.ok(doc.policyProposals && doc.policyChanges && doc.resolvePolicyProposal && doc.undoPolicyChange, "all four ops are forwarded");

    // The agent (data socket) asks for a relaxation.
    const asked = await agent.policyPropose({ edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }], reason: "pip", sessionKey: "s1" });
    assert.ok("proposalId" in asked);

    const listed = await doc.policyProposals("pending");
    assert.deepEqual(listed.proposals.map((p) => p.id), [asked.proposalId]);

    const approved = await doc.resolvePolicyProposal(asked.proposalId, "approved", "dashboard");
    assert.equal(approved.proposal.status, "approved");
    assert.ok(approved.changeId);
    assert.match(readFileSync(policyPath, "utf8"), /pypi\.org/, "approval over the admin channel wrote the law");

    // The agent tightens on its own; the human undoes it through the adapter.
    const tight = await agent.policyPropose({ edits: [{ op: "lock-path", path: "/srv/app/.env", level: "no-model" }], sessionKey: "s1" });
    assert.ok(tight.applied && "changeId" in tight && tight.changeId);
    const history = await doc.policyChanges(10);
    assert.deepEqual(history.changes.map((c) => c.via), ["agent-tighten", "proposal"]);
    const undone = await doc.undoPolicyChange(tight.changeId!, "dashboard");
    assert.equal(undone.undone, tight.changeId);
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /\/srv\/app\/\.env/);
    assert.match(readFileSync(policyPath, "utf8"), /pypi\.org/);
  } finally {
    agent.close();
    wired?.close();
    await server.close();
  }
});
