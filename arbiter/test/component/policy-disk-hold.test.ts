/**
 * policy-disk-hold e2e — a relaxing policy.yaml edit made on disk while the
 * arbiter runs is NOT the law until a human approves it
 * (policy-surface.md §8.4.6; sandbox security review 2026-09-28,
 * finding 2), through the REAL arbiter sockets with a file-backed law and the
 * hand-edit poll timer running:
 *   - a foreign write that adds a standing allow rule leaves the egress gate
 *     closed, and one pending proposal (by "file", with the relaxation named)
 *     waits on the admin channel;
 *   - approving it through `resolvePolicyProposal` on the ADMIN channel (the
 *     op the dashboard's Inbox calls) makes it the law, without rewriting the
 *     file; the data socket cannot approve it;
 *   - a later relaxing edit that is DECLINED stays out of force, is not
 *     re-filed by the poll, and the file is RESTORED to the law in force
 *     (policy-restore.ts);
 *   - the arbiter's own write (mintUserRule) is not mistaken for a foreign
 *     edit.
 * Run in every protection mode: the hold never reads the axes.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { MODE_AXES, stateAxes, type ProtectionMode } from "../axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4); each server pins its own below

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const LAW = "version: 1\npaths:\n  - { path: /home/u/repo/.env, level: no-model }\n";
const ALLOW = (id: string, host: string): string => `  - { id: ${id}, kind: release, to: { host: ${host} }, mode: allow }\n`;

async function waitFor<T>(what: string, probe: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 150; i++) {
    const v = await probe();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

for (const mode of ["secrets", "injection", "full", "off"] as ProtectionMode[]) {
  test(`[${mode}] a relaxing disk edit waits for the human; approving it on the admin channel makes it the law`, async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-disk-hold-e2e-"));
    dirs.push(dir);
    const file = join(dir, "policy.yaml");
    writeFileSync(file, LAW);
    const server = new ArbiterServer({
      socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
      policyPath: file, policyPollMs: 40, log: () => {},
      ...MODE_AXES[mode],
    });
    await server.listen();
    const data = new ArbiterClient(join(dir, "arbiter.sock"));
    const admin = new ArbiterClient(join(dir, "admin.sock"));
    await data.connect();
    await admin.connect();
    const ruleIds = async () => (await data.policySnapshot()).document?.userRules.map((r) => r.id) ?? [];
    const pending = async () => (await admin.policyProposals("pending")).proposals;
    try {
      // A foreign write (the agent's process tree, a script): a standing allow.
      const relaxed = LAW + "user_rules:\n" + ALLOW("hand", "attacker.example");
      writeFileSync(file, relaxed);
      const held = await waitFor("the held proposal", async () => (await pending()).find((p) => p.diskHash));
      assert.equal(held.requestedBy, "file");
      assert.ok(held.relaxes.some((r) => r.facet === "user-rules" && r.subject === "hand"), "the relaxation is listed");
      await new Promise((r) => setTimeout(r, 120)); // several more polls
      assert.deepEqual(await ruleIds(), [], "the law did not change");
      assert.equal((await pending()).length, 1, "one card, not one per poll");

      // The data socket (every interceptor, the agent's tools) cannot approve.
      await assert.rejects(() => data.resolvePolicyProposal(held.id, "approved"), /admin-only/);
      assert.deepEqual(await ruleIds(), []);

      // The human approves in the Inbox: the dashboard's op, on the admin channel.
      const r = await admin.resolvePolicyProposal(held.id, "approved", "dashboard");
      assert.equal(r.proposal.status, "approved");
      assert.ok(r.changeId);
      assert.deepEqual(await ruleIds(), ["hand"], "approved: the held content is the law");
      assert.equal(readFileSync(file, "utf8"), relaxed, "the person's file is not rewritten");

      // A second relaxing edit, declined: the law stays and the poll does not re-file it.
      const relaxed2 = relaxed + ALLOW("more", "paste.example");
      writeFileSync(file, relaxed2);
      const second = await waitFor("the second held proposal", async () => (await pending()).find((p) => p.diskHash));
      const denied = await admin.resolvePolicyProposal(second.id, "denied", "dashboard");
      assert.equal(denied.restored, true);
      await new Promise((r) => setTimeout(r, 120));
      assert.deepEqual(await ruleIds(), ["hand"], "declined: the law stays");
      assert.equal((await pending()).length, 0, "declined bytes are not re-filed on every poll");
      assert.equal(readFileSync(file, "utf8"), relaxed, "the file is restored to the law in force");

      // The arbiter's own write (the developer view mints a rule) replaces the
      // file and is never read back as a foreign edit.
      await admin.mintUserRule({ kind: "release", to: { host: "paste.example" }, mode: "block" }, "dashboard add-rule");
      await new Promise((r) => setTimeout(r, 120));
      assert.equal((await pending()).length, 0, "the arbiter's own write is not held");
      assert.ok((await ruleIds()).includes("hand"));
    } finally {
      data.close();
      admin.close();
      await server.close();
    }
  });
}
