/**
 * policy-change-record e2e — every write to policy.yaml lands in the change
 * log (dashboard.md §4.25j), through the REAL arbiter sockets with a
 * file-backed law and the hand-edit poll running:
 *   - a hand edit is recorded (`via: "disk"`, by "file") with the rules it
 *     touched, and is NOT undoable (Undo would rewrite the person's file);
 *   - the developer view's writes (mint a rule, apply a document) are
 *     recorded with the requester they name, and are undoable;
 *   - a write that changes no rule records nothing;
 *   - the policy surface's own changes are recorded ONCE (not again by the
 *     document store's hook).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const LAW = `version: 1
paths:
  - path: /home/u/repo/.env
    level: no-model
`;

test("hand edits and developer-view writes are recorded with their rules; the surface is recorded once; a no-op records nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-change-record-"));
  dirs.push(dir);
  const file = join(dir, "policy.yaml");
  writeFileSync(file, LAW);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: file, policyPollMs: 40, log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  await data.connect();
  await admin.connect();
  const changes = async () => (await admin.policyChanges(50)).changes;
  try {
    assert.deepEqual(await changes(), [], "loading the law at start is not a change");

    // A hand edit: a new lock, written straight into the file.
    writeFileSync(file, LAW + "  - path: /home/u/repo/id_rsa\n    level: no-model\n");
    let disk;
    for (let i = 0; i < 100 && !disk; i++) {
      await new Promise((r) => setTimeout(r, 20));
      disk = (await changes()).find((c) => c.via === "disk");
    }
    assert.ok(disk, "the hand edit is recorded");
    assert.equal(disk.requestedBy, "file");
    assert.equal(disk.sessionKey, null);
    assert.equal(disk.undoable, false, "a hand edit is not undone from the dashboard");
    assert.deepEqual(disk.rules, [{ rowIds: ["lock:/home/u/repo/id_rsa"], added: true, removed: false, current: true }]);
    assert.ok(disk.delta.some((d) => d.subject.includes("id_rsa")), "the history can say what it did");
    await assert.rejects(() => admin.undoPolicyChange(disk!.id), /hand edit/);
    assert.match(readFileSync(file, "utf8"), /id_rsa/, "the refused Undo wrote nothing");

    // The developer view mints a rule: recorded with its requester, undoable.
    const minted = await admin.mintUserRule({ kind: "release", to: { host: "paste.example" }, mode: "block" }, "dashboard add-rule");
    const mint = (await changes()).find((c) => c.via === "mint-rule");
    assert.ok(mint);
    assert.equal(mint.requestedBy, "dashboard add-rule");
    assert.equal(mint.undoable, true);
    assert.deepEqual(mint.rules, [{ rowIds: [minted.id], added: true, removed: false, current: true }]);

    // Re-applying the same document changes no rule: nothing recorded.
    const n = (await changes()).length;
    const read = await admin.policyDocument();
    await admin.applyPolicyDocument(read.inForce, "dashboard lists", read.lawHash!);
    assert.equal((await changes()).length, n, "a write that changes no rule is not a change");

    // The policy surface records its own change once, not again via the hook.
    const t = await data.policyPropose({ edits: [{ op: "lock-path", path: "/home/u/repo/**/*.pem", level: "no-model" }], sessionKey: "s1" });
    assert.equal(t.applied, true);
    const all = await changes();
    assert.equal(all.length, n + 1);
    assert.equal(all[0]!.via, "agent-tighten");
    // Its own file write is not later mistaken for a hand edit.
    await new Promise((r) => setTimeout(r, 150));
    assert.equal((await changes()).length, n + 1, "the arbiter's own write is not re-read as a hand edit");
  } finally {
    data.close();
    admin.close();
    await server.close();
  }
});
