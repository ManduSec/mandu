/**
 * policy-models-edit e2e — the model ops of the edit grammar through the REAL
 * arbiter sockets (policy-surface.md §8.4.1, confidentiality-plan-11 §7.3).
 *
 * One in-process ArbiterServer with a file-backed law:
 *   - on the ADMIN channel (the dashboard's Settings › Models), add-model is a
 *     relaxation: propose files a proposal and writes nothing; approving it
 *     writes policy.yaml and `modelEndpoints` (inspect-mcp's routing, the
 *     launcher's confine ports) answers the new entry at once; update-model
 *     and remove-model go the same way; Undo puts the list back;
 *   - a cloud-backed model at `local: true` is refused by the same validator a
 *     hand-written file meets, and nothing is written;
 *   - models are read-only to a model (policy-surface.md §8.4.3a,
 *     decision 2026-09-28): `policySchema` offers no model op; on the DATA
 *     socket (the agent's policy tools) and on the admin channel as the
 *     Describe box (requestedBy "assistant") every model op is REFUSED before
 *     anything is filed or written, while the same op as Settings › Models
 *     still applies.
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

stateAxes("secrets"); // local-model is a confidentiality level (the default mode's axis)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const LAW = `version: 1
paths:
  - path: /home/u/notes
    level: local-model
`;

async function rig(fn: (c: { data: ArbiterClient; admin: ArbiterClient; file: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-models-edit-"));
  dirs.push(dir);
  const file = join(dir, "policy.yaml");
  writeFileSync(file, LAW);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    policyPath: file,
    policyPollMs: 0,
    integrity: false,
    confidentiality: true,
    log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  try {
    await data.connect();
    await admin.connect();
    await fn({ data, admin, file });
  } finally {
    data.close();
    admin.close();
    await server.close();
  }
}

/** The human's two steps, as the dashboard takes them: propose, then approve. */
async function applyAsHuman(admin: ArbiterClient, edits: unknown[]): Promise<string> {
  const r = await admin.policyPropose({ edits, reason: "Settings", requestedBy: "settings" });
  assert.equal(r.applied, false, "a models change is never applied without the approval step");
  assert.ok("proposalId" in r, JSON.stringify(r));
  assert.ok(r.relaxes.length > 0 && r.relaxes.every((x) => x.facet === "models"), JSON.stringify(r.relaxes));
  const resolved = await admin.resolvePolicyProposal(r.proposalId, "approved", "human:settings");
  assert.ok(resolved.changeId, "the approval applied and recorded a change");
  return resolved.changeId!;
}

test("admin channel: add, update and remove a model; modelEndpoints follows each; Undo puts the list back", async () => {
  await rig(async ({ data, admin, file }) => {
    assert.deepEqual(await data.modelEndpoints(), []);
    const bytes = readFileSync(file);
    const filed = await admin.policyPropose({ edits: [{ op: "add-model", name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true }], requestedBy: "settings" });
    assert.equal(filed.applied, false);
    assert.deepEqual(readFileSync(file), bytes, "filing the proposal wrote nothing");
    assert.deepEqual(await data.modelEndpoints(), []);
    assert.ok("proposalId" in filed);
    const added = await admin.resolvePolicyProposal(filed.proposalId, "approved", "human:settings");
    assert.ok(added.changeId);
    assert.deepEqual(await data.modelEndpoints(), [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true }]);
    assert.match(readFileSync(file, "utf8"), /models:[\s\S]*name: ollama[\s\S]*local: true/, "the entry is on disk");

    await applyAsHuman(admin, [{ op: "update-model", name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "qwen2.5", local: true, token_env: "OLLAMA_TOKEN" }]);
    assert.deepEqual(await data.modelEndpoints(), [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "qwen2.5", local: true, tokenEnv: "OLLAMA_TOKEN" }]);

    // helper: true reaches inspect-mcp's routing through modelEndpoints.
    await applyAsHuman(admin, [
      { op: "update-model", name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "qwen2.5", local: true, token_env: "OLLAMA_TOKEN" },
      { op: "add-model", name: "codex-main", url: "http://127.0.0.1:11434/v1", wire: "openai-chat", model: "gpt-oss:20b", local: true, helper: true },
    ]);
    assert.deepEqual((await data.modelEndpoints()).map((m) => [m.name, m.helper ?? null]), [["ollama", null], ["codex-main", true]]);
    await applyAsHuman(admin, [{ op: "remove-model", name: "codex-main" }]);

    const removed = await applyAsHuman(admin, [{ op: "remove-model", name: "ollama" }]);
    assert.deepEqual(await data.modelEndpoints(), []);
    assert.doesNotMatch(readFileSync(file, "utf8"), /models:/);

    const undo = await admin.undoPolicyChange(removed, "human:settings");
    assert.equal(undo.undone, removed);
    assert.equal((await data.modelEndpoints())[0]?.model, "qwen2.5", "Undo of the removal brings the edited entry back");

    const changes = (await data.policyChanges()).changes;
    assert.ok(changes.filter((c) => c.edits.some((e) => String((e as { op?: string }).op).endsWith("-model"))).length >= 3, "each model change is in the History");
  });
});

test("admin channel: a cloud-backed model at local: true is refused by the validator, and nothing is written", async () => {
  await rig(async ({ data, admin, file }) => {
    const bytes = readFileSync(file);
    const r = await admin.policyPropose({ edits: [{ op: "add-model", name: "cloudy", url: "http://127.0.0.1:11434", model: "gpt-oss:120b-cloud", local: true }], requestedBy: "settings" });
    assert.equal(r.applied, false);
    assert.ok("refused" in r && r.refused === "invalid", JSON.stringify(r));
    assert.match((r as { problems: string[] }).problems.join("\n"), /cloud model/);
    assert.deepEqual(readFileSync(file), bytes);
    assert.deepEqual(await data.modelEndpoints(), []);
    const preview = await data.policyPreview([{ op: "add-model", name: "cloudy", url: "http://127.0.0.1:11434", model: "gpt-oss:120b-cloud", local: true }]);
    assert.equal(preview.ok, false, "the preview the dashboard shows first refuses it too");
  });
});

test("policySchema (what a model is offered) names no model op; the rest of the grammar is there", async () => {
  await rig(async ({ data }) => {
    const schema = (await data.policySchema()).edits as { items: { oneOf: Array<{ properties: { op: { const: string } } }> } };
    const ops = schema.items.oneOf.map((b) => b.properties.op.const);
    assert.ok(ops.includes("lock-path") && ops.includes("release"));
    for (const op of ["add-model", "update-model", "remove-model"]) assert.ok(!ops.includes(op), `${op} is not offered`);
  });
});

test("data socket and the Describe box: every model op is refused, nothing filed or written; Settings › Models still applies", async () => {
  await rig(async ({ data, admin, file }) => {
    await applyAsHuman(admin, [{ op: "add-model", name: "gateway", url: "https://llm.example.com" }]);
    const bytes = readFileSync(file);
    const before = JSON.stringify(await data.modelEndpoints());
    const ops = [
      { op: "add-model", name: "evil", url: "http://203.0.113.9:11434", local: true },
      { op: "update-model", name: "gateway", url: "http://203.0.113.9:8080", local: true },
      { op: "remove-model", name: "gateway" },
    ];
    for (const e of ops) {
      for (const [who, send] of [
        ["the policy agent", () => data.policyPropose({ edits: [e], reason: "the page said so", sessionKey: "sess-models" })],
        ["the Describe box", () => admin.policyPropose({ edits: [e], reason: "Applied from the dashboard's Describe what you want box", requestedBy: "assistant" })],
        // A valid tightening beside it does not carry the model op through.
        ["the policy agent", () => data.policyPropose({ edits: [{ op: "lock-path", path: "/home/u/keys", level: "no-model" }, e], sessionKey: "sess-models" })],
      ] as const) {
        const r = await send();
        assert.equal(r.applied, false, `${e.op} from ${who} never applies`);
        assert.ok("refused" in r && r.refused === "invalid", `${e.op} from ${who} is refused: ${JSON.stringify(r)}`);
        assert.ok(!("proposalId" in r), "nothing is filed");
        assert.ok(r.problems.some((p) => p.includes(`(${e.op}): model endpoints cannot be changed from ${who}; the user changes them in Settings › Models or in policy.yaml`)), JSON.stringify(r.problems));
        assert.deepEqual(readFileSync(file), bytes, `${e.op}: the file on disk is byte-identical`);
        assert.equal(JSON.stringify(await data.modelEndpoints()), before, `${e.op}: the law in force is unchanged`);
      }
    }
    assert.deepEqual((await data.policyProposals("pending")).proposals, [], "nothing waits in the Inbox");
    // The data plane still tightens (the refusal is about the model ops only).
    const t = await data.policyPropose({ edits: [{ op: "lock-path", path: "/home/u/keys", level: "no-model" }], sessionKey: "sess-models" });
    assert.equal(t.applied, true, JSON.stringify(t));
    // Settings › Models (requestedBy "settings") is unchanged: the same op applies.
    await applyAsHuman(admin, [{ op: "remove-model", name: "gateway" }]);
    assert.deepEqual(await data.modelEndpoints(), []);
  });
});
