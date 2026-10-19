/**
 * dashboard-models-settings e2e — Settings › Models (dashboard.md §4.25l;
 * confidentiality-plan-11 §7.3) through the PRODUCTION wiring:
 * `makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }))` over a
 * REAL ArbiterServer with a file-backed law, the real ArbiterEventSource, a
 * real DashboardServer with its real probe, and HTTP with the admin session.
 *
 *   1. Add: the first POST changes nothing and asks; the second, with what
 *      was shown, writes policy.yaml, and the arbiter's `modelEndpoints`
 *      (inspect-mcp's routing, the launcher's confine ports) answers the
 *      entry; the answer says a running agent needs a restart.
 *   2. Test connection: the real TCP connect and the real GET /v1/models
 *      against a loopback model server, with the token named by token_env
 *      in the request and nowhere in the answer.
 *   3. Edit and remove go the same way; Undo from History puts the entry
 *      back; a cloud-backed model at "my own model" is refused by the
 *      arbiter's validator and nothing is written.
 *   3b. The helper's model: a second local entry at the same server's `/v1`
 *      base (the Codex spelling) chosen as the helper; Test connection reads
 *      `/v1/models` once, not `/v1/v1/models`; choosing the other entry MOVES
 *      the mark in one approved change, so policy.yaml never holds two.
 *   4. The agent page names the main model of a session the launcher bound
 *      to a declared entry (the source's `sessionUpstream`, production
 *      wiring: the parity leg for that op).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // local-model is a confidentiality level (the default mode's axis)

const dirs: string[] = [];
const TOKEN_VAR = "MANDU_E2E_SETTINGS_MODEL_TOKEN";
after(() => {
  delete process.env[TOKEN_VAR];
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const LAW = `version: 1
paths:
  - { path: "~/mandu-models-e2e/contract.md", level: local-model }
`;

test("Settings › Models over the real arbiter: add asks then applies, test connects, edit, remove, undo, a cloud model refused, the main model named", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-models-settings-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, LAW);
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSockIn(dir), dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();

  // A loopback "model server": /v1/models lists llama3.2, and records the
  // Authorization header it was sent.
  const auth: Array<string | undefined> = [];
  const modelServer = createServer((req: IncomingMessage, res) => {
    auth.push(req.headers.authorization);
    res.writeHead(req.url === "/v1/models" ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [{ id: "llama3.2:latest" }, { id: "gpt-oss:120b-cloud" }] }));
  });
  await new Promise<void>((r) => modelServer.listen(0, "127.0.0.1", () => r()));
  const modelUrl = `http://127.0.0.1:${(modelServer.address() as { port: number }).port}`;
  process.env[TOKEN_VAR] = "sk-e2e-model-TOKEN-value";

  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const source = new ArbiterEventSource({ socketPath: dataSock });
  const server = new DashboardServer({ source, approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const post = async (path: string, body?: unknown) => {
    const r = await fetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  const change = async (body: Record<string, unknown>) => {
    const ask = await post("/api/policy/models/change", body);
    assert.equal(ask.status, 200, JSON.stringify(ask.body));
    assert.equal(ask.body.confirm, true, "every models change asks first");
    const done = await post("/api/policy/models/change", { ...body, expected: ask.body.expected });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.equal(done.body.applied, true);
    assert.equal(done.body.note, "New sessions use this. Restart a running agent to use it there.");
    return { ask, changeId: done.body.changeId as string };
  };

  try {
    // 0. No model of your own yet: the your-own-model rule says no model reads it.
    const panelNow = async () => (await (await fetch(`${base}/api/policy/panel`)).json()) as { panel: { models: Array<{ name: string; local: boolean }>; yourRules: Array<{ id: string; warning?: string }> } };
    const lockRow = (p: Awaited<ReturnType<typeof panelNow>>) => p.panel.yourRules.find((r) => r.id.includes("contract.md"));
    assert.match(lockRow(await panelNow())?.warning ?? "", /^No AI of your own is listed, so no AI reads this file/);

    // 1. Add.
    const bytes = readFileSync(policyPath);
    const form = { name: "ollama", url: modelUrl, wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: TOKEN_VAR };
    const first = await post("/api/policy/models/change", { action: "add", model: form });
    assert.equal(first.body.applied, false);
    assert.deepEqual(first.body.expected, ["models\u0000ollama"]);
    assert.deepEqual(readFileSync(policyPath), bytes, "asking wrote nothing");
    assert.deepEqual(await gate.modelEndpoints(), []);
    const added = await change({ action: "add", model: form });
    assert.match(JSON.stringify(added.ask.body.rows), new RegExp(modelUrl.replace(/[.:/]/g, "\\$&")), "the address is shown in full");
    assert.deepEqual(await gate.modelEndpoints(), [{ name: "ollama", url: modelUrl, wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: TOKEN_VAR }]);
    assert.match(readFileSync(policyPath, "utf8"), new RegExp(`token_env: ${TOKEN_VAR}`));
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /sk-e2e-model-TOKEN-value/, "the token never goes in policy.yaml");
    const panel = await panelNow();
    assert.deepEqual(panel.panel.models.map((m) => [m.name, m.local]), [["ollama", true]], "Settings lists it at once");
    assert.ok(lockRow(panel), "the lock row is served");
    assert.equal(lockRow(panel)!.warning, undefined, "with a model of your own, the Rules row no longer warns");

    // 2. Test connection.
    const probe = await post("/api/policy/models/test", { name: "ollama" });
    assert.equal(probe.status, 200, JSON.stringify(probe.body));
    const result = probe.body.result as { ok: boolean; reachable: boolean; modelListed: boolean; cloudListed: string[] };
    assert.equal(result.reachable, true);
    assert.equal(result.modelListed, true);
    assert.deepEqual(result.cloudListed, ["gpt-oss:120b-cloud"]);
    assert.ok(auth.includes("Bearer sk-e2e-model-TOKEN-value"), "the token named by token_env rode to the listing");
    assert.doesNotMatch(JSON.stringify(probe.body), /sk-e2e-model-TOKEN-value/, "and never back to the browser");

    // 3. Edit, remove, undo, a cloud model refused.
    // An update names the entry as the page read it (policy-surface.md §8.4.6).
    const versionOf = async (name: string) => ((await panelNow()).panel.models as unknown as Array<{ name: string; version: string | null }>).find((m) => m.name === name)?.version;
    await change({ action: "update", name: "ollama", model: { ...form, model: "qwen2.5" }, version: await versionOf("ollama") });
    assert.equal((await gate.modelEndpoints())[0]?.model, "qwen2.5");
    const removed = await change({ action: "remove", name: "ollama" });
    assert.deepEqual(await gate.modelEndpoints(), []);
    const undo = await post(`/api/policy/changes/${encodeURIComponent(removed.changeId)}/undo`);
    assert.equal(undo.status, 200, JSON.stringify(undo.body));
    assert.equal((await gate.modelEndpoints())[0]?.model, "qwen2.5", "Undo brings the entry back as it was");
    const history = (await (await fetch(`${base}/api/policy/changes?limit=10`)).json()) as { changes: Array<{ sentence: string }> };
    assert.ok(history.changes.some((c) => c.sentence === "You changed your models in Settings"));

    // 3b. The helper's model, and one server at its /v1 base.
    const codex = { name: "codex-main", url: `${modelUrl}/v1`, wire: "openai-chat", model: "llama3.2", local: true, helper: true };
    await change({ action: "add", model: codex });
    assert.deepEqual((await gate.modelEndpoints()).map((m) => [m.name, m.helper ?? false]), [["ollama", false], ["codex-main", true]]);
    const helperRows = async () => ((await panelNow()).panel.models as unknown as Array<{ name: string; helper: boolean; helperMarked: boolean }>).map((m) => [m.name, m.helperMarked, m.helper]);
    assert.deepEqual(await helperRows(), [["ollama", false, false], ["codex-main", true, true]]);
    const seenBefore = auth.length;
    const v1probe = await post("/api/policy/models/test", { name: "codex-main" });
    assert.equal((v1probe.body.result as { modelListed: boolean }).modelListed, true, "the listing was read at …/v1/models, not …/v1/v1/models");
    assert.ok(auth.length > seenBefore);
    await change({ action: "update", name: "ollama", model: { ...form, model: "qwen2.5", helper: true }, version: await versionOf("ollama") });
    assert.deepEqual((await gate.modelEndpoints()).map((m) => [m.name, m.helper ?? false]), [["ollama", true], ["codex-main", false]], "the mark moved in one change");
    assert.equal(readFileSync(policyPath, "utf8").match(/helper: true/g)?.length, 1, "policy.yaml never holds two");
    await change({ action: "remove", name: "codex-main" });

    const before = readFileSync(policyPath);
    const cloud = await post("/api/policy/models/change", { action: "add", model: { name: "cloudy", url: modelUrl, model: "gpt-oss:120b-cloud", local: true } });
    assert.equal(cloud.status, 422, JSON.stringify(cloud.body));
    assert.match(JSON.stringify(cloud.body.problems), /cloud model/);
    assert.deepEqual(readFileSync(policyPath), before, "nothing was written");

    // 4. The main model on the agent page.
    const bound = await gate.setSessionUpstream({ sessionKey: "sess-models-e2e", endpoint: "ollama", requestedBy: "launcher" });
    assert.equal(bound.location, "local");
    await gate.emit({
      id: "ev-1", seq: 0, sessionId: "sess-models-e2e", turn: 1, ts: new Date().toISOString(), parentId: null, callId: null,
      kind: "tllm_call", view: "AgentView", emitter: "anthropic-proxy", boundary: "model_context",
      input: { symbolized: "hello", original: null, differs: false, symbols: [] }, output: null, invariant: { violatedInvariant: false },
    } as never);
    const agent = (await (await fetch(`${base}/api/home/agent?session=sess-models-e2e`)).json()) as { found: boolean; mainModel: { words: string; local: boolean } | null };
    assert.equal(agent.found, true);
    assert.deepEqual(agent.mainModel, { words: "Main model: your own model (ollama)", local: true });
  } finally {
    await server.close();
    wired.close();
    gate.close();
    source.close();
    await new Promise<void>((r) => modelServer.close(() => r()));
    await arbiter.close();
  }
});
