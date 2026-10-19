/**
 * admin-model-layer e2e — the administrator's `models:` layer (confidentiality
 * plan 12 D5) through the PRODUCTION wiring: a real ArbiterServer whose
 * administrator's directory is a fixture policy.d (the constructor option
 * `adminPolicyDir`, the test build's override of /etc/mandu/policy.d; no
 * environment variable can set it), a file-backed user policy.yaml, the
 * dashboard's `makeApprovalsArbiter` over both sockets, a real
 * DashboardServer, the launcher's `readModelEndpoints`, and inspect-mcp's
 * production adapter and endpoint factory.
 *
 * The layer declares `corp` (a local model the helper uses) and
 * `models_locked: true`. Then:
 *   1. every reader sees it: `modelEndpoints` marks it (file, lock), the
 *      launcher's read carries the layer, Settings shows it set by the
 *      administrator, and the helper sends a local-model document to it;
 *   2. every writer meets the lock: Settings › Models adding a model of your
 *      own, or changing corp's address, is refused with "set by your
 *      administrator (<file>)" and nothing is written; a proposal over the
 *      admin channel is refused (not queued) with the same reason; the policy
 *      agent (data channel) cannot propose a model edit at all;
 *   3. what the lock allows goes through: an outside model is added, and
 *      corp is removed (policy.yaml gains `{ name: corp, disabled: true }`,
 *      the administrator's file is untouched), after which the helper has no
 *      model of your own and refuses;
 *   4. Settings brings corp back (the marker is dropped) and the helper uses
 *      it again.
 *
 * The second test changes the administrator's file under a running arbiter:
 * a lock that arrives wins over the user's own model (the helper moves to
 * the administrator's, the user's is named as not in use by the launcher's
 * read and by Settings), and a fresh start over the same files is not
 * refused.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../arbiter/policy/admin-layer.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { readModelEndpoints } from "../../launcher/src/model-endpoints.js";
import { inspectSymbol } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { createEndpointUllmFactory } from "../../interceptors/inspect-mcp/src/ullm-config.js";
import { MockUllm } from "../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // local-model is a confidentiality level (the default mode's axis)

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const CANARY = "ADMIN_LAYER_CANARY: the merger closes on Friday.";

async function openaiModel(): Promise<{ url: string; bodies: string[]; close: () => Promise<void> }> {
  const bodies: string[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(body);
      const text = body.includes("quarantined content classifier") ? "substantive" : "A summary.";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "qwen", choices: [{ message: { role: "assistant", content: text } }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, bodies, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test("the administrator's locked models: every reader sees them, every writer meets the lock, removal and outside models pass", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-admin-layer-"));
  dirs.push(dir);
  const model = await openaiModel();
  const policyD = join(dir, "policy.d");
  mkdirSync(policyD);
  const adminFile = join(policyD, "10-corp.yaml");
  const adminText = `models:\n  - name: corp\n    url: ${model.url}\n    wire: openai-chat\n    model: qwen\n    local: true\n    helper: true\nmodels_locked: true\n`;
  writeFileSync(adminFile, adminText);
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "/h/notes/minutes.md", level: local-model }\n`);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {}, adminPolicyDir: policyD,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const client = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const gate = await client(dataSock);
  const adminClient = await client(adminSock);

  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const source = new ArbiterEventSource({ socketPath: dataSock });
  const server = new DashboardServer({ source, approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const post = async (path: string, body: unknown) => {
    const r = await fetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  const helper = async (): Promise<Awaited<ReturnType<typeof inspectSymbol>>> => {
    const doc = await gate.symbolizeFull({ tool: "Read", value: CANARY, field: "content", origin: "/h/notes/minutes.md" });
    return inspectSymbol(
      { arbiter: new ArbiterClientAdapter(await client(dataSock)), ullm: new MockUllm({ reply: "the default helper must not run" }), sessionId: "admin-layer", endpointUllm: createEndpointUllmFactory({}) },
      { symbol: doc.symbol, instruction: "Summarize." },
    );
  };

  try {
    // 1. Every reader sees the layer.
    assert.deepEqual((await gate.modelEndpoints()).map((e) => [e.name, e.adminFile, e.locked]), [["corp", adminFile, true]]);
    const read = await readModelEndpoints(dataSock);
    assert.deepEqual(read.admin, { files: [adminFile], locked: true, conflicts: [], refused: [] });
    const panel = (await (await fetch(`${base}/api/policy/panel`)).json()) as { panel: { models: Array<{ name: string; admin: boolean; locked: boolean }>; modelsAdmin: { locked: boolean } | null } };
    assert.deepEqual(panel.panel.models.map((m) => [m.name, m.admin, m.locked]), [["corp", true, true]]);
    assert.equal(panel.panel.modelsAdmin?.locked, true);
    const served = await helper();
    assert.equal(served.ok, true, (served as { error?: string }).error);
    assert.ok(model.bodies.some((b) => b.includes("ADMIN_LAYER_CANARY")), "the helper used the administrator's model");

    // 2. Every writer meets the lock; nothing is written.
    const bytes = readFileSync(policyPath, "utf8");
    const setBy = new RegExp(`set by your administrator \\(${adminFile.replace(/[.\\/]/g, "\\$&")}\\)`);
    const own = await post("/api/policy/models/change", { action: "add", model: { name: "mine", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true } });
    assert.equal(own.status, 422, JSON.stringify(own.body));
    assert.match(JSON.stringify(own.body.problems), /you can add outside models only \(local: true is refused\)/);
    assert.match(JSON.stringify(own.body.problems), setBy);
    const corpVersion = panel.panel.models.find((m) => m.name === "corp") as { version?: string } | undefined;
    const move = await post("/api/policy/models/change", { action: "update", name: "corp", model: { name: "corp", url: "https://evil.example/v1", wire: "openai-chat", model: "qwen", local: true, helper: true }, version: corpVersion?.version });
    assert.equal(move.status, 422, JSON.stringify(move.body));
    assert.match(JSON.stringify(move.body.problems), /'corp' is set by your administrator .*its url cannot be changed here/);
    const proposal = await adminClient.policyPropose({ edits: [{ op: "add-model", name: "mine", url: "http://127.0.0.1:11434", local: true }], requestedBy: "human" });
    assert.equal(proposal.applied, false);
    assert.equal((proposal as { refused?: string }).refused, "invalid", "refused with the reason, not queued");
    assert.match(((proposal as { problems?: string[] }).problems ?? []).join("\n"), /local: true is refused/);
    const agent = await gate.policyPropose({ edits: [{ op: "add-model", name: "mine", url: "http://127.0.0.1:11434", local: true }], sessionKey: "s-agent" });
    assert.equal(agent.applied, false);
    assert.match(((agent as { problems?: string[] }).problems ?? []).join("\n"), /model endpoints cannot be changed from the policy agent/);
    assert.equal(readFileSync(policyPath, "utf8"), bytes, "nothing was written");

    // 3. What the lock allows: an outside model, and removing corp.
    const change = async (body: Record<string, unknown>): Promise<void> => {
      const ask = await post("/api/policy/models/change", body);
      assert.equal(ask.status, 200, JSON.stringify(ask.body));
      const done = await post("/api/policy/models/change", { ...body, expected: ask.body.expected });
      assert.equal(done.status, 200, JSON.stringify(done.body));
      assert.equal(done.body.applied, true);
    };
    await change({ action: "add", model: { name: "gw", url: "https://api.example.com", wire: "anthropic", local: false } });
    await change({ action: "remove", name: "corp" });
    const written = readFileSync(policyPath, "utf8");
    assert.match(written, /- name: gw\n\s+url: https:\/\/api\.example\.com/);
    assert.match(written, /- name: corp\n\s+disabled: true\n/, "the removal is a marker in the user's file");
    assert.equal(readFileSync(adminFile, "utf8"), adminText, "the administrator's file is never written");
    assert.deepEqual((await gate.modelEndpoints()).map((e) => e.name), ["gw"]);
    const before = model.bodies.length;
    const refused = await helper();
    assert.equal(refused.ok, false, "no model of your own is left: the helper refuses a local-model document");
    assert.equal(model.bodies.length, before, "and sends nothing to the removed model");

    // 4. Settings brings corp back (the marker goes; plan 12 D5 follow-up).
    const panel2 = (await (await fetch(`${base}/api/policy/panel`)).json()) as { panel: { modelsAdmin: { removed: Array<{ name: string }> } | null } };
    assert.deepEqual(panel2.panel.modelsAdmin?.removed.map((r) => r.name), ["corp"]);
    await change({ action: "restore", name: "corp" });
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /disabled: true/);
    assert.deepEqual((await gate.modelEndpoints()).map((e) => e.name), ["corp", "gw"]);
    const back = await helper();
    assert.equal(back.ok, true, (back as { error?: string }).error);
  } finally {
    for (const c of clients) c.close();
    source.close?.();
    await server.close();
    await arbiter.close();
    await model.close();
  }
});

test("a lock that arrives under a running arbiter: the administrator wins, the user's model is named as not in use, the helper moves, and a start over the same files is not refused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-admin-reload-"));
  dirs.push(dir);
  const corpModel = await openaiModel();
  const mineModel = await openaiModel();
  const policyD = join(dir, "policy.d");
  mkdirSync(policyD);
  const adminFile = join(policyD, "10-corp.yaml");
  writeFileSync(adminFile, `models:\n  - name: corp\n    url: ${corpModel.url}\n    wire: openai-chat\n    model: qwen\n    local: true\n`);
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "/h/notes/minutes.md", level: local-model }\nmodels:\n  - name: mine\n    url: ${mineModel.url}\n    wire: openai-chat\n    model: llama3.2\n    local: true\n    helper: true\n`);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const opts = { adminSocketPath: adminSock, eventDir: join(dir, "events"), policyPath, policyPollMs: 50, integrity: false, confidentiality: true, log: () => {}, adminPolicyDir: policyD };
  const arbiter = new ArbiterServer({ ...opts, socketPath: dataSock, dbPath: join(dir, "mandu.db") });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const client = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const gate = await client(dataSock);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const source = new ArbiterEventSource({ socketPath: dataSock });
  const server = new DashboardServer({ source, approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const helper = async (): Promise<Awaited<ReturnType<typeof inspectSymbol>>> => {
    const doc = await gate.symbolizeFull({ tool: "Read", value: CANARY, field: "content", origin: "/h/notes/minutes.md" });
    return inspectSymbol(
      { arbiter: new ArbiterClientAdapter(await client(dataSock)), ullm: new MockUllm({ reply: "the default helper must not run" }), sessionId: "admin-reload", endpointUllm: createEndpointUllmFactory({}) },
      { symbol: doc.symbol, instruction: "Summarize." },
    );
  };
  let second: ArbiterServer | null = null;
  try {
    // Unlocked: the user's own helper is used.
    assert.deepEqual((await gate.modelEndpoints()).map((e) => e.name), ["corp", "mine"]);
    assert.equal((await helper()).ok, true);
    assert.ok(mineModel.bodies.some((b) => b.includes("ADMIN_LAYER_CANARY")));
    assert.ok(!corpModel.bodies.some((b) => b.includes("ADMIN_LAYER_CANARY")));

    // The administrator locks the list and names corp the helper. No restart.
    writeFileSync(adminFile, `models:\n  - name: corp\n    url: ${corpModel.url}\n    wire: openai-chat\n    model: qwen\n    local: true\n    helper: true\nmodels_locked: true\n`);
    for (let i = 0; i < 100 && (await gate.modelEndpoints()).length !== 1; i++) await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual((await gate.modelEndpoints()).map((e) => [e.name, e.locked]), [["corp", true]]);
    const read = await readModelEndpoints(dataSock);
    assert.equal(read.admin?.locked, true);
    assert.equal(read.admin?.conflicts.length, 1);
    assert.match(read.admin!.conflicts[0]!, /'mine' is local: true, and your own models are set by your administrator/);
    const panel = (await (await fetch(`http://127.0.0.1:${port}/api/policy/panel`)).json()) as { panel: { modelsAdmin: { conflicts: string[] } | null } };
    assert.match(panel.panel.modelsAdmin?.conflicts.join("\n") ?? "", /'mine' is local: true/);
    const mineBefore = mineModel.bodies.length;
    assert.equal((await helper()).ok, true);
    assert.equal(mineModel.bodies.length, mineBefore, "the user's model gets nothing once the lock is in force");
    assert.ok(corpModel.bodies.some((b) => b.includes("ADMIN_LAYER_CANARY")), "the administrator's helper reads it");

    // A start over the same files: not refused, the conflict still named.
    const logs: string[] = [];
    second = new ArbiterServer({ ...opts, adminSocketPath: join(dir, "admin2.sock"), socketPath: join(dir, "arbiter2.sock"), dbPath: join(dir, "mandu2.db"), log: (m) => logs.push(m) });
    await second.listen();
    const c2 = await client(join(dir, "arbiter2.sock"));
    assert.deepEqual((await c2.modelEndpoints()).map((e) => e.name), ["corp"]);
    assert.ok(logs.some((l) => /not in force, your administrator's policy wins: .*'mine'/.test(l)));
  } finally {
    for (const c of clients) c.close();
    source.close?.();
    await server.close();
    await second?.close();
    await arbiter.close();
    await corpModel.close();
    await mineModel.close();
  }
});
