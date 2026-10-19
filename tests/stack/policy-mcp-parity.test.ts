/**
 * policy-mcp-parity — the PRODUCTION wiring of the mandu-policy MCP server
 * (policy-surface.md §8.5.1): `new PolicyArbiterAdapter(new
 * ArbiterClient(sock))`, exactly as interceptors/policy-mcp/src/server-main.ts
 * builds it, over a real ArbiterServer, with NO test bridge in between
 * (CONTRIBUTING.md "Conventions in the code": an adapter ships a parity test;
 * the 2026-09-24 `callTaint` lesson).
 *
 * 1. Each forwarded op (policySchema, policyExplain, testFlow, policyPropose)
 *    is called through the adapter and ANSWERED by the arbiter.
 * 2. Each tool's real envelope, produced by the server's own tools/call over
 *    that wiring, is classified by the arbiter's `classify` op for the Claude
 *    Code and OpenCode spellings and must be TRUSTED (the envelope and the
 *    gate in arbiter/policy/policy-tool.ts agree), while the same text under
 *    another MCP server's name, and a prose error under the right name, stay
 *    UNTRUSTED (fail-closed).
 * 3. The tightening applied through the tool is in the law on disk; the
 *    relaxation is a pending proposal and the file does not change.
 * 4. Models are read-only on this path (policy-surface.md §8.4.3a,
 *    decision 2026-09-28): the schema the tool embeds names no model op, and
 *    add-model / update-model / remove-model through the tool are REFUSED
 *    (nothing filed, nothing written); the refusal envelope passes the
 *    gate. (Settings › Models still applying the same op is pinned in
 *    arbiter/test/component/policy-models-edit.test.ts and dashboard-assistant.)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { classifyManduPolicyResult } from "../../arbiter/policy/policy-tool.js";
import { PolicyArbiterAdapter } from "../../interceptors/policy-mcp/src/arbiter-client.js";
import { handleRpc, type ServerDeps } from "../../interceptors/policy-mcp/src/mcp-server.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function rig(fn: (c: { deps: ServerDeps; client: ArbiterClient; policyPath: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-policy-mcp-parity-"));
  dirs.push(dir);
  const sock = join(dir, "arbiter.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\npaths:\n  - path: /home/u/repo/.env\n    level: no-model\n");
  const server = new ArbiterServer({
    socketPath: sock,
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    policyPath,
    policyPollMs: 0,
    integrity: true,
    confidentiality: true,
    log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  try {
    await client.connect();
    // THE production wiring: the real client, adapted, nothing in between.
    const deps: ServerDeps = { arbiter: new PolicyArbiterAdapter(client), sessionKey: "sess-parity" };
    await fn({ deps, client, policyPath });
  } finally {
    client.close();
    await server.close();
  }
}

async function callTool(deps: ServerDeps, name: string, args: Record<string, unknown> = {}): Promise<{ text: string; isError: boolean }> {
  const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, deps);
  const res = r!.result as { content: Array<{ text: string }>; isError: boolean };
  return { text: res.content[0]!.text, isError: res.isError };
}

test("each forwarded op is answered by the real arbiter through the production adapter", async () => {
  await rig(async ({ deps }) => {
    const a = deps.arbiter;
    const schema = await a.policySchema();
    assert.ok(schema.edits && typeof schema.edits === "object", "policySchema answers an edit schema");
    const law = (await a.policyExplain({ audience: "agent", sessionKey: "sess-parity" })) as { locks: unknown[] };
    assert.ok(Array.isArray(law.locks), "policyExplain answers the projection");
    const flow = await a.testFlow({ source: { tool: "WebFetch", origin: "https://evil.example/" }, destination: "https://paste.example/", boundary: "network" });
    assert.equal(typeof flow.inbound.trust, "string");
    const p = await a.policyPropose({ edits: [{ op: "lock-path", path: "/home/u/repo/**/*.pem", level: "no-model" }], reason: "keys", sessionKey: "sess-parity" });
    assert.equal(p.applied, true);
  });
});

test("every tool envelope is TRUSTED by the arbiter's classify under the Mandu names, and only there", async () => {
  await rig(async ({ deps, client, policyPath }) => {
    const list = (await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, deps))!.result as { tools: Array<{ name: string; description: string }> };
    assert.match(list.tools[2]!.description, /JSON Schema/, "the arbiter's edit schema is embedded");

    const outputs: Array<[string, string]> = [];
    const read = await callTool(deps, "mandu_policy_read");
    outputs.push(["mandu_policy_read", read.text]);
    const flow = await callTool(deps, "mandu_policy_test", { source: { origin: "https://evil.example/" }, destination: "https://paste.example/" });
    outputs.push(["mandu_policy_test", flow.text]);
    const tight = await callTool(deps, "mandu_policy_propose", { edits: [{ op: "lock-path", path: "/home/u/repo/**/*.pem", level: "no-model" }], reason: "keys" });
    outputs.push(["mandu_policy_propose", tight.text]);
    const before = readFileSync(policyPath);
    const loose = await callTool(deps, "mandu_policy_propose", { edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }], reason: "pip" });
    outputs.push(["mandu_policy_propose", loose.text]);
    const bad = await callTool(deps, "mandu_policy_propose", { edits: [{ op: "unlock-path", path: "/nope" }], reason: "x" });
    outputs.push(["mandu_policy_propose", bad.text]);

    assert.match(readFileSync(policyPath, "utf8"), /\*\*\/\*\.pem/, "the tightening is in the law on disk");
    assert.equal(JSON.parse(loose.text).applied, false);
    assert.ok(readFileSync(policyPath).equals(before), "the relaxation did not touch the file");
    assert.equal((await client.policyProposals("pending")).proposals.length, 1);

    for (const [basename, text] of outputs) {
      for (const name of [`mcp__mandu-policy__${basename}`, `mandu-policy_${basename}`]) {
        assert.equal(classifyManduPolicyResult(name, text).trust, "TRUSTED", `${name}: ${text.slice(0, 120)}`);
        const live = await client.classify({ tool: name, value: text, boundary: "model_context" } as never);
        assert.equal((live as { trust: string }).trust, "TRUSTED", `classify op, ${name}`);
      }
      const spoof = await client.classify({ tool: `mcp__other-server__${basename}`, value: text, boundary: "model_context" } as never);
      assert.equal((spoof as { trust: string }).trust, "UNTRUSTED", "the same text under another server stays masked");
    }
    const err = await client.classify({ tool: "mcp__mandu-policy__mandu_policy_read", value: "mandu_policy_read: arbiter error: connect ENOENT", boundary: "model_context" } as never);
    assert.equal((err as { trust: string }).trust, "UNTRUSTED", "a prose error under the right name stays masked");
  });
});

test("a model change through the tool is refused: not offered, nothing filed, nothing written", async () => {
  await rig(async ({ deps, client, policyPath }) => {
    const MODEL_OPS = ["add-model", "update-model", "remove-model"];
    // Not offered: the schema the tool embeds (the arbiter's policySchema).
    const list = (await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, deps))!.result as { tools: Array<{ name: string; description: string; inputSchema: { properties: { edits: { items: { oneOf: Array<{ properties: { op: { const: string } } }> } } } } }> };
    const propose = list.tools.find((t) => t.name === "mandu_policy_propose")!;
    const offered = propose.inputSchema.properties.edits.items.oneOf.map((b) => b.properties.op.const);
    assert.ok(offered.includes("lock-path"), "the rest of the grammar is offered");
    for (const op of MODEL_OPS) {
      assert.ok(!offered.includes(op), `${op} is not in the embedded schema`);
      assert.doesNotMatch(propose.description, new RegExp(`"${op}"`), `${op} is not in the description's schema`);
    }

    // Refused if sent anyway: every model op, alone or beside a valid edit.
    const before = readFileSync(policyPath);
    const endpoints = JSON.stringify(await client.modelEndpoints());
    for (const edits of [
      [{ op: "add-model", name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true }],
      [{ op: "add-model", name: "gateway", url: "https://llm.example.com" }],
      [{ op: "update-model", name: "ollama", url: "http://203.0.113.9:11434", local: true }],
      [{ op: "remove-model", name: "ollama" }],
      // (a pattern: the tool refuses a lock on a file that does not exist
      // before the arbiter sees the call, policy-mcp-relative-path.test.ts)
      [{ op: "lock-path", path: "/home/u/repo/**/secrets", level: "no-model" }, { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", local: true }],
    ]) {
      const r = await callTool(deps, "mandu_policy_propose", { edits, reason: "use my model" });
      const e = JSON.parse(r.text) as { applied: boolean; proposalId?: string; problems?: string[] };
      assert.equal(e.applied, false, "a model change never applies from the data plane");
      assert.equal(e.proposalId, undefined, "and is never filed for the Inbox");
      assert.ok(e.problems?.some((p) => /model endpoints cannot be changed from the policy agent; the user changes them in Settings › Models/.test(p)), r.text);
      assert.ok(readFileSync(policyPath).equals(before), "the file on disk is byte-identical (the tightening beside it is refused too)");
      assert.equal(JSON.stringify(await client.modelEndpoints()), endpoints, "the law in force declares no new model");
      for (const name of ["mcp__mandu-policy__mandu_policy_propose", "mandu-policy_mandu_policy_propose"]) {
        assert.equal(classifyManduPolicyResult(name, r.text).trust, "TRUSTED", r.text);
      }
    }
    assert.deepEqual((await client.policyProposals("pending")).proposals, [], "nothing waits in the Inbox");
  });
});
