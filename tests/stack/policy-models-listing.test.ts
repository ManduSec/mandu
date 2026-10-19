/**
 * policy-models-listing e2e — the declared models (policy.yaml `models:`,
 * confidentiality plan 11 D2) in the two views a configuring model reads
 * (policy-surface.md §8.4.4), over a REAL ArbiterServer that loads a real
 * policy file, through each consumer's PRODUCTION wiring:
 *
 *   1. the confined agent's `mandu_policy_read` (policy-mcp:
 *      `new PolicyArbiterAdapter(new ArbiterClient(sock))`, the tool's own
 *      tools/call) lists every model with name, url, wire, model, local and
 *      the token's variable NAME; the envelope is TRUSTED by the arbiter's
 *      classify under Mandu's names (the listing passes the §4.4 gate);
 *   2. the dashboard's "Describe what you want" (`makeApprovalsArbiter`, the
 *      assistant module's `suggestRules` with only the model faked) puts the
 *      same list in the current rules the quarantined model reads;
 *   3. neither carries the token's VALUE (a canary in the environment the
 *      arbiter runs in) nor a key hidden in the URL's query string;
 *   4. the listing is read-only: reading writes nothing to policy.yaml.
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
import { handleRpc } from "../../interceptors/policy-mcp/src/mcp-server.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { suggestRules, type AssistantModel } from "../../dashboard/src/policy-assistant.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4)

const TOKEN_VAR = "MANDU_E2E_GATEWAY_TOKEN";
const TOKEN_CANARY = "sk-canary-5d7c0e1f-never-listed";
const QUERY_CANARY = "QUERYKEY-3a9f";

const POLICY = [
  "version: 1",
  "paths:",
  "  - path: /home/u/repo/.env",
  "    level: no-model",
  "models:",
  "  - name: ollama",
  "    url: http://127.0.0.1:11434",
  "    wire: openai-chat",
  "    model: llama3.2",
  "    local: true",
  "  - name: gateway",
  `    url: https://llm.example.com/v1?key=${QUERY_CANARY}`,
  `    token_env: ${TOKEN_VAR}`,
  "",
].join("\n");

const EXPECTED = [
  { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
  { name: "gateway", url: "https://llm.example.com/v1", wire: "anthropic", local: false, tokenEnv: TOKEN_VAR },
];

const dirs: string[] = [];
const prevToken = process.env[TOKEN_VAR];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  if (prevToken === undefined) delete process.env[TOKEN_VAR];
  else process.env[TOKEN_VAR] = prevToken;
});

test("the policy agent's read view and the Describe box both list the declared models, read-only, with no key value", async () => {
  process.env[TOKEN_VAR] = TOKEN_CANARY; // the arbiter's own environment holds the real value
  const dir = mkdtempSync(join(tmpdir(), "mandu-policy-models-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, POLICY);
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: true, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const client = new ArbiterClient(dataSock);
  await client.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  try {
    const before = readFileSync(policyPath);
    assert.equal((await client.modelEndpoints()).length, 2, "the law in force declares both models");

    // 1. The confined agent's read tool, production wiring.
    const deps = { arbiter: new PolicyArbiterAdapter(client), sessionKey: "sess-models" };
    const rpc = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mandu_policy_read", arguments: {} } }, deps);
    const res = rpc!.result as { content: Array<{ text: string }>; isError: boolean };
    assert.equal(res.isError, false);
    const text = res.content[0]!.text;
    const law = (JSON.parse(text) as { law: { models: unknown } }).law;
    assert.deepEqual(law.models, EXPECTED, "every declared model, every field, the key's variable name only");
    assert.ok(!text.includes(TOKEN_CANARY), "the token's value never reaches the agent");
    assert.ok(!text.includes(QUERY_CANARY), "a key in the URL's query string never reaches the agent");
    for (const name of ["mcp__mandu-policy__mandu_policy_read", "mandu-policy_mandu_policy_read"]) {
      assert.equal(classifyManduPolicyResult(name, text).trust, "TRUSTED", "the listing passes the gate as a whole");
      const live = await client.classify({ tool: name, value: text, boundary: "model_context" } as never);
      assert.equal((live as { trust: string }).trust, "TRUSTED", `classify op, ${name}`);
    }

    // 2. The Describe box: the current rules the quarantined model reads.
    assert.ok(wired?.policyDoc?.policyExplain && wired.policyDoc.policySchema && wired.policyDoc.policyPreview);
    const doc = wired.policyDoc;
    const seen: Array<{ system: string; user: string }> = [];
    const model = async (): Promise<AssistantModel> => ({
      async complete(call) { seen.push(call); return { text: JSON.stringify({ edits: [], note: "" }), model: "fake" }; },
    });
    const arb = { policyExplain: doc.policyExplain!.bind(doc), policySchema: doc.policySchema!.bind(doc), policyPreview: doc.policyPreview!.bind(doc) };
    const s = await suggestRules({ arbiter: arb as never, model }, "which models do I have set up?");
    assert.deepEqual(s.edits, []);
    const current = JSON.parse(/Current rules \(JSON\):\n(.*)\n/.exec(seen[0]!.user)![1]!) as { models: unknown };
    assert.deepEqual(current.models, EXPECTED, "the Describe box's context lists the same models");
    const shown = seen[0]!.system + seen[0]!.user;
    assert.ok(!shown.includes(TOKEN_CANARY), "the token's value never reaches the quarantined model");
    assert.ok(!shown.includes(QUERY_CANARY));

    // 3. Reading is read-only.
    assert.ok(readFileSync(policyPath).equals(before), "the policy file is byte-identical");
    assert.equal((await client.policyProposals("pending")).proposals.length, 0, "nothing was proposed");
  } finally {
    wired?.close();
    client.close();
    await arbiter.close();
  }
});
