/**
 * policy-tool-words — the session page's words for the agent's calls to
 * Mandu's own rule tools (dashboard.md §4.25b, "Mandu's own tools"), from the
 * REAL tool results. The mandu-policy server's tools/call runs over the
 * production wiring (`new PolicyArbiterAdapter(new ArbiterClient(sock))`, as
 * interceptors/policy-mcp/src/server-main.ts builds it) and a real
 * ArbiterServer. Each call is recorded as the model proxy records one
 * (tool_use, then tool_result) and told by the dashboard's own view-model
 * pipeline (`toSessionViewModel`, `buildAgentPage`).
 *
 * 1. The dashboard's spellings are exactly those the arbiter's trust gate
 *    vouches for (`POLICY_TOOL_SPELLINGS`), so the page uses Mandu's words
 *    only for a name the gate knows as Mandu's own.
 * 2. Each real answer gives the words its outcome means: a lock applied at
 *    once, the same lock again (nothing changed), a loosening waiting for the
 *    person, an invalid edit, a test's allow / ask / block, a read. The lock
 *    is in the law on disk and the loosening is a pending proposal, so the
 *    words match what the arbiter did. The agent's reason never reaches the
 *    page, and no step changes the turn's counts.
 * 3. The same real answer under another server's name keeps "Used …" and
 *    claims nothing.
 *
 * Axes: secrets (the product default).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { POLICY_TOOL_SPELLINGS } from "../../arbiter/policy/policy-tool.js";
import { PolicyArbiterAdapter } from "../../interceptors/policy-mcp/src/arbiter-client.js";
import { handleRpc, type ServerDeps } from "../../interceptors/policy-mcp/src/mcp-server.js";
import type { ManduEvent } from "../../dashboard/src/event-model.js";
import { toSessionViewModel } from "../../dashboard/src/view-model.js";
import { buildAgentPage, type StoryStep } from "../../dashboard/src/view-model/agent-page.js";
import { MANDU_POLICY_TOOL_SPELLINGS } from "../../dashboard/src/view-model/mandu-tool-words.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function rig(fn: (c: { deps: ServerDeps; client: ArbiterClient; policyPath: string; envFile: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-policy-words-"));
  dirs.push(dir);
  const sock = join(dir, "arbiter.sock");
  const policyPath = join(dir, "policy.yaml");
  mkdirSync(join(dir, "proj"));
  const envFile = join(dir, "proj", "staging.conf");
  writeFileSync(envFile, "token = fake\n");
  writeFileSync(policyPath, "version: 1\n");
  const server = new ArbiterServer({
    socketPath: sock,
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    policyPath,
    policyPollMs: 0,
    integrity: false,
    confidentiality: true,
    log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  try {
    await client.connect();
    // THE production wiring: the real client, adapted, nothing in between.
    const deps: ServerDeps = { arbiter: new PolicyArbiterAdapter(client), sessionKey: "sess-words", projectDir: join(dir, "proj") };
    await fn({ deps, client, policyPath, envFile });
  } finally {
    client.close();
    await server.close();
  }
}

async function callTool(deps: ServerDeps, name: string, args: Record<string, unknown> = {}): Promise<string> {
  const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, deps);
  const res = r!.result as { content: Array<{ text: string }>; isError: boolean };
  assert.equal(res.isError, false, res.content[0]!.text);
  return res.content[0]!.text;
}

/** The calls as the model proxy records them (tool_use, then tool_result,
 *  in Secrets mode), told by the dashboard's real pipeline: the steps of the
 *  one turn, in order. */
function told(calls: Array<{ tool: string; args: Record<string, unknown>; result: string }>) {
  const S = "sess-words";
  const events: ManduEvent[] = [];
  let seq = 0;
  const t0 = Date.parse("2026-10-05T01:42:00.000Z");
  const dr = (symbolized: string) => ({ symbolized, original: null, differs: false, symbols: [] });
  const ev = (kind: string, f: Record<string, unknown> = {}): void => {
    events.push({
      id: `${S}-${String(seq).padStart(3, "0")}`, sessionId: S, turn: 0, ts: new Date(t0 + seq * 1000).toISOString(), seq,
      callId: null, parentId: null, kind, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: null, output: null, invariant: { violatedInvariant: false }, ...f,
    } as unknown as ManduEvent);
    seq++;
  };
  ev("launch_posture", { view: "HumanView", boundary: "shell", emitter: "launcher", protection: { mode: "secrets", integrity: false, reported: true } });
  const user = "▸ user\nUse Mandu's policy tools to mark staging.conf as a secret hidden from you.";
  calls.forEach((call, i) => {
    const use = `${call.tool}(${JSON.stringify(call.args)})`;
    ev("tllm_call", { turn: i, input: dr(user), output: dr(`→ ${use}`) });
    ev("tool_use", { turn: i, callId: `c${i}`, input: dr(use) });
    ev("tool_result", { turn: i, callId: `c${i}`, output: dr(call.result), policy: { trust: "TRUSTED", reason: "integrity axis OFF — trust classification disabled" } });
  });
  const vm = toSessionViewModel(S, events);
  const page = buildAgentPage({
    session: { id: S, label: null, eventCount: events.length, firstTs: events[0]!.ts, lastTs: events[events.length - 1]!.ts, violated: false, agent: "claude", status: "ended" } as never,
    id: S, vm, cwd: null, waiting: [],
  });
  assert.equal(page.story.length, 1, "one question, one turn");
  const steps = page.story[0]!.steps.filter((s): s is Extract<StoryStep, { kind: "action" }> => s.kind === "action");
  assert.equal(steps.length, calls.length, "one step per call");
  return { page, steps, words: steps.map((s) => s.sentence.map((p) => (p.kind === "masked" ? `[${p.text}]` : p.text)).join("")) };
}

test("the dashboard reads Mandu's words only for the names the arbiter's gate vouches for", () => {
  assert.deepEqual([...MANDU_POLICY_TOOL_SPELLINGS].sort(), [...POLICY_TOOL_SPELLINGS].sort());
});

test("each real answer of the policy server gives the page the words its outcome means, matching what the arbiter did", async () => {
  await rig(async ({ deps, client, policyPath, envFile }) => {
    const lockArgs = { edits: [{ op: "lock-path", path: envFile, level: "no-model" }], reason: "REASON-NEVER-SHOWN" };
    const lock = await callTool(deps, "mandu_policy_propose", lockArgs);
    assert.ok(readFileSync(policyPath, "utf8").includes(envFile), "the lock is in the law on disk");
    const again = await callTool(deps, "mandu_policy_propose", lockArgs);
    const relaxArgs = { edits: [{ op: "allow-connect", host: "pypi.org", port: 443 }], reason: "pip" };
    const relax = await callTool(deps, "mandu_policy_propose", relaxArgs);
    assert.equal((await client.policyProposals("pending")).proposals.length, 1, "the loosening waits for the person");
    const badArgs = { edits: [{ op: "lock-path", path: envFile, level: "top-secret" }], reason: "x" };
    const bad = await callTool(deps, "mandu_policy_propose", badArgs);
    const read = await callTool(deps, "mandu_policy_read");
    const testArgs = { source: { tool: "Read", origin: envFile }, destination: "https://paste.example/" };
    const asked = await callTool(deps, "mandu_policy_test", testArgs);
    const egress = (JSON.parse(asked) as { egress: string | null }).egress;
    assert.ok(egress === "allow" || egress === "ask" || egress === "block", `a test with a destination answers allow, ask or block (got ${egress})`);

    const P = "mcp__mandu-policy__";
    const { page, steps, words } = told([
      { tool: `${P}mandu_policy_propose`, args: lockArgs, result: lock },
      { tool: `${P}mandu_policy_propose`, args: lockArgs, result: again },
      { tool: `${P}mandu_policy_propose`, args: relaxArgs, result: relax },
      { tool: `${P}mandu_policy_propose`, args: badArgs, result: bad },
      { tool: `${P}mandu_policy_read`, args: {}, result: read },
      { tool: `${P}mandu_policy_test`, args: testArgs, result: asked },
    ]);
    assert.deepEqual(words, [
      `Asked Mandu to make ${envFile} a secret no AI may read`,
      `Asked Mandu to make ${envFile} a secret no AI may read`,
      "Asked Mandu to let your agent's programs connect to pypi.org:443",
      `Asked Mandu to set ${envFile} to an unknown level`,
      "Read your Mandu rules",
      `Asked Mandu whether data from ${envFile} could be sent to https://paste.example/`,
    ]);
    const answer = egress === "allow" ? "Mandu answered that it may go there." : egress === "ask" ? "Mandu answered that it would ask you first." : "Mandu answered that it would be blocked.";
    assert.deepEqual(steps.map((s) => s.note), [
      "Mandu applied it at once, because it only adds protection. You can undo it under Rule changes in Approvals.",
      "Nothing changed: your rules already said this.",
      "Not applied: it would loosen protection, so Mandu asked for your OK in Approvals.",
      "Mandu did not apply it, so nothing changed.",
      null,
      `Only a question: nothing was sent or changed. ${answer}`,
    ]);
    for (const s of steps) {
      assert.equal(s.icon, "shield");
      assert.equal(s.outcome, "plain", "a rule change changes no count or tone");
    }
    assert.equal(page.blocked + page.sent, 0);
    assert.doesNotMatch(JSON.stringify(page), /REASON-NEVER-SHOWN|mandu_policy_|\$MDU:/, "no reason, no tool name, no token");
  });
});

test("the same real answer under another server's name keeps the tool's own name and claims nothing", async () => {
  await rig(async ({ deps, envFile }) => {
    const args = { edits: [{ op: "lock-path", path: envFile, level: "no-model" }], reason: "keys" };
    const lock = await callTool(deps, "mandu_policy_propose", args);
    assert.equal((JSON.parse(lock) as { applied: boolean }).applied, true);
    const { steps, words } = told([{ tool: "mcp__other-server__mandu_policy_propose", args, result: lock }]);
    assert.deepEqual(words, ["Used other-server mandu_policy_propose"]);
    assert.equal(steps[0]!.note, null);
    assert.equal(steps[0]!.icon, "tool");
  });
});
