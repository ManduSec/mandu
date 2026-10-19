/**
 * trust-not-checked — in Secrets mode no result reads TRUSTED on the
 * inspector's trace (dashboard.md §4.2), across the REAL components:
 *
 *   L1  a real ArbiterServer in `secrets` (confidentiality ON, integrity
 *       OFF) with a policy file that locks `deploy/staging.conf` at
 *       no-model, and the REAL anthropic-proxy in its production wiring
 *       (`new ArbiterClientAdapter(data, human)`), a mock model behind it:
 *       a Read of that file reaches the model as a symbol, with no byte of
 *       the file (the oracle), and a `git status` Bash result as printed;
 *   L2  the proxy records the masked Read's `tool_result` with the
 *       arbiter's integrity-OFF reason behind its provenance prefix
 *       ("secret content (no-model) symbolized by provenance: integrity
 *       axis OFF — …"), and the Bash result with the bare reason: the two
 *       shapes the dashboard reads;
 *   L3  the REAL dashboard over the arbiter's store (`/api/events`, no
 *       launcher, so no recorded mode): both rows are `checked: false` (the
 *       inspector says "trust not checked", never the recorded TRUSTED), the
 *       masked one is masked, and the session is inferred integrity `off`,
 *       never `on` (which drew "untrusted results reached the AI only as
 *       masked tokens"); the trace's view-model carries no byte of the
 *       file.
 *
 * The tour of 2026-10-05 had the 10:42 Read of this shape: the only TRUSTED
 * badge in a Secrets-mode session, on its masked secret.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const SESSION = `trust-not-checked-${process.pid}`;
const TOKEN = "ghp_FakeTrustToken3Kd8Lw2Qp5Zx7Vb9Nm1";
const FILE = `[staging]\nhost = "staging.internal.example"\ntoken = "${TOKEN}"\n`;
const FILE_PIECES = [TOKEN, "ghp_FakeTrust", "staging.internal.example", "[staging]"];
/** Claude Code's Read rendering of FILE. */
const READ_RENDER = FILE.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/;

type Row = { row: string; stepId: string; masked?: boolean; checked?: boolean };
type Paired = { integrity: string; mode: string | null; turns: { rows: Row[] }[] };

test("a secret the real anthropic-proxy masks in Secrets mode is 'trust not checked' on the real dashboard, and the session is never inferred integrity-on (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-trust-not-checked-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const conf = join(ws, "deploy", "staging.conf");
  writeFileSync(conf, FILE);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${conf}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: upstream.fetcher, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  try {
    // ── L1: the Read reaches the model as a symbol, the Bash result as printed ─
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Read", input_schema: { type: "object" } }, { name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "What is in deploy/staging.conf? And what branch am I on?" },
          { role: "assistant", content: [
            { type: "tool_use", id: "toolu_read", name: "Read", input: { file_path: conf } },
            { type: "tool_use", id: "toolu_git", name: "Bash", input: { command: "git branch --show-current" } },
          ] },
          { role: "user", content: [
            { type: "tool_result", tool_use_id: "toolu_read", content: READ_RENDER },
            { type: "tool_result", tool_use_id: "toolu_git", content: "master\n" },
          ] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const sent = upstream.requests.at(-1)!;
    const results = new Map<string, string>();
    for (const m of (sent.json() as { messages: Array<{ content: unknown }> }).messages) {
      if (!Array.isArray(m.content)) continue;
      for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
        if (b.type !== "tool_result") continue;
        results.set(b.tool_use_id!, typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join(""));
      }
    }
    assert.match(results.get("toolu_read")!.split("\n\n")[0]!, SYM_RE, `the locked file reaches the model as a symbol: ${results.get("toolu_read")}`);
    assert.equal(results.get("toolu_git"), "master\n", "an unlocked result goes as printed: Secrets mode masks no untrusted text");
    for (const piece of FILE_PIECES) assert.ok(!sent.bodyText.includes(piece), `the model got file byte(s): ${piece}`);

    // ── L2: the two reasons the proxy records ───────────────────────────────
    type Ev = { kind: string; callId?: string | null; policy?: { trust?: string; reason?: string } };
    let reasons = new Map<string, string>();
    for (let i = 0; i < 100 && reasons.size < 2; i++) {
      // emission is best-effort and asynchronous
      const events = (await human.events(SESSION)) as unknown as Ev[];
      reasons = new Map(events.filter((e) => e.kind === "tool_result" && e.callId && e.policy?.reason).map((e) => [e.callId!, e.policy!.reason!]));
      if (reasons.size < 2) await new Promise((r) => setTimeout(r, 20));
    }
    assert.match(reasons.get("toolu_read") ?? "", /^secret content \(no-model\) symbolized by provenance: integrity axis OFF\b/,
      "the masked secret: the arbiter's integrity-OFF reason behind the proxy's provenance prefix");
    assert.match(reasons.get("toolu_git") ?? "", /^integrity axis OFF\b/, "the plain result: the bare reason");

    // ── L3: the real dashboard reads both as not checked, the session as off ─
    const ev = await fetch(`${base}/api/events?session=${SESSION}`);
    assert.equal(ev.status, 200);
    const { viewModel } = (await ev.json()) as { viewModel: { paired: Paired } };
    const tools = viewModel.paired.turns.flatMap((t) => t.rows).filter((r) => r.row === "tool");
    const read = tools.find((r) => r.stepId === "tool:toolu_read");
    const git = tools.find((r) => r.stepId === "tool:toolu_git");
    assert.ok(read && git, `both calls are rows: ${JSON.stringify(tools.map((r) => r.stepId))}`);
    assert.equal(read.masked, true, "the Read is a masked row");
    assert.equal(read.checked, false, "masked as a secret, never judged: 'trust not checked', not TRUSTED");
    assert.equal(git.masked, false);
    assert.equal(git.checked, false);
    assert.equal(viewModel.paired.mode, null, "no launcher: no recorded mode");
    assert.equal(viewModel.paired.integrity, "off", "inferred from the reasons: never integrity-on in Secrets mode");
    const vm = JSON.stringify(viewModel);
    for (const piece of FILE_PIECES) assert.ok(!vm.includes(piece), `the trace's view-model carried file byte(s): ${piece}`);
  } finally {
    await dashboard.close();
    await proxy.close();
    data.close(); human.close();
    await arbiter.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(tmp, { recursive: true, force: true });
  }
});
