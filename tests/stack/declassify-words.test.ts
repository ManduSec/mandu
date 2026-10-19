/**
 * declassify-words — the product page's words for the agent's request for a
 * secret's real value (`declassify_symbol`, the in-context read;
 * dashboard.md §4.25b, "A request for a secret's real value"), from the REAL
 * answers, across the real components. Mandu-new.
 *
 * Until 2026-10-13 the agent page told such a call as "Used `mandu-inspect
 * declassify_symbol`" with no note. Here a real ArbiterServer runs at the
 * `secrets` axes; the mandu-inspect MCP server's `tools/call` answers over its
 * production adapter (`new ArbiterClientAdapter(new ArbiterClient(sock))`, as
 * server-main.ts builds it) for the Mandu session; the REAL anthropic-proxy
 * on its production client carries one turn in which a scripted model reads a
 * no-model `.env` and an any-model memo, then asks for the real value of the
 * `.env` (refused), of the memo once the session took in untrusted data (the
 * person is asked), and of the memo again once the person allowed it
 * (released); a real DashboardServer reads it over a real ArbiterEventSource,
 * signed out:
 *
 *   W1  the dashboard's spellings are exactly the ones the arbiter's rule
 *       keeps (`isManduDeclassifyTool`), so the page uses Mandu's words only
 *       for a name the arbiter knows as Mandu's own;
 *   W2  /api/home/agent: each request reads "Asked Mandu for the real value
 *       of" its secret's chip, by the secret's name, with the note its real
 *       answer means (refused, asked, released); shield, plain, no count;
 *   W3  the served agent page draws the same words;
 *   W4  the oracle: the `.env` value never reached the model, the memo's only
 *       after its release; neither the page's answer nor the rendered page
 *       carries a value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { isManduDeclassifyTool } from "../../arbiter/policy/inspect-tool.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { ArbiterClientAdapter as InspectAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { handleRpc } from "../../interceptors/inspect-mcp/src/mcp-server.js";
import type { InspectSymbolDeps } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import type { UllmClient } from "../../interceptors/inspect-mcp/src/ullm-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM, StoryStep } from "../../dashboard/src/view-model/agent-page.js";
import { MANDU_DECLASSIFY_TOOL_SPELLINGS } from "../../dashboard/src/view-model/declassify-words.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791500000-${process.pid}`;
const TOOL = "mcp__mandu-inspect__declassify_symbol";
const ENV_VALUE = `sk_live_declassifyWordsEnv_${process.pid}_0000`;
const MEMO_BODY = `Deal memo: margin 31 percent. DECL_WORDS_MEMO_${process.pid}`;
const REASON = "REASON_NEVER_SHOWN";
const NOMODEL_RE = /\$MDU:nomodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_]*)?/;
const ANYMODEL_RE = /\$MDU:anymodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;
const ASKED_WORDS = "Asked Mandu for the real value of ";

const NO_ULLM = { async complete() { throw new Error("the U-LLM is not part of the in-context read"); } } as unknown as UllmClient;

/** The model's answer: one tool_use per call, in one message. */
function toolUses(calls: Array<{ id: string; name: string; input: unknown }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: `msg_${calls[0]!.id}`, role: "assistant", content: [] } });
  calls.forEach((c, i) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index: i, content_block: { type: "tool_use", id: c.id, name: c.name, input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index: i, delta: { type: "input_json_delta", partial_json: JSON.stringify(c.input) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index: i });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

function post(port: number, messages: unknown[]): Promise<number> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }, { name: TOOL, input_schema: { type: "object" } }], messages });
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": SESSION } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    r.on("error", reject);
    r.end(body);
  });
}

type Action = Extract<StoryStep, { kind: "action" }>;
const words = (s: Action) => s.sentence.map((p) => (p.kind === "masked" ? `[${p.name ?? p.text}]` : p.text)).join("");

test("W1: the dashboard reads the in-context read's words only for the names the arbiter's rule knows as Mandu's own", () => {
  for (const name of MANDU_DECLASSIFY_TOOL_SPELLINGS) assert.equal(isManduDeclassifyTool(name), true, name);
  // The arbiter's set has no spelling the page lacks: every spelling of the
  // server and basename, in each agent's convention, is one the page knows.
  const candidates = ["mandu-inspect", "mandu_inspect"].flatMap((s) => [`mcp__${s}__declassify_symbol`, `${s}_declassify_symbol`, `${s}__declassify_symbol`]).concat(["declassify_symbol", "mcp__evil__declassify_symbol", "mcp__mandu-inspect__inspect_symbol"]);
  for (const name of candidates) assert.equal(MANDU_DECLASSIFY_TOOL_SPELLINGS.includes(name), isManduDeclassifyTool(name), name);
});

test("W2-W4: each request for a secret's real value says which secret and what Mandu really answered, refused, asked, released; no value or token on the page (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-declassify-words-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "memo"), { recursive: true });
  const env = join(ws, ".env");
  const memo = join(ws, "memo", "deal.md");
  writeFileSync(env, `API_KEY=${ENV_VALUE}\n`);
  writeFileSync(memo, MEMO_BODY + "\n");
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const data = new ArbiterClient(sock); await data.connect();
  const gate = new ArbiterClient(sock); await gate.connect();
  const humanClient = new ArbiterClient(human); await humanClient.connect();
  const inspectClient = new ArbiterClient(sock); await inspectClient.connect();
  await admin.setPathLabel({ path: env, confidentiality: "no-model", recursive: false });
  await admin.setPathLabel({ path: join(ws, "memo"), confidentiality: "any-model", recursive: true });
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  // The mandu-inspect MCP server for this Mandu session, on its production adapter.
  const inspect: InspectSymbolDeps = { arbiter: new InspectAdapter(inspectClient), ullm: NO_ULLM, sessionId: SESSION };
  const declassify = async (symbol: string): Promise<{ text: string; isError: boolean }> => {
    const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "declassify_symbol", arguments: { symbol, reason: REASON } } }, inspect);
    const res = r!.result as { content: Array<{ text: string }>; isError?: boolean };
    return { text: res.content.map((c) => c.text).join(""), isError: res.isError === true };
  };

  // The scripted model: two reads, then a request for each value, then a reply.
  const seen: string[] = [];
  const plan: Array<(body: string) => string> = [
    () => toolUses([{ id: "toolu_dw_r1", name: "Read", input: { file_path: env } }, { id: "toolu_dw_r2", name: "Read", input: { file_path: memo } }]),
  ];
  const upstream: UpstreamFetcher = async ({ body }) => {
    const text = body.toString("utf8");
    seen.push(text);
    const next = plan[seen.length - 1];
    const sse = next ? next(text) : buildTextSse("I read the memo.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(gate, humanClient), upstream, sessionKey: SESSION, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(ENV_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
    assert.ok(!text.includes(MEMO_BODY), `CONFIDENTIALITY VIOLATION: ${where} carries the memo's value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  try {
    const ask = "Read the deal memo into your context.";
    const messages: unknown[] = [{ role: "user", content: ask }];
    assert.equal(await post(proxyPort, messages), 200);
    messages.push(
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_dw_r1", name: "Read", input: { file_path: env } }, { type: "tool_use", id: "toolu_dw_r2", name: "Read", input: { file_path: memo } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_dw_r1", content: `     1\tAPI_KEY=${ENV_VALUE}\n` }, { type: "tool_result", tool_use_id: "toolu_dw_r2", content: `     1\t${MEMO_BODY}\n` }] },
    );
    // The model gets both files as placeholders and asks for each value in turn.
    let envSym = "";
    let memoSym = "";
    const calls: Array<{ id: string; symbol: () => string }> = [
      { id: "toolu_dw_d1", symbol: () => envSym },
      { id: "toolu_dw_d2", symbol: () => memoSym },
      { id: "toolu_dw_d3", symbol: () => memoSym },
    ];
    plan.push((b) => {
      envSym = NOMODEL_RE.exec(b)?.[0] ?? "";
      memoSym = ANYMODEL_RE.exec(b)?.[0] ?? "";
      return toolUses([{ id: calls[0]!.id, name: TOOL, input: { symbol: envSym, reason: REASON } }]);
    });
    for (const c of calls.slice(1)) plan.push(() => toolUses([{ id: c.id, name: TOOL, input: { symbol: c.symbol(), reason: REASON } }]));
    assert.equal(await post(proxyPort, messages), 200);
    assert.ok(envSym && memoSym, `both files reached the model as placeholders: ${seen[1]?.slice(0, 600)}`);

    const answers: string[] = [];
    for (const [i, c] of calls.entries()) {
      if (i === 1) {
        // The session takes in untrusted data (§9 rule 2's session half): the
        // next read waits for the person.
        await data.symbolizeFull({ tool: "webfetch", value: "a web page", field: "content", origin: "https://example.com", integrity: "untrusted", sessionKey: SESSION });
      }
      if (i === 2) {
        // The person allows the queued read on the dashboard.
        const pending = await admin.egressApprovals("pending");
        const entry = pending.find((a) => a.symbol === memoSym && a.destination === "model_context:in-context-read");
        assert.ok(entry, "the read is queued for the person");
        await admin.resolveEgressApproval(entry!.id, true, "once");
      }
      const r = await declassify(c.symbol());
      answers.push(r.text);
      messages.push(
        { role: "assistant", content: [{ type: "tool_use", id: c.id, name: TOOL, input: { symbol: c.symbol(), reason: REASON } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: c.id, content: r.text, ...(r.isError ? { is_error: true } : {}) }] },
      );
      assert.equal(await post(proxyPort, messages), 200);
    }
    // The real answers: refused, asked, released.
    assert.match(answers[0]!, /^declassify_symbol: REFUSED: no-model/);
    assert.match(answers[1]!, /The user has been asked to approve this/);
    assert.match(answers[2]!, /^\[DECLASSIFIED — this session is now HIGH \(any-model\)\./);
    // W4 on the model's side: the .env value never; the memo's after its release.
    assert.ok(!seen.join("\n").includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    assert.ok(!seen.slice(0, 4).join("\n").includes(MEMO_BODY), "the memo's value reached the model before its release");
    assert.ok(seen[4]!.includes(MEMO_BODY), "the released value reaches the model");

    // W2: the page's answer, signed out (emission is best-effort and asynchronous).
    let text = "";
    let page: AgentPageVM | null = null;
    let asked: Action[] = [];
    for (let i = 0; i < 200; i++) {
      const res = await pageFetch(`${base}/api/home/agent?session=${SESSION}`);
      text = await res.text();
      page = JSON.parse(text) as AgentPageVM;
      const steps = (page.story ?? []).flatMap((t) => t.steps).filter((s): s is Action => s.kind === "action");
      asked = steps.filter((s) => s.sentence[0]?.text === ASKED_WORDS);
      if (asked.length === 3 && asked.every((s) => s.note !== null)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(page?.found, text.slice(0, 400));
    assert.deepEqual(asked.map(words), [`${ASKED_WORDS}[.env]`, `${ASKED_WORDS}[deal.md]`, `${ASKED_WORDS}[deal.md]`], "each secret by its name");
    assert.deepEqual(asked.map((s) => s.note), [
      "Mandu did not give the AI the real value.",
      "Mandu asked for your OK in Approvals first, so the AI did not get the real value.",
      "Mandu gave the AI the real value. From then on, a request or command of this session that could carry it to a place it may not go waits for your OK in Approvals.",
    ]);
    for (const s of asked) {
      assert.equal(s.icon, "shield");
      assert.equal(s.outcome, "plain", "no count, tone or fold changes");
      assert.equal(s.split, null, "the value is never drawn");
    }
    assert.doesNotMatch(text, /declassify_symbol|mandu-inspect|REASON_NEVER_SHOWN/, "neither the tool's name nor the agent's reason");
    noValue(text, "/api/home/agent");

    // W3: the served page draws the same words.
    await servedProductPage(base, `/agents/${SESSION}`, (doc) => doc.querySelectorAll("#agent-story .step").length > 0, (doc) => {
      const drawn = asked.map((s) => doc.querySelector(`#agent-story [data-step-id="${s.id}"] .what`));
      assert.ok(drawn.every(Boolean), "each request is drawn");
      assert.deepEqual(drawn.map((w) => w.querySelector(".note").textContent), asked.map((s) => s.note));
      for (const w of drawn) assert.match(w.textContent, /^Asked Mandu for the real value of /);
      assert.match(drawn[0].textContent, /\.env/);
      assert.match(drawn[2].textContent, /deal\.md/);
      assert.doesNotMatch(doc.body.textContent, /declassify_symbol/);
      noValue(doc.body.textContent, "the rendered agent page");
    });
  } finally {
    await proxy.close();
    await dashboard.close();
    for (const c of [admin, data, gate, humanClient, inspectClient]) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
