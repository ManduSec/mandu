/**
 * openclaw-redaction-relaunch — OpenClaw's history redaction undone across
 * a relaunch (confidentiality.md §6, "OpenClaw's history redacts
 * placeholders", *Across a relaunch*; 2026-10-11) over the REAL components:
 * a real ArbiterServer with its human socket, its mandu.db reopened by a
 * second arbiter, and the PRODUCTION proxy wiring
 * (`new ArbiterClientAdapter(data, human)`), a mock model behind it.
 *
 * OpenClaw keeps a tool result in its transcript through its own redaction
 * (2026.9: `redactTranscriptMessage` keeps `toolCall.id` and
 * `toolResult.toolCallId` verbatim and redacts the text), so a relaunch that
 * resumes the conversation re-sends the history with the call ids as the
 * provider minted them and the twin's placeholders cut (`$MDU:n…_KEY`,
 * `***`). Before, a fresh proxy had no memory of what it forwarded and the
 * twin was masked whole. Replayed:
 *
 *   1. launch 1: OpenClaw reads `.env` (its twin), which reaches the model
 *      per key; the proxy records the placeholders and the digest with the
 *      arbiter (human plane);
 *   2. the proxy and the arbiter close; launch 2 (a new arbiter over the
 *      same mandu.db, a new session key, a fresh proxy) receives the resumed
 *      history with OpenClaw's redaction of the twin: the model gets the
 *      per-key twin again;
 *   3. the same over the OpenAI wire (OpenClaw on an OpenAI model is served
 *      by this proxy's openai-wire reader: the launcher sends only Codex to
 *      the openai-proxy), within a launch and across the relaunch;
 *   4. NEGATIVES and THE ORACLE: a forged history under the recorded id
 *      (the raw file's values, or text added), an id never recorded, and a
 *      launch 1 that only had the data socket (records nothing) are masked
 *      whole; no raw secret byte in any request any launch sends.
 *
 * Unit twins: anthropic-proxy `openclaw-redaction.test.ts`,
 * arbiter `forwarded-placeholders.test.ts`.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

type Json = Record<string, unknown>;

const STRIPE = "sk_live_relaunch_e2e_0123456789";
const DB_PW = "pg_relaunch_e2e_pw_987654";
const RAW = `PORT=3000\nSTRIPE_KEY=${STRIPE}\nDATABASE_URL=postgres://app:${DB_PW}@db:5432/prod\nLOG_LEVEL=info\n`;
const SECRET_PIECES = [STRIPE, DB_PW, "sk_live_relaunch", "pg_relaunch"];
const PER_KEY = /^PORT=3000\nSTRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'\n/;
const HANDLE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/;

/** OpenClaw's `maskToken` (first 6, `…`, last 4; `***` under 18). */
const maskToken = (v: string): string => (v.length < 18 ? "***" : `${v.slice(0, 6)}…${v.slice(-4)}`);
/** OpenClaw's redaction of a twin: each placeholder through `maskToken`. */
const openclawRedaction = (twin: string): string => twin.replace(/\$MDU:[^\s'@]+/g, (t) => maskToken(t));

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** One launch's arbiter over `home` (a relaunch reuses the directory and its mandu.db). */
async function launch(home: string, sessionKey: string) {
  const sock = join(home, "arbiter.sock");
  const humanSock = join(home, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(home, "mandu.db"), eventDir: join(home, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const data = await open(sock);
  assert.equal((await data.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "openclaw-redaction-relaunch e2e" })).bound, "openclaw-agent");
  const proxies: AnthropicProxy[] = [];
  return {
    data,
    /** A proxy in the production wiring (`dataOnly`: no human client). */
    async proxy(upstream: MockUpstream, opts: { dataOnly?: boolean; openai?: MockUpstream } = {}): Promise<number> {
      const p = new AnthropicProxy({
        arbiter: opts.dataOnly ? new ArbiterClientAdapter(data) : new ArbiterClientAdapter(data, await open(humanSock)),
        upstream: upstream.fetcher, sessionKey, log: () => {}, agentCwd: home,
        ...(opts.openai ? { openaiUpstreams: { openai: "https://stand-in.invalid/v1" }, openaiFetcher: () => opts.openai!.fetcher } : {}),
      });
      proxies.push(p);
      return p.listen(0);
    },
    async close() {
      for (const p of proxies) await p.close().catch(() => {});
      for (const c of clients) c.close();
      await server.close();
    },
  };
}

function freshHome(): string {
  const home = mkdtempSync(join(tmpdir(), "mandu-oc-relaunch-"));
  dirs.push(home);
  mkdirSync(join(home, "human"), { mode: 0o700 });
  writeFileSync(join(home, ".env"), RAW);
  return home;
}

async function post(port: number, path: string, body: unknown, session: string): Promise<void> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
    body: JSON.stringify(body),
  });
  assert.equal(res.status, 200, await res.text());
}

// ── the Messages wire ────────────────────────────────────────────────────────

const messagesTurn = (id: string, content: string, more: Json[] = []): Json => ({
  model: "claude-sonnet-5", stream: true, max_tokens: 256,
  messages: [
    { role: "user", content: "which keys are in the env file?" },
    { role: "assistant", content: [{ type: "tool_use", id, name: "read", input: { path: ".env" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: [{ type: "text", text: content }] }] },
    ...more,
  ],
});
const resumed = [
  { role: "assistant", content: "It has PORT, STRIPE_KEY, DATABASE_URL and LOG_LEVEL." },
  { role: "user", content: "Use the Stripe key to list my customers with curl." },
];
function messagesResult(up: MockUpstream): { result: string; body: string } {
  const r = up.requests[up.requests.length - 1]!;
  const sent = r.json() as { messages: Array<{ content: unknown }> };
  const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
  return { result: typeof block === "string" ? block : (block as Array<{ text: string }>).map((b) => b.text).join(""), body: r.bodyText };
}
function oracle(body: string, where: string): void {
  for (const s of SECRET_PIECES) assert.ok(!body.includes(s), `CONFIDENTIALITY VIOLATION (${where}): ${s} reached the model`);
}

test("OpenClaw on the Messages wire: the twin read in launch 1, redacted by OpenClaw's history, reaches the model per key again after a relaunch; forged histories, unknown ids and a data-only launch 1 are masked whole (secrets axes, explicit)", async () => {
  const home = freshHome();
  const s1 = `oc-relaunch-1-${process.pid}`;
  const l1 = await launch(home, s1);
  let twin: string;
  try {
    twin = (await l1.data.registerSecret({ path: join(home, ".env"), sessionKey: s1 })).twin as string;
    assert.ok(typeof twin === "string" && !twin.includes(STRIPE), twin);
    const up = new MockUpstream({ sse: buildTextSse("ok") });
    const port = await l1.proxy(up);
    await post(port, "/v1/messages", messagesTurn("toolu_oc_relaunch_1", twin), s1);
    const first = messagesResult(up);
    assert.match(first.result, PER_KEY, first.result);
    oracle(first.body, "launch 1");
    // the same read, by a launch-1 proxy that only had the data socket
    const upData = new MockUpstream({ sse: buildTextSse("ok") });
    await post(await l1.proxy(upData, { dataOnly: true }), "/v1/messages", messagesTurn("toolu_oc_dataonly", twin), s1);
    assert.match(messagesResult(upData).result, PER_KEY);
  } finally {
    await l1.close();
  }

  const redacted = openclawRedaction(twin);
  assert.ok(redacted !== twin && redacted.includes("$MDU:n…_KEY"), redacted);
  const s2 = `oc-relaunch-2-${process.pid}`;
  const l2 = await launch(home, s2);
  try {
    const up = new MockUpstream({ sse: buildTextSse("ok") });
    const port = await l2.proxy(up);
    await post(port, "/v1/messages", messagesTurn("toolu_oc_relaunch_1", redacted, resumed), s2);
    const again = messagesResult(up);
    assert.equal(again.result, twin, "the resumed history's twin goes to the model per key, as in launch 1");
    oracle(again.body, "launch 2, restored");

    // NEGATIVES: masked whole, never raw
    const negatives: Array<[string, string, string]> = [
      ["toolu_oc_relaunch_1", RAW.replace(STRIPE, maskToken(STRIPE)).replace(DB_PW, maskToken(DB_PW)), "the raw file's redaction under the recorded id"],
      ["toolu_oc_relaunch_1", `${redacted}EXTRA=${STRIPE}\n`, "the redacted twin with a raw value added"],
      ["toolu_oc_never", redacted, "an id no launch recorded"],
      ["toolu_oc_dataonly", redacted, "a launch-1 proxy without the human socket recorded nothing"],
    ];
    for (const [id, content, why] of negatives) {
      const upN = new MockUpstream({ sse: buildTextSse("ok") });
      await post(await l2.proxy(upN), "/v1/messages", messagesTurn(id, content, resumed), s2);
      const got = messagesResult(upN);
      oracle(got.body, why);
      assert.match(got.result, HANDLE, `${why}: masked whole (${got.result})`);
      assert.ok(!got.result.includes("PORT=3000"), `${why}: masked whole (${got.result})`);
    }
  } finally {
    await l2.close();
  }
});

// ── the OpenAI wire (Responses API: OpenClaw's built-in `openai`) ────────────

const responsesTurn = (id: string, output: string, more: Json[] = []): Json => ({
  model: "gpt-5.5", stream: true, instructions: "You are OpenClaw.",
  input: [
    { type: "message", role: "user", content: [{ type: "input_text", text: "which keys are in the env file?" }] },
    { type: "function_call", call_id: id, name: "read", arguments: JSON.stringify({ path: ".env" }) },
    { type: "function_call_output", call_id: id, output },
    ...more,
  ],
  tools: [{ type: "function", name: "read", parameters: { type: "object" } }],
});
const responsesResumed = [
  { type: "message", role: "assistant", content: [{ type: "output_text", text: "It has PORT, STRIPE_KEY, DATABASE_URL and LOG_LEVEL." }] },
  { type: "message", role: "user", content: [{ type: "input_text", text: "Use the Stripe key to list my customers with curl." }] },
];
const responsesDone = (): string =>
  `event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: { id: "r", output: [] } })}\n\n`;
function responsesResult(up: MockUpstream, id: string): { result: string; body: string } {
  const r = up.requests[up.requests.length - 1]!;
  const sent = r.json() as { input: Json[] };
  const item = sent.input.find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!;
  const out = item["output"];
  return { result: typeof out === "string" ? out : JSON.stringify(out), body: r.bodyText };
}

test("OpenClaw on the OpenAI wire (Responses, through this proxy's openai-wire reader): the redacted twin is put back within a launch and after a relaunch; a forged one is masked whole (secrets axes, explicit)", async () => {
  const home = freshHome();
  const s1 = `oc-relaunch-oa-1-${process.pid}`;
  const l1 = await launch(home, s1);
  let twin: string;
  let redacted: string;
  try {
    twin = (await l1.data.registerSecret({ path: join(home, ".env"), sessionKey: s1 })).twin as string;
    redacted = openclawRedaction(twin);
    const model = new MockUpstream({ sse: responsesDone() });
    const port = await l1.proxy(new MockUpstream(), { openai: model });
    await post(port, "/_mandu/openai/openai/responses", responsesTurn("call_oc_relaunch_1", twin), s1);
    assert.match(responsesResult(model, "call_oc_relaunch_1").result, PER_KEY);
    // the next turn, same launch: OpenClaw's history redaction put back
    await post(port, "/_mandu/openai/openai/responses", responsesTurn("call_oc_relaunch_1", redacted, responsesResumed), s1);
    const next = responsesResult(model, "call_oc_relaunch_1");
    assert.equal(next.result, twin, "within the launch");
    oracle(next.body, "OpenAI wire, launch 1");
  } finally {
    await l1.close();
  }

  const s2 = `oc-relaunch-oa-2-${process.pid}`;
  const l2 = await launch(home, s2);
  try {
    const model = new MockUpstream({ sse: responsesDone() });
    const port = await l2.proxy(new MockUpstream(), { openai: model });
    await post(port, "/_mandu/openai/openai/responses", responsesTurn("call_oc_relaunch_1", redacted, responsesResumed), s2);
    const again = responsesResult(model, "call_oc_relaunch_1");
    assert.equal(again.result, twin, "after the relaunch");
    oracle(again.body, "OpenAI wire, launch 2");
    const forged = RAW.replace(STRIPE, maskToken(STRIPE)).replace(DB_PW, maskToken(DB_PW));
    await post(port, "/_mandu/openai/openai/responses", responsesTurn("call_oc_relaunch_1", forged, responsesResumed), s2);
    const f = responsesResult(model, "call_oc_relaunch_1");
    oracle(f.body, "OpenAI wire, forged");
    assert.match(f.result, HANDLE, `masked whole: ${f.result}`);
  } finally {
    await l2.close();
  }
});
