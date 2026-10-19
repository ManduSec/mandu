/**
 * path-derived-note — confidentiality.md §7.1, "the path-derived note"
 * (2026-10-05), over the REAL components: a real ArbiterServer in `secrets`,
 * the real anthropic-proxy and openai-proxy over HTTP in their production
 * wiring (`new ArbiterClientAdapter(data, human)`), a mock model behind each.
 *
 * The beta-tester tour ran `set -a && . ./.env && set +a && curl … -u
 * "$STRIPE_KEY:"`. The command names `./.env`, so the arbiter's classify
 * verdict masks the whole result (`no-model`, path-derived); no taint answer
 * masked it, so no `[mandu:secret]` note was added and `is_error` was
 * cleared: the model read one bare symbol and told the user the request had
 * worked. Now the proxy appends a note built from the model's OWN command:
 *
 *   - Claude Code (Bash) and Codex (exec_command): the result is still a
 *     symbol, followed by the note naming `./.env` as the command wrote it;
 *   - THE ORACLE: no byte of the output (Stripe's answer, which quotes the
 *     key's last 4 characters) and no value of the .env is in any request to
 *     the model, the note included;
 *   - only that case: a command naming no secret path gets neither a symbol
 *     nor a note.
 *
 * Unit twins: the proxies' `path-derived-note.test.ts`, arbiter
 * `named-paths.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = "sk_live_fake_PDNOTE_7f3a9d3456";
const TOUR = 'set -a && . ./.env && set +a && curl -sS https://api.stripe.com/v1/customers -u "$STRIPE_KEY:"';
/** What the run printed: Stripe's answer for a fake key, quoting its tail. */
const OUTPUT = '{"error":{"message":"Invalid API Key provided: sk_live_****3456","type":"invalid_request_error"}}';
const NOTE = "[mandu:secret] masked: the command names a secret file (./.env), so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.";
const OUTPUT_PIECES = ["Invalid API Key", "sk_live_****3456", "invalid_request_error", KEY];

async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-path-note-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  writeFileSync(join(ws, ".env"), `STRIPE_KEY=${KEY}\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  return {
    ws, sock, humanSock, open,
    async close() {
      for (const c of clients) c.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

test("Claude Code: the tour's Bash result is a symbol plus the path-derived note naming ./.env, and no byte of the output reaches the model; a command naming no secret path gets neither (secrets axes, explicit)", async () => {
  const s = await stack();
  const session = `path-note-claude-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const bashCall = async (id: string, command: string, output: string): Promise<{ content?: unknown; is_error?: boolean }> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "Use the Stripe key in .env to list my Stripe customers with curl." },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output, is_error: true }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown; is_error?: boolean }> }> };
    return body.messages[2]!.content[0]!;
  };
  try {
    const tour = await bashCall("toolu_pdn_tour", TOUR, OUTPUT);
    const t = String(tour.content);
    const [symbol, note, ...rest] = t.split("\n\n");
    assert.match(symbol!, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/, t);
    assert.equal(note, NOTE);
    assert.deepEqual(rest, []);
    assert.equal(tour.is_error, false, "R4 unchanged");

    const plain = await bashCall("toolu_pdn_plain", "ls -la", "total 0\n");
    assert.equal(plain.content, "total 0\n", "no secret path: neither a symbol nor a note");

    // THE ORACLE: no byte of the output, and not the key, in any request to the model
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    for (const piece of OUTPUT_PIECES) assert.ok(!wire.includes(piece), `the model got output byte(s): ${piece}`);
  } finally {
    await proxy.close();
    await s.close();
  }
});

// The second live demo battery (2026-10-17): asked to fix a 401, the model ran
// `cat .env.example` and a redacted listing of `.env` in ONE command, the
// whole output (the template's setting name included) was masked, and the
// note's only advice, "say you cannot see the result, or ask the user", made
// it stop. The note now names the way out, and this proves the way is real:
// the part that names no secret file, run on its own, reaches the model.
test("Claude Code: a compound command naming .env is masked whole and the note says to run the other part apart; that part, run on its own, reaches the model in clear (secrets axes, explicit)", async () => {
  const s = await stack();
  writeFileSync(join(s.ws, ".env.example"), "STRIPE_SECRET_KEY=\nPORT=4242\n");
  const session = `path-note-apart-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const bashCall = async (id: string, command: string, output: string): Promise<{ content?: unknown; is_error?: boolean }> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "My payments check gets a 401; fix it." },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown; is_error?: boolean }> }> };
    return body.messages[2]!.content[0]!;
  };
  try {
    const both = await bashCall("toolu_pdn_both", "cat ./.env.example; echo ---; sed 's/=.*/=<redacted>/' ./.env", "STRIPE_SECRET_KEY=\nPORT=4242\n---\nSTRIPE_KEY=<redacted>\n");
    const t = String(both.content);
    const [symbol, note, ...rest] = t.split("\n\n");
    assert.match(symbol!, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/, t);
    assert.equal(note, NOTE, "the note names ./.env and the way out");
    assert.match(note!, /run that part again as a command of its own that names no secret file/);
    assert.deepEqual(rest, []);
    assert.ok(!t.includes("STRIPE_SECRET_KEY") && !t.includes("4242"), "masked whole: no byte of either part");

    const apart = await bashCall("toolu_pdn_apart", "cat ./.env.example", "STRIPE_SECRET_KEY=\nPORT=4242\n");
    assert.equal(apart.content, "STRIPE_SECRET_KEY=\nPORT=4242\n", "the template on its own: in clear, no note");

    // THE ORACLE: the key never reaches the model
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(KEY), "the .env's value reached the model");
  } finally {
    await proxy.close();
    await s.close();
  }
});

test("Codex: the tour's exec_command output is a symbol plus the same note, and no byte of the output reaches the model (secrets axes, explicit)", async () => {
  const s = await stack();
  const session = `path-note-codex-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await s.open(s.sock), await s.open(s.humanSock)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const head = "Chunk ID: 5e1f\nWall time: 0.4123 seconds\nProcess exited with code 0\nOriginal token count: 30\nOutput:\n";
  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify({
        model: "gpt-5.5", stream: true, instructions: "You are Codex.",
        input: [
          { type: "message", role: "user", content: [{ type: "input_text", text: "Use the Stripe key in .env to list my Stripe customers with curl." }] },
          { type: "function_call", call_id: "c_tour", name: "exec_command", arguments: JSON.stringify({ cmd: TOUR, workdir: s.ws }) },
          { type: "function_call_output", call_id: "c_tour", output: `${head}${OUTPUT}\n` },
          { type: "function_call", call_id: "c_plain", name: "exec_command", arguments: JSON.stringify({ cmd: "ls", workdir: s.ws }) },
          { type: "function_call_output", call_id: "c_plain", output: `${head}notes.md\n` },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests[0]!.bodyText;
    const outputOf = (id: string): string => {
      const item = (JSON.parse(toModel).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!;
      const o = item["output"];
      return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
    };
    const tour = outputOf("c_tour");
    assert.match(tour, /\$MDU:nomodel_/, tour);
    assert.ok(tour.endsWith(`\n\n${NOTE}`), tour);
    const plain = outputOf("c_plain");
    assert.ok(plain.includes("notes.md") && !plain.includes("[mandu:secret]") && !plain.includes("$MDU:"), plain);
    for (const piece of OUTPUT_PIECES) assert.ok(!toModel.includes(piece), `the model got output byte(s): ${piece}`);
  } finally {
    await proxy.close();
    await s.close();
  }
});
