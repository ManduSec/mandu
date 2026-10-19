/**
 * web-fetch-secret-ingress — `model-ingress/web` on the real path
 * (test-reorganization.md §11.1): a web page that carries a REGISTERED secret
 * reaches the model only as a symbol, through the real model proxy over HTTP.
 *
 *   a page server on 127.0.0.1 (the web) ──► the agent's fetch tool
 *     ──► the REAL AnthropicProxy over HTTP (production adapter:
 *         `new ArbiterClientAdapter(new ArbiterClient(sock))`)
 *     ──► the scripted fake model (tests/lib/fake-anthropic.ts),
 *         reached by the proxy's own upstream transport (plain http to
 *         loopback), which records every request it is sent.
 *
 * The secret is registered as the launcher registers it (`registerSecret` on a
 * `~/.npmrc` under the session's HOME, a catalog file) on a real ArbiterServer
 * in `secrets`. The agent is the one stand-in: this test plays its loop (send
 * the turn, run the tool the model asked for, send the result), because the
 * agent's tool runs on the agent's side of Mandu either way. Each agent's own
 * web tool is driven: Claude Code `WebFetch` (whose page goes first to the
 * client's own summarizer call, a zero-tool request with one user message,
 * then the summary comes back as the tool result), OpenCode `webfetch` and
 * OpenClaw `web_fetch` (the page is the tool result).
 *
 * The oracle, per agent: no request the fake model received holds the token;
 * the tool result it received is a `$MDU:` symbol; and a page with no secret
 * reaches the model raw (`secrets` does not mask untrusted text, so an
 * over-block would be a utility regression). No paid model, no network beyond
 * loopback.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Readable } from "node:stream";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { SIDE_CALL_SECRET_NOTE } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { startScriptedAnthropic, textTurn, toolUseTurn, type FakeAnthropic } from "../lib/fake-anthropic.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const TOKEN = "npm_WebIngressCanary7f3a9c21d84e5b60aa19";
const SECRET_PAGE = `<html><body>\n<h1>Build notes</h1>\n<p>CI publishes with the token ${TOKEN} (rotate monthly).</p>\n<p>Deploys run nightly at 02:00.</p>\n</body></html>`;
const CLEAN_MARK = "CLEAN_PAGE_MARK_5521";
const CLEAN_PAGE = `<html><body><h1>Release notes</h1><p>${CLEAN_MARK}: the proxy shipped.</p></body></html>`;
const SYMBOL_RE = /\$MDU:[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;

interface Agent {
  name: string;
  /** the spec the arbiter binds the session to (the launcher does this) */
  spec: "claude-code" | "opencode" | "openclaw-agent";
  tool: string;
  urlField: string;
  /** Claude Code's WebFetch hands the page to its own summarizer call first */
  summarizer: boolean;
}

const AGENTS: Agent[] = [
  { name: "Claude Code", spec: "claude-code", tool: "WebFetch", urlField: "url", summarizer: true },
  { name: "OpenCode", spec: "opencode", tool: "webfetch", urlField: "url", summarizer: false },
  { name: "OpenClaw", spec: "openclaw-agent", tool: "web_fetch", urlField: "url", summarizer: false },
];

/** POST one Messages request to the proxy; the raw response body. */
function post(port: number, body: unknown, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

/** The tool_use the model streamed back: its id, name and (reassembled) input. */
function toolUseFromSse(sse: string): { id: string; name: string; input: Record<string, unknown> } {
  let id = "", name = "", json = "";
  for (const line of sse.split("\n")) {
    if (!line.startsWith("data: ")) continue;
    const d = JSON.parse(line.slice(6)) as { type?: string; content_block?: { type?: string; id?: string; name?: string }; delta?: { type?: string; partial_json?: string } };
    if (d.type === "content_block_start" && d.content_block?.type === "tool_use") { id = d.content_block.id!; name = d.content_block.name!; }
    if (d.type === "content_block_delta" && d.delta?.type === "input_json_delta") json += d.delta.partial_json ?? "";
  }
  assert.ok(id, `the model's turn carries a tool_use: ${sse.slice(0, 400)}`);
  return { id, name, input: JSON.parse(json || "{}") as Record<string, unknown> };
}

/** The agent's fetch tool: a plain GET. */
async function fetchPage(url: string): Promise<string> {
  const r = await fetch(url);
  return r.text();
}

/** Claude Code's WebFetch summarizer request: zero tools, one user message
 *  opening `Web page content:` (dashboard.md §4, the side-call shapes). */
function summarizerRequest(page: string, prompt: string): unknown {
  return {
    model: "claude-haiku-4-5", stream: true, max_tokens: 1024,
    messages: [{ role: "user", content: `Web page content:\n---\n${page}\n---\n\n${prompt}\n\nProvide a concise response based only on the content above.` }],
  };
}

/** What the summarizer was given: its one user message's text. */
function summarizerInput(body: string): string {
  const m = (JSON.parse(body) as { messages: Array<{ content: unknown }> }).messages[0]!.content;
  return typeof m === "string" ? m : JSON.stringify(m);
}

const MARK = (agent: Agent, page: string) => `WEB_INGRESS_${agent.spec}_${page}`;

async function boot(): Promise<{
  tmp: string; sock: string; server: ArbiterServer; pages: http.Server; pagesOrigin: string; fake: FakeAnthropic;
  stop(): Promise<void>;
}> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-web-ingress-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=${TOKEN}\n`);
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  // The launcher's registration of a catalog secret under the session's HOME.
  const reg = new ArbiterClient(sock);
  await reg.connect();
  const r = await reg.registerSecret({ path: join(home, ".npmrc"), home });
  reg.close();
  assert.match(String(r.symbol), /^\$MDU:/, `the .npmrc is registered: ${JSON.stringify(r)}`);

  const pages = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(req.url === "/build-notes" ? SECRET_PAGE : CLEAN_PAGE);
  });
  await new Promise<void>((ok) => pages.listen(0, "127.0.0.1", ok));
  const pagesOrigin = `http://127.0.0.1:${(pages.address() as AddressInfo).port}`;

  // The scripted model: the first turn of each scenario asks for the page with
  // the agent's own tool; a summarizer call is answered by quoting the page
  // (the worst case: a summary that repeats the token); a tool result ends it.
  const script = AGENTS.flatMap((agent) => (["build-notes", "release-notes"] as const).map((page) => ({
    match: (req: { body: string; hasToolResult: boolean }) => !req.hasToolResult && req.body.includes(MARK(agent, page)),
    respond: () => toolUseTurn(`toolu_${agent.spec}_${page.replace("-", "_")}`, agent.tool, { [agent.urlField]: `${pagesOrigin}/${page}`, prompt: "What does the page say?" }),
    once: true,
  })));
  const fake = await startScriptedAnthropic({
    script: [
      ...script,
      {
        // The summarizer side call (no tools): its answer quotes what it was
        // given, the worst case (a summary that repeats the token).
        match: (req) => !(JSON.parse(req.body) as { tools?: unknown[] }).tools?.length,
        respond: (req) => textTurn(`Summary: ${summarizerInput(req.body)}`),
      },
      { match: (req) => req.hasToolResult, respond: () => textTurn("done") },
    ],
  });
  return {
    tmp, sock, server, pages, pagesOrigin, fake,
    async stop() {
      await fake.close();
      await new Promise<void>((ok) => pages.close(() => ok()));
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

/** Run one agent turn: prompt → the model's fetch → the agent's tool → the result. */
async function runTurn(s: Awaited<ReturnType<typeof boot>>, port: number, agent: Agent, page: "build-notes" | "release-notes", session: string): Promise<{ toolResultBody: string; all: string[]; side?: string }> {
  const before = s.fake.requests.length;
  const tools = [{ name: agent.tool, description: "Fetch a URL", input_schema: { type: "object", properties: { url: { type: "string" }, prompt: { type: "string" } } } }];
  const prompt = { role: "user", content: `${MARK(agent, page)}: read the page and tell me what it says.` };
  const first = await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 1024, tools, messages: [prompt] }, session);
  assert.equal(first.status, 200, first.body);
  const use = toolUseFromSse(first.body);
  assert.equal(use.name, agent.tool);
  const url = String(use.input[agent.urlField]);
  assert.ok(url.startsWith(s.pagesOrigin), `the fetch goes to the page server: ${url}`);
  // The agent's tool.
  let result = await fetchPage(url);
  let side: string | undefined;
  if (agent.summarizer) {
    const at = s.fake.requests.length;
    const sideRes = await post(port, summarizerRequest(result, String(use.input["prompt"])), session);
    assert.equal(sideRes.status, 200, sideRes.body);
    side = s.fake.requests[at]!.body;
    result = sideRes.body.split("\n").filter((l) => l.startsWith("data: ")).map((l) => JSON.parse(l.slice(6)) as { delta?: { text?: string } }).map((d) => d.delta?.text ?? "").join("");
  }
  const second = await post(port, {
    model: "claude-sonnet-4-5", stream: true, max_tokens: 1024, tools,
    messages: [prompt, { role: "assistant", content: [{ type: "tool_use", id: use.id, name: use.name, input: use.input }] }, { role: "user", content: [{ type: "tool_result", tool_use_id: use.id, content: result }] }],
  }, session);
  assert.equal(second.status, 200, second.body);
  const sent = s.fake.requests.slice(before).map((r) => r.body);
  const last = JSON.parse(sent[sent.length - 1]!) as { messages: Array<{ content: unknown }> };
  const tr = (last.messages[2]!.content as Array<{ type: string; content: unknown }>).find((b) => b.type === "tool_result")!;
  return { toolResultBody: JSON.stringify(tr.content), all: sent, ...(side !== undefined ? { side } : {}) };
}

for (const agent of AGENTS) {
  test(`model-ingress/web (${agent.name} ${agent.tool}): a page carrying a registered secret reaches the model only as a symbol; a clean page reaches it raw (secrets axes, the real proxy over HTTP)`, async () => {
    const s = await boot();
    const client = new ArbiterClient(s.sock);
    await client.connect();
    // The launcher's wiring: the session bound to the agent's spec, and the
    // proxy started for that session (MANDU_SESSION_KEY).
    const session = `web-ingress-${agent.spec}-${process.pid}`;
    await client.setSessionSpec({ sessionKey: session, spec: agent.spec });
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client), upstreamOrigin: s.fake.origin, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    try {

      const dirty = await runTurn(s, port, agent, "build-notes", session);
      const leaked = dirty.all.filter((b) => b.includes(TOKEN));
      assert.deepEqual(leaked.map((b) => b.slice(0, 200)), [], `CONFIDENTIALITY VIOLATION: a registered secret on a web page reached the model (${agent.name})`);
      assert.match(dirty.toolResultBody, SYMBOL_RE, `the page's result reaches the model as a symbol: ${dirty.toolResultBody}`);
      if (agent.summarizer) {
        // The page went to the summarizer model first: it got a symbol and the note, not the page.
        assert.match(dirty.side!, SYMBOL_RE, `the summarizer call carries the page as a symbol: ${dirty.side}`);
        assert.ok(dirty.side!.includes(SIDE_CALL_SECRET_NOTE.slice(0, 40)), "and the proxy's note says why");
        // Since plan 15 the side-call scan runs under filterPrompt, which has
        // offsets: the token's span is masked, not its whole line.
        assert.ok(!dirty.side!.includes(TOKEN), "the token is masked");
        assert.ok(dirty.side!.includes("CI publishes with the token $MDU:"), "only the token's span: the rest of its line reads");
        assert.ok(dirty.side!.includes("Deploys run nightly"), "the rest of the page stays readable to the summarizer");
      }

      const clean = await runTurn(s, port, agent, "release-notes", session);
      assert.ok(clean.toolResultBody.includes(CLEAN_MARK), `a page with no secret reaches the model raw in secrets (no over-block): ${clean.toolResultBody}`);
      assert.doesNotMatch(clean.toolResultBody, SYMBOL_RE, "nothing is symbolized on a clean page");
      if (agent.summarizer) assert.ok(clean.side!.includes(CLEAN_MARK), "a clean page reaches the summarizer raw");
    } finally {
      await proxy.close();
      client.close();
      await s.stop();
    }
  });
}

test("model-ingress/web FAIL CLOSED: with the arbiter gone, the page result is refused, never forwarded raw (secrets axes)", async () => {
  const s = await boot();
  const client = new ArbiterClient(s.sock);
  await client.connect();
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client), upstreamOrigin: s.fake.origin, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const page = await fetchPage(`${s.pagesOrigin}/build-notes`);
    await s.server.close();
    client.close();
    const before = s.fake.requests.length;
    const res = await post(port, {
      model: "claude-sonnet-4-5", stream: true, max_tokens: 1024,
      tools: [{ name: "WebFetch", description: "Fetch a URL", input_schema: { type: "object" } }],
      messages: [
        { role: "user", content: "read it" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_fc", name: "WebFetch", input: { url: `${s.pagesOrigin}/build-notes` } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_fc", content: page }] },
      ],
    }, "web-ingress-fail-closed");
    assert.notEqual(res.status, 200, "the proxy refuses the request");
    assert.ok(!s.fake.requests.slice(before).some((r) => r.body.includes(TOKEN)), "CONFIDENTIALITY VIOLATION: the page went to the model with the arbiter down");
  } finally {
    await proxy.close();
    await s.stop().catch(() => {});
  }
});

// The !292 side-call floor on the OpenAI-family wires (OpenClaw and OpenCode
// to a non-Anthropic model, /_mandu/openai/<provider>): a tool-less request
// whose user text carries a fetched page with a registered secret. Verified
// 2026-10-02: the wire's shadow hands every user text to `filterPrompt` as a
// `side-call` segment and writes the masked text back, so the page reaches
// the provider with the value as its symbol. Pinned here over the real
// arbiter (the value registered as the launcher registers `~/.npmrc`) and the
// production adapter; the provider is a recording stand-in.
test("model-ingress/web on the OpenAI wires: a side call's page with a registered secret reaches the provider only as a symbol (Chat Completions and Responses; secrets axes, the real proxy over HTTP)", async () => {
  const s = await boot();
  const client = new ArbiterClient(s.sock);
  await client.connect();
  const sent: string[] = [];
  const recorder = (provider: string) => async ({ body }: { body: Buffer }) => {
    sent.push(body.toString("utf8"));
    const sse = provider === "chat"
      ? `data: ${JSON.stringify({ id: "c", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index: 0, delta: { content: "ok" }, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`
      : `event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: { id: "r", output: [] } })}\n\n`;
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const session = `web-ingress-openai-${process.pid}`;
  await client.setSessionSpec({ sessionKey: session, spec: "openclaw-agent" });
  const proxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(client), upstreamOrigin: s.fake.origin, sessionKey: session, log: () => {},
    openaiUpstreams: { chat: "https://chat.invalid/v1", resp: "https://resp.invalid/v1" },
    openaiFetcher: recorder,
  });
  const port = await proxy.listen(0);
  const send = (path: string, body: unknown): Promise<{ status: number; body: string }> => new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), "x-mandu-session-id": session, authorization: "Bearer sk-test" } },
      (res) => { let buf = ""; res.setEncoding("utf8"); res.on("data", (c) => (buf += c)); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf })); });
    req.on("error", reject);
    req.end(data);
  });
  try {
    const page = await fetchPage(`${s.pagesOrigin}/build-notes`);
    const side = `Web page content:\n---\n${page}\n---\n\nWhat does the page say?`;
    for (const [path, body] of [
      ["/_mandu/openai/chat/chat/completions", { model: "m", stream: true, messages: [{ role: "user", content: side }] }],
      ["/_mandu/openai/chat/chat/completions", { model: "m", stream: true, messages: [{ role: "user", content: [{ type: "text", text: side }] }] }],
      ["/_mandu/openai/resp/responses", { model: "m", stream: true, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: side }] }] }],
      ["/_mandu/openai/resp/responses", { model: "m", stream: true, input: side }],
    ] as const) {
      const r = await send(path, body);
      assert.equal(r.status, 200, `${path}: ${r.body}`);
    }
    assert.equal(sent.length, 4);
    sent.forEach((b, i) => {
      assert.ok(!b.includes(TOKEN), `CONFIDENTIALITY VIOLATION: OpenAI-wire side call ${i} carried the registered secret raw`);
      assert.match(b, SYMBOL_RE, `side call ${i} carries the symbol`);
      assert.ok(b.includes("Deploys run nightly"), `the rest of the page reads (${i})`);
    });
  } finally {
    await proxy.close();
    client.close();
    await s.stop();
  }
});
