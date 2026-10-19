/**
 * prompt-filter-note-restart — the note under the person's message clears
 * across a PROXY RESTART (confidentiality-plan-15-prompt-filter.md §13.7
 * item 10; dashboard.md §4.25y), over the PRODUCTION wiring: a real
 * ArbiterServer (data, human and admin sockets, a file-backed mandu.db and
 * law, the person's pack), the REAL model proxy over HTTP on its two
 * production clients, a scripted fake model, and the real DashboardServer
 * over `makeApprovalsArbiter(dataSock, admin)` and `ArbiterEventSource`.
 *
 * The story, for each proxy (the anthropic-proxy on the Messages wire, the
 * openai-proxy on the Responses wire):
 *   - proxy A carries a message whose ticket the filter removes, and one with
 *     a registered key, which it masks; the product page shows the notes;
 *   - A is replaced by a FRESH proxy B on the same arbiter and session (a
 *     stack restart, a resumed conversation): B has none of A's memory;
 *   - an exception added in Settings › Prompt filters lets the ticket
 *     through; the conversation goes on through B, which resends the
 *     ticket's message with nothing found;
 *   - B records that outcome under the message's reference, which only the
 *     arbiter could tell it (holds.ts, noted messages), so the ticket's
 *     note clears, while the registered key's note stays;
 *   - the registered key never reaches the fake model raw, through A or B,
 *     and the ticket only after the exception; no value in the page's data.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../arbiter/policy/admin-layer.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { startScriptedResponses } from "../lib/fake-responses.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis the prompt filter serves; integrity off

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const KEY = "sk-live-NoteRestartCanary5Hx2Pj8Lw4";
const TICKET = "ACME-20417";
const REMOVED = "One value in your prompt was removed before the AI read your message (acme.ticket).";
const KEY_HIDDEN = "One value in your prompt was hidden from the AI (a secret Mandu already knows).";

function post(port: number, path: string, body: unknown, session: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": session, ...headers } },
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

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** One wire's proxy, its fake model and how a conversation goes on it. */
interface Wire {
  name: string;
  start(arbiter: { data: ArbiterClient; human: ArbiterClient }, session: string): Promise<{ port: number; close(): Promise<void> }>;
  fakeOrigin: string;
  sent(): string[];
  /** The request for `text` after `history`, the whole conversation resent. */
  request(text: string, history: string[]): { path: string; body: unknown; headers?: Record<string, string> };
  close(): Promise<void>;
}

async function anthropicWire(): Promise<Wire> {
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  return {
    name: "anthropic-proxy",
    fakeOrigin: fake.origin,
    async start(a, session) {
      const proxy = new AnthropicProxy({ arbiter: new AnthropicAdapter(a.data, a.human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
      const port = await proxy.listen(0);
      return { port, close: () => proxy.close() };
    },
    sent: () => fake.requests.filter((q) => q.url.includes("/v1/messages") && q.body.includes('"tools"')).map((q) => q.body),
    request: (text, history) => ({
      path: "/v1/messages",
      body: {
        model: "claude-sonnet-4-5", stream: true, max_tokens: 64,
        tools: [{ name: "Read", input_schema: { type: "object" } }],
        messages: [
          ...history.flatMap((h) => [{ role: "user", content: [{ type: "text", text: h }] }, { role: "assistant", content: [{ type: "text", text: "ok" }] }]),
          { role: "user", content: [{ type: "text", text }] },
        ],
      },
    }),
    close: () => fake.close(),
  };
}

async function openaiWire(): Promise<Wire> {
  const fake = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const msg = (role: "user" | "assistant", text: string) => ({ type: "message", role, content: [{ type: role === "user" ? "input_text" : "output_text", text }] });
  return {
    name: "openai-proxy",
    fakeOrigin: fake.origin,
    async start(a, session) {
      const proxy = new OpenAiProxy({ arbiter: new OpenAiAdapter(a.data, a.human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
      const port = await proxy.listen(0);
      return { port, close: () => proxy.close() };
    },
    sent: () => fake.requests.filter((q) => q.url.includes("/responses") && q.body.includes('"tools"')).map((q) => q.body),
    request: (text, history) => ({
      path: "/v1/responses",
      headers: { authorization: "Bearer sk-test-not-real" },
      body: {
        model: "gpt-5", stream: true,
        tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
        input: [msg("user", "<environment_context>\n  <cwd>/w</cwd>\n</environment_context>"), ...history.flatMap((h) => [msg("user", h), msg("assistant", "ok")]), msg("user", text)],
      },
    }),
    close: () => fake.close(),
  };
}

type PromptFilterEvent = { kind: string; emitter?: string; promptFilter?: { origin: string; findings: unknown[]; turn?: string } };

async function restartStory(makeWire: () => Promise<Wire>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pf-note-restart-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = humanSockIn(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), "pack: acme-dlp\nversion: 1\npatterns:\n  - id: ticket\n    category: acme.ticket\n    regex: 'ACME-\\d{4,}'\n");
  const adminPolicyDir = join(dir, "policy.d");
  mkdirSync(adminPolicyDir);
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir, packDir: null, packKeysDir: join(dir, "keys"),
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  const wire = await makeWire();
  const session = `pf-note-restart-${wire.name}-${process.pid}`;
  await data.setSessionSpec({ sessionKey: session, spec: wire.name === "anthropic-proxy" ? "claude-code" : "codex" });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const source = new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock });
  const server = new DashboardServer({ source, policyDocArbiter: wired.policyDoc, approvalsArbiter: wired.arbiter, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const call = async (method: "GET" | "POST", path: string, body?: unknown, headers: Record<string, string> = { ...CSRF_ADMIN, "Content-Type": "application/json" }) => {
    const r = await fetch(`http://127.0.0.1:${port}/api/${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, any> };
  };
  /** Every note line the product page shows for the session. */
  const noteLines = async (): Promise<{ lines: string[]; json: string }> => {
    const r = await call("GET", `home/agent?session=${encodeURIComponent(session)}`, undefined, {});
    const story = (r.body["story"] ?? []) as Array<{ promptNote: { lines: string[] } | null }>;
    const unplaced = (r.body["unplacedNotes"] ?? []) as Array<{ lines: string[] }>;
    return { lines: [...story.flatMap((t) => t.promptNote?.lines ?? []), ...unplaced.flatMap((n) => n.lines)], json: JSON.stringify(r.body) };
  };
  const pfEvents = async () => (await human.events(session) as unknown as PromptFilterEvent[]).filter((e) => e.kind === "prompt_filter" && e.promptFilter?.origin === "human");
  const convo: string[] = [];
  let proxy = await wire.start({ data, human }, session);
  const say = async (text: string) => {
    const q = wire.request(text, [...convo]);
    const r = await post(proxy.port, q.path, q.body, session, q.headers);
    convo.push(text);
    return r;
  };
  try {
    // ── Proxy A: the ticket removed, the key masked; the notes say so. ──
    assert.equal((await say(`see ${TICKET} today`)).status, 200);
    assert.ok(wire.sent().at(-1)!.includes("see [redacted: acme.ticket] today"), wire.sent().at(-1));
    assert.equal((await say(`deploy with ${KEY}`)).status, 200);
    assert.match(wire.sent().at(-1)!, /deploy with \$MDU:/);
    await waitFor("proxy A's notes", async () => {
      const n = await noteLines();
      return n.lines.includes(REMOVED) && n.lines.includes(KEY_HIDDEN) ? n : undefined;
    });
    const before = await pfEvents();
    const noted = before.find((e) => e.promptFilter!.findings.length > 0 && typeof e.promptFilter!.turn === "string");
    assert.ok(noted, `proxy A recorded the ticket's message under its reference: ${JSON.stringify(before.map((e) => e.promptFilter))}`);
    const ticketTurn = noted!.promptFilter!.turn!;

    // ── A is replaced by a fresh proxy B: same arbiter, same session. ──
    await proxy.close();
    proxy = await wire.start({ data, human }, session);

    // ── An exception lets the ticket through (asked first, then applied). ──
    const exc = { op: "add-prompt-exception", category: "acme.ticket", match: "ACME-2*" };
    const q = await call("POST", "policy/prompt-filters/change", { edit: exc });
    assert.equal(q.body["confirm"], true, JSON.stringify(q.body));
    const agreed = await call("POST", "policy/prompt-filters/change", { edit: exc, expected: q.body["expected"] });
    assert.equal(agreed.body["applied"], true, JSON.stringify(agreed.body));

    // ── The conversation goes on through B. ──
    assert.equal((await say("and now?")).status, 200);
    const resent = wire.sent().at(-1)!;
    assert.ok(resent.includes(`see ${TICKET} today`), `B resends the excepted message as written: ${resent}`);
    assert.match(resent, /deploy with \$MDU:/, "the key still masked through B");

    // ── B clears the ticket's note, a message it never recorded. ──
    const cleared = await waitFor("the ticket's note to clear", async () => {
      const n = await noteLines();
      return !n.lines.includes(REMOVED) ? n : undefined;
    });
    assert.ok(cleared.lines.includes(KEY_HIDDEN), `the key's note stays: ${JSON.stringify(cleared.lines)}`);
    const clearing = (await pfEvents()).filter((e) => e.promptFilter!.findings.length === 0);
    assert.equal(clearing.length, 1, `B recorded the cleared outcome once: ${JSON.stringify(clearing)}`);
    assert.equal(clearing[0]!.emitter, wire.name);
    assert.equal(clearing[0]!.promptFilter!.turn, ticketTurn, "under the message's reference, which only the arbiter could name");
    assert.ok(!JSON.stringify(clearing[0]).includes(TICKET), "a clearing event carries no value");
    assert.equal((await say("still there?")).status, 200);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal((await pfEvents()).filter((e) => e.promptFilter!.findings.length === 0).length, 1, "a further resend records nothing more");

    // ── The invariant: the key never raw at the model; the ticket only after the exception. ──
    const all = wire.sent();
    for (const b of all) assert.ok(!b.includes(KEY), `CONFIDENTIALITY VIOLATION: the registered key reached the model raw through ${wire.name}`);
    assert.ok(!all.slice(0, 2).some((b) => b.includes(TICKET)), "the ticket was not sent before the exception");
    assert.ok(!cleared.json.includes(KEY) && !cleared.json.includes(TICKET), "no value in the page's data");
  } finally {
    await proxy.close();
    await server.close?.();
    wired.close();
    await wire.close();
    data.close();
    human.close();
    await arbiter.close();
    setAdminLayer(NO_ADMIN_LAYER);
  }
}

test("anthropic-proxy: a fresh proxy on the same arbiter clears the note an earlier one wrote, once nothing is found; the key never raw (secrets axes)", async () => {
  await restartStory(anthropicWire);
});

test("openai-proxy: a fresh proxy on the same arbiter clears the note an earlier one wrote, once nothing is found; the key never raw (secrets axes)", async () => {
  await restartStory(openaiWire);
});
