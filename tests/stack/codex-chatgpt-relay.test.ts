/**
 * e2e — Codex on a ChatGPT sign-in, across the real components
 * (docs/design/agents/agent-sign-in.md §2.4, §2.5, §2.7 "E2E").
 *
 * With no key variable, `mandu codex` gives Codex a provider that sends its
 * own sign-in (a ChatGPT bearer plus `chatgpt-account-id`) to the openai-proxy,
 * which relays it to the ChatGPT backend's Codex base instead of the API. The
 * backend is an OUTSIDE model, the same class as api.openai.com, so the
 * confidentiality oracle must hold there exactly as it does for the API.
 * PRODUCTION wiring (`new ArbiterClientAdapter(new ArbiterClient(sock))` over
 * a real ArbiterServer), the default fetcher over real loopback sockets, two
 * scripted upstreams:
 *   - a ChatGPT-shaped one at `/backend-api/codex` (answers only a JWT-shaped
 *     bearer with a `chatgpt-account-id`, else 401);
 *   - an API-shaped one at the origin (answers only a `sk-` bearer).
 * What it pins, for BOTH destinations:
 *   - a labelled file Codex read reaches the model only as `$MDU:`;
 *   - each request lands on its own upstream and path, never the other;
 *   - the sign-in is relayed as sent and appears in no event;
 *   - an unreachable arbiter fails closed: 502, nothing reaches the backend.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { CHATGPT_ACCOUNT_HEADER, OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { buildTextSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const CANARY = "CODEX_CHATGPT_RELAY_CANARY";
const BODY = `Payroll export: salary band L7 = $412,000. ${CANARY}`;
// Dummies, never real: a JWT-shaped bearer and an account id.
const BEARER = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlMmUtZHVtbXkifQ.ZTJlLXNpZ25hdHVyZS1kdW1teQ";
const ACCOUNT = "acct-e2e-dummy-7c1d";
const API_KEY = "sk-e2e-dummy-key-0000000000000000";

interface Captured { path: string; auth: string; account: string | undefined; body: string }

/** A scripted upstream. `chatgpt`: under `/backend-api/codex`, 200 only for a
 *  JWT-shaped bearer with an account id. `api`: 200 only for an `sk-` bearer. */
async function upstream(kind: "chatgpt" | "api"): Promise<{ origin: string; seen: Captured[]; close: () => Promise<void> }> {
  const seen: Captured[] = [];
  const srv: Server = createServer((req, res) => {
    let b = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const auth = String(req.headers["authorization"] ?? "");
      const account = req.headers[CHATGPT_ACCOUNT_HEADER] as string | undefined;
      seen.push({ path: req.url ?? "", auth, account, body: b });
      const ok = kind === "chatgpt"
        ? (req.url ?? "").startsWith("/backend-api/codex/") && /^Bearer eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(auth) && !!account
        : /^Bearer sk-/.test(auth) && account === undefined;
      if (!ok) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: `${kind} stand-in: not my credential` } }));
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse(`${kind}-answered`));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  return { origin, seen, close: () => new Promise<void>((r) => srv.close(() => r())) };
}

function post(port: number, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json", ...headers } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** Codex read the labelled file through exec_command (the ChatGPT-mode body shape). */
function readTurn(path: string): string {
  return JSON.stringify({
    model: "gpt-5.4",
    stream: true,
    store: false,
    include: ["reasoning.encrypted_content"],
    instructions: "You are Codex.",
    tools: [{ type: "function", name: "exec_command" }],
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Summarize the payroll export." }] },
      { type: "function_call", call_id: "call_cg1", name: "exec_command", arguments: JSON.stringify({ cmd: `cat ${path}` }) },
      { type: "function_call_output", call_id: "call_cg1", output: BODY },
    ],
  });
}

const SIGNED_IN = { authorization: `Bearer ${BEARER}`, [CHATGPT_ACCOUNT_HEADER]: ACCOUNT, originator: "codex_exec" };
const KEYED = { authorization: `Bearer ${API_KEY}` };

test("a ChatGPT sign-in and a key each reach their own upstream, and the labelled file reaches either only as $MDU:", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-chatgpt-"));
  mkdirSync(join(tmp, "home", "notes"), { recursive: true });
  const file = join(tmp, "home", "notes", "payroll.md");
  writeFileSync(file, BODY + "\n");
  const chatgpt = await upstream("chatgpt");
  const api = await upstream("api");
  const socketPath = join(tmp, "arbiter.sock");
  const eventDir = join(tmp, "events");
  const arbiter = new ArbiterServer({
    socketPath, dbPath: join(tmp, "symbols.sqlite"), eventDir, log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: file, level: "local-model" }] } as never,
  });
  await arbiter.listen();
  const client = new ArbiterClient(socketPath);
  await client.connect();
  const proxy = new OpenAiProxy({
    arbiter: new ProxyAdapter(client),
    upstreamOrigin: api.origin,
    chatgptOrigin: `${chatgpt.origin}/backend-api/codex`,
    sessionKey: "cx-chatgpt",
    log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    const signed = await post(port, SIGNED_IN, readTurn(file));
    assert.equal(signed.status, 200, signed.body);
    assert.match(signed.body, /chatgpt-answered/);
    const keyed = await post(port, KEYED, readTurn(file));
    assert.equal(keyed.status, 200, keyed.body);
    assert.match(keyed.body, /api-answered/);

    assert.deepEqual(chatgpt.seen.map((s) => s.path), ["/backend-api/codex/responses"]);
    assert.deepEqual(api.seen.map((s) => s.path), ["/v1/responses"]);
    assert.equal(chatgpt.seen[0]!.auth, `Bearer ${BEARER}`, "the sign-in is relayed as Codex sent it");
    assert.equal(chatgpt.seen[0]!.account, ACCOUNT);
    for (const [name, up] of [["ChatGPT backend", chatgpt], ["API", api]] as const) {
      const body = up.seen[0]!.body;
      assert.ok(!body.includes(CANARY), `the ${name} never saw the file's content`);
      assert.match(body, /\$MDU:[a-z]+_[A-Za-z_]+\[[0-9a-f]+\]/, `the file reached the ${name} as a symbol`);
      assert.ok(!body.includes(ACCOUNT) && !body.includes(BEARER), `no credential in the ${name}'s body`);
    }
    // No credential in the session's events on disk. (The file's content is
    // there by design: an event carries both forms, DualRepr, for the
    // human-side dashboard.)
    await proxy.close();
    const events = readdirSync(eventDir, { recursive: true }).map(String)
      .filter((f) => f.endsWith(".ndjson")).map((f) => readFileSync(join(eventDir, f), "utf8")).join("\n");
    assert.ok(events.length > 0, "the exchange emitted events");
    for (const v of [BEARER, ACCOUNT, API_KEY]) assert.ok(!events.includes(v), `no ${v.slice(0, 8)}… in events`);
  } finally {
    await proxy.close();
    client.close();
    await arbiter.close();
    await chatgpt.close();
    await api.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("FAIL-CLOSED: with the arbiter gone, a ChatGPT sign-in's turn is refused (502) and nothing reaches the backend", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-chatgpt-fc-"));
  const file = join(tmp, "payroll.md");
  writeFileSync(file, BODY + "\n");
  const chatgpt = await upstream("chatgpt");
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: file, level: "local-model" }] } as never,
  });
  await arbiter.listen();
  const client = new ArbiterClient(socketPath);
  await client.connect();
  const proxy = new OpenAiProxy({
    arbiter: new ProxyAdapter(client), upstreamOrigin: "http://127.0.0.1:9",
    chatgptOrigin: `${chatgpt.origin}/backend-api/codex`, sessionKey: "cx-chatgpt-fc", log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    client.close();
    await arbiter.close();
    const r = await post(port, SIGNED_IN, readTurn(file));
    assert.equal(r.status, 502, r.body);
    assert.equal(chatgpt.seen.length, 0, "nothing reached the ChatGPT backend");
  } finally {
    await proxy.close();
    await chatgpt.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
