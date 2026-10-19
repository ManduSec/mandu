/**
 * auth-substitution.test.ts — Codex's saved key put back in the auth header
 * of the request the openai-proxy forwards (agent-sign-in.md §3.9): the
 * copied pure step (kept equal to the anthropic-proxy's), the adapter asking
 * the gate and the resolve on the HUMAN client only, and the proxy over real
 * loopback listeners standing in for the API origin and the ChatGPT base:
 *
 *   - `Authorization: Bearer <placeholder>` to the API origin: the key, when
 *     the gate allows it at that origin's host; the body keeps the symbol;
 *   - an origin the gate does not allow: the placeholder (the provider
 *     answers 401); the proxy makes no 401 up;
 *   - a ChatGPT sign-in's request: never asked about, relayed as written;
 *   - no op (no human plane): the placeholder.
 *
 * Made-up keys only; no network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CHATGPT_ACCOUNT_HEADER, OpenAiProxy } from "../../src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { buildTextSse } from "../helpers/mock-upstream.js";

// Axes: none. The arbiter is the in-test MockArbiter plus a scripted
// authCredential; the real gate on this path is tests/stack/auth-substitution.test.ts.

const HERE = dirname(fileURLToPath(import.meta.url));
const SYM = "$MDU:nomodel_Read[c0de].OPENAI_API_KEY";
const KEY = "sk-proj-MANDUFAKEcodexSAVEDkey0123456789";

interface Seen { path: string; headers: Record<string, string | string[] | undefined>; body: string }

async function standIn(): Promise<{ server: Server; origin: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push({ path: req.url ?? "", headers: req.headers, body: b });
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("hello"));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

const close = (s: Server): Promise<void> => new Promise((r) => s.close(() => r()));

function send(port: number, headers: Record<string, string>, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json", ...headers } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(body);
  });
}

const turn = (text: string): string => JSON.stringify({ model: "gpt-5.4", stream: true, input: [{ type: "message", role: "user", content: [{ type: "input_text", text }] }] });

/** A mock arbiter whose authCredential releases KEY at `host` only. */
function arbiterReleasingAt(host: string): MockArbiter & { asks: string[] } {
  const a = new MockArbiter() as MockArbiter & { asks: string[]; authCredential: (req: { symbol: string; destination: string }) => Promise<{ value: string | null; reason: string }> };
  a.asks = [];
  a.authCredential = async (req) => {
    a.asks.push(`${req.symbol}@${req.destination}`);
    if (req.symbol !== SYM) return { value: null, reason: "unknown" };
    return req.destination.replace(/:\d+$/, "") === host ? { value: KEY, reason: "bound" } : { value: null, reason: `unbound destination '${req.destination}'` };
  };
  return a;
}

test("the copied step stays equal to the anthropic-proxy's", () => {
  const strip = (s: string) => s.slice(s.indexOf("/** The placeholder grammar"));
  const mine = readFileSync(join(HERE, "..", "..", "src", "auth-substitution.ts"), "utf8");
  const theirs = readFileSync(join(HERE, "..", "..", "..", "anthropic-proxy", "src", "auth-substitution.ts"), "utf8");
  assert.equal(strip(mine), strip(theirs), "keep interceptors/*/src/auth-substitution.ts equal below the header");
});

test("Bearer <placeholder> to the API origin: the key, the body keeps the symbol; another origin keeps the placeholder", async () => {
  const api = await standIn();
  const arbiter = arbiterReleasingAt("127.0.0.1");
  const logs: string[] = [];
  const proxy = new OpenAiProxy({ arbiter, upstreamOrigin: api.origin, log: (m) => logs.push(m) });
  const port = await proxy.listen(0);
  try {
    assert.equal(await send(port, { authorization: `Bearer ${SYM}` }, turn(`my key ${SYM}`)), 200);
    const up = api.seen.at(-1)!;
    assert.equal(up.headers["authorization"], `Bearer ${KEY}`, "the key put back");
    assert.ok(up.body.includes(SYM) && !up.body.includes(KEY), "the model's context keeps the symbol");
    assert.ok(logs.some((l) => /put the key back in authorization/.test(l)));
    assert.ok(!logs.join("\n").includes(KEY), "never a value in a log line");
    // Another header holding the symbol is relayed as written.
    await send(port, { authorization: `Bearer ${SYM}`, "x-other": SYM }, turn("hi"));
    assert.equal(api.seen.at(-1)!.headers["x-other"], SYM);
  } finally {
    await proxy.close();
  }
  // The same symbol toward an origin the gate does not release at.
  const other = new OpenAiProxy({ arbiter: arbiterReleasingAt("api.openai.com"), upstreamOrigin: api.origin, log: () => {} });
  const port2 = await other.listen(0);
  try {
    assert.equal(await send(port2, { authorization: `Bearer ${SYM}` }, turn("hi")), 200, "relayed; the provider would answer 401, the proxy makes none up");
    assert.equal(api.seen.at(-1)!.headers["authorization"], `Bearer ${SYM}`);
  } finally {
    await other.close();
    await close(api.server);
  }
});

test("a ChatGPT sign-in's request is never asked about; without the op the placeholder is relayed", async () => {
  const api = await standIn();
  const chatgpt = await standIn();
  const arbiter = arbiterReleasingAt("127.0.0.1");
  const proxy = new OpenAiProxy({ arbiter, upstreamOrigin: api.origin, chatgptOrigin: `${chatgpt.origin}/backend-api/codex`, log: () => {} });
  const port = await proxy.listen(0);
  try {
    await send(port, { authorization: `Bearer ${SYM}`, [CHATGPT_ACCOUNT_HEADER]: "acct-dummy" }, turn("hi"));
    assert.equal(chatgpt.seen.at(-1)!.headers["authorization"], `Bearer ${SYM}`, "relayed as written");
    assert.deepEqual(arbiter.asks, [], "the gate was not asked");
  } finally {
    await proxy.close();
  }
  const bare = new OpenAiProxy({ arbiter: new MockArbiter(), upstreamOrigin: api.origin, log: () => {} });
  const port2 = await bare.listen(0);
  try {
    await send(port2, { authorization: `Bearer ${SYM}` }, turn("hi"));
    assert.equal(api.seen.at(-1)!.headers["authorization"], `Bearer ${SYM}`, "no op: the placeholder");
  } finally {
    await bare.close();
    await close(api.server);
    await close(chatgpt.server);
  }
});

test("ArbiterClientAdapter.authCredential: the gate then the resolve, both on the HUMAN client; none ⇒ null", async () => {
  const calls: string[] = [];
  const data = { resolve: async () => { calls.push("data.resolve"); return KEY; } } as unknown as RealArbiterClient;
  const human = {
    symbolShape: async () => null, sessionRelay: async () => null, noteReserveBlock: async () => {},
    desymbolizationDecision: async (req: { positions?: string[]; destination?: string }) => { calls.push(`gate ${req.destination} ${req.positions?.join(",")}`); return { allow: true as const, reason: "bound" }; },
    resolve: async (s: string) => { calls.push(`human.resolve ${s}`); return KEY; },
  };
  const a = new ArbiterClientAdapter(data, human);
  assert.deepEqual(await a.authCredential({ symbol: SYM, destination: "api.openai.com", scheme: "https" }), { value: KEY, reason: "bound" });
  assert.deepEqual(calls, ["gate api.openai.com authorization", `human.resolve ${SYM}`], "never the data socket");
  const denied = new ArbiterClientAdapter(data, { ...human, desymbolizationDecision: async () => ({ allow: false as const, reason: "unbound" }) });
  assert.deepEqual(await denied.authCredential({ symbol: SYM, destination: "evil.example", scheme: "https" }), { value: null, reason: "unbound" });
  assert.equal((await new ArbiterClientAdapter(data).authCredential({ symbol: SYM, destination: "api.openai.com", scheme: "https" })).value, null, "no human plane");
});
