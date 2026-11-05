/**
 * ollama-wire-secrets — an OpenClaw provider on Ollama's native chat API
 * routed through the model proxy at /_mandu/ollama/<id> (model-wires.md,
 * "The Ollama wire"), over the REAL arbiter, its REAL IPC and the PRODUCTION
 * proxy wiring (`new ArbiterClientAdapter(new ArbiterClient(sock),
 * humanPlane)`), against a scripted Ollama model (no key, no network, no
 * Ollama install). `secrets` axes: the product default, stated.
 *
 * THE INVARIANT on the new ingress: a registered secret in a tool result
 * reaches the Ollama model ONLY as its `$MDU:` placeholder, in each request
 * shape the OpenClaw releases send:
 *   - 2026.9.9 / 2026.10.7: a `read` of the registered file, the result
 *     carrying `tool_call_id`;
 *   - 2026.3.12: two `read`s with NO ids anywhere, results by `tool_name` in
 *     order (the second is the registered file: correlation by position);
 *   - an `exec` that printed the value (the value backstop);
 *   - a tool result with an image (masked whole with it, the image gone);
 * and the placeholder sits in the tool message's `content`. And fail-closed:
 * with the arbiter gone, the proxy answers 502 and the model receives
 * nothing.
 *
 * The mock-arbiter version is
 * interceptors/anthropic-proxy/test/component/ollama-route.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";
import { confCanary, modelSawCanary, secretFileBody } from "../lib/conf-exfil.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

type Json = Record<string, unknown>;

const SYMBOL_RE = /^\$MDU:[a-z]+_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_]+)*$/;
/** A masked `read` of a no-model file ends with the protected-file note (confidentiality.md §7.1, "A protected file read whole"): the symbol is what comes before it. */
const beforeNote = (s: string): string => {
  const at = s.indexOf("\n\n[mandu:secret] masked: ");
  if (at >= 0) assert.match(s.slice(at), /is a protected file that no AI model may read/, "the note says what the symbol is");
  return at < 0 ? s : s.slice(0, at);
};
const PATH = "/_mandu/ollama/ollama/api/chat";
const IMG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB";

function send(port: number, path: string, body: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), authorization: "Bearer ollama-local" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

const answer = [
  { model: "qwen3:8b", created_at: "2026-10-26T00:00:00Z", message: { role: "assistant", content: "ok" }, done: false },
  { model: "qwen3:8b", created_at: "2026-10-26T00:00:01Z", message: { role: "assistant", content: "" }, done: true, done_reason: "stop" },
].map((o) => `${JSON.stringify(o)}\n`).join("");

const TOOLS = [
  { type: "function", function: { name: "read", description: "", parameters: { type: "object" } } },
  { type: "function", function: { name: "exec", description: "", parameters: { type: "object" } } },
];

/** One OpenClaw turn on the Ollama wire: the model's calls, then each tool message. */
const turn = (calls: Json[], results: Json[]): Json => ({
  model: "qwen3:8b",
  messages: [
    { role: "system", content: "You are the agent." },
    { role: "user", content: "look at the project" },
    { role: "assistant", content: "", tool_calls: calls },
    ...results.map((r) => ({ role: "tool", ...r })),
  ],
  stream: true,
  tools: TOOLS,
  options: { num_ctx: 32768 },
});

/** The tool messages the model received. */
const forwardedTools = (up: MockUpstream): Json[] =>
  ((up.requests[0]!.json() as Json)["messages"] as Json[]).filter((m) => m["role"] === "tool");

test("secrets: a registered secret in an Ollama tool message reaches the model only as its placeholder (OpenClaw 2026.3.12 to 2026.10.7 shapes); the arbiter gone, nothing is sent", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ollama-wire-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  const canary = confCanary("OLLAMA");
  const vault = join(ws, "vault", "partner.env");
  const fileBody = secretFileBody(canary);
  writeFileSync(vault, fileBody);
  const pub = join(ws, "README.md");
  writeFileSync(pub, "# a public readme\n");

  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "vault"), level: "no-model", recursive: true }] } as never,
  });
  await server.listen();
  const launcher = new ArbiterClient(sock);
  const real = new ArbiterClient(sock);
  const humanPlane = new ArbiterClient(join(tmp, "human", "h.sock"));
  await Promise.all([launcher.connect(), real.connect(), humanPlane.connect()]);
  const sessionKey = `ollama-wire-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  const ups: MockUpstream[] = [];
  const through = async (body: Json): Promise<{ up: MockUpstream; status: number }> => {
    const up = new MockUpstream({ sse: answer, headers: { "content-type": "application/x-ndjson" } });
    ups.push(up);
    const proxy = new AnthropicProxy({
      // THE PRODUCTION WIRING: the adapter over the real clients, no bridge.
      arbiter: new ArbiterClientAdapter(real, humanPlane),
      upstream: async () => { throw new Error("the Anthropic upstream was called"); },
      sessionKey,
      log: () => {},
      ollamaUpstreams: { ollama: "http://127.0.0.1:11434" },
      ollamaFetcher: () => up.fetcher,
    });
    proxies.push(proxy);
    const r = await send(await proxy.listen(0), PATH, body);
    return { up, status: r.status };
  };
  try {
    const bound = await real.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "ollama-wire-secrets e2e" });
    assert.equal(bound.bound, "openclaw-agent");
    const reg = await launcher.registerSecret({ path: vault, home, sessionKey });
    assert.ok(typeof (reg.twin ?? reg.symbol) === "string", `registered: ${reg.reason}`);

    // 2026.9.9 / 2026.10.7: `read` of the registered file, with ids both ways.
    const a = await through(turn(
      [{ id: "mandu_r1", function: { name: "read", arguments: { path: vault } } }],
      [{ content: fileBody, tool_call_id: "mandu_r1", tool_name: "read" }],
    ));
    assert.equal(a.status, 200);
    const outA = forwardedTools(a.up)[0]!;
    assert.match(beforeNote(String(outA["content"])), SYMBOL_RE, `the read reaches the model as its placeholder: ${String(outA["content"])}`);
    assert.equal(outA["tool_call_id"], "mandu_r1", "the agent's own fields stay");

    // 2026.3.12: no ids anywhere; the second read is the registered file.
    const b = await through(turn(
      [{ function: { name: "read", arguments: { path: pub } } }, { function: { name: "read", arguments: { path: vault } } }],
      [{ content: "# a public readme\n", tool_name: "read" }, { content: fileBody, tool_name: "read" }],
    ));
    assert.equal(b.status, 200);
    const outB = forwardedTools(b.up);
    assert.equal(outB[0]!["content"], "# a public readme\n", "the public file's read goes as it is");
    assert.match(beforeNote(String(outB[1]!["content"])), SYMBOL_RE, `correlated by position, the registered file's read is its placeholder: ${String(outB[1]!["content"])}`);

    // An `exec` that printed the value (the value backstop).
    const c = await through(turn(
      [{ id: "e1", function: { name: "exec", arguments: { command: "env | grep PARTNER" } } }],
      [{ content: `HOME=${home}\nPARTNER_API_TOKEN=sk-live-${canary}\n`, tool_call_id: "e1", tool_name: "exec" }],
    ));
    assert.equal(c.status, 200);
    const textC = String(forwardedTools(c.up)[0]!["content"]);
    assert.ok(!textC.includes(canary), `CONFIDENTIALITY VIOLATION: the exec output reached the model raw: ${textC}`);
    assert.match(textC, /\$MDU:/, "the value is a placeholder");

    // A tool result with an image: masked whole, the image gone.
    const d = await through(turn(
      [{ id: "v1", function: { name: "read", arguments: { path: vault } } }],
      [{ content: `${fileBody}\n(see attached image)`, images: [IMG], tool_call_id: "v1", tool_name: "read" }],
    ));
    assert.equal(d.status, 200);
    const outD = forwardedTools(d.up)[0]!;
    assert.match(String(outD["content"]), /\$MDU:/);
    assert.equal(outD["images"], undefined, "the tool's image left with its masked result");

    // THE ORACLE over every request the model received.
    assert.equal(modelSawCanary(ups.flatMap((u) => u.requests.map((r) => ({ body: r.bodyText }))), canary), false, "no request to the Ollama model carries the secret");

    // Fail-closed: the arbiter gone, the proxy refuses and sends nothing.
    real.close();
    humanPlane.close();
    await server.close();
    const e = await through(turn(
      [{ id: "r4", function: { name: "read", arguments: { path: vault } } }],
      [{ content: fileBody, tool_call_id: "r4", tool_name: "read" }],
    ));
    assert.equal(e.status, 502, "the arbiter unreachable: 502");
    assert.equal(e.up.requests.length, 0, "INVARIANT: nothing reaches the model when the arbiter is gone");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    for (const cl of [launcher, real, humanPlane]) cl.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
