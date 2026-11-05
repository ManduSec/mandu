/**
 * gemini-wire-secrets — a Gemini provider routed through the model proxy at
 * /_mandu/google/<id> (model-wires.md §4), over the REAL arbiter, its REAL
 * IPC and the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock), humanPlane)`), against a scripted Gemini model (no
 * key, no network). `secrets` axes: the product default, stated.
 *
 * THE INVARIANT on the new ingress: a registered secret in a tool result
 * reaches the Gemini model ONLY as its `$MDU:` placeholder, whatever wrapper
 * the client puts the tool's text in:
 *   - OpenClaw (`{output}`): a `read` of the registered file;
 *   - Goose (`{content: {text}}`): an `exec` that printed the value;
 *   - OpenCode (`{name, content}`): a JSON result carrying the value;
 * and the placeholder sits where the tool's text was. And fail-closed: with
 * the arbiter gone, the proxy answers 502 and the model receives nothing.
 *
 * The mock-arbiter version is
 * interceptors/anthropic-proxy/test/component/gemini-route.test.ts.
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
const PATH = "/_mandu/google/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse";

function send(port: number, path: string, body: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-goog-api-key": "AIzaSy-test-not-real" } },
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

const answer = `data: ${JSON.stringify({ candidates: [{ content: { role: "model", parts: [{ text: "ok" }] }, finishReason: "STOP", index: 0 }], responseId: "r1" })}\r\n\r\n`;

/** One Gemini turn: the model called `name(args)`, the tool answered `response`. */
const turn = (name: string, args: Json, response: Json, id: string): Json => ({
  contents: [
    { role: "user", parts: [{ text: "look at the project" }] },
    { role: "model", parts: [{ functionCall: { id, name, args }, thoughtSignature: "c2ln" }] },
    { role: "user", parts: [{ functionResponse: { id, name, response } }] },
  ],
  systemInstruction: { parts: [{ text: "You are the agent." }] },
  tools: [{ functionDeclarations: [{ name: "read", parametersJsonSchema: { type: "object" } }, { name: "exec", parametersJsonSchema: { type: "object" } }] }],
});

/** The function response the model received. */
const forwardedResponse = (up: MockUpstream): Json =>
  (((((up.requests[0]!.json() as Json)["contents"] as Json[])[2]!["parts"]) as Json[])[0]!["functionResponse"] as Json)["response"] as Json;

test("secrets: a registered secret in a Gemini function response reaches the model only as its placeholder (OpenClaw, Goose, OpenCode shapes); the arbiter gone, nothing is sent", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gemini-wire-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  const canary = confCanary("GEMINI");
  const vault = join(ws, "vault", "partner.env");
  const fileBody = secretFileBody(canary);
  writeFileSync(vault, fileBody);

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
  const sessionKey = `gemini-wire-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  const ups: MockUpstream[] = [];
  const through = async (body: Json): Promise<{ up: MockUpstream; status: number }> => {
    const up = new MockUpstream({ sse: answer });
    ups.push(up);
    const proxy = new AnthropicProxy({
      // THE PRODUCTION WIRING: the adapter over the real clients, no bridge.
      arbiter: new ArbiterClientAdapter(real, humanPlane),
      upstream: async () => { throw new Error("the Anthropic upstream was called"); },
      sessionKey,
      log: () => {},
      googleUpstreams: { google: "https://stand-in.invalid/v1beta" },
      googleFetcher: () => up.fetcher,
    });
    proxies.push(proxy);
    const r = await send(await proxy.listen(0), PATH, body);
    return { up, status: r.status };
  };
  try {
    const bound = await real.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "gemini-wire-secrets e2e" });
    assert.equal(bound.bound, "openclaw-agent");
    const reg = await launcher.registerSecret({ path: vault, home, sessionKey });
    assert.ok(typeof (reg.twin ?? reg.symbol) === "string", `registered: ${reg.reason}`);

    // OpenClaw: `read` of the registered file, its text as `{output}`.
    const a = await through(turn("read", { path: vault }, { output: fileBody }, "read_1"));
    assert.equal(a.status, 200);
    const outA = forwardedResponse(a.up);
    assert.deepEqual(Object.keys(outA), ["output"], "the placeholder sits where the tool's text was");
    assert.match(beforeNote(String(outA["output"])), SYMBOL_RE, `OpenClaw's read reaches the model as its placeholder: ${String(outA["output"])}`);

    // Goose: an `exec` that printed the value, as `{content: {text}}`.
    const b = await through(turn("exec", { command: "env | grep PARTNER" }, { content: { text: `HOME=${home}\nPARTNER_API_TOKEN=sk-live-${canary}\n` } }, "toolu_2"));
    assert.equal(b.status, 200);
    const textB = String(((forwardedResponse(b.up)["content"]) as Json)["text"]);
    assert.ok(!textB.includes(canary), `CONFIDENTIALITY VIOLATION: Goose's exec output reached the model raw: ${textB}`);
    assert.match(textB, /\$MDU:/, "the value is a placeholder");

    // OpenCode: a JSON result carrying the value (`{name, content: {...}}`).
    const c = await through(turn("exec", { command: "./report --json" }, { name: "exec", content: { stdout: `token sk-live-${canary}`, exitCode: 0 } }, "call_3"));
    assert.equal(c.status, 200);
    assert.ok(!c.up.requests[0]!.bodyText.includes(canary), "CONFIDENTIALITY VIOLATION: the JSON result reached the model raw");

    // THE ORACLE over every request the model received.
    assert.equal(modelSawCanary(ups.flatMap((u) => u.requests.map((r) => ({ body: r.bodyText }))), canary), false, "no request to the Gemini model carries the secret");

    // Fail-closed: the arbiter gone, the proxy refuses and sends nothing.
    real.close();
    humanPlane.close();
    await server.close();
    const d = await through(turn("read", { path: vault }, { output: fileBody }, "read_4"));
    assert.equal(d.status, 502, "the arbiter unreachable: 502");
    assert.equal(d.up.requests.length, 0, "INVARIANT: nothing reaches the model when the arbiter is gone");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    for (const cl of [launcher, real, humanPlane]) cl.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
