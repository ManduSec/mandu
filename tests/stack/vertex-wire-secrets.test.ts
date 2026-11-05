/**
 * vertex-wire-secrets — OpenClaw's google-vertex provider (Vertex AI's Gemini
 * models) routed through the model proxy at its ROOT (model-wires.md §4.1,
 * "Vertex AI at the root"), over the REAL arbiter, its REAL IPC and the
 * PRODUCTION proxy wiring (`new ArbiterClientAdapter(new ArbiterClient(sock),
 * humanPlane)`), against a scripted Vertex model per origin (no key, no
 * network). `secrets` axes: the product default, stated.
 *
 * THE INVARIANT on the new ingress: a registered secret in a tool result
 * reaches the Vertex model ONLY as its `$MDU:` placeholder, on OpenClaw's own
 * Vertex path (`/v1/projects/{p}/locations/{l}/publishers/google/models/
 * {m}:streamGenerateContent?alt=sse`), at Google's Vertex host for the
 * path's location, with the OAuth bearer as OpenClaw sent it. And
 * fail-closed: with the arbiter gone the proxy answers 502 and the model
 * receives nothing; a session that routes no Vertex provider sends nothing.
 *
 * The mock-arbiter version is
 * interceptors/anthropic-proxy/test/component/vertex-route.test.ts.
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
const PATH = "/v1/projects/acme-prod/locations/europe-west4/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse";
const BEARER = "Bearer ya29.vertex-stack-test-not-a-token";

function send(port: number, path: string, body: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), authorization: BEARER, "x-mandu-session-id": "vertex-stack" } },
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

/** OpenClaw's Vertex turn: the model called `read`, the tool answered `{output}`. */
const turn = (path: string, output: string, id: string): Json => ({
  contents: [
    { role: "user", parts: [{ text: "look at the project" }] },
    { role: "model", parts: [{ functionCall: { id, name: "read", args: { path } } }] },
    { role: "user", parts: [{ functionResponse: { id, name: "read", response: { output } } }] },
  ],
  systemInstruction: { parts: [{ text: "You are OpenClaw." }] },
  tools: [{ functionDeclarations: [{ name: "read", parametersJsonSchema: { type: "object" } }] }],
});

const forwardedOutput = (up: MockUpstream): unknown =>
  ((((((up.requests[0]!.json() as Json)["contents"] as Json[])[2]!["parts"]) as Json[])[0]!["functionResponse"] as Json)["response"] as Json)["output"];

test("secrets: a registered secret in a Vertex AI function response reaches the model only as its placeholder, at Google's host for the location; the arbiter gone or no Vertex route, nothing is sent", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-vertex-wire-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  const canary = confCanary("VERTEX");
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
  const sessionKey = `vertex-wire-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  const ups: MockUpstream[] = [];
  const origins: string[] = [];
  const through = async (body: Json, vertex = true): Promise<{ up: MockUpstream; status: number }> => {
    const up = new MockUpstream({ sse: answer });
    ups.push(up);
    const proxy = new AnthropicProxy({
      // THE PRODUCTION WIRING: the adapter over the real clients, no bridge.
      arbiter: new ArbiterClientAdapter(real, humanPlane),
      upstream: async () => { throw new Error("the Anthropic upstream was called"); },
      sessionKey,
      log: () => {},
      ...(vertex ? { vertexUpstream: { provider: "google-vertex", upstream: null } } : {}),
      vertexFetcher: (origin) => { origins.push(origin); return up.fetcher; },
    });
    proxies.push(proxy);
    const r = await send(await proxy.listen(0), PATH, body);
    return { up, status: r.status };
  };
  try {
    const bound = await real.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "vertex-wire-secrets e2e" });
    assert.equal(bound.bound, "openclaw-agent");
    const reg = await launcher.registerSecret({ path: vault, home, sessionKey });
    assert.ok(typeof (reg.twin ?? reg.symbol) === "string", `registered: ${reg.reason}`);

    const a = await through(turn(vault, fileBody, "read_1"));
    assert.equal(a.status, 200);
    assert.deepEqual(origins, ["https://europe-west4-aiplatform.googleapis.com"], "Google's own host for the path's location");
    assert.equal(a.up.requests[0]!.path, PATH, "OpenClaw's own Vertex path");
    assert.equal(a.up.requests[0]!.headers["authorization"], BEARER, "the OAuth bearer passes as sent");
    assert.match(beforeNote(String(forwardedOutput(a.up))), SYMBOL_RE, `the read reaches the model as its placeholder: ${String(forwardedOutput(a.up))}`);
    assert.equal(modelSawCanary(ups.flatMap((u) => u.requests.map((r) => ({ body: r.bodyText }))), canary), false, "no request to the Vertex model carries the secret");

    // No Vertex provider in the session: refused, nothing sent.
    const n = await through(turn(vault, fileBody, "read_2"), false);
    assert.equal(n.status, 403);
    assert.equal(n.up.requests.length, 0, "a session that routes no Vertex provider sends nothing");

    // Fail-closed: the arbiter gone, the proxy refuses and sends nothing.
    real.close();
    humanPlane.close();
    await server.close();
    const d = await through(turn(vault, fileBody, "read_3"));
    assert.equal(d.status, 502, "the arbiter unreachable: 502");
    assert.equal(d.up.requests.length, 0, "INVARIANT: nothing reaches the model when the arbiter is gone");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    for (const cl of [launcher, real, humanPlane]) cl.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
