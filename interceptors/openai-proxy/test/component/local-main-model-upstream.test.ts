/**
 * local-main-model-upstream.test.ts — E2E: Codex's declared main model (plan
 * 11 §7.2) over a REAL HTTP upstream. The proxy's own default fetcher points
 * at a loopback server standing in for a local OpenAI-compatible server
 * (Ollama, vLLM), with the launcher's phase 3 settings: MANDU_UPSTREAM is the
 * entry's url, the model_provider base_url Codex would have used
 * (`upstreamIsBaseUrl`), and the entry is `local: true` (`upstreamLocal`).
 *
 *   1. The proxy's own `/v1` maps onto the entry's base path: Codex's
 *      `/v1/responses` reaches `<base>/responses`, never `<base>/v1/responses`.
 *   2. A request naming a cloud-backed model is refused with a 400 and the
 *      stand-in records ZERO connections; a local model goes through
 *      (positive control, so the zero is not a dead upstream).
 *
 * The analogue of anthropic-proxy/test/component/cloud-model-local-upstream.test.ts.
 * Run: npm run test:component
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { OpenAiProxy } from "../../src/proxy.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { buildTextSse } from "../helpers/mock-upstream.js";

// Axes: none. The path mapping and the refusal read no protection axis, and
// the arbiter is the in-test MockArbiter (no policy, no axis resolution).

const CANARY = "LOCAL_CANARY_2026 Acme pays $4,200,000";

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } },
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

const body = (model: string): string => JSON.stringify({
  model,
  stream: true,
  input: [{ type: "message", role: "user", content: [{ type: "input_text", text: `Summarize this: ${CANARY}` }] }],
});

async function standIn(): Promise<{ server: Server; origin: string; paths: string[]; bodies: string[]; connections: () => number }> {
  let connections = 0;
  const paths: string[] = [];
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      paths.push(req.url ?? "");
      bodies.push(b);
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("from-the-local-model"));
    });
  });
  server.on("connection", () => { connections++; });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { server, origin, paths, bodies, connections: () => connections };
}

test("a declared base URL: Codex's /v1/responses reaches <base>/responses (no doubled /v1)", async () => {
  for (const [basePath, want] of [["/v1", "/v1/responses"], ["/openai", "/openai/responses"], ["", "/responses"]] as const) {
    const up = await standIn();
    const proxy = new OpenAiProxy({
      arbiter: new MockArbiter(), upstreamOrigin: `${up.origin}${basePath}`, upstreamIsBaseUrl: true, upstreamLocal: true, log: () => {},
    });
    const port = await proxy.listen(0);
    try {
      const r = await post(port, body("gpt-oss:20b"));
      assert.equal(r.status, 200, r.body);
      assert.match(r.body, /from-the-local-model/);
      assert.deepEqual(up.paths, [want], `base ${JSON.stringify(basePath)}`);
    } finally {
      await proxy.close();
      await new Promise<void>((r) => up.server.close(() => r()));
    }
  }
});

test("a cloud-backed model at a declared local upstream: 400 to Codex, zero connections at the upstream; a local model goes through", async () => {
  const up = await standIn();
  const proxy = new OpenAiProxy({
    arbiter: new MockArbiter(), upstreamOrigin: `${up.origin}/v1`, upstreamIsBaseUrl: true, upstreamLocal: true, log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    for (const model of ["gpt-oss:120b-cloud", "deepseek-v3.1:671b-cloud", "minimax-m2:cloud"]) {
      const r = await post(port, body(model));
      assert.equal(r.status, 400, r.body);
      assert.match(r.body, /"type":"invalid_request_error"/);
      assert.match(r.body, /runs on the vendor's servers \(a cloud model\)/);
      assert.match(r.body, /codex -m <name>/);
    }
    assert.equal(up.connections(), 0, "the upstream saw no connection at all");

    const ok = await post(port, body("gpt-oss:20b"));
    assert.equal(ok.status, 200, ok.body);
    assert.equal(up.bodies.length, 1, "the local model's request was forwarded");
  } finally {
    await proxy.close();
    await new Promise<void>((r) => up.server.close(() => r()));
  }
});

test("without upstreamLocal the same cloud name is forwarded (the refusal is for a declared local main model only)", async () => {
  const up = await standIn();
  const proxy = new OpenAiProxy({ arbiter: new MockArbiter(), upstreamOrigin: up.origin, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const r = await post(port, body("gpt-oss:120b-cloud"));
    assert.equal(r.status, 200, r.body);
    assert.deepEqual(up.paths, ["/v1/responses"], "an origin upstream keeps the path as is");
  } finally {
    await proxy.close();
    await new Promise<void>((r) => up.server.close(() => r()));
  }
});
