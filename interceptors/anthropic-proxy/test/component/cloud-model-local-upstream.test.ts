/**
 * cloud-model-local-upstream.test.ts — E2E: plan 11 §8 item 3 over a REAL
 * HTTP upstream. The proxy's own default fetcher points at a loopback server
 * standing in for a local Ollama (the phase 3 shape: MANDU_UPSTREAM is a
 * declared `local: true` model, MANDU_UPSTREAM_LOCAL=1). A request naming a
 * cloud-backed model (`gpt-oss:120b-cloud`, which Ollama would relay to
 * ollama.com) is refused and the stand-in records ZERO connections, while
 * the same stack forwards a model that runs locally (positive control, so
 * the zero is not a dead upstream).
 *
 * Run: npm run test:component
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { AnthropicProxy } from "../../src/proxy.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { buildTextSse } from "../helpers/mock-upstream.js";

// Axes: none. The refusal reads no protection axis, and the arbiter is the
// in-test MockArbiter (no policy, no axis resolution).

const CANARY = "LOCAL_CANARY_2026 Acme pays $4,200,000";

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
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
  max_tokens: 64,
  messages: [{ role: "user", content: `Summarize this: ${CANARY}` }],
});

test("a cloud-backed model at a declared local upstream: 400 to the agent, zero connections at the upstream; a local model goes through", async () => {
  let connections = 0;
  const seen: string[] = [];
  const upstream: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push(b);
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("from-the-local-model", { deltas: 1 }));
    });
  });
  upstream.on("connection", () => { connections++; });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const proxy = new AnthropicProxy({ arbiter: new MockArbiter(), upstreamOrigin: origin, upstreamLocal: true, log: () => {}, retry: { maxAttempts: 1 } });
  const port = await proxy.listen(0);
  try {
    for (const model of ["gpt-oss:120b-cloud", "deepseek-v3.1:671b-cloud", "minimax-m2:cloud"]) {
      const r = await post(port, body(model));
      assert.equal(r.status, 400, r.body);
      assert.match(r.body, /"type":"invalid_request_error"/);
      assert.match(r.body, /runs on the vendor's servers \(a cloud model\)/);
    }
    assert.equal(connections, 0, "the upstream saw no connection at all");
    assert.deepEqual(seen, [], "and no request");

    const ok = await post(port, body("gpt-oss:20b"));
    assert.equal(ok.status, 200, ok.body);
    assert.match(ok.body, /from-the-local-model/);
    assert.equal(seen.length, 1, "the local model's request was forwarded");
    assert.ok(connections >= 1);
  } finally {
    await proxy.close();
    await new Promise<void>((r) => upstream.close(() => r()));
  }
});
