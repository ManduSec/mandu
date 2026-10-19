/**
 * cloud-model.test — plan 11 §8 item 3 in the model proxy: with its upstream
 * a main model declared `local: true` (`upstreamLocal`, env
 * MANDU_UPSTREAM_LOCAL=1), a request naming a cloud-backed model (Ollama's
 * `:cloud` / `-cloud` tags run on the vendor's servers behind the same
 * loopback API) is refused with an Anthropic-shaped 400 and NOTHING reaches
 * the upstream, before any arbiter call. Without the flag, or with a model
 * that runs locally, the request is forwarded as before.
 *
 * The predicate's mirrors are pinned together by
 * tests/stack/cloud-model-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { isCloudBackedModel } from "../../src/cloud-model.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildTextSse } from "../helpers/mock-upstream.js";

// Axes: none. The refusal reads no protection axis (a cloud model at a local
// upstream is refused in every mode), and the arbiter here is the in-test
// MockArbiter (no policy, no axis resolution).

function post(port: number, path: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json" } },
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
  messages: [
    { role: "user", content: "summarize the contract" },
    { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Read", input: { file_path: "/w/contract.md" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "Acme pays $4,200,000. LOCAL_CANARY_2026" }] },
  ],
});

async function withProxy<T>(upstreamLocal: boolean | undefined, fn: (port: number, upstream: MockUpstream, arbiter: MockArbiter) => Promise<T>): Promise<T> {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, ...(upstreamLocal === undefined ? {} : { upstreamLocal }) });
  const port = await proxy.listen(0);
  try {
    return await fn(port, upstream, arbiter);
  } finally {
    await proxy.close();
  }
}

test("isCloudBackedModel (proxy copy): cloud tags yes, local names and near misses no", () => {
  for (const n of ["gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", "glm-4.6:cloud", "deepseek-v3.1-cloud", "GPT-OSS:120B-CLOUD"]) assert.equal(isCloudBackedModel(n), true, n);
  for (const n of ["gpt-oss:20b", "llama3.2:latest", "claude-sonnet-4-5", "wordcloud:7b", ""]) assert.equal(isCloudBackedModel(n), false, n);
});

test("upstreamLocal: a cloud-backed model is refused with an Anthropic-shaped 400; nothing is sent, the arbiter is not asked", async () => {
  await withProxy(true, async (port, upstream, arbiter) => {
    for (const [path, model] of [["/v1/messages", "gpt-oss:120b-cloud"], ["/v1/messages?beta=true", "glm-4.6:cloud"], ["/v1/messages/count_tokens", "qwen3-coder:480b-cloud"]] as const) {
      const r = await post(port, path, body(model));
      assert.equal(r.status, 400, `${path}: ${r.body}`);
      const j = JSON.parse(r.body) as { type: string; error: { type: string; message: string } };
      assert.equal(j.type, "error");
      assert.equal(j.error.type, "invalid_request_error");
      assert.match(j.error.message, new RegExp(`^mandu: refusing model ${model.replace(/[.]/g, "\\.")}: it runs on the vendor's servers \\(a cloud model\\), and your main model is declared local: true in policy\\.yaml models:, so nothing was sent\\.`));
      assert.ok(!/ — /.test(j.error.message), "no em-dash interjection");
    }
    assert.equal(upstream.requests.length, 0, "nothing reached the upstream");
    assert.equal(arbiter.classifyCalls.length, 0, "refused before any classify");
    assert.equal(arbiter.gateSurfaceCalls.length, 0, "refused before the gate surface is read");
  });
});

test("upstreamLocal: a model that runs on this machine is forwarded as before", async () => {
  await withProxy(true, async (port, upstream) => {
    const r = await post(port, "/v1/messages", body("gpt-oss:20b"));
    assert.equal(r.status, 200, r.body);
    assert.equal(upstream.requests.length, 1);
    assert.equal((upstream.lastJson() as { model: string }).model, "gpt-oss:20b");
    assert.ok(!upstream.requests[0]!.bodyText.includes("LOCAL_CANARY_2026"), "the usual rewrite still ran (the tool result is a symbol)");
  });
});

test("not a local upstream (the default, or false): a cloud-named model is forwarded; the rule is only for a declared local model", async () => {
  for (const flag of [undefined, false]) {
    await withProxy(flag, async (port, upstream) => {
      const r = await post(port, "/v1/messages", body("gpt-oss:120b-cloud"));
      assert.equal(r.status, 200, r.body);
      assert.equal(upstream.requests.length, 1, `forwarded with upstreamLocal=${String(flag)}`);
    });
  }
});
