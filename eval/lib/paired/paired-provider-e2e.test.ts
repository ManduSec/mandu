/** Real HTTPS client -> two budget observers -> local HTTPS provider fixture.
 * Keys are fake, no provider network access, invariant tests remain in paired-e2e.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer, request } from "node:https";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { approvalProposal, BatchBudget, PAID_MODEL, summarizeUsage } from "./paired-budget.js";
import { providerTransport, startBudgetObserver } from "./paired-provider.js";

const fixedNow = Date.parse("2026-09-11T09:00:00Z");

test("HTTPS forwarding shares reservations, pins credentials, and fails closed on missing usage", async () => {
  const dir = mkdtempSync(join(tmpdir(), "paired-provider-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", join(dir, "key"), "-out", join(dir, "cert")], { stdio: "pipe" });
  const tls = { key: readFileSync(join(dir, "key")), cert: readFileSync(join(dir, "cert")) };
  const forwarded: { headers: Record<string, unknown>; body: any }[] = [];
  let incomplete = false;
  let budget: BatchBudget;
  const provider = createServer(tls, (req, res) => {
    let data = ""; req.on("data", (b) => { data += b; });
    req.on("end", () => {
      forwarded.push({ headers: req.headers, body: JSON.parse(data) });
      assert.ok(budget.snapshot().requests.some((r) => r.state === "reserved"));
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ type: "message", model: PAID_MODEL, stop_reason: "end_turn", content: [{ type: "text", text: "benign" }], ...(incomplete ? {} : { usage: { input_tokens: 20, output_tokens: 10 } }) }));
    });
  });
  await new Promise<void>((resolve) => provider.listen(0, "127.0.0.1", resolve));
  const origin = `https://127.0.0.1:${(provider.address() as AddressInfo).port}`;
  const snapshots: unknown[] = [];
  budget = new BatchBudget({ ...approvalProposal(fixedNow), approved: true }, () => fixedNow, (s) => snapshots.push(s));
  const send = providerTransport("test-provider-key-never-log", { origin, ca: tls.cert });
  const model = await startBudgetObserver(tls, budget, "BP-01-wrapped-default", "model", send);
  const inspection = await startBudgetObserver(tls, budget, "BP-01-wrapped-default", "inspection", send);
  const post = (endpoint: string, body: unknown) => new Promise<number>((resolve, reject) => {
    const req = request(endpoint + "/v1/messages?beta=true", { method: "POST", ca: tls.cert, headers: { "content-type": "application/json", "x-api-key": "local-dummy", "authorization": "Bearer local-only", "anthropic-beta": "unapproved-feature" } }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode!)); });
    req.on("error", reject); req.end(JSON.stringify(body));
  });
  const body = { model: PAID_MODEL, messages: [{ role: "user", content: "benign" }], max_tokens: 32000 };
  try {
    assert.deepEqual(await Promise.all([post(model.origin, body), post(inspection.origin, body)]), [200, 200]);
    assert.equal(forwarded.length, 2);
    assert.ok(forwarded.every((r) => r.headers["x-api-key"] === "test-provider-key-never-log" && !r.headers.authorization && !r.headers["anthropic-beta"]));
    assert.ok(forwarded.every((r) => r.body.max_tokens === 4096 && r.body.service_tier === "standard_only"));
    assert.equal(budget.snapshot().upperBoundUsd, 0.00018);
    assert.deepEqual(summarizeUsage(budget.snapshot(), "BP-01-wrapped-default", "model").observedTokens, { uncachedInput: 20, cacheWrite: 0, cacheRead: 0, output: 10 });
    assert.deepEqual(new Set(budget.snapshot().requests.map((r) => r.channel)), new Set(["model", "inspection"]));
    incomplete = true;
    assert.equal(await post(inspection.origin, body), 502);
    assert.equal(budget.snapshot().requests[2].state, "uncertain");
    assert.equal(await post(model.origin, body), 502);
    assert.equal(forwarded.length, 3);
    assert.equal(budget.snapshot().upperBoundUsd, 0.42066);
    const partial = summarizeUsage(budget.snapshot(), "BP-01-wrapped-default", "inspection");
    assert.equal(partial.status, "partial");
    assert.equal(partial.completionRequests, 2);
    assert.equal(partial.observedResponses, 1);
    assert.equal(partial.observedTokens?.output, 10);
    assert.doesNotMatch(JSON.stringify([model.requests, model.receipts, model.errors, inspection.requests, inspection.receipts, inspection.errors, snapshots]), /test-provider-key-never-log|local-dummy|Bearer local-only/);
    const tooSmall = new BatchBudget({ ...approvalProposal(fixedNow), approved: true, maxUsd: 0.1 }, () => fixedNow);
    const capped = await startBudgetObserver(tls, tooSmall, "BP-02-unwrapped", "model", send);
    try {
      assert.equal(await post(capped.origin, body), 502);
      assert.equal(forwarded.length, 3, "budget refusal precedes provider contact");
      assert.match(tooSmall.snapshot().stopped!, /Insufficient budget/);
    } finally { await capped.close(); }
  } finally {
    await model.close(); await inspection.close();
    await new Promise<void>((resolve) => { provider.closeAllConnections(); provider.close(() => resolve()); });
    rmSync(dir, { recursive: true, force: true });
  }
});
