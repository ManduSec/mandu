/** Real HTTPS client -> two subscription relays -> loopback provider; no real credentials. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer, request } from "node:https";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PAID_MODEL } from "./paired-budget.js";
import { SubscriptionBudget, startSubscriptionObserver } from "./paired-subscription.js";

test("subscription relay preserves native bytes and stops both channels after provider refusal", async () => {
  const dir = mkdtempSync(join(tmpdir(), "paired-subscription-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", join(dir, "key"), "-out", join(dir, "cert")], { stdio: "pipe" });
  const tls = { key: readFileSync(join(dir, "key")), cert: readFileSync(join(dir, "cert")) };
  const b = new SubscriptionBudget();
  const forwarded: { headers: any; text: string }[] = [];
  let refuse = false;
  const provider = createServer(tls, (req, res) => {
    let text = ""; req.on("data", (v) => { text += v; });
    req.on("end", () => {
      forwarded.push({ headers: req.headers, text });
      assert.ok(b.snapshot().requests.some((r) => r.state === "reserved"));
      res.writeHead(refuse ? 429 : 200, { "content-type": "application/json" });
      res.end(refuse ? '{"error":"provider-private-error"}' : JSON.stringify({ type: "message", model: PAID_MODEL, stop_reason: "end_turn", content: [{ type: "text", text: "benign" }], usage: { input_tokens: 20, output_tokens: 10 } }));
    });
  });
  await new Promise<void>((resolve) => provider.listen(0, "127.0.0.1", resolve));
  const fixture = { origin: `https://127.0.0.1:${(provider.address() as AddressInfo).port}`, ca: tls.cert };
  const model = await startSubscriptionObserver(tls, b, "leg", "model", fixture);
  const inspection = await startSubscriptionObserver(tls, b, "leg", "inspection", fixture);
  const body = JSON.stringify({ model: PAID_MODEL, max_tokens: 4096, system: [ { type: "text", text: "native prefix" } ], messages: [{ role: "user", content: "benign" }] }, null, 2);
  const post = (origin: string, key = false) => new Promise<number>((resolve, reject) => {
    const req = request(origin + "/v1/messages?beta=true", { method: "POST", ca: tls.cert, headers: { "content-type": "application/json", authorization: "Bearer fake-private-oauth", "anthropic-beta": "native-beta", "user-agent": "native-cli", ...(key ? {"x-api-key":"fake-key"} : {}) } }, (res) => {
      let text = ""; res.on("data", (b) => {text += b;}); res.on("end", () => {assert.doesNotMatch(text, /provider-private-error/); resolve(res.statusCode!);});
    }); req.on("error", reject); req.end(body);
  });
  try {
    assert.deepEqual(await Promise.all([post(model.origin), post(inspection.origin)]), [200, 200]);
    assert.ok(forwarded.every((r) => r.text === body && r.headers.authorization === "Bearer fake-private-oauth" && r.headers["anthropic-beta"] === "native-beta" && r.headers["user-agent"] === "native-cli" && !r.headers["x-api-key"]));
    refuse = true;
    assert.equal(await post(inspection.origin), 502);
    assert.equal(await post(model.origin), 502);
    assert.equal(forwarded.length, 3);
    assert.equal(b.snapshot().requests[2].status, 429);
    assert.equal(b.snapshot().requests[2].state, "uncertain");
    assert.doesNotMatch(JSON.stringify([model.requests, model.errors, inspection.requests, inspection.errors, b.snapshot()]), /fake-private-oauth|provider-private-error/);
    const fresh = await startSubscriptionObserver(tls, new SubscriptionBudget(), "other", "model", fixture);
    try { assert.equal(await post(fresh.origin, true), 502); assert.equal(forwarded.length, 3); } finally {await fresh.close();}
  } finally {
    await model.close(); await inspection.close();
    await new Promise<void>((resolve) => {provider.closeAllConnections(); provider.close(() => resolve());});
    rmSync(dir, {recursive:true, force:true});
  }
});
