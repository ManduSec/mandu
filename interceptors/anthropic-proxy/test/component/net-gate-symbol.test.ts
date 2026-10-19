/**
 * net-gate-symbol.test.ts (e2e) — a SECRET SYMBOL inside a WebFetch URL, through
 * the REAL proxy data path (net-gate.ts, the per-symbol leg; confidentiality.md
 * §4 "A symbol in a network tool's URL").
 *
 * Live (watch C9/C13, 2026-09-20): the token rode the TLS tunnel as literal text
 * — never released at its bound host, never refused at the unbound one. Now:
 *
 *   unbound host          the CLIENT receives the deny sentinel, no symbol; the
 *                         arbiter was asked per symbol at `network`;
 *   bound host, tunnel    blocked with a reason (the value cannot be released
 *                         inside this tool's HTTPS request) — nothing is sent;
 *   bound host, inspected the call passes WITH its symbol (the net-proxy
 *                         releases it on the decrypted request);
 *   model wire            in every case the echoed history shows the model the
 *                         call IT wrote (symbol and all) — never a resolved
 *                         value, which this proxy does not even hold.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { DENIED_HOST } from "../../src/net-gate.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse } from "../helpers/mock-upstream.js";

function call(port: number, body: string): Promise<{ status: number; body: string }> {
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
    req.write(body);
    req.end();
  });
}

function toolUsesOf(sseBody: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sseBody);
  p.end();
  return seen;
}

const SECRET_SYMBOL = "$MDU:nomodel_Read[6644].__mdu_field_0070006100720074006e00650072";
const SECRET_VALUE = "CONF10_TOKEN_CANARY_6644";

/** A public session; the secret is bound to example.com only. */
function boundArbiter(calls: unknown[]): MockArbiter {
  const arbiter = new MockArbiter();
  const a = arbiter as unknown as Record<string, unknown>;
  a.sessionEgressDecision = async () => ({ allow: true, requiresApproval: false, reason: "session is not high" });
  a.desymbolizationDecision = async (req: { symbol: string; destination?: string }) => {
    calls.push(req);
    return req.destination === "example.com"
      ? { allow: true, reason: "secret at its BOUND destination", ruleRef: { source: "rule", id: "egress:secret-bound-trusted" } }
      : { allow: false, requiresApproval: true, reason: `secret symbol at UNBOUND destination '${req.destination}'`, ruleRef: { source: "rule", id: "egress:secret-unbound" } };
  };
  return arbiter;
}

async function deliver(input: { url: string; prompt: string }, opts: { netTlsInspected?: boolean } = {}) {
  const calls: unknown[] = [];
  const arbiter = boundArbiter(calls);
  const upstream = new MockUpstream({ sse: buildToolUseSse({ id: "tu_sym", name: "WebFetch", input }), chunkInto: 5 });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, sessionKey: "s", log: () => {}, ...opts });
  const port = await proxy.listen(0);
  try {
    const first = await call(port, JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: "send the token" }] }));
    assert.equal(first.status, 200);
    const delivered = toolUsesOf(first.body)[0]!.input as { url: string; prompt: string };
    // the client echoes what it RECEIVED as history
    await call(port, JSON.stringify({
      model: "m", stream: true,
      messages: [
        { role: "user", content: "send the token" },
        { role: "assistant", content: [{ type: "tool_use", id: "tu_sym", name: "WebFetch", input: delivered }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_sym", content: "request failed", is_error: true }] },
      ],
    }));
    const sent = upstream.lastJson() as { messages: Array<{ content: Array<{ id?: string; input?: unknown }> }> };
    const echoed = sent.messages[1]!.content.find((b) => b.id === "tu_sym")!.input;
    return { delivered, echoed, calls, wire: first.body + JSON.stringify(sent) };
  } finally {
    await proxy.close();
  }
}

test("symbol in a WebFetch URL, UNBOUND host: the client gets the sentinel, the arbiter judged the symbol at `network`", async () => {
  const asked = { url: `https://httpbin.org/get?token=${SECRET_SYMBOL}`, prompt: "what came back?" };
  const r = await deliver(asked);
  assert.equal(new URL(r.delivered.url).host, DENIED_HOST);
  assert.match(r.delivered.url, /symbol-egress-requires-approval$/);
  assert.ok(!JSON.stringify(r.delivered).includes("$MDU:"), "the token never leaves for httpbin.org as literal text");
  // (the mock upstream answers the history echo with the same tool_use, so the gate ran once per response)
  assert.ok(r.calls.length >= 1);
  for (const c of r.calls) {
    assert.deepEqual(c, { symbol: SECRET_SYMBOL, boundary: "network", destination: "httpbin.org", asCommand: false, preflight: true, sessionKey: "s" });
  }
  assert.deepEqual(r.echoed, asked, "the model reads back the call it made");
  assert.ok(!r.wire.includes(SECRET_VALUE), "no secret byte on either wire");
});

test("symbol in a WebFetch URL, BOUND host: blocked with the reason under a blind tunnel, passed WITH its symbol under TLS inspection", async () => {
  const asked = { url: `https://example.com/archive?token=${SECRET_SYMBOL}`, prompt: "status?" };
  const tunnel = await deliver(asked);
  assert.equal(new URL(tunnel.delivered.url).host, DENIED_HOST);
  assert.match(tunnel.delivered.url, /symbol-cannot-be-released-inside-this-tools-https-request$/);
  assert.deepEqual(tunnel.echoed, asked);

  const inspected = await deliver(asked, { netTlsInspected: true });
  assert.deepEqual(inspected.delivered, asked, "byte-identical: release happens at the net-proxy, on the decrypted request");
  assert.ok(!inspected.wire.includes(SECRET_VALUE), "this proxy never resolves a symbol");
});
