/**
 * upstream-limit — the model provider's usage limit over the REAL
 * components: the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`) over a real ArbiterServer, a registered secret, and
 * a mock Anthropic upstream that answers 429 with the weekly-limit headers a
 * subscription got live on 2026-10-28.
 *
 * Asserted (mandu.md §4.1, "Upstream throttles and plan limits"):
 *   - the proxy relays the plan's limit at ONCE (one upstream attempt, no
 *     backoff), its status, headers and body unchanged, so the agent shows
 *     the limit instead of a spinner;
 *   - the turn's `tllm_call` in the arbiter's event log carries
 *     `upstreamLimit` (the claim, both windows, the reset, Retry-After);
 *   - the request that went upstream is the usual symbolized one: the
 *     secret's raw bytes never left, and the caller's credential went to
 *     the upstream verbatim and to NO event;
 *   - a short throttle is still absorbed by the retries (no regression).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const STRIPE = "sk_live_upstream_limit_e2e_0123456789";
const RAW = `PORT=3000\nSTRIPE_KEY=${STRIPE}\n`;
// a subscription-shaped credential the caller sends (made up; no real token)
const BEARER = "Bearer sk-ant-oat01-upstream-limit-e2e-FAKE-0000000000";
const WEEKLY = {
  "content-type": "application/json",
  "retry-after": "45151",
  "x-should-retry": "true",
  "anthropic-ratelimit-unified-status": "rejected",
  "anthropic-ratelimit-unified-representative-claim": "seven_day",
  "anthropic-ratelimit-unified-reset": "1793221200",
  "anthropic-ratelimit-unified-7d-status": "rejected",
  "anthropic-ratelimit-unified-7d-utilization": "1.0",
  "anthropic-ratelimit-unified-7d-reset": "1793221200",
  "anthropic-ratelimit-unified-5h-status": "allowed",
  "anthropic-ratelimit-unified-5h-utilization": "0.0",
  "anthropic-ratelimit-unified-5h-reset": "1793193600",
  "anthropic-ratelimit-unified-overage-status": "rejected",
};
const LIMIT_BODY = JSON.stringify({ type: "error", error: { type: "rate_limit_error", message: "This request would exceed your account's rate limit. Please try again later." } });

function post(port: number, body: string, session: string): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", authorization: BEARER, "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/** Claude Code's Read of the raw .env, then the next request. */
function readTurn(path: string): string {
  return JSON.stringify({
    model: "claude-haiku-4-5",
    stream: true,
    messages: [
      { role: "user", content: "what port does the app use?" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_lim_1", name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_lim_1", content: RAW }] },
    ],
  });
}

test("the provider's weekly limit: relayed at once and unchanged, recorded as upstreamLimit, the request symbolized and no credential in any event (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-upstream-limit-e2e-"));
  const env = join(tmp, ".env");
  writeFileSync(env, RAW);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    humanSocketPath: humanSockIn(tmp), // the event log's reader (arbiter-human-plane.md)
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const reader = new ArbiterClient(humanSockIn(tmp));
  const sessionKey = `upstream-limit-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  try {
    await real.registerSecret({ path: env, sessionKey });
    const run = async (answer: () => { status: number; headers: Record<string, string | undefined>; body: string }) => {
      const sent: Array<{ headers: Record<string, string | string[] | undefined>; body: string }> = [];
      const upstream: UpstreamFetcher = async ({ headers, body }) => {
        sent.push({ headers, body: body.toString("utf8") });
        const a = answer();
        return { status: a.status, headers: a.headers, body: Readable.from([Buffer.from(a.body)]) };
      };
      const slept: number[] = [];
      const proxy = new AnthropicProxy({
        arbiter: new ArbiterClientAdapter(real), upstream, sessionKey, log: () => {},
        retry: { maxAttempts: 12, baseDelayMs: 1 }, sleep: async (ms: number) => { slept.push(ms); },
      } as ConstructorParameters<typeof AnthropicProxy>[0]);
      proxies.push(proxy);
      const res = await post(await proxy.listen(0), readTurn(env), sessionKey);
      return { res, sent, slept };
    };

    const before = (await reader.events(sessionKey)).length;
    const { res, sent, slept } = await run(() => ({ status: 429, headers: WEEKLY, body: LIMIT_BODY }));
    // relayed at once, unchanged
    assert.equal(sent.length, 1, "one upstream attempt");
    assert.deepEqual(slept, [], "no backoff");
    assert.equal(res.status, 429);
    assert.equal(res.body, LIMIT_BODY, "the provider's body, byte for byte");
    assert.equal(res.headers["retry-after"], "45151");
    assert.equal(res.headers["anthropic-ratelimit-unified-representative-claim"], "seven_day", "the provider's own headers reach the agent");
    // the request that went upstream: the caller's credential verbatim, the secret symbolized
    assert.equal(sent[0]!.headers["authorization"], BEARER);
    assert.ok(!sent[0]!.body.includes(STRIPE), "the secret's raw bytes never left");
    assert.match(sent[0]!.body, /"tool_result","tool_use_id":"tu_lim_1","content":"\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]"/, "the secret file went as its placeholder");

    // the event: which limit, until when; no credential, no secret
    let tllm: Record<string, unknown> | undefined;
    for (let i = 0; i < 50 && !tllm; i++) {
      tllm = (await reader.events(sessionKey)).slice(before).find((e) => (e as { kind?: string }).kind === "tllm_call") as Record<string, unknown> | undefined;
      if (!tllm) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(tllm, "the relayed limit is in the arbiter's event log");
    assert.deepEqual(tllm!["upstreamLimit"], {
      status: 429, unifiedStatus: "rejected", claim: "seven_day",
      fiveHour: { status: "allowed", utilization: 0, resetsAt: "2026-10-28T13:20:00.000Z" },
      sevenDay: { status: "rejected", utilization: 1, resetsAt: "2026-10-28T21:00:00.000Z" },
      overageStatus: "rejected", resetsAt: "2026-10-28T21:00:00.000Z", retryAfterS: 45151, hard: true,
    });
    const all = JSON.stringify(await reader.events(sessionKey));
    assert.ok(!all.includes("sk-ant-oat01-upstream-limit-e2e"), "the caller's credential is in no event");
    // (the event log is the human plane: its symbol refs hold originals by
    // design; the limit and the output text say nothing of the request)
    assert.ok(!JSON.stringify([tllm!["upstreamLimit"], tllm!["output"]]).includes(STRIPE), "the limit and the output text carry nothing of the request");

    // a short throttle: still retried, then the success relayed
    let n = 0;
    const spike = await run(() => (++n < 3
      ? { status: 429, headers: { "content-type": "application/json", "retry-after": "1" }, body: LIMIT_BODY }
      : { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "message", role: "assistant", content: [{ type: "text", text: "3000" }] }) }));
    assert.equal(spike.res.status, 200);
    assert.equal(spike.sent.length, 3, "retried twice, then answered");
    assert.deepEqual(spike.slept, [1000, 1000]);
    for (const s of spike.sent) assert.ok(!s.body.includes(STRIPE), "every retry carries the same symbolized body");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    reader.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
