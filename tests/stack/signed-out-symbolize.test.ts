/**
 * signed-out-symbolize — the signed-out projection (dashboard.md §6 "Reads
 * and the admin session", `redact.ts`) leaves out every value the AI did not
 * see, over the REAL components:
 *
 *   - a real ArbiterServer in `secrets` with a policy file that locks
 *     `deploy/staging.conf` at no-model, the REAL anthropic-proxy in its
 *     production wiring, a mock model behind it: a Read of that file
 *     reaches the model only as a symbol;
 *   - the arbiter's own record of the proxy's `symbolize` event keeps the
 *     file's bytes only in its HumanView forms (`original`, the symbol's
 *     `value`): its input's AgentView form is the symbol (`makeSymbolize`);
 *   - the REAL dashboard over the arbiter's store, read WITHOUT the admin
 *     session: no listed read (`READ_ROUTES`: the events, the SSE stream,
 *     the agent page, the files, the sessions...) carries a byte of the file;
 *   - signed in, the events carry it (the human's real value).
 *
 * Found by nightly run 2026-10-06-0330: the proxies and fs-sync recorded a
 * `symbolize` event's input, the value before masking, as its `symbolized`
 * form too, and the projection keeps every `symbolized`, so the signed-out
 * `/api/events` carried it. §6 names the reader this guards against: a
 * program the agent runs can reach the port through the session net-proxy's
 * relay. Logs written before the fix keep the old shape;
 * dashboard/test/component/value-gate.test.ts and
 * tests/stack/dashboard-value-gate.test.ts walk every read over it.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { allSamples } from "../../dashboard/test/unit/read-route-samples.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const SESSION = `signed-out-symbolize-${process.pid}`;
const TOKEN = "ghp_FakeSignedOutToken4Hj7Rt2Ws9Yu6Ki3";
const FILE = `[staging]\nhost = "staging.internal.example"\ntoken = "${TOKEN}"\n`;
const FILE_PIECES = [TOKEN, "ghp_FakeSignedOut", "staging.internal.example"];
const READ_RENDER = FILE.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

/** GET `url` and read the body; an SSE route is read for a moment, then cut. */
async function get(url: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  const ac = new AbortController();
  const res = await fetch(url, { headers, signal: ac.signal });
  if (!(res.headers.get("content-type") ?? "").startsWith("text/event-stream")) return { status: res.status, body: await res.text() };
  let body = "";
  const reader = res.body!.getReader();
  const timer = setTimeout(() => ac.abort(), 400);
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      body += new TextDecoder().decode(value);
    }
  } catch { /* cut */ }
  clearTimeout(timer);
  return { status: res.status, body };
}

test("signed out, /api/events carries no byte of a no-model file the AI only got as a symbol (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-signed-out-sym-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const conf = join(ws, "deploy", "staging.conf");
  writeFileSync(conf, FILE);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${conf}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: upstream.fetcher, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const source = new ArbiterEventSource({ socketPath });
  const dashboard = new DashboardServer({ ...ADMIN_OPTS, source, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "What is in deploy/staging.conf?" },
          { role: "assistant", content: [{ type: "tool_use", id: "toolu_read", name: "Read", input: { file_path: conf } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_read", content: READ_RENDER }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const sent = upstream.requests.at(-1)!.bodyText;
    for (const piece of FILE_PIECES) assert.ok(!sent.includes(piece), `the model got file byte(s): ${piece}`);

    let body = "";
    for (let i = 0; i < 100; i++) {
      // emission is best-effort and asynchronous: wait for the symbolize event
      const r = await fetch(`${base}/api/events?session=${SESSION}`);
      assert.equal(r.status, 200);
      body = await r.text();
      if ((JSON.parse(body) as { events: { kind: string }[] }).events.some((e) => e.kind === "symbolize")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal((JSON.parse(body) as { valuesShown?: boolean }).valuesShown, false, "read signed out");
    for (const piece of FILE_PIECES) assert.ok(!body.includes(piece), `the signed-out payload carried file byte(s): ${piece}`);

    // The emitter: the arbiter's own record keeps the bytes only in HumanView
    // forms; the input's AgentView form is the symbol the model got.
    const recorded = await source.readEvents(SESSION);
    const mint = recorded.find((e) => e.kind === "symbolize");
    assert.ok(mint?.input && mint.output, "the proxy recorded the mint");
    assert.match(mint.output.symbolized, /^\$MDU:/);
    assert.equal(mint.input.symbolized, mint.output.symbolized, "the input's AgentView form is the symbol");
    assert.ok(mint.input.original?.includes(TOKEN), "the value stays in the record, for the signed-in human");
    for (const e of recorded) {
      for (const piece of FILE_PIECES) {
        assert.ok(!(e.input?.symbolized ?? "").includes(piece) && !(e.output?.symbolized ?? "").includes(piece),
          `event ${e.kind} put file byte(s) in an AgentView form: ${piece}`);
      }
    }

    // Every listed read, signed out: none carries a byte of the file.
    for (const { path } of allSamples(SESSION)) {
      const r = await get(base + path);
      for (const piece of FILE_PIECES) assert.ok(!r.body.includes(piece), `${path} carried file byte(s) signed out (${r.status}): ${piece}`);
    }

    // Signed in, the human's real value is there.
    const signedIn = await get(`${base}/api/events?session=${SESSION}`, CSRF_ADMIN);
    assert.match(signedIn.body, /"valuesShown":true/);
    assert.ok(signedIn.body.includes(TOKEN), "signed in, the events carry the real value");
  } finally {
    await dashboard.close();
    await proxy.close();
    data.close(); human.close();
    await arbiter.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(tmp, { recursive: true, force: true });
  }
});
