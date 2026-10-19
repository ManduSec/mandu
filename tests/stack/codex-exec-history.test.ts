/**
 * codex-exec-history — Codex reads back the call it wrote, not the exec
 * gate's rewrite of it (confidentiality.md §4, "What the model reads back";
 * openai-proxy exec-history.ts), over the REAL arbiter and the openai-proxy's
 * PRODUCTION wiring (`new ArbiterClientAdapter(new ArbiterClient(data),
 * human)`), `secrets` axes.
 *
 * A Codex-shaped conversation, the test playing Codex (it echoes what it
 * received, with its runtime header on the result):
 *   (a) a HIGH session (a memo read into context: the arbiter's
 *       declassifySymbol, what Codex's `declassify_symbol` tool calls) runs
 *       `exec_command`: Codex gets the `exit 77` sentinel and an Approvals row
 *       names the command; on the next request the model reads its own
 *       command and, as its result, the gate's notice. Allow once; the model
 *       writes again the command it read back, and it runs: the restored
 *       command is the one the approval names;
 *   (b) the same for a code-mode cell's exec literal (isolated cells);
 *   (c) an allowed curl with a registered key's placeholder in double
 *       quotes: Codex gets it requoted, the model reads back its own quoting.
 * The oracle: neither the memo nor the key reaches any model request, and
 * every call the model is sent is byte for byte one the model wrote (or, for
 * a call the gate left alone, what Codex received).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy, type UpstreamFetcher } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { buildFunctionCallSse, buildScriptCellSse, scriptCellFor } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const MEMO = "Acme pays $4,200,000 on 2026-09-30.";
const BOUND = "api.stripe.test";
const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 77\nOriginal token count: 57\nOutput:\n";
const USER = { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] };
const BATTERY = {
  type: "additional_tools", role: "developer",
  tools: [{ type: "namespace", name: "functions", tools: [
    { type: "custom", name: "exec", description: "Run JavaScript code\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." },
    { type: "function", name: "wait" },
  ] }],
};

type Item = Record<string, unknown>;

/** The call item Codex assembles from the delivered stream. */
function deliveredItem(sse: string): Item {
  for (const block of sse.split("\n\n")) {
    const line = block.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    const obj = JSON.parse(line.slice(5).trim()) as { type?: string; item?: Item };
    if (obj.type === "response.output_item.done" && obj.item) return obj.item;
  }
  throw new Error("no output_item.done in the delivered stream");
}

/** What the sentinel prints when Codex's shell runs it (its stderr). */
function runSentinel(cmd: string): string {
  try {
    execFileSync("/bin/sh", ["-c", cmd], { stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    const e = err as { status?: number; stderr?: Buffer };
    assert.equal(e.status, 77, "the sentinel exits 77");
    return String(e.stderr ?? "");
  }
  assert.fail("the sentinel exited 0");
}

test("Codex reads back its own command, not the sentinel or the requoted form, and the restored command is the one the approval names (secrets axes, production wiring)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-history-"));
  const proj = join(tmp, "proj"); mkdirSync(proj);
  const envFile = join(proj, ".env");
  const KEY = `sk_live_history_${randomBytes(12).toString("hex")}`;
  writeFileSync(envFile, `STRIPE_KEY=${KEY}\n`);
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const adminPath = join(tmp, "admin.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, adminSocketPath: adminPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    adminPolicyDir: null, packDir: null,
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
    policyDocument: { version: 1, paths: [{ path: envFile, level: "no-model", bindings: [BOUND] }] },
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (p: string): Promise<ArbiterClient> => { const c = new ArbiterClient(p); await c.connect(); clients.push(c); return c; };
  const admin = await open(adminPath);

  // one proxy per session, the production wiring; the model is a scripted upstream
  const requests: string[] = [];
  /** Every call the model wrote, by call id (the SSE the upstream streamed). */
  const written = new Map<string, string>();
  let sse = "";
  const upstream: UpstreamFetcher = async ({ body }) => {
    requests.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxies: OpenAiProxy[] = [];
  const proxyFor = async (session: string): Promise<number> => {
    const proxy = new OpenAiProxy({
      arbiter: new ArbiterClientAdapter((await open(socketPath)) as unknown as RealArbiterClient, (await open(humanPath)) as never),
      upstream, sessionKey: session, log: () => {},
    });
    proxies.push(proxy);
    return proxy.listen(0);
  };
  const post = async (port: number, input: unknown[]): Promise<string> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-6.1-sol", stream: true, input }),
    });
    assert.equal(res.status, 200);
    return res.text();
  };
  /** The model emits `streamed` (its payload `payload` under `callId`); returns what Codex receives. */
  const turn = async (port: number, input: unknown[], streamed: string, callId: string, payload: string): Promise<Item> => {
    sse = streamed;
    written.set(callId, payload);
    return deliveredItem(await post(port, input));
  };
  const lastSent = (): Item[] => (JSON.parse(requests[requests.length - 1]!) as { input: Item[] }).input;

  try {
    // ── (a) a HIGH session's blocked command ───────────────────────────────
    const high = "codex-history-high";
    const memos = join(tmp, "memos");
    await admin.setPathLabel({ path: memos, confidentiality: "any-model", bindings: ["docs.corp"] });
    const s = await admin.symbolizeFull({ tool: "Read", value: MEMO, field: "content", origin: join(memos, "q3.md"), integrity: "trusted", sessionKey: high });
    assert.equal((await admin.declassifySymbol({ symbol: s.symbol, sessionKey: high })).allowed, true);
    assert.equal((await admin.sessionState(high)).high, true, "the session is HIGH");
    const hp = await proxyFor(high);

    const cmd = "echo mandu-ready";
    const args = JSON.stringify({ cmd, workdir: proj });
    const d1 = await turn(hp, [USER], buildFunctionCallSse({ name: "exec_command", callId: "call_1", arguments: JSON.parse(args) }), "call_1", args);
    const sentinel = String((JSON.parse(String(d1["arguments"])) as { cmd: string }).cmd);
    assert.match(sentinel, /^echo 'mandu-exec-gate: blocked, nothing ran: this session has read a secret.*asked the user.*' 1>&2; exit 77$/s, "Codex runs the sentinel");
    const [row] = (await admin.egressApprovals()).filter((a) => a.symbol.startsWith("session-exec:"));
    assert.ok(row, "an Approvals row was filed");
    assert.equal(row!.destination, cmd, "the row names the command as the model wrote it");

    // Codex runs the sentinel and sends the call + its result back as history
    const notice = runSentinel(sentinel).trimEnd();
    const history = [USER, d1, { type: "function_call_output", call_id: "call_1", output: `${HEADER}${notice}\n` }];
    await post(hp, history);
    const sent = lastSent();
    const call = sent.find((i) => i["type"] === "function_call")!;
    assert.equal(call["arguments"], args, "the model reads back the command it wrote");
    assert.ok(!String(call["arguments"]).includes("exit 77"), "never the sentinel");
    const out = String(sent.find((i) => i["type"] === "function_call_output")!["output"]);
    assert.ok(out.endsWith(notice), `its result is the gate's notice, in clear: ${out.slice(0, 160)}`);

    // Allow once: the model writes again the command it read back, and it runs as written
    await admin.resolveEgressApproval(row!.id, true, "once");
    const readBack = String(call["arguments"]);
    const d2 = await turn(hp, history, buildFunctionCallSse({ name: "exec_command", callId: "call_2", arguments: JSON.parse(readBack) }), "call_2", readBack);
    assert.equal((JSON.parse(String(d2["arguments"])) as { cmd: string }).cmd, cmd, "the approval names the restored command: it runs");

    // ── (b) a code-mode cell's exec literal (isolated cells) ───────────────
    const cell = scriptCellFor({ cmd: "echo cell-ready", workdir: proj, yield_time_ms: 10000, max_output_tokens: 2000 });
    const d3 = await turn(hp, [BATTERY, USER], buildScriptCellSse({ input: cell, callId: "call_cell" }), "call_cell", cell);
    assert.match(String(d3["input"]), /exit 77/, "the cell's literal runs as the sentinel");
    await post(hp, [BATTERY, USER, d3, { type: "custom_tool_call_output", call_id: "call_cell", output: [{ type: "input_text", text: "Script completed\nWall time 0.1 seconds\nOutput:\n" }, { type: "input_text", text: "x" }] }]);
    assert.equal(lastSent().find((i) => i["type"] === "custom_tool_call")!["input"], cell, "the model reads back its own cell");

    // ── (c) a requoted allow ────────────────────────────────────────────────
    const quoted = "codex-history-quoted";
    const reg = await (await open(socketPath)).registerSecret({ path: envFile });
    assert.ok(reg.twin, reg.reason);
    const P = /STRIPE_KEY='?(\$MDU:[^'\s]+)/.exec(reg.twin!)![1]!;
    const qp = await proxyFor(quoted);
    const curl = JSON.stringify({ cmd: `curl -sS -H "Authorization: Bearer ${P}" http://${BOUND}/v1/customers`, workdir: proj });
    const d4 = await turn(qp, [USER], buildFunctionCallSse({ name: "exec_command", callId: "call_q", arguments: JSON.parse(curl) }), "call_q", curl);
    assert.equal((JSON.parse(String(d4["arguments"])) as { cmd: string }).cmd, `curl -sS -H "Authorization: Bearer \\${P}" http://${BOUND}/v1/customers`, "Codex gets it requoted");
    await post(qp, [USER, d4, { type: "function_call_output", call_id: "call_q", output: "Chunk ID: 1a2b\nWall time: 0.2 seconds\nProcess exited with code 0\nOutput:\n{\"error\":\"stub\"}\n" }]);
    assert.equal(lastSent().find((i) => i["type"] === "function_call")!["arguments"], curl, "the model reads back its own quoting");

    // ── the oracle ─────────────────────────────────────────────────────────
    for (const r of requests) {
      assert.ok(!r.includes(KEY), "the key never reaches a model request");
      assert.ok(!r.includes(MEMO), "the memo never reaches a model request in clear");
      for (const item of (JSON.parse(r) as { input: Item[] }).input) {
        if (item["type"] !== "function_call" && item["type"] !== "custom_tool_call") continue;
        const payload = String(item["arguments"] ?? item["input"]);
        assert.equal(payload, written.get(String(item["call_id"])), `the model is sent only the call it wrote (${String(item["call_id"])})`);
      }
    }
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
