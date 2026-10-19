/**
 * e2e — the value-backstop note (confidentiality.md §7.1, 2026-10-17),
 * through the PRODUCTION wiring: the model proxy's adapter over the data and
 * human sockets, a real ArbiterServer, `secrets` axes, a mock model behind
 * the proxy.
 *
 * The shape (demo-api-401-debug's old payments log, found by a scripted
 * probe): a `no-model` .env holding a Stripe key is registered; the agent
 * reads an UNLABELLED log in which an old debug line printed the same key.
 * The path rules call the log public, the arbiter's value backstop finds the
 * key in it and raises the result, and the proxy masks it whole. Before, the
 * note beside the symbol was the path-derived one ("the command names a
 * secret file … run that part again as a command of its own that names no
 * secret file"), false here: the model was told the log was a secret file.
 * Since the value-only release (backstop-value-only.md) a clean call gets
 * such a log with only the key as its symbol; this log also carries a
 * rotated key's 12-character prefix (`rotated from …`), which the release's
 * residue scan refuses, so it is masked whole and the note is what is tested.
 *
 * Proves:
 *   1. a Bash `cat` and a Read of the log: one symbol, then the
 *      value-backstop note, and no path-derived line;
 *   2. the note's advice works: the log read with the key's lines left out
 *      (`grep -v -e Bearer -e rotated`) reaches the model as it is, with no note;
 *   3. control: a `cat` of the labelled .env itself keeps the path-derived
 *      note naming it;
 *   4. THE ORACLE: no request to the model ever carries the key.
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
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const KEY = "sk_test_NoteE2E7Kq2Xr9Lm4Tz8Vb3";
const LOG = [
  "[2026-10-16 08:00:01] check-payments (cron, DEBUG=1) release 1.8.3",
  "DEBUG: Authorization: Bearer " + KEY,
  "[2026-10-16 08:00:02] ok: Stripe balance HTTP 200",
  "[2026-10-16 19:42:10] deploy: release 1.9.0",
  "payments: warning: STRIPE_KEY is empty",
  "config: STRIPE key rotated from " + KEY.slice(0, 12) + "...",
  "[2026-10-16 20:00:02] FAILED: Stripe balance HTTP 401",
  "",
].join("\n");
const FILTERED = LOG.split("\n").filter((l) => !l.includes("Bearer") && !l.includes("rotated")).join("\n");
const SYMBOL_RE = /^\$MDU:[a-z]+_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;
const BACKSTOP_LINE = "[mandu:secret] masked: this output contains the value of a registered secret, so the whole output is withheld from you";

type Msg = { role: "user" | "assistant"; content: unknown };
const userText = (text: string): Msg => ({ role: "user", content: [{ type: "text", text }] });
const toolUse = (id: string, name: string, input: Record<string, unknown>): Msg =>
  ({ role: "assistant", content: [{ type: "tool_use", id, name, input }] });
const toolResult = (id: string, text: string): Msg =>
  ({ role: "user", content: [{ type: "tool_result", tool_use_id: id, content: text }] });
/** Claude Code's Read rendering: `cat -n` style. */
const rendered = (text: string): string => text.split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

function resultOf(up: MockUpstream, id: string): string {
  const sent = JSON.parse(up.requests[up.requests.length - 1]!.bodyText) as { messages: Msg[] };
  for (const m of sent.messages) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
      if (b.type !== "tool_result" || b.tool_use_id !== id) continue;
      return typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join("");
    }
  }
  throw new Error(`no tool_result ${id}`);
}

test("secrets: an old log holding a registered key is masked whole with the value-backstop note, never the path-derived one; the filtered log is raw", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-backstop-note-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "shop-app", "logs"), { recursive: true });
  const env = join(ws, "shop-app", ".env");
  writeFileSync(env, `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`);
  const log = join(ws, "shop-app", "logs", "payments-2026-10-16.log"); // unlabelled
  writeFileSync(log, LOG);

  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model" }] } as never,
  });
  await arbiter.listen();
  const launcher = new ArbiterClient(sock);
  const real = new ArbiterClient(sock);
  const humanPlane = new ArbiterClient(join(tmp, "human", "h.sock"));
  await Promise.all([launcher.connect(), real.connect(), humanPlane.connect()]);
  const proxies: AnthropicProxy[] = [];
  const ups: MockUpstream[] = [];
  const through = async (messages: Msg[]): Promise<MockUpstream> => {
    const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
    const p = new AnthropicProxy({ arbiter: new ProxyAdapter(real, humanPlane), upstream: up.fetcher, sessionKey: "N", log: () => {} });
    proxies.push(p);
    const tools = ["Read", "Bash"].map((name) => ({ name, input_schema: { type: "object" } }));
    const res = await post(await p.listen(0), JSON.stringify({ model: "claude-haiku-4-5", stream: true, tools, messages }));
    assert.equal(res.status, 200, res.body);
    ups.push(up);
    return up;
  };
  try {
    const reg = await launcher.registerSecret({ path: env, home, sessionKey: "N" });
    assert.ok(typeof (reg.twin ?? reg.symbol) === "string", `registered: ${reg.reason}`);

    // ── 1. cat and Read of the log: a symbol, then the value-backstop note
    const cmd = "cat shop-app/logs/payments-2026-10-16.log";
    const cat = resultOf(await through([userText("Payments broke last night; read the log."), toolUse("tu_cat", "Bash", { command: cmd }), toolResult("tu_cat", LOG)]), "tu_cat");
    const read = resultOf(await through([userText("Read the log."), toolUse("tu_read", "Read", { file_path: log }), toolResult("tu_read", rendered(LOG))]), "tu_read");
    for (const [what, got] of [["cat", cat], ["Read", read]] as const) {
      const [symbol, note, ...rest] = got.split("\n\n");
      assert.match(symbol!, SYMBOL_RE, `${what}: masked whole: ${got}`);
      assert.ok(note?.startsWith(BACKSTOP_LINE), `${what}: the value-backstop note: ${got}`);
      assert.deepEqual(rest, [], `${what}: one note`);
      assert.ok(!got.includes("the command names"), `${what}: no path-derived line`);
      assert.ok(!got.includes("names no secret file"), `${what}: no path-derived advice`);
      assert.ok(!got.includes("STRIPE_KEY is empty"), `${what}: no output byte`);
    }

    // ── 2. the advice works: the log without the key's lines is raw, no note
    const filtered = resultOf(await through([userText("Read it without the key lines."), toolUse("tu_grep", "Bash", { command: "grep -v -e Bearer -e rotated shop-app/logs/payments-2026-10-16.log" }), toolResult("tu_grep", FILTERED)]), "tu_grep");
    assert.equal(filtered, FILTERED, "the filtered log reaches the model as it is");

    // ── 3. control: the labelled .env itself keeps the path-derived note
    const envCat = resultOf(await through([userText("Show the env."), toolUse("tu_env", "Bash", { command: "cat shop-app/.env" }), toolResult("tu_env", `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`)]), "tu_env");
    assert.match(envCat, /\[mandu:secret\] masked: the command names a secret file \(shop-app\/\.env\)/, envCat);
    assert.ok(!envCat.includes("value of a registered secret"), envCat);

    // ── 4. THE ORACLE
    for (const up of ups) for (const r of up.requests) assert.ok(!r.bodyText.includes(KEY), "no request to the model carries the key");
  } finally {
    for (const p of proxies) await p.close();
    for (const c of [launcher, real, humanPlane]) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
