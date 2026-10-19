/**
 * e2e — a result the value backstop raised registers only what made it
 * secret (confidentiality-plan-15-prompt-filter.md §4.1, "What a raised row
 * registers"), through the PRODUCTION wiring: the model proxy's adapter over
 * the data and human sockets, a real ArbiterServer, `secrets` axes, a mock
 * model behind the proxy.
 *
 * The shape: a `no-model` file is registered; the agent Reads an UNLABELLED
 * copy of one of its lines inside an ordinary notes file (the drill's
 * "written to another file and read back"). The path rules call the Read
 * public, the value backstop finds the secret line in it and raises it, and
 * the proxy masks it whole. Before, every long line of that result became a
 * piece of its row, so a later Read of an unrelated README that shared an
 * ordinary heading line was masked whole too.
 *
 * Proves:
 *   1. the raised result itself is masked (one symbol), and stays masked on
 *      the re-send (the same symbol);
 *   2. a later unrelated result sharing an ordinary line of it reaches the
 *      model raw (the fix);
 *   3. THE ORACLE: a later result carrying the secret line, the secret token
 *      alone, or the line of the raised result that held the secret (in
 *      another context) is masked; no request to the model ever carries the
 *      secret;
 *   4. fail-closed where the result is secret by its own path as well (a
 *      Read of the labelled file itself, with the same ordinary line): its
 *      row keeps every line, so a later result sharing that line is masked.
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

const TOKEN = "sk_live_RaisedRow7Kq2Xr9Lm4Tz8Vb3Pw6";
const SECRET_LINE = `STRIPE_SECRET_KEY=${TOKEN}`;
const HEADING = "## Deployment checklist for the release team";
const LOGLINE = "INFO  starting worker pool with 8 workers";
const SYMBOL_RE = /\$MDU:[a-z]+_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;

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

test("secrets: a Read the value backstop raised registers only its secret line; a later result sharing an ordinary line is raw, every result with the secret is masked", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-raised-row-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  const vault = join(ws, "vault", "billing.env");
  writeFileSync(vault, `# billing service\n${SECRET_LINE}\nSTRIPE_ACCOUNT=acct_public_example\n`);
  const notes = join(ws, "notes.md"); // unlabelled: a copy of the secret line among ordinary lines
  const notesText = `${HEADING}\n\n- bump the version\n${SECRET_LINE}\n${LOGLINE}\n- tag the release\n`;
  writeFileSync(notes, notesText);
  const readme = join(ws, "README.md");
  const readmeText = `# Service\n\n${HEADING}\n\nRun the tests first.\n${LOGLINE}\n`;
  writeFileSync(readme, readmeText);
  const elsewhere = join(ws, "other.md");

  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "vault"), level: "no-model", recursive: true }] } as never,
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
    const p = new AnthropicProxy({ arbiter: new ProxyAdapter(real, humanPlane), upstream: up.fetcher, sessionKey: "R", log: () => {} });
    proxies.push(p);
    const tools = ["Read", "Bash"].map((name) => ({ name, input_schema: { type: "object" } }));
    const res = await post(await p.listen(0), JSON.stringify({ model: "claude-haiku-4-5", stream: true, tools, messages }));
    assert.equal(res.status, 200, res.body);
    ups.push(up);
    return up;
  };
  try {
    const reg = await launcher.registerSecret({ path: vault, home, sessionKey: "R" });
    assert.ok(typeof (reg.twin ?? reg.symbol) === "string", `registered: ${reg.reason}`);

    // ── 1. the raised Read: masked whole, the same symbol on the re-send
    const first: Msg[] = [userText("Read notes.md."), toolUse("tu_notes", "Read", { file_path: notes }), toolResult("tu_notes", rendered(notesText))];
    const a = await through(first);
    const masked = resultOf(a, "tu_notes");
    assert.match(masked, SYMBOL_RE, `the Read carrying the secret line is masked: ${masked}`);
    assert.ok(!masked.includes(HEADING), "masked whole");
    const again = await through(first);
    assert.equal(resultOf(again, "tu_notes"), masked, "the re-send keeps the same symbol");

    // ── 2. THE FIX: an unrelated README sharing the heading and the log line reaches the model raw
    const b = await through([userText("Read the README."), toolUse("tu_readme", "Read", { file_path: readme }), toolResult("tu_readme", rendered(readmeText))]);
    assert.equal(resultOf(b, "tu_readme"), rendered(readmeText), "a later result sharing only ordinary lines of the raised result is raw");
    const bash = await through([userText("Run it."), toolUse("tu_log", "Bash", { command: "./run.sh" }), toolResult("tu_log", `${LOGLINE}\ndone\n`)]);
    assert.equal(resultOf(bash, "tu_log"), `${LOGLINE}\ndone\n`, "a command output sharing the log line is raw");

    // ── 3. THE ORACLE: anything with the secret stays masked
    const oracle: Array<[string, string, Record<string, unknown>, string]> = [
      ["tu_o1", "Read", { file_path: elsewhere }, rendered(`intro\n${SECRET_LINE}\n`)],
      ["tu_o2", "Bash", { command: "env" }, `HOME=/home/u\nexported ${TOKEN}\n`],
      ["tu_o3", "Bash", { command: "grep -r KEY ." }, `notes.md:${SECRET_LINE}\n`],
    ];
    for (const [id, name, input, result] of oracle) {
      const up = await through([userText("Look."), toolUse(id, name, input), toolResult(id, result)]);
      const got = resultOf(up, id);
      assert.match(got, SYMBOL_RE, `${id}: a later result with the secret is masked: ${got}`);
      assert.ok(!got.includes(TOKEN), `${id}: the secret never reaches the model`);
    }

    // ── 4. fail-closed: a result secret by its own path keeps every line
    const vaultRead = `# billing service\n${HEADING} (vault copy)\n${SECRET_LINE}\n`;
    const c = await through([userText("Read the vault."), toolUse("tu_vault", "Read", { file_path: vault }), toolResult("tu_vault", rendered(vaultRead))]);
    assert.match(resultOf(c, "tu_vault"), SYMBOL_RE, "the labelled file's Read is masked");
    const d = await through([userText("Read it."), toolUse("tu_other", "Read", { file_path: elsewhere }), toolResult("tu_other", rendered(`intro\n${HEADING} (vault copy)\n`))]);
    assert.match(resultOf(d, "tu_other"), SYMBOL_RE, "a line of a path-secret result is still a piece: a later result sharing it is masked");

    for (const up of ups) for (const r of up.requests) assert.ok(!r.bodyText.includes(TOKEN), "no request to the model carries the secret");
  } finally {
    for (const p of proxies) await p.close();
    for (const c of [launcher, real, humanPlane]) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
