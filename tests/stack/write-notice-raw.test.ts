/**
 * e2e — a Write's own result reaches the model raw
 * (confidentiality-plan-15-prompt-filter.md §13.10, "A Write's own result";
 * confidentiality.md §7.1, "The write notice"), through the PRODUCTION
 * wiring: the model proxy's adapter over the data and human sockets
 * (`new ArbiterClientAdapter(data, human)`), inspect-mcp's over the data
 * socket, a real ArbiterServer, `secrets` axes, a mock model behind the
 * proxy.
 *
 * The live shape (drill conf-derived-label-next-session, replayed
 * 2026-10-11 on Claude Code 2.1.296): session A declassifies an `any-model`
 * brief (A is HIGH), the model Writes summary.md, the proxy labels the path
 * `any-model` on disk at the tool_use (Plan 9), and Claude Code's answer
 * "File created successfully at: <path> (file state is current …)" plus its
 * token-budget reminder came back to A's model as `$MDU:anymodel_Write[…]`,
 * classified by the path. Now it reaches the model as written.
 *
 * Proves:
 *   1. the drill shape: the path is labelled (not vacuous), and the Write's
 *      own result (create, and update with the budget tail) is forwarded
 *      byte for byte;
 *   2. THE INVARIANT HALF, in a session that is not HIGH, beside a file
 *      labelled `no-model`: the model's own Write notice for that file is
 *      raw, while a Read of it is a symbol, and every result that could
 *      carry a byte the model did not write stays masked: an older Claude
 *      Code's update echoing a snippet of the file, the notice with another
 *      reminder block after it, an Edit's notice (the Edit is not
 *      released), a notice naming another path, a Write with no content;
 *   3. THE ORACLE: no byte of the labelled file's secret anywhere in what
 *      the model received.
 *   4. the same for OpenClaw and OpenCode 1, each session bound to its own
 *      spec (`openclaw-agent`, `opencode`): the agent's own `write` notice
 *      for the no-model file is raw (OpenClaw 2026.7.1-2's "Successfully
 *      wrote N bytes to <path>", OpenCode 1.18.13's "Wrote file
 *      successfully."), while OpenClaw's "No changes made" answer, a forged
 *      count or path, a notice with file lines after it, OpenCode's
 *      diagnostics form, a Read and a call with no content stay symbols,
 *      and each sentence in another agent's session is a symbol; no byte of
 *      the file reaches the model.
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
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { ArbiterClientAdapter as InspectAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { declassifySymbol } from "../../interceptors/inspect-mcp/src/declassify-symbol.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const BRIEF_CANARY = "WRITE_NOTICE_BRIEF_CANARY_5521";
const SENTENCE = "The deal closes in the third quarter.";
const TOKEN = "ghp_FakeWriteNotice7Kq2Xr9Lm4Tz8Vb3";
const DECLASSIFY = "mcp__mandu-inspect__declassify_symbol";
const SYMBOL_RE = /\$MDU:[a-z]+_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;
const CURRENT = " (file state is current in your context — no need to Read it back)";
const BUDGET = "<system-reminder>\n<total_tokens>15000000 tokens left</total_tokens>\n</system-reminder>";
const MCP_REMINDER = "<system-reminder>\n# MCP Server Instructions\nThe server says hello.\n</system-reminder>";

interface Sent { status: number; body: string }

function post(port: number, body: string): Promise<Sent> {
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

type Msg = { role: "user" | "assistant"; content: unknown };
const userText = (text: string): Msg => ({ role: "user", content: [{ type: "text", text }] });
const toolUse = (id: string, name: string, input: Record<string, unknown>): Msg =>
  ({ role: "assistant", content: [{ type: "tool_use", id, name, input }] });
/** Claude Code sends a Write's result as a string. */
const toolResult = (id: string, text: string): Msg =>
  ({ role: "user", content: [{ type: "tool_result", tool_use_id: id, content: text }] });
const TOOLS = ["Read", "Write", "Edit", "Bash", DECLASSIFY].map((name) => ({ name, input_schema: { type: "object" } }));
const body = (messages: Msg[]): string => JSON.stringify({ model: "claude-haiku-4-5", stream: true, tools: TOOLS, messages });

/** The forwarded tool_result text for `id` in the upstream's last request. */
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

interface Rig {
  tmp: string;
  ws: string;
  home: string;
  real: ArbiterClient;
  launcher: ArbiterClient;
  mcp: ArbiterClient;
  through: (session: string, messages: Msg[], sse: string) => Promise<{ up: MockUpstream; res: Sent }>;
  close: () => Promise<void>;
}

async function rig(paths: Array<{ path: string; level: string; recursive?: boolean; bindings?: string[] }>, tmp: string, ws: string, home: string): Promise<Rig> {
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths } as never,
  });
  await arbiter.listen();
  const launcher = new ArbiterClient(sock);
  const real = new ArbiterClient(sock);
  const humanPlane = new ArbiterClient(join(tmp, "human", "h.sock"));
  const mcp = new ArbiterClient(sock);
  await Promise.all([launcher.connect(), real.connect(), humanPlane.connect(), mcp.connect()]);
  const proxies: AnthropicProxy[] = [];
  return {
    tmp, ws, home, real, launcher, mcp,
    through: async (sessionKey, messages, sse) => {
      const up = new MockUpstream({ sse });
      const p = new AnthropicProxy({ arbiter: new ProxyAdapter(real, humanPlane), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(p);
      const res = await post(await p.listen(0), body(messages));
      assert.equal(res.status, 200, res.body);
      return { up, res };
    },
    close: async () => {
      for (const p of proxies) await p.close();
      for (const c of [launcher, real, humanPlane, mcp]) c.close();
      await arbiter.close();
    },
  };
}

test("secrets: a HIGH session's Write to its own derived-labelled file gets its own result back raw (the drill shape)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-write-notice-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws-notice");
  mkdirSync(join(ws, "memo"), { recursive: true });
  const brief = join(ws, "memo", "brief.md");
  writeFileSync(brief, `Deal brief. Reference code: ${BRIEF_CANARY}. Keep internal.\n`);
  const summary = join(ws, "summary.md");
  const r = await rig([{ path: join(ws, "memo"), level: "any-model", recursive: true, bindings: ["example.com"] }], tmp, ws, home);
  try {
    // ── A goes HIGH: Read the brief's twin, declassify it. ─────────────────
    const reg = await r.launcher.registerSecret({ path: brief, home, sessionKey: "A" });
    const twin = reg.twin ?? reg.symbol;
    assert.ok(typeof twin === "string" && SYMBOL_RE.test(twin), `registered: ${reg.reason}`);
    const first = userText("Read memo/brief.md, then declassify it.");
    const readA = toolUse("tu_read", "Read", { file_path: brief });
    const held = await r.through("A", [first, readA, toolResult("tu_read", `     1\t${twin}\n     2\t`)], buildTextSse("ok", { deltas: 1 }));
    const outer = resultOf(held.up, "tu_read").match(SYMBOL_RE)?.[0];
    assert.ok(outer, "the model holds a symbol for the brief");
    const decl = await declassifySymbol({ arbiter: new InspectAdapter(r.mcp), sessionId: "A" }, { symbol: outer, reason: "the user authorized it" });
    assert.ok(decl.ok, decl.ok ? "" : decl.error);
    assert.equal((await r.real.sessionState("A")).high, true, "A is HIGH");
    const history: Msg[] = [first, readA, toolResult("tu_read", `     1\t${twin}\n     2\t`),
      toolUse("tu_decl", DECLASSIFY, { symbol: outer }), toolResult("tu_decl", decl.text)];

    // ── The model Writes summary.md; the proxy labels the path at the tool_use.
    const ask = userText(`Write a file named summary.md containing the sentence: ${SENTENCE}`);
    const input = { file_path: summary, content: SENTENCE };
    await r.through("A", [...history, ask], buildToolUseSse({ id: "tu_write", name: "Write", input }));
    writeFileSync(summary, SENTENCE);
    const level = await r.real.pathLevel(summary);
    assert.equal(level.level, "any-model", "summary.md is labelled at A's watermark: the result's path is secret (not vacuous)");

    // ── The Write's own result: forwarded as Claude Code wrote it. ─────────
    const created = `File created successfully at: ${summary}${CURRENT}\n\n${BUDGET}`;
    const after = await r.through("A", [...history, ask, toolUse("tu_write", "Write", input), toolResult("tu_write", created)], buildTextSse("Done.", { deltas: 1 }));
    const got = resultOf(after.up, "tu_write");
    assert.equal(got, created, `A's model reads its Write's result as written, not $MDU:anymodel_Write[…]: ${got}`);

    // an overwrite of the same file, the update form
    const input2 = { file_path: summary, content: `${SENTENCE}\nSigned.\n` };
    const updated = `The file ${summary} has been updated successfully.${CURRENT}\n\n${BUDGET}`;
    const again = await r.through("A", [...history, ask, toolUse("tu_write", "Write", input), toolResult("tu_write", created),
      toolUse("tu_write2", "Write", input2), toolResult("tu_write2", updated)], buildTextSse("Done.", { deltas: 1 }));
    assert.equal(resultOf(again.up, "tu_write2"), updated, "the update notice is raw too");
    assert.equal(resultOf(again.up, "tu_write"), created, "and the earlier notice stays raw on resend");
  } finally {
    await r.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: beside a no-model file, only the model's own Write notice is raw; every result that could carry a byte the model did not write stays masked", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-write-notice-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws-notice");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const conf = join(ws, "deploy", "app.env");
  const FILE = `API_TOKEN=${TOKEN}\nHOST=internal.example\n`;
  writeFileSync(conf, FILE);
  const r = await rig([{ path: join(ws, "deploy"), level: "no-model", recursive: true }], tmp, ws, home);
  try {
    const mine = { file_path: conf, content: "API_TOKEN=placeholder\n" };
    const created = `File created successfully at: ${conf}${CURRENT}\n\n${BUDGET}`;
    const snippet = `The file ${conf} has been updated. Here's the result of running \`cat -n\` on a snippet of the edited file:\n     1\tAPI_TOKEN=${TOKEN}\n     2\tHOST=internal.example`;
    const cases: Array<[string, string, Record<string, unknown>, string]> = [
      ["tu_read", "Read", { file_path: conf }, `     1\tAPI_TOKEN=${TOKEN}\n     2\tHOST=internal.example\n`],
      ["tu_own", "Write", mine, created],
      ["tu_snippet", "Write", mine, snippet],
      ["tu_reminder", "Write", mine, `File created successfully at: ${conf}${CURRENT}\n\n${MCP_REMINDER}`],
      ["tu_edit", "Edit", { file_path: conf, old_string: "API_TOKEN=placeholder", new_string: "API_TOKEN=changeme" }, `The file ${conf} has been updated successfully.${CURRENT}`],
      ["tu_other", "Write", mine, `File created successfully at: ${join(ws, "deploy", "other.env")}`],
      ["tu_nocontent", "Write", { file_path: conf }, `File created successfully at: ${conf}`],
    ];
    const messages: Msg[] = [userText("Look at deploy/app.env and rewrite it with a placeholder token.")];
    for (const [id, name, input, result] of cases) messages.push(toolUse(id, name, input), toolResult(id, result));
    const { up } = await r.through("B", messages, buildTextSse("ok", { deltas: 1 }));
    assert.equal((await r.real.sessionState("B")).high, false, "B is not HIGH: the release does not lean on a watermark");

    assert.equal(resultOf(up, "tu_own"), created, "the model's own Write notice for the no-model file reaches it raw");
    for (const id of ["tu_read", "tu_snippet", "tu_reminder", "tu_edit", "tu_other", "tu_nocontent"]) {
      const got = resultOf(up, id);
      assert.match(got, SYMBOL_RE, `${id} stays masked: ${got}`);
      assert.ok(!got.includes("successfully"), `${id}: no notice text beside the symbol: ${got}`);
    }

    // THE ORACLE: no byte of the file's secret in anything the model received.
    const sent = up.requests[up.requests.length - 1]!.bodyText;
    for (const piece of [TOKEN, "ghp_FakeWriteNotice", "internal.example"]) {
      assert.ok(!sent.includes(piece), `the model never receives ${piece}`);
    }
  } finally {
    await r.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** OpenCode 1.18.13's `write{filePath, content}` answer (the compiled tool in
 *  the opencode-ai binary): a fixed sentence, then LSP diagnostics if any. */
const OC1_NOTICE = "Wrote file successfully.";
/** OpenClaw 2026.7.1-2's `write{path, content}` answer (dist/sessions-*.js). */
const oclNotice = (n: number, path: string): string => `Successfully wrote ${n} bytes to ${path}`;
const NOTICE_WORDS = /successfully|No changes/i;

/** A rig beside a `no-model` deploy/app.env, sessions OC1 (`opencode`) and
 *  OCL (`openclaw-agent`) bound to their agents' specs. */
async function agentRig(): Promise<Rig & { conf: string; read: string }> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-write-notice-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws-notice");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const conf = join(ws, "deploy", "app.env");
  writeFileSync(conf, `API_TOKEN=${TOKEN}\nHOST=internal.example\n`);
  const r = await rig([{ path: join(ws, "deploy"), level: "no-model", recursive: true }], tmp, ws, home);
  for (const [sessionKey, spec] of [["OC1", "opencode"], ["OCL", "openclaw-agent"]] as const) {
    assert.equal((await r.real.setSessionSpec({ sessionKey, spec, requestedBy: "write-notice-raw e2e" })).bound, spec);
  }
  return { ...r, conf, read: `     1\tAPI_TOKEN=${TOKEN}\n     2\tHOST=internal.example\n` };
}

/** THE ORACLE: no byte of the file's secret in anything a model received. */
function assertNoFileByte(ups: MockUpstream[]): void {
  for (const up of ups) {
    for (const req of up.requests) {
      for (const piece of [TOKEN, "ghp_FakeWriteNotice", "internal.example"]) {
        assert.ok(!req.bodyText.includes(piece), `the model never receives ${piece}`);
      }
    }
  }
}

test("secrets: OpenClaw's and OpenCode 1's own write notice for a no-model file is raw in their own sessions; every altered or other answer stays masked", async () => {
  const r = await agentRig();
  const { conf, read } = r;
  try {
    const NEW = "API_TOKEN=placeholder\n";

    // ── OpenClaw: write{path, content} → "Successfully wrote N bytes to <path>"
    const ocl = { path: conf, content: NEW };
    const own = oclNotice(NEW.length, conf);
    const oclCases: Array<[string, string, Record<string, unknown>, string]> = [
      ["tu_ocl_read", "read", { path: conf }, read],
      ["tu_ocl_own", "write", ocl, own],
      ["tu_ocl_same", "write", ocl, `No changes made to ${conf}. The file already has identical content.`],
      ["tu_ocl_count", "write", ocl, oclNotice(NEW.length + 17, conf)],
      ["tu_ocl_path", "write", ocl, oclNotice(NEW.length, conf.replace("app.env", "other.env"))],
      ["tu_ocl_tail", "write", ocl, `${own}\n${read}`],
      ["tu_ocl_nocontent", "write", { path: conf }, own],
    ];
    const oclMsgs: Msg[] = [userText("Rewrite deploy/app.env with a placeholder token.")];
    for (const [id, name, input, result] of oclCases) oclMsgs.push(toolUse(id, name, input), toolResult(id, result));
    const a = await r.through("OCL", oclMsgs, buildTextSse("ok", { deltas: 1 }));
    assert.equal(resultOf(a.up, "tu_ocl_own"), own, "OpenClaw's own write notice for the no-model file reaches the model raw");
    for (const id of ["tu_ocl_read", "tu_ocl_same", "tu_ocl_count", "tu_ocl_path", "tu_ocl_tail", "tu_ocl_nocontent"]) {
      const got = resultOf(a.up, id);
      assert.match(got, SYMBOL_RE, `${id} stays masked: ${got}`);
      assert.doesNotMatch(got, NOTICE_WORDS, `${id}: no notice text beside the symbol: ${got}`);
    }

    // ── OpenCode 1: write{filePath, content} → "Wrote file successfully."
    const oc1 = { filePath: conf, content: NEW };
    const oc1Cases: Array<[string, string, Record<string, unknown>, string]> = [
      ["tu_oc1_read", "read", { filePath: conf }, read],
      ["tu_oc1_own", "write", oc1, OC1_NOTICE],
      ["tu_oc1_diag", "write", oc1, `${OC1_NOTICE}\n\nLSP errors detected in this file, please fix:\n<diagnostics file="${conf}">\nERROR [1:11] ${TOKEN}\n</diagnostics>`],
      ["tu_oc1_forged", "write", oc1, `${OC1_NOTICE} ${TOKEN}`],
      ["tu_oc1_nocontent", "write", { filePath: conf }, OC1_NOTICE],
    ];
    const oc1Msgs: Msg[] = [userText("Rewrite deploy/app.env with a placeholder token.")];
    for (const [id, name, input, result] of oc1Cases) oc1Msgs.push(toolUse(id, name, input), toolResult(id, result));
    const b = await r.through("OC1", oc1Msgs, buildTextSse("ok", { deltas: 1 }));
    assert.equal(resultOf(b.up, "tu_oc1_own"), OC1_NOTICE, "OpenCode 1's own write notice for the no-model file reaches the model raw");
    for (const id of ["tu_oc1_read", "tu_oc1_diag", "tu_oc1_forged", "tu_oc1_nocontent"]) {
      const got = resultOf(b.up, id);
      assert.match(got, SYMBOL_RE, `${id} stays masked: ${got}`);
      assert.doesNotMatch(got, NOTICE_WORDS, `${id}: no notice text beside the symbol: ${got}`);
    }

    // ── The value backstop (plan 15 §13.10, "The notice is no piece"): the
    // masked results above were registered as secret values (the diagnostics
    // form, the notice with file lines after it, the no-content calls), and
    // the notice line was a piece of them. The agents re-send the history
    // every turn: the own notices stay raw on the resend, and another OpenCode
    // 1 session's notice for an unlabelled file stays raw too.
    const a2 = await r.through("OCL", oclMsgs, buildTextSse("ok", { deltas: 1 }));
    assert.equal(resultOf(a2.up, "tu_ocl_own"), own, "OpenClaw's own notice stays raw on the resend");
    const b2 = await r.through("OC1", oc1Msgs, buildTextSse("ok", { deltas: 1 }));
    assert.equal(resultOf(b2.up, "tu_oc1_own"), OC1_NOTICE, "OpenCode 1's own notice stays raw on the resend, after its diagnostics form was masked");
    assert.equal((await r.real.setSessionSpec({ sessionKey: "OC1B", spec: "opencode", requestedBy: "write-notice-raw e2e" })).bound, "opencode");
    const notes = conf.replace("deploy/app.env", "notes.md");
    const c = await r.through("OC1B", [userText("Write notes.md."), toolUse("tu_b_notes", "write", { filePath: notes, content: "hello\n" }), toolResult("tu_b_notes", OC1_NOTICE)], buildTextSse("ok", { deltas: 1 }));
    assert.equal(resultOf(c.up, "tu_b_notes"), OC1_NOTICE, "another session's OpenCode 1 notice for an unlabelled file is raw");
    // Fail-closed beside it: the masked rows' own lines still count. A later
    // result that prints the diagnostics' line is masked by the backstop.
    const d = await r.through("OC1B", [userText("Run the linter."), toolUse("tu_b_lint", "bash", { command: "npx tsc --noEmit" }),
      toolResult("tu_b_lint", `ERROR [1:11] ${TOKEN}\n`)], buildTextSse("ok", { deltas: 1 }));
    assert.match(resultOf(d.up, "tu_b_lint"), SYMBOL_RE, "a later result carrying the masked diagnostics' line is masked");

    assertNoFileByte([a.up, b.up, a2.up, b2.up, c.up, d.up]);
  } finally {
    await r.close();
    rmSync(r.tmp, { recursive: true, force: true });
  }
});

test("secrets: each agent's write sentence is masked in another agent's session (OpenCode 1's in OpenClaw, OpenClaw's in OpenCode 1 and Claude Code)", async () => {
  // Each check first in its own request, before any value it could match is
  // registered, so the mask is the rule's verdict and not the value backstop.
  const r = await agentRig();
  const { conf } = r;
  try {
    const ups: MockUpstream[] = [];
    const one = async (session: string, name: string, input: Record<string, unknown>, result: string, why: string): Promise<void> => {
      const { up } = await r.through(session, [userText("Rewrite deploy/app.env."), toolUse("tu_x", name, input), toolResult("tu_x", result)], buildTextSse("ok", { deltas: 1 }));
      ups.push(up);
      const got = resultOf(up, "tu_x");
      assert.match(got, SYMBOL_RE, `${why}: ${got}`);
      assert.doesNotMatch(got, NOTICE_WORDS, `${why}: no notice text beside the symbol: ${got}`);
    };
    const c1 = "API_TOKEN=one\n";
    const c2 = "API_TOKEN=second\n";
    await one("OCL", "write", { path: conf, content: c1 }, OC1_NOTICE, "OpenCode 1's sentence in an OpenClaw session");
    await one("OC1", "write", { filePath: conf, content: c1 }, oclNotice(c1.length, conf), "OpenClaw's sentence in an OpenCode session");
    await one("CC", "Write", { file_path: conf, content: c2 }, oclNotice(c2.length, conf), "OpenClaw's sentence from Claude Code's Write");
    assertNoFileByte(ups);
  } finally {
    await r.close();
    rmSync(r.tmp, { recursive: true, force: true });
  }
});

test("secrets: a masked write result whose first line is the agent's notice (Claude Code, OpenCode 2, Goose) does not mask that agent's later notice for the path; its other lines still do", async () => {
  // Plan 15 §13.10, "The notice is no piece". Each agent's first write of
  // the no-model file comes back with more than its notice (Claude Code: the
  // MCP instructions reminder the proxy splits off, leaving the notice as the
  // symbol's whole value; OpenCode 2: LSP diagnostics; Goose: a warning
  // line), so it is masked and registered. Before, the notice (the whole
  // value, or its first line) was a piece of that row and the agent's next
  // notice for the same path came back as a symbol.
  const r = await agentRig();
  const { conf } = r;
  try {
    assert.equal((await r.real.setSessionSpec({ sessionKey: "GS", spec: "goose", requestedBy: "write-notice-raw e2e" })).bound, "goose");
    const ups: MockUpstream[] = [];
    const DIAG = `\n\nLSP errors detected in this file, please fix:\n<diagnostics file="${conf}">\nERROR [1:11] ${TOKEN}\n</diagnostics>`;
    const agents: Array<{ session: string; tool: string; input: Record<string, unknown>; notice: string; masked: string }> = [
      { session: "CCP", tool: "Write", input: { file_path: conf, content: "API_TOKEN=a\n" },
        notice: `File created successfully at: ${conf}${CURRENT}`, masked: `File created successfully at: ${conf}${CURRENT}\n\n${MCP_REMINDER}` },
      { session: "OC2", tool: "write", input: { path: conf, content: "API_TOKEN=b\n" },
        notice: `Created file successfully: ${conf}`, masked: `Created file successfully: ${conf}${DIAG}` },
      { session: "GS", tool: "write", input: { path: conf, content: "API_TOKEN=c\n" },
        notice: `Created ${conf} (1 lines)`, masked: `Created ${conf} (1 lines)\nwarning: ${TOKEN} looked like a key` },
    ];
    assert.equal((await r.real.setSessionSpec({ sessionKey: "OC2", spec: "opencode", requestedBy: "write-notice-raw e2e" })).bound, "opencode");
    for (const a of agents) {
      const first: Msg[] = [userText("Rewrite deploy/app.env."), toolUse("tu_1", a.tool, a.input), toolResult("tu_1", a.masked)];
      const one = await r.through(a.session, first, buildTextSse("ok", { deltas: 1 }));
      ups.push(one.up);
      assert.match(resultOf(one.up, "tu_1"), SYMBOL_RE, `${a.session}: the write result with more than the notice is masked`);
      const later = [...first, toolUse("tu_2", a.tool, a.input), toolResult("tu_2", a.notice)];
      const two = await r.through(a.session, later, buildTextSse("ok", { deltas: 1 }));
      ups.push(two.up);
      assert.equal(resultOf(two.up, "tu_2"), a.notice, `${a.session}: the agent's later notice for the path is raw, not masked by the first result's row`);
    }
    // Fail-closed beside it: a result that prints the masked rows' other
    // lines is masked by the backstop.
    for (const [session, line] of [["OC2", `ERROR [1:11] ${TOKEN}`], ["GS", `warning: ${TOKEN} looked like a key`]] as const) {
      const { up } = await r.through(session, [userText("Run it."), toolUse("tu_3", "bash", { command: "make" }), toolResult("tu_3", `${line}\n`)], buildTextSse("ok", { deltas: 1 }));
      ups.push(up);
      assert.match(resultOf(up, "tu_3"), SYMBOL_RE, `${session}: a later result with the masked row's line is masked`);
    }
    assertNoFileByte(ups);
  } finally {
    await r.close();
    rmSync(r.tmp, { recursive: true, force: true });
  }
});
