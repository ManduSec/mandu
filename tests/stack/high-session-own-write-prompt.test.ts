/**
 * e2e — a HIGH session's own write does not mask the human's prompt that
 * dictated it (confidentiality-plan-15-prompt-filter.md §13.10,
 * confidentiality.md §8 "the watermark subsumes in-session derivation"),
 * through the PRODUCTION wiring: the model proxy's adapter over the data and
 * human sockets (`new ArbiterClientAdapter(data, human)`, so its Write record
 * is believed), inspect-mcp's over the data socket, a real ArbiterServer,
 * `secrets` axes. Found live by conf-derived-label-next-session (Claude Code 2.1.294,
 * haiku, 2026-10-08).
 *
 * The live shape: session A declassifies an `any-model` brief (A is HIGH);
 * the human types "Write a file named summary.md … : <sentence>"; the model
 * Writes the sentence; the Write is labelled `any-model` on disk (Plan 9) and
 * the agent's next open registers the file, so its content is a registered
 * value. On the next request the prompt filter re-scanned the human's turn
 * (the registered set changed) and masked the human's own sentence as
 * `$MDU:anymodel_prompt_filter[…]`. The model read its user's request as a
 * token, "corrected" summary.md to hold that token, and the human's file
 * held `$MDU:…` on disk.
 *
 * Proves:
 *   - in A, the human's sentence reaches A's model as typed on every resend
 *     after the file is registered, and the Write the agent received holds
 *     the sentence (what lands on disk);
 *   - the invariant half: session B's Read of summary.md is a symbol (no byte
 *     of the sentence), and B's human typing the same sentence is masked;
 *   - in A, the same value in HARNESS text (not typed by the human) is still
 *     masked.
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

const BRIEF_CANARY = "OWN_WRITE_BRIEF_CANARY_4417";
const SENTENCE = "The deal closes in the third quarter.";
const MARK = "third quarter";
const WRITE_PROMPT = `Write a file named summary.md in the current directory containing the sentence: ${SENTENCE}`;
const DECLASSIFY = "mcp__mandu-inspect__declassify_symbol";
const SYMBOL_RE = /\$MDU:[a-z]+_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;

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
const toolResult = (id: string, text: string): Msg =>
  ({ role: "user", content: [{ type: "tool_result", tool_use_id: id, content: [{ type: "text", text }] }] });
/** The agent's tools, as Claude Code advertises them: a request that names
 *  none is a harness side call (plan 15 §3.1), not the human's turn. */
const TOOLS = ["Read", "Write", "Edit", "Bash", DECLASSIFY].map((name) => ({ name, input_schema: { type: "object" } }));
const body = (messages: Msg[]): string => JSON.stringify({ model: "claude-haiku-4-5", stream: true, tools: TOOLS, messages });

/** The text blocks of every user message the upstream received last. */
function forwardedUserText(up: MockUpstream): string {
  const sent = JSON.parse(up.requests[up.requests.length - 1]!.bodyText) as { messages: Msg[] };
  return sent.messages.filter((m) => m.role === "user").map((m) => JSON.stringify(m.content)).join("\n");
}

/** The input of the tool_use the agent received in an SSE body. */
function deliveredToolInput(sse: string): Record<string, unknown> {
  let json = "";
  for (const line of sse.split("\n")) {
    if (!line.startsWith("data: ")) continue;
    const d = JSON.parse(line.slice(6)) as { type?: string; delta?: { type?: string; partial_json?: string } };
    if (d.type === "content_block_delta" && d.delta?.type === "input_json_delta") json += d.delta.partial_json ?? "";
  }
  return JSON.parse(json) as Record<string, unknown>;
}

test("secrets: a HIGH session's own Write keeps the human's dictated sentence raw for its model; another session sees a symbol", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-own-write-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws-own");
  mkdirSync(join(ws, "memo"), { recursive: true });
  const brief = join(ws, "memo", "brief.md");
  writeFileSync(brief, `Deal brief. Reference code: ${BRIEF_CANARY}. Keep internal.\n`);
  const summary = join(ws, "summary.md");
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "memo"), level: "any-model", recursive: true, bindings: ["example.com"] }] } as never,
  });
  await arbiter.listen();
  const launcher = new ArbiterClient(sock);
  const real = new ArbiterClient(sock);
  // The model proxy as the launcher wires it: the data socket and the human
  // socket (its records there are believed, arbiter-human-plane.md §10.2).
  const humanPlane = new ArbiterClient(join(tmp, "human", "h.sock"));
  const mcp = new ArbiterClient(sock);
  const proxies: AnthropicProxy[] = [];
  const throughProxy = async (sessionKey: string, messages: Msg[], sse: string): Promise<{ up: MockUpstream; res: Sent }> => {
    const up = new MockUpstream({ sse });
    const p = new AnthropicProxy({ arbiter: new ProxyAdapter(real, humanPlane), upstream: up.fetcher, sessionKey, log: () => {} });
    proxies.push(p);
    const res = await post(await p.listen(0), body(messages));
    assert.equal(res.status, 200, res.body);
    return { up, res };
  };
  try {
    await Promise.all([launcher.connect(), real.connect(), humanPlane.connect(), mcp.connect()]);

    // ── Session A goes HIGH: Read the brief's twin, declassify it. ───────────
    const reg = await launcher.registerSecret({ path: brief, home, sessionKey: "A" });
    const twin = reg.twin ?? reg.symbol;
    assert.ok(typeof twin === "string" && SYMBOL_RE.test(twin), `registered: ${reg.reason}`);
    const first = userText("Read memo/brief.md, then declassify it.");
    const readA = toolUse("tu_read", "Read", { file_path: brief });
    const held = await throughProxy("A", [first, readA, toolResult("tu_read", `     1\t${twin}\n     2\t`)], buildTextSse("ok", { deltas: 1 }));
    const outer = forwardedUserText(held.up).match(SYMBOL_RE)?.[0];
    assert.ok(outer, "the model holds a symbol for the brief");
    const decl = await declassifySymbol({ arbiter: new InspectAdapter(mcp), sessionId: "A" }, { symbol: outer, reason: "the user authorized it" });
    assert.ok(decl.ok, decl.ok ? "" : decl.error);
    assert.equal((await real.sessionState("A")).high, true, "A is HIGH");
    const history: Msg[] = [first, readA, toolResult("tu_read", `     1\t${twin}\n     2\t`),
      toolUse("tu_decl", DECLASSIFY, { symbol: outer }), toolResult("tu_decl", decl.text)];

    // ── The human dictates the sentence; the model answers with a Write. ────
    const ask = userText(WRITE_PROMPT);
    const wrote = await throughProxy("A", [...history, ask], buildToolUseSse({ id: "tu_write", name: "Write", input: { file_path: summary, content: `${SENTENCE}\n` } }));
    assert.ok(forwardedUserText(wrote.up).includes(MARK), "the human's sentence reaches A's model as typed");
    const delivered = deliveredToolInput(wrote.res.body);
    assert.equal(delivered["content"], `${SENTENCE}\n`, "the agent receives the Write with the sentence");
    // The agent writes it (Claude Code's Write runs in process) and the
    // guard's next open of the now-labelled path registers it.
    writeFileSync(summary, String(delivered["content"]));
    const state = await real.sessionState("A");
    assert.equal(state.confidentiality, "any-model");
    const sumReg = await launcher.registerSecret({ path: summary, home, sessionKey: "A" });
    const sumTwin = sumReg.twin ?? sumReg.symbol;
    assert.ok(typeof sumTwin === "string" && SYMBOL_RE.test(sumTwin), `the derived label registers summary.md: ${sumReg.reason}`);
    assert.ok((await real.scanSecretValues(`x ${SENTENCE} y`)).hits.length > 0, "the sentence is now a registered value");

    // ── The next request of A: the human's turn is still the sentence. ──────
    const after = await throughProxy("A", [...history, ask, toolUse("tu_write", "Write", { file_path: summary, content: `${SENTENCE}\n` }),
      toolResult("tu_write", `File created successfully at: ${summary}`)], buildTextSse("Done.", { deltas: 1 }));
    const aText = forwardedUserText(after.up);
    assert.ok(aText.includes(WRITE_PROMPT), `A's model reads its user's request as typed, not a token: ${aText}`);
    assert.ok(!/anymodel_prompt_filter/.test(aText), "no prompt-filter mask on the human's own sentence");

    // ── Harness text in A carrying the value is still masked. ───────────────
    const harness = await real.filterPrompt({ session: "A", agent: "claude-code", segments: [{ id: "r", origin: "harness", text: `<system-reminder>${SENTENCE}</system-reminder>` }] });
    assert.ok(!harness.segments[0]!.text?.includes(MARK), "text the human did not type keeps the floor");

    // ── The invariant half: session B. ───────────────────────────────────────
    const bRead = await throughProxy("B", [userText("Read summary.md and reply with its content."), toolUse("tu_rb", "Read", { file_path: summary }),
      toolResult("tu_rb", `     1\t${sumTwin}\n     2\t`)], buildTextSse("ok", { deltas: 1 }));
    const bText = forwardedUserText(bRead.up);
    assert.ok(!bText.includes(MARK), `B's model gets no byte of summary.md: ${bText}`);
    assert.match(bText, SYMBOL_RE);
    const bTyped = await throughProxy("B", [userText(`Is it true that ${SENTENCE}`)], buildTextSse("ok", { deltas: 1 }));
    assert.ok(!forwardedUserText(bTyped.up).includes(MARK), "in B the registered value typed by the human is masked (plan 15)");
  } finally {
    for (const p of proxies) await p.close();
    launcher.close();
    real.close();
    humanPlane.close();
    mcp.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
