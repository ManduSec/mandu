/**
 * codex-document-twin — plan 10 §11.8, "A document's own twin" (2026-10-12),
 * over the REAL components: a Codex `cat` of a labelled document that the
 * guard served as its whole-file twin reaches the model as Codex's head and
 * the document's OWN token, not wrapped in a fresh whole-result token.
 *
 *   a real ArbiterServer in `secrets` (a policy file labels `memo/brief.md`
 *   any-model, bound to example.com, and `memo/plan.md` no-model), the real
 *   openai-proxy over HTTP in its production wiring, a scripted model behind
 *   it. The launcher's registration gives each document its whole-file twin
 *   (the base token and the file's own terminator); `.env` gets its
 *   structured twin. Each call is relayed through the proxy (gated and its
 *   command recorded) and the guard records Codex's shell for it, as the
 *   live stack does; `cat` opens the document and is served the twin.
 *
 * Before (!1025's finding, 2026-10-08): the command names a labelled file,
 * so the result was masked whole under the path-derived precaution as a new
 * row, `$MDU:anymodel_exec_command[…]`, whose value was the head plus the
 * document's token: a token for a token, with no binding of its own.
 *
 * Positive: `cat memo/brief.md` reaches the model as the head and the
 * registration's own token, with the whole-file `twin:` line; the token
 * keeps the document's law (released at example.com, withheld elsewhere).
 * Claude Code's Bash `cat` of it takes the same answer. Control: `.env`'s
 * structured twin is unchanged.
 *
 * Negatives, each still masked whole (one symbol, no document token): a
 * mixed output (`cat …; echo done`), a truncated one (`head -c 12`), two
 * files, `cat -n`'s gutter, a call the guard never recorded, and a tree in
 * which a process read the document raw.
 *
 * THE ORACLE: no request to the model carries a byte of either document or
 * of the `.env`'s secret values, in any case.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream, buildExecCommandSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { ArbiterClientAdapter as AnthropicAdapter, type RealArbiterClient as AnthropicRealClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteMessagesRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const DOC_CANARY = "CODEX_DOC_TWIN_CANARY_8086";
const PLAN_CANARY = "CODEX_PLAN_TWIN_CANARY_6502";
const STRIPE = "sk_live_doc_twin_e2e_0123456789";
const DOC = `Deal brief. Reference code: ${DOC_CANARY}. Keep internal.\n`;
const PLAN = `Plan B. Codeword ${PLAN_CANARY}.\n`;
const ENV = `PORT=3000\nSTRIPE_KEY=${STRIPE}\n`;
const CANARIES = [DOC_CANARY, PLAN_CANARY, STRIPE, "Deal brief", "Plan B"];
const head = (chunk: string): string => `Chunk ID: ${chunk}\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 9\nOutput:\n`;
const TWIN_LINE = (path: string): string => `[mandu:secret] twin: this is ${path} as you see it: the whole file is one symbol. Use the symbol where the file's content belongs (a command that sends it is checked against the file's rules); the user sees the real content.`;
const ONE_SYMBOL = /^\$MDU:[a-z]+_exec_command\[[0-9a-f]{4,8}\]\n\n\[mandu:secret\] masked: /;

function codexTurn(...items: unknown[]): unknown {
  return { model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "read the brief" }] }, ...items] };
}

function codexOutputOf(body: string, callId: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === callId)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("a Codex `cat` of a labelled document's whole-file twin reaches the model as the document's own token; mixed, truncated, two-file, gutter, unrecorded and tainted outputs stay masked whole; no document byte reaches the model (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-doc-twin-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "memo"), { recursive: true });
  const brief = join(ws, "memo", "brief.md");
  const plan = join(ws, "memo", "plan.md");
  const env = join(ws, ".env");
  writeFileSync(brief, DOC);
  writeFileSync(plan, PLAN);
  writeFileSync(env, ENV);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${brief}`, "    level: any-model", "    bindings: [example.com]", `  - path: ${plan}`, "    level: no-model", ""].join("\n"));
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(human); // what the guard writes, on the human socket (plan 13 D9)
  const session = `codex-doc-twin-${process.pid}`;
  // the launcher registers each labelled file at launch (secret-setup.ts)
  const data = await open(sock);
  const regBrief = await data.registerSecret({ path: brief, sessionKey: session });
  const regPlan = await data.registerSecret({ path: plan, sessionKey: session });
  const regEnv = await data.registerSecret({ path: env, sessionKey: session });
  const tok = String(regBrief.symbol);
  const tokPlan = String(regPlan.symbol);
  assert.match(tok, /^\$MDU:anymodel_Read\[[0-9a-f]{4,8}\]$/, JSON.stringify(regBrief));
  assert.equal(regBrief.twin, undefined, "a document: the whole-file twin");
  assert.equal(regBrief.terminator, "\n");
  assert.ok(typeof regEnv.twin === "string" && !regEnv.twin.includes(STRIPE), JSON.stringify(regEnv));

  let upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const seen: string[] = [];
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const send = async (body: unknown, sse = "event: response.completed\ndata: {}\n\n"): Promise<string> => {
    upstream = new OpenAiMockUpstream({ sse });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests[0]!.bodyText;
    seen.push(toModel);
    return toModel;
  };
  /** One model turn asking for `cmd`, relayed (gated + recorded), the guard's
   *  record of Codex's shell for it, and `cat`'s open of each file served the twin. */
  const relay = async (n: number, cmd: string, opens: string[] = []): Promise<{ callId: string; call: unknown }> => {
    const callId = `call_dt_${n}`;
    await send(codexTurn(), buildExecCommandSse({ cmd, callId, itemId: `fc_${n}` }));
    await guard.recordExecRoot({ procKey: `dt-sh-${n}`, ancestors: ["dt-agent-0"], argv: ["/bin/bash", "-lc", cmd], session, callRoot: true });
    for (const path of opens) {
      const chain = [`dt-sh-${n}`, "dt-agent-0"];
      const d = await guard.decideSecretOpen({ path, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: `dt-cat-${n}`, parentKey: chain[0], ancestorKeys: chain, session });
      assert.equal(d.verdict, "twin", `no reader list: cat is served the twin (${d.reason})`);
    }
    return { callId, call: { type: "function_call", call_id: callId, name: "exec_command", arguments: JSON.stringify({ cmd }) } };
  };
  const output = (callId: string, text: string) => ({ type: "function_call_output", call_id: callId, output: text });
  try {
    // ── POSITIVE: the document's own token ────────────────────────────────────
    const catBrief = await relay(1, `cat ${brief}`, [brief]);
    const catEnv = await relay(2, `cat ${env}`, [env]);
    // ── NEGATIVES (each in a clean, recorded tree) ────────────────────────────
    const mixed = await relay(3, `cat ${brief}; echo done`, [brief]);
    const cut = await relay(4, `head -c 12 ${brief}`, [brief]);
    const two = await relay(5, `cat ${brief} ${plan}`, [brief, plan]);
    const gutter = await relay(6, `cat -n ${brief}`, [brief]);
    // a call no shell of the guard's record ran (never relayed, never recorded)
    const ghost = { callId: "call_dt_ghost", call: { type: "function_call", call_id: "call_dt_ghost", name: "exec_command", arguments: JSON.stringify({ cmd: `more ${brief}` }) } };
    const history = [
      catBrief.call, output(catBrief.callId, `${head("9a3f")}${tok}\n`),
      catEnv.call, output(catEnv.callId, `${head("1b2c")}${regEnv.twin as string}`),
      mixed.call, output(mixed.callId, `${head("2c3d")}${tok}\ndone\n`),
      cut.call, output(cut.callId, `${head("3d4e")}${tok.slice(0, 12)}`),
      two.call, output(two.callId, `${head("4e5f")}${tok}\n${tokPlan}\n`),
      gutter.call, output(gutter.callId, `${head("5f60")}     1\t${tok}\n`),
      ghost.call, output(ghost.callId, `${head("6071")}${tok}\n`),
    ];
    const first = await send(codexTurn(...history));

    // the document's own token, exactly Codex's head and the twin bytes, then the line
    assert.equal(codexOutputOf(first, catBrief.callId), `${head("9a3f")}${tok}\n\n\n${TWIN_LINE(brief)}`);
    // control: the structured twin is unchanged (keys visible, values as field symbols)
    const envOut = codexOutputOf(first, catEnv.callId);
    assert.ok(envOut.startsWith(`${head("1b2c")}PORT=3000\nSTRIPE_KEY=`), envOut);
    assert.match(envOut, /twin: this is .*\.env as you see it: the keys as written/);
    for (const [name, id] of [["mixed", mixed.callId], ["truncated", cut.callId], ["two files", two.callId], ["cat -n", gutter.callId], ["no record", ghost.callId]] as const) {
      const o = codexOutputOf(first, id);
      assert.match(o, ONE_SYMBOL, `${name}: masked whole`);
      assert.ok(!o.includes(tok) && !o.includes("twin:"), `${name}: the document's token is not released: ${o}`);
    }

    // The released token keeps the document's law: its bound host, nowhere else.
    const decide = await open(human);
    assert.equal((await decide.desymbolizationDecision({ symbol: tok, boundary: "network", destination: "example.com" })).allow, true, "the document's own token is released at its bound host");
    assert.equal((await decide.desymbolizationDecision({ symbol: tok, boundary: "network", destination: "attacker.test" })).allow, false, "and withheld at any other");

    // Claude Code's Bash `cat` of the same document takes the same answer.
    const claude = new AnthropicAdapter(await open(sock) as unknown as AnthropicRealClient, await open(human) as never);
    const bashCmd = `cat ${brief}`;
    await claude.recordCallCommand!({ callId: "toolu_dt_1", command: bashCmd, sessionKey: session });
    await guard.recordExecRoot({ procKey: "dt-sh-cc", ancestors: ["dt-agent-cc"], argv: ["/bin/bash", "-c", bashCmd], session, callRoot: true });
    const bash = await rewriteMessagesRequest({
      model: "claude-test",
      messages: [
        { role: "user", content: "read the brief" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_dt_1", name: "Bash", input: { command: bashCmd } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_dt_1", content: tok }] },
      ],
    } as MessagesRequest, { arbiter: claude, sessionKey: session });
    const bashOut = (bash.request.messages[2]!.content as Array<{ content: string }>)[0]!.content;
    seen.push(JSON.stringify(bash.request));
    assert.equal(bashOut, `${tok}\n\n${TWIN_LINE(brief)}`);

    // ── NEGATIVE: a process in the tree read the document raw (rule (i)) ─────
    // Last: the session then holds a raw read, which is the point.
    const raw = await relay(7, `cat ${brief}`);
    await guard.recordExecRoot({ procKey: "dt-reader-7", ancestors: ["dt-sh-7", "dt-agent-0"], argv: ["reader", brief], session });
    await guard.taintProcessSecret({ procKey: "dt-reader-7", path: brief, level: "any-model", app: "reader", session });
    const later = await send(codexTurn(raw.call, output(raw.callId, `${head("7182")}${tok}\n`)));
    const rawOut = codexOutputOf(later, raw.callId);
    assert.match(rawOut, ONE_SYMBOL, "a tainted tree: masked whole even for twin-shaped text");
    assert.ok(!rawOut.includes(tok), rawOut);

    // THE ORACLE: no request to the model carried a byte of either document
    // or of the .env's secret value, in any case.
    const wire = seen.join("\n");
    for (const c of CANARIES) assert.ok(!wire.includes(c), `CONFIDENTIALITY VIOLATION: ${c} reached the model`);
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
