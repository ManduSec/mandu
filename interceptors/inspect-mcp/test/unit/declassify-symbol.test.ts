/**
 * declassify-symbol unit tests — the shared rung-3 relay (src/declassify-symbol.ts)
 * that the MCP server and the OpenClaw plugin tool both run.
 *
 * The arbiter decides; the relay must (1) thread the symbol, the reason and
 * the Mandu session through unchanged, (2) return the released value only on
 * an explicit allow, in the one shape the arbiter's result rule accepts, and
 * (3) fail closed with NO content on every refusal, a missing op, or an
 * arbiter that cannot answer.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { declassifySymbol, declassifiedNotice, type DeclassifyDeps } from "../../src/declassify-symbol.js";
import { handleRpc } from "../../src/mcp-server.js";
import type { DeclassifyResult } from "../../src/arbiter-client.js";
import { INSPECT_FALLBACK_SESSION, scopeSessionId } from "../../src/inspect-symbol.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUllm } from "../helpers/mock-ullm.js";

const SYM = "$MDU:anymodel_read[7b21]";
const BODY = "Reference code R-2718. DECLASSIFY_UNIT_CANARY";

/** An arbiter whose rung-3 op answers `verdict` (or throws), recording calls. */
function arbiterWith(verdict: DeclassifyResult | Error): { deps: DeclassifyDeps; calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    calls,
    deps: {
      sessionId: "scope-1",
      arbiter: {
        async declassify(args) {
          calls.push(args);
          if (verdict instanceof Error) throw verdict;
          return verdict;
        },
      },
    },
  };
}

/** The arbiter's acceptance rule for a declassify result (server.ts
 *  declassifyResultTrusted), replicated as a drift tripwire. */
function arbiterAccepts(text: string, released: string): boolean {
  if (text === released) return true;
  const tail = `\n\n${released}`;
  if (!text.endsWith(tail)) return false;
  return /^\[DECLASSIFIED[^\n\]]*\]$/.test(text.slice(0, text.length - tail.length));
}

test("the notice tells the model to keep making its calls, and to make a stopped one again after the user answers", () => {
  // Live 2026-10-10 (OpenCode, haiku, watch-20261010T003401): told "every
  // shell command requires the user's approval", the model never issued
  // `echo mandu-ready` and asked the user to approve it on the dashboard,
  // where nothing was waiting (handling-prompt.md §7). Since 2026-10-11 the
  // gate stops the call AND files the ask (§8): the model makes the call,
  // tells the user, and makes it again after the answer.
  const n = declassifiedNotice("any-model");
  assert.match(n, /^\[DECLASSIFIED — this session is now HIGH \(any-model\)\. /);
  // A request to a bound host is allowed: OpenClaw's haiku (watch-20261010T004120)
  // refused example.com, the memo's bound host, on the old words.
  assert.match(n, /Requests to the hosts this content is bound to still go through; any other network request or shell command that could carry it out is stopped while Mandu asks the user on its Approvals page\./);
  assert.match(n, /Keep making the calls the user asks for and let Mandu decide each one/);
  assert.match(n, /never refuse one yourself or ask the user to approve it first/);
  assert.match(n, /if Mandu stops one, tell the user and make it again after they answer\./);
  assert.match(n, /Do not repeat this content into any tool call you would not want released\.\]$/);
  assert.doesNotMatch(n, /requires the user's approval/);
  assert.ok(arbiterAccepts(`${n}\n\n${BODY}`, BODY), "still one line with no early `]`");
});

test("allowed: the value follows the one-line notice, in the shape the arbiter's result rule accepts", async () => {
  const { deps, calls } = arbiterWith({ value: BODY, allowed: true, requiresApproval: false, reason: "ok", watermark: "any-model" });
  const out = await declassifySymbol(deps, { symbol: SYM, reason: "the user asked" });
  assert.equal(out.ok, true);
  if (!out.ok) return;
  assert.equal(out.text, `${declassifiedNotice("any-model")}\n\n${BODY}`);
  assert.ok(arbiterAccepts(out.text, BODY), "the arbiter must recognize its own release");
  assert.deepEqual(calls, [{ symbol: SYM, sessionKey: "scope-1", reason: "the user asked" }],
    "symbol, reason and the Mandu session go through unchanged");
});

test("approval pending: an error that says to wait, and no content", async () => {
  const { deps } = arbiterWith({ value: null, allowed: false, requiresApproval: true, reason: "the session ingested untrusted data" });
  const out = await declassifySymbol(deps, { symbol: SYM, reason: "r" });
  assert.equal(out.ok, false);
  if (out.ok) return;
  assert.match(out.error, /asked to approve/);
  assert.match(out.error, /untrusted data/);
});

test("hard refusal: an error that says not to retry", async () => {
  const { deps } = arbiterWith({ value: null, allowed: false, requiresApproval: false, reason: "REFUSED: no-model data" });
  const out = await declassifySymbol(deps, { symbol: SYM, reason: "r" });
  assert.equal(out.ok, false);
  if (!out.ok) assert.match(out.error, /do not retry/);
});

test("an allowed verdict with a null value is still a refusal (no empty release)", async () => {
  const { deps } = arbiterWith({ value: null, allowed: true, requiresApproval: false, reason: "odd" });
  assert.equal((await declassifySymbol(deps, { symbol: SYM })).ok, false);
});

test("fail closed: an arbiter that throws (unreachable) yields an error with no content", async () => {
  const { deps } = arbiterWith(new Error("connect ENOENT /run/mandu/arbiter.sock"));
  const out = await declassifySymbol(deps, { symbol: SYM, reason: "r" });
  assert.equal(out.ok, false);
  if (!out.ok) assert.match(out.error, /arbiter error: connect ENOENT/);
});

test("no symbol, or an arbiter without the op: refused before any content can exist", async () => {
  const { deps, calls } = arbiterWith({ value: BODY, allowed: true, requiresApproval: false, reason: "ok" });
  assert.equal((await declassifySymbol(deps, {})).ok, false);
  assert.equal((await declassifySymbol(deps, "not an object")).ok, false);
  assert.equal(calls.length, 0, "the arbiter is never asked without a symbol");
  const bare = await declassifySymbol({ arbiter: {}, sessionId: "s" }, { symbol: SYM });
  assert.equal(bare.ok, false);
  if (!bare.ok) assert.match(bare.error, /use inspect_symbol/);
});

test("the MCP server's declassify_symbol is this relay: same text on allow, a tool error on refusal", async () => {
  const arbiter = new MockArbiter();
  let verdict: DeclassifyResult = { value: BODY, allowed: true, requiresApproval: false, reason: "ok", watermark: "any-model" };
  (arbiter as unknown as { declassify: () => Promise<DeclassifyResult> }).declassify = async () => verdict;
  const deps = { arbiter, ullm: new MockUllm({ reply: "x" }), sessionId: "scope-1" };
  const call = () => handleRpc({
    jsonrpc: "2.0", id: 9, method: "tools/call",
    params: { name: "declassify_symbol", arguments: { symbol: SYM, reason: "r" } },
  }, deps);
  const ok = (await call())!.result as { isError?: boolean; content: { text: string }[] };
  assert.equal(ok.isError, undefined);
  assert.equal(ok.content[0]!.text, `${declassifiedNotice("any-model")}\n\n${BODY}`);
  verdict = { value: null, allowed: false, requiresApproval: false, reason: "REFUSED" };
  const no = (await call())!.result as { isError?: boolean; content: { text: string }[] };
  assert.equal(no.isError, true);
  assert.ok(!JSON.stringify(no).includes("DECLASSIFY_UNIT_CANARY"));
});

test("FAIL CLOSED: no Mandu scope (absent, blank, or the stdio server's inspect fallback) → refused before the arbiter is asked", async () => {
  for (const sessionId of [undefined, "", "   ", INSPECT_FALLBACK_SESSION]) {
    const { deps, calls } = arbiterWith({ value: BODY, allowed: true, requiresApproval: false, reason: "ok", watermark: "any-model" });
    const out = await declassifySymbol({ ...deps, sessionId }, { symbol: SYM, reason: "r" });
    assert.equal(out.ok, false, `sessionId=${JSON.stringify(sessionId)}`);
    if (!out.ok) assert.match(out.error, /no Mandu scope is configured \(MANDU_SCOPE_ID\)/);
    assert.ok(!JSON.stringify(out).includes("DECLASSIFY_UNIT_CANARY"));
    assert.equal(calls.length, 0, "nothing is queued or released: the arbiter is never asked");
  }
});

test("the stdio server's session: MANDU_SCOPE_ID when set, else the inspect fallback (which inspect accepts and declassify refuses)", async () => {
  assert.equal(scopeSessionId({ MANDU_SCOPE_ID: "scope-7" }), "scope-7");
  assert.equal(scopeSessionId({ MANDU_SCOPE_ID: "  scope-7 " }), "scope-7");
  assert.equal(scopeSessionId({}), INSPECT_FALLBACK_SESSION);
  assert.equal(scopeSessionId({ MANDU_SCOPE_ID: "" }), INSPECT_FALLBACK_SESSION);
  // through the MCP handler, with the server's own derivation of the session
  const arbiter = new MockArbiter();
  let asked = 0;
  (arbiter as unknown as { declassify: () => Promise<DeclassifyResult> }).declassify = async () => {
    asked++;
    return { value: BODY, allowed: true, requiresApproval: false, reason: "ok", watermark: "any-model" };
  };
  const deps = { arbiter, ullm: new MockUllm({ reply: "x" }), sessionId: scopeSessionId({}) };
  const r = (await handleRpc({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "declassify_symbol", arguments: { symbol: SYM, reason: "r" } },
  }, deps))!.result as { isError?: boolean; content: { text: string }[] };
  assert.equal(r.isError, true);
  assert.match(r.content[0]!.text, /no Mandu scope/);
  assert.ok(!JSON.stringify(r).includes("DECLASSIFY_UNIT_CANARY"));
  assert.equal(asked, 0);
});
