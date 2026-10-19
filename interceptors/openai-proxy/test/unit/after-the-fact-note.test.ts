/**
 * after-the-fact-note.test.ts — the openai-proxy twin of the anthropic
 * proxy's test (confidentiality.md §7.1, "Masked after the fact",
 * 2026-10-05): a Codex output this proxy forwarded in clear in an earlier
 * request and masks now (the file was labelled since) carries the same
 * static `[mandu:secret]` line; no byte of the output; only that case.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AFTER_THE_FACT_MARKER, AFTER_THE_FACT_SYSTEM_NOTE, ClearResultLedger, afterTheFactLine, arbiterClearResultStore } from "../../src/after-the-fact.js";
import { ownForwardedText, rewriteRequest, RewriteRefusal } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { CallTaintWire, ClassifyRequest, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const TOKEN = "ghp_FakeTourToken0123456789abcdefABCDEF";
const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\n";
const BODY = `[staging]\nhost = "staging.internal.example"\ntoken = "${TOKEN}"\n`;
// Pinned byte-identical to the anthropic proxy's lines.
const LINE_PLAIN = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; it was marked secret after that (a lock or a label, possibly one made later in this conversation), so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this.";
const LINE_TAINT = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; Mandu masks it now for the reason above, so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this.";
const LINE_READ = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; it was marked secret after that (a lock or a label, possibly one made later in this conversation), so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this. If you Read this file again while it is unchanged, Claude Code answers with its own \"file unchanged since your last Read\" notice, not the file: that notice points back to this result, which now shows only the symbol.";

const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });
const labelArbiter = (state: { labelled: boolean }, taint: CallTaintWire = wire({})): MockArbiter => new MockArbiter({
  classifyFn: (r: ClassifyRequest): ClassifyResult => {
    const names = typeof r.params?.["cmd"] === "string" && (r.params["cmd"] as string).includes("staging.conf");
    return state.labelled && names
      ? { trust: "TRUSTED", category: null, reason: "mock: user label", confidentiality: "no-model", namedPaths: ["deploy/staging.conf"] }
      : { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" };
  },
  callTaintFn: () => taint,
});

function history(extra: unknown[] = []): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "What is in deploy/staging.conf?" }] },
      { type: "function_call", call_id: "call_cat", name: "exec_command", arguments: JSON.stringify({ cmd: "cat deploy/staging.conf" }) },
      { type: "function_call_output", call_id: "call_cat", output: `${HEADER}${BODY}` },
      ...extra,
    ],
  } as unknown as ResponsesRequest;
}
const outOf = (r: Awaited<ReturnType<typeof rewriteRequest>>, id = "call_cat"): string => {
  const o = (r.request.input as Array<{ type: string; call_id?: string; output?: unknown }>).find((x) => x.type === "function_call_output" && x.call_id === id)!.output;
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
};

test("the same three lines as the Claude proxy", () => {
  assert.equal(`[mandu:secret] ${afterTheFactLine({ taintCause: false, harnessRead: false })}`, LINE_PLAIN);
  assert.equal(`[mandu:secret] ${afterTheFactLine({ taintCause: true, harnessRead: false })}`, LINE_TAINT);
  assert.equal(`[mandu:secret] ${afterTheFactLine({ taintCause: false, harnessRead: true })}`, LINE_READ);
});

test("the tour under Codex: the cat output went in clear, the file is labelled, the next request masks it and says so after the fact; no output byte in the note", async () => {
  const state = { labelled: false };
  const clearResults = new ClearResultLedger();
  const first = await rewriteRequest(history(), { arbiter: labelArbiter(state), clearResults });
  assert.equal(outOf(first), `${HEADER}${BODY}`);
  assert.ok(clearResults.wasClear("call_cat"));

  state.labelled = true;
  const second = await rewriteRequest(history(), { arbiter: labelArbiter(state), clearResults });
  const t = outOf(second);
  assert.match(t, /\$MDU:/);
  assert.ok(t.endsWith(`\n\n${LINE_PLAIN}`), t);
  assert.ok(!t.includes("the command names"), "the path-derived line gives way");
  for (const piece of [TOKEN, "ghp_", "staging.internal", "[staging]"]) assert.ok(!t.includes(piece), `output byte(s): ${piece}`);
  const own = ownForwardedText(second.rewrites[0]!);
  assert.ok(!own.includes("[mandu:secret]"), "the own-block oracle strips the whole note");

  const third = await rewriteRequest(history(), { arbiter: labelArbiter(state), clearResults });
  assert.equal(outOf(third), t, "byte-stable across requests");
});

test("a taint-masked output after the fact keeps its masked: line and joins the after-the-fact one", async () => {
  const state = { labelled: false };
  const clearResults = new ClearResultLedger();
  await rewriteRequest(history(), { arbiter: labelArbiter(state), clearResults });
  state.labelled = true;
  const t = outOf(await rewriteRequest(history(), { arbiter: labelArbiter(state, wire({ level: "no-model", files: ["/w/deploy/staging.conf"], apps: ["cat"] })), clearResults }));
  const lines = t.slice(t.indexOf("\n\n[mandu:secret]") + 2).split("\n");
  assert.match(lines[0]!, /^\[mandu:secret\] masked: cat read \/w\/deploy\/staging\.conf;/);
  assert.equal(lines[1], LINE_TAINT);
  assert.equal(lines.length, 2);
});

test("only after the fact: masked from the first request, or no ledger, gets no line; a refused rewrite remembers nothing", async () => {
  const state = { labelled: true };
  const clearResults = new ClearResultLedger();
  await rewriteRequest(history(), { arbiter: labelArbiter(state), clearResults });
  assert.ok(!clearResults.wasClear("call_cat"));
  assert.ok(!outOf(await rewriteRequest(history(), { arbiter: labelArbiter(state), clearResults })).includes("after the fact"));
  assert.ok(!outOf(await rewriteRequest(history(), { arbiter: labelArbiter(state) })).includes("after the fact"));

  const ledger = new ClearResultLedger();
  const failing = new MockArbiter({
    classifyFn: (r: ClassifyRequest): ClassifyResult => {
      if (typeof r.params?.["cmd"] === "string" && (r.params["cmd"] as string) === "boom") throw new Error("arbiter down");
      return { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" };
    },
    callTaintFn: () => wire({}),
  });
  const bad = history([
    { type: "function_call", call_id: "call_bad", name: "exec_command", arguments: JSON.stringify({ cmd: "boom" }) },
    { type: "function_call_output", call_id: "call_bad", output: `${HEADER}x\n` },
  ]);
  await assert.rejects(rewriteRequest(bad, { arbiter: failing, clearResults: ledger }), RewriteRefusal);
  assert.ok(!ledger.wasClear("call_cat"));
});

test("Mandu's note rides in the instructions with the line: once, byte-stable, not before, not when injection is skipped", async () => {
  const state = { labelled: false };
  const clearResults = new ClearResultLedger();
  const count = (hay: unknown, needle: string): number => String(hay ?? "").split(needle).length - 1;
  const first = await rewriteRequest({ ...history(), instructions: "You are Codex." } as ResponsesRequest, { arbiter: labelArbiter(state), clearResults });
  assert.equal(count(first.request.instructions, AFTER_THE_FACT_MARKER), 0);
  state.labelled = true;
  const second = await rewriteRequest({ ...history(), instructions: "You are Codex." } as ResponsesRequest, { arbiter: labelArbiter(state), clearResults });
  assert.ok(String(second.request.instructions).endsWith(`\n\n${AFTER_THE_FACT_SYSTEM_NOTE}`), String(second.request.instructions));
  const again = await rewriteRequest(second.request, { arbiter: labelArbiter(state), clearResults });
  assert.equal(count(again.request.instructions, AFTER_THE_FACT_MARKER), 1);
  assert.equal(again.request.instructions, second.request.instructions);
  const skipped = await rewriteRequest(history(), { arbiter: labelArbiter(state), clearResults, skipPromptInjection: true });
  assert.equal(count(skipped.request.instructions, AFTER_THE_FACT_MARKER), 0);
});

// ── Across a resume (confidentiality.md §7.1, *Across a resume*) ─────────────

/** labelArbiter with the arbiter's forwarded-in-clear ids (one Set: one arbiter). */
const resumeArbiter = (state: { labelled: boolean }, db: Set<string>, fail = false): MockArbiter => new MockArbiter({
  classifyFn: (r: ClassifyRequest): ClassifyResult => {
    const names = typeof r.params?.["cmd"] === "string" && (r.params["cmd"] as string).includes("staging.conf");
    return state.labelled && names
      ? { trust: "TRUSTED", category: null, reason: "mock: user label", confidentiality: "no-model", namedPaths: ["deploy/staging.conf"] }
      : { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" };
  },
  callTaintFn: () => wire({}),
  forwardedClearIds: db,
  failForwardedClear: fail,
});

test("the tour under `codex resume`: launch 1 records the clear output's id with the arbiter; launch 2 (a fresh ledger) masks the resumed output WITH the note and Mandu's note in the instructions; no output byte", async () => {
  const state = { labelled: false };
  const db = new Set<string>();
  const a1 = resumeArbiter(state, db);
  const l1 = new ClearResultLedger(undefined, { store: arbiterClearResultStore(a1) });
  assert.equal(outOf(await rewriteRequest(history(), { arbiter: a1, clearResults: l1 })), `${HEADER}${BODY}`);
  assert.deepEqual([...db], ["call_cat"], "only the id reached the arbiter");

  state.labelled = true;
  const a2 = resumeArbiter(state, db);
  const l2 = new ClearResultLedger(undefined, { store: arbiterClearResultStore(a2) });
  const out = await rewriteRequest({ ...history(), instructions: "You are Codex." } as ResponsesRequest, { arbiter: a2, clearResults: l2 });
  const t = outOf(out);
  assert.match(t, /\$MDU:/);
  assert.ok(t.endsWith(`\n\n${LINE_PLAIN}`), t);
  assert.ok(String(out.request.instructions).endsWith(AFTER_THE_FACT_SYSTEM_NOTE));
  assert.deepEqual(a2.forwardedClearCalls, [["call_cat"]]);
  for (const piece of [TOKEN, "ghp_", "staging.internal", "[staging]"]) {
    assert.ok(!t.includes(piece), `output byte(s): ${piece}`);
    assert.ok(!String(out.request.instructions).includes(piece), `instruction byte(s): ${piece}`);
  }
});

test("across a resume, fail-safe: an arbiter that cannot answer leaves the resumed output masked with no note", async () => {
  const a = resumeArbiter({ labelled: true }, new Set(["call_cat"]), true);
  const l = new ClearResultLedger(undefined, { store: arbiterClearResultStore(a), log: () => {} });
  const t = outOf(await rewriteRequest(history(), { arbiter: a, clearResults: l }));
  assert.match(t, /\$MDU:/);
  assert.ok(!t.includes("after the fact") && !t.includes(TOKEN), t);
});
