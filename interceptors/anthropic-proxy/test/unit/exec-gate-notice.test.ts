/**
 * exec-gate-notice.test.ts — the exec gate's own block notice reaches the
 * model in clear, and nothing else rides with it (confidentiality plan 10
 * §11.8, "The exec gate's own notice"; exec-routing.md §3.2).
 *
 * The case from the live run (2026-10-03, conf-declassify-confines-session):
 * a HIGH session's Bash call was rewritten to the block sentinel; its result
 * came back as `Exit code 77\n<notice>`, and the classify verdict marked it
 * `no-model` because the sentinel command says "secret" (the catalog's
 * `*secret*` shape). The model got one `$MDU:nomodel_Bash[…]` symbol. The mock
 * classify here answers `no-model` for every result, as that scan did.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import { blockNoticeText, blockSentinelCommand, ExecGateNotices, EXEC_BLOCK_EXIT_CODE } from "../../src/exec-gate.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const REASON =
  "HIGH SESSION (any-model): this session has read secret content into context, so anything it emits may be derived from it. Egress to an unspecified destination is not a bound destination of the data it read → human approval required (§4).";
const NOTICE = blockNoticeText(REASON);
const FRAMED = `Exit code ${EXEC_BLOCK_EXIT_CODE}\n${NOTICE}`;
const BUDGET_TAIL = "\n\n<system-reminder>\n<total_tokens>14999813 tokens left</total_tokens>\n</system-reminder>";
/** A test-only stand-in for a program's output (not a real credential). */
const PROGRAM_BYTES = "FIXTURE-PROGRAM-OUTPUT-7f3a";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;

const secretEverything = (): ClassifyResult => ({
  trust: "TRUSTED",
  category: null,
  reason: "integrity axis OFF — trust classification disabled",
  confidentiality: "no-model",
});

function request(content: string | { type: string; text: string }[], id = "toolu_gate"): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "send it" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: blockSentinelCommand(REASON) } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}

function notices(id = "toolu_gate"): ExecGateNotices {
  const n = new ExecGateNotices();
  n.remember(id, NOTICE);
  return n;
}

function forwarded(out: Awaited<ReturnType<typeof rewriteRequest>>): string {
  const c = (out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
  return typeof c === "string" ? c : (c as Array<{ text: string }>).map((b) => b.text).join("");
}

test("the sentinel's result reaches the model as Mandu's notice, in clear; the harness tail is dropped", async () => {
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  const out = await rewriteRequest(request(FRAMED + BUDGET_TAIL), { arbiter, execGateNotices: notices() });
  assert.equal(forwarded(out), FRAMED, "the model reads why its command was blocked");
  assert.equal(arbiter.symbolizeCalls.length, 0, "nothing is minted for Mandu's own text");
  const audit = out.rewrites[0]!;
  assert.equal(audit.symbolized, false);
  assert.equal(audit.forwardedText, FRAMED);
  assert.equal(audit.droppedTail, BUDGET_TAIL.trimStart());
  assert.match(audit.reason ?? "", /exec gate notice/);
});

test("an array-shaped result and the bare notice form both match", async () => {
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  const out = await rewriteRequest(request([{ type: "text", text: `${NOTICE}\n` }]), { arbiter, execGateNotices: notices() });
  assert.equal(forwarded(out), NOTICE);
});

test("program output beside the notice is never forwarded: the whole result takes the classify path and is masked", async () => {
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  for (const body of [`${FRAMED}\n${PROGRAM_BYTES}`, `${PROGRAM_BYTES}\n${FRAMED}`, `Exit code 1\n${NOTICE}`]) {
    const out = await rewriteRequest(request(body + BUDGET_TAIL), { arbiter, execGateNotices: notices() });
    const text = forwarded(out);
    assert.match(text, SYM_RE, `masked: ${JSON.stringify(body.slice(0, 40))}`);
    assert.ok(!text.includes(PROGRAM_BYTES), "the program's bytes never reach the model");
    assert.ok(!text.includes("mandu-exec-gate"), "and the notice is not split out of a mixed result");
  }
});

test("no record for the call (another call, a restarted proxy) → the result is classified as before", async () => {
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  const other = await rewriteRequest(request(FRAMED), { arbiter, execGateNotices: notices("toolu_other") });
  assert.match(forwarded(other), SYM_RE);
  const none = await rewriteRequest(request(FRAMED), { arbiter });
  assert.match(forwarded(none), SYM_RE);
});

test("the value backstop gates the release: a hit, a failure or a missing op keeps the mask", async () => {
  const hit = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [{ symbol: "$MDU:nomodel_Read[ab12]", level: "no-model" }] }) });
  assert.match(forwarded(await rewriteRequest(request(FRAMED), { arbiter: hit, execGateNotices: notices() })), SYM_RE);
  const failing = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => { throw new Error("down"); } });
  assert.match(forwarded(await rewriteRequest(request(FRAMED), { arbiter: failing, execGateNotices: notices() })), SYM_RE);
  const missing = new MockArbiter({ classifyFn: secretEverything });
  assert.match(forwarded(await rewriteRequest(request(FRAMED), { arbiter: missing, execGateNotices: notices() })), SYM_RE);
});
