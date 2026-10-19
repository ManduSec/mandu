/**
 * side-call-secret — the registered-value floor on a harness side call, now
 * under the prompt filter (prompt-filter.ts; confidentiality-plan-15 §3.1;
 * confidentiality.md §7, "A harness side call").
 *
 * Claude Code's WebFetch hands the fetched page to its own summarizer call:
 * a request with no tools whose one user message is "Web page content: ---
 * <page> ---". No tool_result carries the page, so until 2026-10-02 a page
 * holding a registered secret reached the vendor's model raw (found by
 * tests/stack/web-fetch-secret-ingress.test.ts). Since plan 15 every user
 * text of such a request is a `side-call` segment of `filterPrompt`: the
 * registered value becomes its symbol (exact spans now, where the !292 scan
 * narrowed to whole lines), the rest of the page reads, the note says why,
 * and a failing op refuses the request.
 *
 * Axes: secrets (the proxy is axis-agnostic; the mock answers as the arbiter
 * does with the confidentiality axis ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest, RewriteRefusal, SIDE_CALL_SECRET_NOTE } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { registeredValueFilter } from "../helpers/mock-prompt-filter.js";

const TOKEN = "npm_SideCallUnitCanary0123456789abcdef";
const SYM = "$MDU:nomodel_Read[1a2b].authToken";

function summarizer(page: string): MessagesRequest {
  return {
    model: "claude-haiku-4-5", stream: true,
    messages: [{ role: "user", content: `Web page content:\n---\n${page}\n---\n\nWhat does it say?` }],
  };
}

test("a side call's page: the registered value becomes its symbol; the rest of the page and the note stay", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: registeredValueFilter({ [TOKEN]: SYM }) });
  const page = `<h1>Build notes</h1>\n<p>publish with ${TOKEN}</p>\n<p>Deploys run nightly.</p>`;
  const { request, promptFilter } = await rewriteRequest(summarizer(page), { arbiter, skipPromptInjection: true });
  const out = request.messages[0]!.content as string;
  assert.ok(!out.includes(TOKEN), "the value never reaches the model");
  assert.ok(out.includes(`<p>publish with ${SYM}</p>`), "only the value's span is replaced");
  assert.ok(out.includes("Deploys run nightly.") && out.includes("<h1>Build notes</h1>"), "the other lines stay readable");
  assert.ok(out.includes("What does it say?"), "the harness's own instruction stays");
  assert.ok(out.endsWith(SIDE_CALL_SECRET_NOTE), "the note says why");
  assert.deepEqual(arbiter.filterPromptCalls[0]!.segments.map((s) => s.origin), ["side-call"]);
  assert.equal(promptFilter!.segments[0]!.findings[0]!.symbol, SYM);
});

test("the array form: each text block is a segment; a clean block is untouched", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: registeredValueFilter({ [TOKEN]: SYM }) });
  const req: MessagesRequest = {
    model: "m",
    messages: [{ role: "user", content: [{ type: "text", text: "clean title request" }, { type: "text", text: `key ${TOKEN}` }] }],
  };
  const { request } = await rewriteRequest(req, { arbiter, skipPromptInjection: true });
  const blocks = request.messages[0]!.content as Array<{ text: string }>;
  assert.equal(blocks[0]!.text, "clean title request");
  assert.ok(!blocks[1]!.text.includes(TOKEN) && blocks[1]!.text.includes(SIDE_CALL_SECRET_NOTE));
});

test("a short registered value (postgres) is masked in a side call: no prompt floor there", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: registeredValueFilter({ postgres: "$MDU:nomodel_env[7a7a]" }) });
  const { request } = await rewriteRequest(summarizer("db password: postgres"), { arbiter, skipPromptInjection: true });
  assert.ok(!(request.messages[0]!.content as string).includes("postgres"));
});

test("FAIL CLOSED: an op that throws refuses the request; an arbiter without the op filters nothing", async () => {
  const failing = new MockArbiter({ filterPromptFn: () => { throw new Error("arbiter down"); } });
  await assert.rejects(rewriteRequest(summarizer(`x ${TOKEN}`), { arbiter: failing, skipPromptInjection: true }), RewriteRefusal);
  const old = new MockArbiter();
  const { request } = await rewriteRequest(summarizer("plain"), { arbiter: old, skipPromptInjection: true });
  assert.ok((request.messages[0]!.content as string).includes("plain"));
});
