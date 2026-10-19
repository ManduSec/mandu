/**
 * prompt-filter — the openai-proxy's segmenter for Codex and the user-message
 * path (src/prompt-filter.ts; confidentiality-plan-15-prompt-filter.md §3,
 * phase 1). Before plan 15 this proxy never read a user message for masking.
 *
 * Proves: Codex's runtime context (`<environment_context>`, AGENTS.md text,
 * `<user_instructions>`, a `!` command's `<user_shell_command>` record, the
 * compaction hand-off) is `harness`, the typed text is `human`, a request
 * with no tools is a `side-call`; through rewriteRequest a registered key in
 * the human's message reaches the model as its symbol while `postgres` stays
 * there and is masked in AGENTS.md text; the Chat Completions shadow writes
 * the rewritten user text back (string and parts) and places a chat request
 * as Codex's only on Codex's own context (else no human segment); every
 * failure refuses the request.
 *
 * Axes: secrets (the mock answers as the arbiter does with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { pieceText, segmentAgentFor, segmentRequest } from "../../src/prompt-filter.js";
import { rewriteRequest, RewriteRefusal } from "../../src/rewrite-request.js";
import { chatShadow } from "../../src/chat-wire.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { registeredValueFilter } from "../helpers/mock-prompt-filter.js";

const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb4R";
const KEY_SYM = "$MDU:nomodel_env[9c1d]";
const PG_SYM = "$MDU:nomodel_env[5e5e]";
const filter = () => registeredValueFilter({ [KEY]: KEY_SYM, postgres: PG_SYM });
const TOOLS = [{ type: "function", name: "exec_command", parameters: {} }];
const msg = (text: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });

test("Codex: runtime context is harness, the typed text is human", () => {
  for (const t of [
    "<environment_context>\n  <cwd>/w</cwd>\n</environment_context>",
    "# AGENTS.md instructions for /w\n\nDB_PASSWORD=postgres",
    "<user_instructions>be brief</user_instructions>",
    "<user_shell_command>cat .env\nDB=postgres</user_shell_command>",
    "Another language model started to solve this problem and produced a summary",
  ]) assert.deepEqual(pieceText("codex", t).map((p) => p.origin), ["harness"], t);
  const typed = "fix it <environment_context>x</environment_context> please";
  assert.deepEqual(pieceText("codex", typed).map((p) => [p.origin, typed.slice(p.start, p.end)]), [
    ["human", "fix it "], ["harness", "<environment_context>x</environment_context>"], ["human", " please"],
  ]);
  assert.deepEqual(pieceText("generic", "anything").map((p) => p.origin), ["harness"], "an unplaced text is never human");
  const side: ResponsesRequest = { model: "m", input: [msg("summarize this conversation") as never] };
  assert.deepEqual(segmentRequest(side, "codex").segments.map((s) => s.origin), ["side-call"]);
});

test("a registered key in the human's message reaches the model as its symbol; postgres stays, and is masked in AGENTS.md", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const req: ResponsesRequest = {
    model: "gpt-5", tools: TOOLS,
    input: [msg("# AGENTS.md instructions for /w\n\nDB_PASSWORD=postgres") as never, msg(`use ${KEY}, user postgres`) as never],
  };
  const { request, promptFilter } = await rewriteRequest(req, { arbiter, skipPromptInjection: true, sessionKey: "s1" });
  const texts = (request.input ?? []).map((i) => ((i as { content: Array<{ text: string }> }).content[0]!.text));
  assert.deepEqual(texts, [`# AGENTS.md instructions for /w\n\nDB_PASSWORD=${PG_SYM}`, `use ${KEY_SYM}, user postgres`]);
  assert.equal(arbiter.filterPromptCalls[0]!.agent, "codex");
  assert.equal(arbiter.filterPromptCalls[0]!.session, "s1");
  assert.equal(promptFilter!.segments.find((s) => s.origin === "human")!.skipped, 1);
  assert.ok(!JSON.stringify(req).includes(KEY_SYM), "the caller's body is not mutated");
});

test("a string content and the script-cell wire's additional_tools battery are read", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const req: ResponsesRequest = {
    model: "gpt-5",
    input: [
      { type: "additional_tools", id: "t", role: "developer", tools: [{ type: "namespace", name: "n", tools: [{ type: "custom", name: "exec" }] }] } as never,
      { type: "message", role: "user", content: `key ${KEY}` } as never,
    ],
  };
  const { request } = await rewriteRequest(req, { arbiter, skipPromptInjection: true });
  assert.equal((request.input![1] as { content: string }).content, `key ${KEY_SYM}`);
  assert.equal(arbiter.filterPromptCalls[0]!.segments[0]!.origin, "human", "tools advertised in-band: not a side call");
});

test("Chat Completions: the rewritten user text is written back; a chat client is Codex only on Codex's own context", async () => {
  const body = {
    model: "m", tools: [{ type: "function", function: { name: "exec_command", parameters: {} } }],
    messages: [
      { role: "system", content: "sys" },
      { role: "user", content: "<environment_context><cwd>/w</cwd></environment_context>" },
      { role: "user", content: `my key ${KEY}, user postgres` },
      { role: "user", content: [{ type: "text", text: `again ${KEY}` }, { type: "image_url", image_url: { url: "data:x" } }] },
    ],
  };
  const sh = chatShadow(body);
  assert.equal(segmentAgentFor(sh.shadow, "chat"), "codex");
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const { request } = await rewriteRequest(sh.shadow, { arbiter, skipPromptInjection: true, promptAgent: segmentAgentFor(sh.shadow, "chat") });
  const out = sh.apply(request) as typeof body;
  assert.equal(out.messages[2]!.content, `my key ${KEY_SYM}, user postgres`);
  assert.deepEqual(out.messages[3]!.content, [{ type: "text", text: `again ${KEY_SYM}` }, { type: "image_url", image_url: { url: "data:x" } }]);
  assert.ok(!JSON.stringify(out).includes(KEY));
  // Another chat client (no Codex context): no human segment, postgres masked too.
  const other = chatShadow({ model: "m", tools: body.tools, messages: [{ role: "user", content: "user postgres" }] });
  assert.equal(segmentAgentFor(other.shadow, "chat"), "generic");
  const r2 = await rewriteRequest(other.shadow, { arbiter, skipPromptInjection: true, promptAgent: "generic" });
  assert.equal((other.apply(r2.request) as { messages: Array<{ content: string }> }).messages[0]!.content, `user ${PG_SYM}`);
});

test("FAIL CLOSED: a throw, a missing answer or a block refuses the request; no op filters nothing", async () => {
  const req: ResponsesRequest = { model: "m", tools: TOOLS, input: [msg(`use ${KEY}`) as never] };
  const empty = { enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" } };
  for (const arbiter of [
    new MockArbiter({ filterPromptFn: () => { throw new Error("down"); } }),
    new MockArbiter({ filterPromptFn: () => ({ ...empty, segments: [] }) }),
    new MockArbiter({ filterPromptFn: (r) => ({ ...empty, segments: r.segments.map((s) => ({ id: s.id, origin: s.origin, action: "block" as const, findings: [], skipped: 0, cached: false })) }) }),
  ]) {
    await assert.rejects(rewriteRequest(req, { arbiter, skipPromptInjection: true }), RewriteRefusal);
  }
  const { request } = await rewriteRequest(req, { arbiter: new MockArbiter(), skipPromptInjection: true });
  assert.ok(JSON.stringify(request).includes(KEY), "an in-test arbiter without the op: nothing to do");
});
