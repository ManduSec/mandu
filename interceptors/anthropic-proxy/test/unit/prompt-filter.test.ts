/**
 * prompt-filter — the anthropic-proxy's segmenter and apply step
 * (src/prompt-filter.ts; confidentiality-plan-15-prompt-filter.md §3, phase 1).
 *
 * Proves, per agent, that the rules place user-role text by who wrote it:
 * Claude Code's `<system-reminder>` and local-command / bash-mode / IDE tag
 * spans, its compaction summary and a text beside a tool_result are
 * `harness`; OpenClaw's text is `human` only after its wall-clock envelope;
 * OpenCode's pre-read file parts are `harness`; an unknown agent (the union
 * surface) has no `human` segment (the fail direction). Then, through
 * rewriteRequest with a mock `filterPrompt`: a registered key pasted into the
 * human's prompt reaches the model as its symbol, `postgres` stays in the
 * human's text and is masked in a reminder, the trusted-context haystack
 * excludes what the filter replaced, the OpenAI-family shadow writes the
 * rewritten user text back (Chat and Responses, string and parts), and every
 * failure refuses the request.
 *
 * Axes: secrets (the mock answers as the arbiter does with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { pieceText, segmentAgentFor, segmentRequest, textHash } from "../../src/prompt-filter.js";
import { buildTrustedContextHaystack, rewriteRequest, RewriteRefusal } from "../../src/rewrite-request.js";
import { chatShadow, responsesShadow } from "../../src/openai-wire.js";
import { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { registeredValueFilter } from "../helpers/mock-prompt-filter.js";

const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb4R";
const KEY_SYM = "$MDU:nomodel_env[9c1d]";
const PG_SYM = "$MDU:nomodel_env[5e5e]";
const filter = () => registeredValueFilter({ [KEY]: KEY_SYM, postgres: PG_SYM });
const pieces = (agent: Parameters<typeof pieceText>[0], text: string) =>
  pieceText(agent, text).map((p) => [p.origin, text.slice(p.start, p.end)]);

// ── the segmenter rules ─────────────────────────────────────────────────────

test("Claude Code: tag spans are harness, the typed text around them is human", () => {
  const text = "<system-reminder>CLAUDE.md says hi</system-reminder>\nfix the bug\n<bash-stdout>DB=postgres</bash-stdout>";
  assert.deepEqual(pieces("claude-code", text), [
    ["harness", "<system-reminder>CLAUDE.md says hi</system-reminder>"],
    ["human", "\nfix the bug\n"],
    ["harness", "<bash-stdout>DB=postgres</bash-stdout>"],
  ]);
  assert.deepEqual(pieces("claude-code", "<local-command-stdout>x</local-command-stdout>"), [["harness", "<local-command-stdout>x</local-command-stdout>"]]);
  assert.deepEqual(pieces("claude-code", "<ide_selection>code</ide_selection> explain"), [["harness", "<ide_selection>code</ide_selection>"], ["human", " explain"]]);
  // An unclosed tag cannot be placed: it runs to the end.
  assert.deepEqual(pieces("claude-code", "hi <system-reminder>no close"), [["human", "hi "], ["harness", "<system-reminder>no close"]]);
});

test("Claude Code: whole-message harness instructions are harness", () => {
  for (const t of [
    "This session is being continued from a previous conversation that ran out of context. Summary: ...",
    "[SUGGESTION MODE: predict the next prompt]",
    "The user stepped away and is coming back. Recap the session.",
  ]) assert.deepEqual(pieces("claude-code", t).map((p) => p[0]), ["harness"], t);
});

test("OpenClaw: only the text after the wall-clock envelope is human; no envelope is harness", () => {
  const t = 'Sender (untrusted metadata):\n```json\n{"id":"gateway-client"}\n```\n\n[Thu 2026-08-06 10:48 GMT+9] read the notes';
  assert.deepEqual(pieces("openclaw", t).map((p) => p[0]), ["harness", "human"]);
  assert.equal(pieces("openclaw", t)[1]![1], "read the notes");
  assert.deepEqual(pieces("openclaw", "Image(s) from tool result #1 (read):").map((p) => p[0]), ["harness"]);
});

test("OpenCode: a pre-read file part and the part after its marker are harness", () => {
  const req: MessagesRequest = {
    model: "m", tools: [{ name: "read" }],
    messages: [{ role: "user", content: [
      { type: "text", text: "Called the Read tool with the following input: {\"filePath\":\"/w/.env\"}" },
      { type: "text", text: "00001| DB_PASSWORD=postgres" },
      { type: "text", text: "summarize the file" },
    ] }],
  };
  const { segments } = segmentRequest(req, "opencode");
  assert.deepEqual(segments.map((s) => s.origin), ["harness", "harness", "human"]);
});

test("goose (1.53.0's wire): the typed part is the human's, its <turn-context> part the harness's; a tag inside a typed part is cut out", () => {
  assert.equal(segmentAgentFor("goose"), "goose");
  const req: MessagesRequest = {
    model: "m", tools: [{ name: "shell" }],
    messages: [{ role: "user", content: [
      { type: "text", text: "deploy with postgres" },
      { type: "text", text: "<turn-context>\n<current-time>2026-10-05 10:07:00 +09:00</current-time>\n<working-directory>/w</working-directory>\n</turn-context>" },
    ] }],
  };
  assert.deepEqual(segmentRequest(req, "goose").segments.map((s) => s.origin), ["human", "harness"]);
  assert.deepEqual(pieces("goose", "a <turn-context>x</turn-context> b"), [["human", "a "], ["harness", "<turn-context>x</turn-context>"], ["human", " b"]]);
  // an unclosed tag runs to the end: it cannot be placed
  assert.deepEqual(pieces("goose", "a <turn-context>x"), [["human", "a "], ["harness", "<turn-context>x"]]);
  // a text beside a shell result stays the harness's
  const beside: MessagesRequest = {
    model: "m", tools: [{ name: "shell" }],
    messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "ok" }, { type: "text", text: "typed" }] }],
  };
  assert.deepEqual(segmentRequest(beside, "goose").segments.map((s) => s.origin), ["harness"]);
});

test("the fail direction: an unknown agent, a text beside a tool_result and a side call are never human", () => {
  assert.equal(segmentAgentFor(UNION_GATE_SURFACE.spec), "generic");
  assert.equal(segmentAgentFor("fail-closed"), "generic");
  assert.equal(segmentAgentFor("openclaw-agent"), "openclaw");
  assert.deepEqual(pieces("generic", "plain words").map((p) => p[0]), ["harness"]);
  const beside: MessagesRequest = {
    model: "m", tools: [{ name: "Bash" }],
    messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "ok" }, { type: "text", text: "typed while it ran" }] }],
  };
  assert.deepEqual(segmentRequest(beside, "claude-code").segments.map((s) => s.origin), ["harness"]);
  const side: MessagesRequest = { model: "m", messages: [{ role: "user", content: "Web page content:\n---\npage\n---" }] };
  assert.deepEqual(segmentRequest(side, "claude-code").segments.map((s) => s.origin), ["side-call"]);
  assert.match(textHash("x"), /^[0-9a-f]{8}$/);
});

// ── through rewriteRequest ──────────────────────────────────────────────────

function conversation(user: string): MessagesRequest {
  return { model: "claude-sonnet-4-5", tools: [{ name: "Read" }], messages: [{ role: "user", content: [{ type: "text", text: user }] }] };
}

test("a registered key in the human's prompt reaches the model as its symbol; postgres stays as typed", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const user = `<system-reminder>DB_PASSWORD=postgres</system-reminder>\nuse ${KEY} to connect as postgres`;
  const { request, promptFilter } = await rewriteRequest(conversation(user), { arbiter, skipPromptInjection: true, sessionKey: "s1" });
  const out = (request.messages[0]!.content as Array<{ text: string }>)[0]!.text;
  assert.equal(out, `<system-reminder>DB_PASSWORD=${PG_SYM}</system-reminder>\nuse ${KEY_SYM} to connect as postgres`);
  const call = arbiter.filterPromptCalls[0]!;
  assert.equal(call.agent, "claude-code");
  assert.equal(call.session, "s1");
  assert.deepEqual(call.segments.map((s) => s.origin), ["harness", "human"]);
  assert.equal(promptFilter!.segments.find((s) => s.origin === "human")!.skipped, 1);
  assert.deepEqual(promptFilter!.replaced.sort(), [KEY_SYM, PG_SYM].sort());
});

test("the union surface (the arbiter could not say which agent): postgres is masked everywhere", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const { request } = await rewriteRequest(conversation("connect as postgres"), { arbiter, skipPromptInjection: true, surface: UNION_GATE_SURFACE as GateSurface });
  assert.equal((request.messages[0]!.content as Array<{ text: string }>)[0]!.text, `connect as ${PG_SYM}`);
});

test("the trusted-context haystack excludes the spans the filter replaced", async () => {
  const req = conversation(`key ${KEY} here`);
  const before = buildTrustedContextHaystack(req);
  assert.ok(before.includes(KEY));
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const { request } = await rewriteRequest(req, { arbiter, skipPromptInjection: true });
  const after = buildTrustedContextHaystack(request, [KEY_SYM]);
  assert.ok(!after.includes(KEY), "the original is gone");
  assert.ok(!after.includes(KEY_SYM), "and so is the symbol that stands for it");
  assert.ok(after.includes("key ") && after.includes(" here"));
});

test("FAIL CLOSED: a throw, a missing answer, a hold or a block refuses the request", async () => {
  const user = `use ${KEY}`;
  const cases: Array<MockArbiter> = [
    new MockArbiter({ filterPromptFn: () => { throw new Error("down"); } }),
    new MockArbiter({ filterPromptFn: () => ({ enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" }, segments: [] }) }),
    new MockArbiter({ filterPromptFn: (r) => ({ enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" }, segments: r.segments.map((s) => ({ id: s.id, origin: s.origin, action: "hold" as const, findings: [], skipped: 0, cached: false })) }) }),
    new MockArbiter({ filterPromptFn: (r) => ({ enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" }, segments: r.segments.map((s) => ({ id: s.id, origin: s.origin, action: "block" as const, reason: "no", findings: [], skipped: 0, cached: false })) }) }),
    new MockArbiter({ filterPromptFn: (r) => ({ enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" }, segments: r.segments.map((s) => ({ id: s.id, origin: s.origin, action: "rewrite" as const, findings: [], skipped: 0, cached: false })) }) }),
  ];
  for (const arbiter of cases) {
    await assert.rejects(rewriteRequest(conversation(user), { arbiter, skipPromptInjection: true }), RewriteRefusal);
  }
});

test("count_tokens and the default surface still filter (the provider counts the masked request)", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const { request } = await rewriteRequest(conversation(KEY), { arbiter, skipPromptInjection: true, surface: CLAUDE_CODE_GATE_SURFACE });
  assert.ok(!JSON.stringify(request).includes(KEY));
});

// ── the OpenAI-family write-back (openai-wire.ts) ───────────────────────────

const OPENCLAW_SURFACE = { ...UNION_GATE_SURFACE, spec: "openclaw" } as GateSurface;
const ENVELOPE = "[Thu 2026-08-06 10:48 GMT+9] ";

test("Chat Completions: a rewritten user text is written back (string and parts); the rest is byte-identical", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const body = {
    model: "m", tools: [{ type: "function", function: { name: "read", parameters: {} } }], extra: { keep: 1 },
    messages: [
      { role: "system", content: "sys" },
      { role: "user", content: `${ENVELOPE}my key ${KEY}` },
      { role: "assistant", content: "ok" },
      { role: "user", content: [{ type: "text", text: `${ENVELOPE}again ${KEY}` }, { type: "image_url", image_url: { url: "data:x" } }] },
    ],
  };
  const sh = chatShadow(body);
  const { request } = await rewriteRequest(sh.shadow, { arbiter, skipPromptInjection: true, surface: OPENCLAW_SURFACE });
  const out = sh.apply(request) as typeof body;
  assert.equal(out.messages[1]!.content, `${ENVELOPE}my key ${KEY_SYM}`);
  assert.deepEqual(out.messages[3]!.content, [{ type: "text", text: `${ENVELOPE}again ${KEY_SYM}` }, { type: "image_url", image_url: { url: "data:x" } }]);
  assert.ok(!JSON.stringify(out).includes(KEY));
  assert.deepEqual(out.extra, { keep: 1 });
  assert.equal(arbiter.filterPromptCalls[0]!.agent, "openclaw");
});

test("Responses: a string input and input_text parts are written back", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: filter() });
  const one = { model: "m", tools: [{ type: "function", name: "read", parameters: {} }], input: `${ENVELOPE}k ${KEY}` };
  const sh1 = responsesShadow(one);
  const r1 = await rewriteRequest(sh1.shadow, { arbiter, skipPromptInjection: true, surface: OPENCLAW_SURFACE });
  assert.equal((sh1.apply(r1.request) as { input: string }).input, `${ENVELOPE}k ${KEY_SYM}`);
  const two = { model: "m", tools: [{ type: "function", name: "read", parameters: {} }], input: [{ type: "message", role: "user", content: [{ type: "input_text", text: `${ENVELOPE}k ${KEY}` }] }] };
  const sh2 = responsesShadow(two);
  const r2 = await rewriteRequest(sh2.shadow, { arbiter, skipPromptInjection: true, surface: OPENCLAW_SURFACE });
  const out2 = sh2.apply(r2.request) as typeof two;
  assert.equal(out2.input[0]!.content[0]!.text, `${ENVELOPE}k ${KEY_SYM}`);
  // Nothing found: the body goes as the agent sent it.
  const clean = { model: "m", input: "hello" };
  const sh3 = responsesShadow(clean);
  const r3 = await rewriteRequest(sh3.shadow, { arbiter, skipPromptInjection: true, surface: OPENCLAW_SURFACE });
  assert.deepEqual(sh3.apply(r3.request), clean);
});
