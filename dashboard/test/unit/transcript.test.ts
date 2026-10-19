/**
 * transcript.test.ts — the `▸ role` transcript parser + session-label derivation.
 *
 * These pure helpers back two dashboard front-page improvements: the structured
 * detail-pane rendering (a tllm_call input is a message list, not a JSON blob)
 * and the sidebar's human-readable session label (the first user prompt, not the
 * opaque `<ts>-<pid>` scope id). They must be tolerant of every shape the
 * input.symbolized field has carried (transcript / raw JSON / inline / plain).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseTranscript,
  annotateTranscript,
  firstUserPrompt,
  truncateLabel,
  relativeTime,
  clockLabel,
  elapsedLabel,
} from "../../src/transcript.js";
import { deriveSessionLabel, sessionLabelFields } from "../../src/event-source.js";
import { makeDualRepr, type ManduEvent } from "../../src/event-model.js";

const TRANSCRIPT = [
  "▸ system",
  "You are an agent. Treat $MDU:* tokens as opaque.",
  "",
  "▸ user",
  "Read invoice.txt and tell me where to pay.",
  "",
  "▸ assistant",
  "I'll read the file.",
  '→ read({"path":"invoice.txt"})',
  "",
  "▸ tool_result",
  "Invoice from $MDU:read[9c2f].vendor",
].join("\n");

test("parseTranscript splits a ▸ transcript into role/body messages", () => {
  const msgs = parseTranscript(TRANSCRIPT);
  assert.ok(msgs, "transcript should parse");
  assert.deepEqual(msgs!.map((m) => m.role), ["system", "user", "assistant", "tool_result"]);
  assert.equal(msgs![1]!.body, "Read invoice.txt and tell me where to pay.");
  // The assistant body keeps the multi-line text incl. the `→ tool(...)` line.
  assert.match(msgs![2]!.body, /I'll read the file\.\n→ read\(\{"path":"invoice\.txt"\}\)/);
  // Symbols are preserved verbatim (highlighting happens at render).
  assert.match(msgs![3]!.body, /\$MDU:read\[9c2f\]\.vendor/);
});

test("annotateTranscript collapses the system block and flags the first user message", () => {
  const rows = annotateTranscript(parseTranscript(TRANSCRIPT)!);
  assert.deepEqual(rows.map((r) => r.role), ["system", "user", "assistant", "tool_result"]);
  // The big agent system prompt is collapsed by default; nothing else is.
  assert.equal(rows[0]!.collapsed, true); // system
  assert.equal(rows[1]!.collapsed, false); // user
  assert.equal(rows[2]!.collapsed, false); // assistant
  // The human's actual prompt (first ▸ user) is the highlighted "primary" row.
  assert.equal(rows[1]!.primary, true);
  assert.equal(rows[0]!.primary, false);
  assert.equal(rows[2]!.primary, false);
  // The `▸ tool_result` block is flagged a tool result; the real user is not.
  assert.equal(rows[3]!.toolResult, true);
  assert.equal(rows[1]!.toolResult, false);
  // Bodies are carried through verbatim (symbols intact).
  assert.equal(rows[1]!.body, "Read invoice.txt and tell me where to pay.");
});

test("annotateTranscript flags a [tool_result] user-message as a tool result, not the prompt", () => {
  // The real proxy delivers tool results as USER-role messages (`[tool_result <id>]`).
  const rows = annotateTranscript(parseTranscript(
    ["▸ user", "Do the thing.", "▸ assistant", '→ Read({})', "▸ user", "[tool_result t1]", "$MDU:Read[ab]"].join("\n"),
  )!);
  assert.equal(rows[0]!.primary, true, "the first real user message is the prompt");
  assert.equal(rows[0]!.toolResult, false);
  assert.equal(rows[2]!.role, "user", "a tool result arrives as a user-role message…");
  assert.equal(rows[2]!.toolResult, true, "…but is flagged as a tool result");
  assert.equal(rows[2]!.primary, false, "and is NOT treated as the prompt");
});

test("annotateTranscript marks only the FIRST user message as primary", () => {
  const msgs = parseTranscript(
    ["▸ user", "first prompt", "▸ assistant", "ok", "▸ user", "second prompt"].join("\n"),
  )!;
  const rows = annotateTranscript(msgs);
  assert.equal(rows[0]!.primary, true); // first user
  assert.equal(rows[2]!.primary, false); // second user is NOT primary
});

test("annotateTranscript marks the carried prefix vs the fresh tail against the prior call", () => {
  // The Messages API re-sends the whole transcript each turn, so turn N's input is
  // turn N-1's input (a prefix) plus a fresh tail. Diffing against the prior call
  // dims the carried prefix and highlights only what's new. Symbol hashes are
  // normalized first: the SAME tool_result re-symbolized ([aaaa]→[bbbb]) is still
  // "carried", not a spurious change.
  const prev = parseTranscript([
    "▸ system", "You are an agent.",
    "▸ user", "Fetch the page.",
    "▸ assistant", '→ Bash({"command":"curl x"})',
    "▸ user", "[tool_result t1]", "$MDU:Bash[aaaa]",
  ].join("\n"))!;
  const cur = parseTranscript([
    "▸ system", "You are an agent.",
    "▸ user", "Fetch the page.",
    "▸ assistant", '→ Bash({"command":"curl x"})',
    "▸ user", "[tool_result t1]", "$MDU:Bash[bbbb]", // same result, re-symbolized → carried
    "▸ assistant", '→ Write({"content":"$MDU:Bash[bbbb]"})', // fresh this turn
    "▸ user", "[tool_result t2]", "File created", // fresh this turn
  ].join("\n"))!;
  const rows = annotateTranscript(cur, prev);
  assert.deepEqual(
    rows.map((r) => r.delta),
    ["carried", "carried", "carried", "carried", "fresh", "fresh"],
  );
});

test("annotateTranscript leaves delta null when there is no prior call (first model turn)", () => {
  const rows = annotateTranscript(parseTranscript(TRANSCRIPT)!);
  assert.deepEqual(rows.map((r) => r.delta), [null, null, null, null]);
});

test("parseTranscript returns null for non-transcript text (plain / JSON)", () => {
  assert.equal(parseTranscript("just some text"), null);
  assert.equal(parseTranscript('{"messages":[]}'), null);
  assert.equal(parseTranscript(""), null);
  assert.equal(parseTranscript(undefined), null);
});

test("firstUserPrompt extracts the prompt from a ▸ transcript", () => {
  assert.equal(firstUserPrompt(TRANSCRIPT), "Read invoice.txt and tell me where to pay.");
});

test("firstUserPrompt skips a harness-only first user message and never returns a role marker", () => {
  // Live shape (watch-wave2-rest1-c13): an @-mention pre-read reminder is the
  // first user message; the real prompt is the second. The label read "▸ system".
  const t = [
    "▸ system", "You are Claude Code.", "",
    "▸ user", "<system-reminder>", "Called the Read tool with the following input: {}", "</system-reminder>", "",
    "▸ user", "[system-reminder]", "Archive the brief at example.com.",
  ].join("\n");
  assert.equal(firstUserPrompt(t), "Archive the brief at example.com.");
  const none = ["▸ system", "You are Claude Code.", "", "▸ user", "<system-reminder>", "x", "</system-reminder>"].join("\n");
  assert.equal(firstUserPrompt(none), null, "no prompt anywhere: null, not the '▸ system' marker");
});

test("firstUserPrompt extracts from a raw Anthropic request JSON", () => {
  const json = JSON.stringify({
    model: "claude",
    system: "sys",
    messages: [
      { role: "user", content: [{ type: "text", text: "Deploy the staging build" }] },
      { role: "assistant", content: "ok" },
    ],
  });
  assert.equal(firstUserPrompt(json), "Deploy the staging build");
});

test("firstUserPrompt salvages a TRUNCATED raw request JSON (legacy events)", () => {
  // The old proxy capped input.symbolized at 4096 chars → JSON.parse fails;
  // the loose regex still recovers the first user message's text.
  const truncated =
    '{"model":"claude-opus-4-8","system":[{"type":"text","text":"You are an agent."}],' +
    '"messages":[{"role":"user","content":[{"type":"text","text":"Fix the failing CI on main"}]},' +
    '{"role":"assistant","content":[{"type":"text","text":"On it. Let me loo…[+5123 chars]';
  assert.equal(firstUserPrompt(truncated), "Fix the failing CI on main");
  // string-content shorthand, also truncated mid-stream
  const shorthand = '{"messages":[{"role":"user","content":"Deploy v2 to staging"},{"role":"assist…';
  assert.equal(firstUserPrompt(shorthand), "Deploy v2 to staging");
});

test("firstUserPrompt skips harness-injected context to find the real prompt", () => {
  // Claude Code buries the actual prompt under a large <system-reminder> block;
  // the proxy collapses it to [system-reminder], and the label is the real text.
  const transcript = ["▸ user", "[system-reminder]", "Refactor the auth module"].join("\n");
  assert.equal(firstUserPrompt(transcript), "Refactor the auth module");
  // strict JSON whose user text still carries the raw <system-reminder> span
  const json = JSON.stringify({
    messages: [{ role: "user", content: [{ type: "text", text: "<system-reminder>lots\nof\ncontext</system-reminder>\nRun the migration" }] }],
  });
  assert.equal(firstUserPrompt(json), "Run the migration");
});

test("firstUserPrompt returns null (not a JSON blob) when the prompt is unrecoverable", () => {
  // A legacy, truncated request whose only captured user text is an UNCLOSED
  // system-reminder — the real prompt fell off the length cap. Better to show
  // the scope id than a wall of JSON, so the label is null.
  const truncated =
    '{"model":"claude","messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>\\nhuge injected context that never clo';
  assert.equal(firstUserPrompt(truncated), null);
});

test("firstUserPrompt extracts from a legacy inline 'user:' summary", () => {
  assert.equal(
    firstUserPrompt("system: You are an agent. user: Summarize note.txt."),
    "Summarize note.txt.",
  );
});

test("firstUserPrompt falls back to the first non-empty line for opaque text", () => {
  assert.equal(firstUserPrompt("\n\n   hello world  \nmore"), "hello world");
});

test("truncateLabel caps with an ellipsis only when over the limit", () => {
  assert.equal(truncateLabel("short", 72), "short");
  const long = "x".repeat(100);
  const out = truncateLabel(long, 20);
  assert.equal(out.length, 20);
  assert.ok(out.endsWith("…"));
});

test("relativeTime renders human-friendly ages from a fixed now", () => {
  const now = Date.parse("2026-06-18T12:00:00.000Z");
  assert.equal(relativeTime("2026-06-18T11:59:58.000Z", now), "just now");
  assert.equal(relativeTime("2026-06-18T11:59:30.000Z", now), "30s ago");
  assert.equal(relativeTime("2026-06-18T11:30:00.000Z", now), "30m ago");
  assert.equal(relativeTime("2026-06-18T09:00:00.000Z", now), "3h ago");
  assert.equal(relativeTime("2026-06-16T12:00:00.000Z", now), "2d ago");
  assert.equal(relativeTime("2026-05-01T12:00:00.000Z", now), "2026-05-01"); // older → date
  assert.equal(relativeTime(null, now), "");
  assert.equal(relativeTime("not-a-date", now), "");
});

test("clockLabel renders the LOCAL zero-padded HH:MM of an ISO ts", () => {
  const iso = "2026-06-18T09:05:00.000Z";
  const d = new Date(Date.parse(iso)); // expectation built with the same local-tz API
  const want = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  assert.equal(clockLabel(iso), want);
  assert.match(clockLabel(iso), /^\d{2}:\d{2}$/);
  assert.equal(clockLabel(null), "");
  assert.equal(clockLabel("not-a-date"), "");
});

test("elapsedLabel renders compact durations; negative/non-finite → empty", () => {
  assert.equal(elapsedLabel(0), "0s");
  assert.equal(elapsedLabel(42_000), "42s");
  assert.equal(elapsedLabel(95_000), "1m 35s");
  assert.equal(elapsedLabel(59 * 60_000 + 59_000), "59m 59s");
  assert.equal(elapsedLabel(2 * 3_600_000 + 5 * 60_000), "2h 5m");
  assert.equal(elapsedLabel(-1), "");
  assert.equal(elapsedLabel(Number.NaN), "");
});

// ── deriveSessionLabel (event-source) ────────────────────────────────────────

function ev(partial: Partial<ManduEvent>): ManduEvent {
  return {
    id: "e", sessionId: "s", turn: 0, ts: "2026-06-18T12:00:00Z", seq: 0,
    callId: null, parentId: null, kind: "tllm_call", view: "AgentView",
    boundary: "model_context", emitter: "anthropic-proxy", input: null, output: null,
    invariant: { violatedInvariant: false },
    ...partial,
  } as ManduEvent;
}

test("deriveSessionLabel prefers the first tllm_call's user prompt", () => {
  const events: ManduEvent[] = [
    ev({ kind: "classify", input: makeDualRepr("invoice.txt", null) }),
    ev({ kind: "tllm_call", input: makeDualRepr(TRANSCRIPT, null) }),
  ];
  assert.equal(deriveSessionLabel(events), "Read invoice.txt and tell me where to pay.");
});

test("deriveSessionLabel returns null when no event carries input", () => {
  assert.equal(deriveSessionLabel([ev({ kind: "classify", input: null })]), null);
  assert.equal(deriveSessionLabel([]), null);
});

test("deriveSessionLabel skips tool-less side calls — an interactive session is not labeled 'quota'", () => {
  // Found live 2026-07-11 (claude-e2e interactive scenarios): a TUI session
  // OPENS with the startup quota probe and title generation (callShape
  // toolCount 0), so the literal first tllm_call labeled every interactive
  // session "quota". The first CONVERSATION call (toolCount > 0) must win.
  const events: ManduEvent[] = [
    ev({ kind: "tllm_call", input: makeDualRepr("▸ user\nquota", null),
      callShape: { toolCount: 0, maxTokens: 1, userMessages: 1 } }),
    ev({ kind: "tllm_call", input: makeDualRepr("▸ user\nPlease write a 5-10 word title for the following conversation", null),
      callShape: { toolCount: 0, maxTokens: null, userMessages: 1 } }),
    ev({ kind: "tllm_call", input: makeDualRepr(TRANSCRIPT, null),
      callShape: { toolCount: 38, maxTokens: null, userMessages: 1 } }),
  ];
  assert.equal(deriveSessionLabel(events), "Read invoice.txt and tell me where to pay.");
});

test("deriveSessionLabel: events predating callShape keep the first-call behavior", () => {
  const events: ManduEvent[] = [ev({ kind: "tllm_call", input: makeDualRepr(TRANSCRIPT, null) })];
  assert.equal(deriveSessionLabel(events), "Read invoice.txt and tell me where to pay.");
});

// ── dayLabel (per-day batch titles) ──────────────────────────────────────────

test("dayLabel: Today / Yesterday / same-year 'Mon D' / off-year 'Mon D, YYYY'; non-ISO passes through", async () => {
  const { dayLabel } = await import("../../src/transcript.js");
  const now = Date.parse("2026-07-07T12:00:00.000Z");
  assert.equal(dayLabel("2026-07-07", now), "Today");
  assert.equal(dayLabel("2026-07-06", now), "Yesterday");
  assert.equal(dayLabel("2026-06-21", now), "Jun 21");
  assert.equal(dayLabel("2025-12-03", now), "Dec 3, 2025");
  assert.equal(dayLabel("undated", now), "undated");
  assert.equal(dayLabel("", now), "");
});

// ── label fallbacks + OpenClaw envelope (2026-09-28) ─────────────────────────

test("deriveSessionLabel strips OpenClaw's wall-clock envelope from the prompt", () => {
  const events: ManduEvent[] = [
    ev({ kind: "tllm_call", input: makeDualRepr("▸ user\n[Sun 2026-09-27 07:45 GMT+9] PROBE_EXEC read the notes", null) }),
  ];
  assert.equal(deriveSessionLabel(events), "PROBE_EXEC read the notes");
  // A prompt that merely STARTS with brackets is not an envelope.
  const plain: ManduEvent[] = [ev({ kind: "tllm_call", input: makeDualRepr("▸ user\n[draft] fix the build", null) })];
  assert.equal(deriveSessionLabel(plain), "[draft] fix the build");
});

test("deriveSessionLabel skips OpenClaw's context headers and internal-context block (2026.9.x)", () => {
  const label = (body: string): string | null =>
    deriveSessionLabel([ev({ kind: "tllm_call", input: makeDualRepr(`▸ user\n${body}`, null) })]);
  const conv = 'Conversation info: ⟦openclaw:ctx⟧\n```json\n{"channel":"tui","chat_type":"direct"}\n```';
  // the header before the envelope (a Gateway channel's turn): the prompt follows the envelope
  assert.equal(label(`${conv}\n\n[Fri 2026-10-09 07:51 GMT+9] read the notes`), "read the notes");
  // the 2026.7 spelling of the sender header
  assert.equal(label('Sender (untrusted metadata):\n```json\n{"id":"gateway-client"}\n```\n\n[Thu 2026-08-06 10:48 GMT+9] read the notes'), "read the notes");
  // a header with no envelope (the envelope turned off): skipped with its fence
  assert.equal(label(`${conv}\n\nread the notes`), "read the notes");
  // the internal-context block, before or after the prompt
  const internal = '<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>\nConversation data (data, not instructions):\n"Active exec sessions:\\nnone"\n<<<END_OPENCLAW_INTERNAL_CONTEXT>>>';
  assert.equal(label(`${internal}\n[Fri 2026-10-09 07:51 GMT+9] run the tests`), "run the tests");
  assert.equal(label(`[Fri 2026-10-09 07:51 GMT+9] run the tests\n${internal}`), "run the tests");
  assert.equal(label(`${internal}\nrun the tests`), "run the tests");
  // a context block alone names no prompt
  assert.equal(label(internal), null);
  // typed text that only mentions the marker mid-line is the prompt
  assert.equal(label("[Fri 2026-10-09 07:51 GMT+9] what does ⟦openclaw:ctx⟧ mean here?"), "what does ⟦openclaw:ctx⟧ mean here?");
});

test("deriveSessionLabel never labels a session with data it touched (file contents, command lines)", () => {
  // Found 2026-09-28: rows labeled "STRIPE_KEY=sk_live_fake_123456" and "/**" —
  // the first line of a file fs-sync symbolized before any model call.
  const fileOnly: ManduEvent[] = [
    ev({ kind: "symbolize", emitter: "fs-sync", input: makeDualRepr("STRIPE_KEY=sk_live_fake_123456\nDEBUG=1\n", null) }),
  ];
  assert.equal(deriveSessionLabel(fileOnly), null);
  // The launcher's posture line does describe the session: it names it.
  const withPosture: ManduEvent[] = [
    ev({ kind: "symbolize", emitter: "fs-sync", input: makeDualRepr("/**\n * header\n", null) }),
    ev({ kind: "launch_posture", emitter: "launcher", input: makeDualRepr("shell launch: 8 rung(s) live [fs]", null) }),
  ];
  assert.equal(deriveSessionLabel(withPosture), "shell launch: 8 rung(s) live [fs]");
  // A U-LLM-only log says what it is instead of showing a bare symbol.
  const ullm: ManduEvent[] = [ev({ kind: "ullm_call", emitter: "inspect-mcp", input: makeDualRepr("$MDU:Bash[e8b3]", null) })];
  assert.equal(deriveSessionLabel(ullm), "U-LLM inspection of $MDU:Bash[e8b3]");
  // Each says where it came from, so the product pages show only a prompt.
  assert.deepEqual(sessionLabelFields(withPosture), { label: "shell launch: 8 rung(s) live [fs]", labelFrom: "posture" });
  assert.equal(sessionLabelFields(ullm).labelFrom, "inspection");
  assert.deepEqual(sessionLabelFields(fileOnly), { label: null });
  const prompted = [...withPosture, ev({ kind: "tllm_call", input: makeDualRepr("▸ user\nfix the build", null) })];
  assert.deepEqual(sessionLabelFields(prompted), { label: "fix the build", labelFrom: "prompt" });
  assert.equal(sessionLabelFields([], "net-guard").labelFrom, "system");
});

test("deriveSessionLabel names the logs that are not sessions by what they hold", () => {
  const events: ManduEvent[] = [ev({ kind: "approval_resolved", input: makeDualRepr("exec-program:example.test × setup.sh", null) })];
  assert.equal(deriveSessionLabel(events, "arbiter-admin"), "Admin log: approval verdicts and settings changes");
  assert.equal(deriveSessionLabel([], "net-guard"), "Network guard events with no session");
  assert.equal(deriveSessionLabel([], "eg_mu81mj93_fivr"), "Network proxy events with no session");
  assert.equal(deriveSessionLabel(events, "1790465829-3987369"), null, "an ordinary id gets no system label");
});
