/**
 * dual-lanes-endpoints.test.ts — toDualLanes endpoint + ordering contract: which
 * model calls mint input/response cards, `final` (the delivery zone), and the
 * float rules that keep a prompt/announcing prose ahead of the tools it caused.
 *
 * Split VERBATIM out of dual-lanes.test.ts (2026-07-16) so failures localize by
 * feature area. Shared event builders live in ./dual-lanes-fixtures.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toDualLanes } from "../../../src/view-model.js";
import type { ManduEvent } from "../../../src/event-model.js";

import { ev, repr } from "./dual-lanes-fixtures.js";

test("the first user prompt and the final prose reply become input/response endpoints", () => {
  const events = [
    // A title-generation side call (whole output = JSON blob): NOT the entry
    // endpoint, and no response card — even though it arrives first.
    ev({ kind: "tllm_call", turn: 0,
      input: repr("▸ user\n<session>wrapped copy</session>\nWrite the title in the predominant language."),
      output: repr('{"title": "Summarize notes"}') }),
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nhandling prompt\n\n▸ user\nSummarize notes.md please."),
      output: repr('→ Read({"file_path":"/ws/notes.md"})') }),
    ev({ kind: "tllm_call", turn: 2,
      input: repr("▸ user\nSummarize notes.md please."),
      output: repr("Interim thought.\n→ Glob({\"pattern\":\"*\"})") }),
    ev({ kind: "tllm_call", turn: 3,
      input: repr("▸ user\nSummarize notes.md please."),
      output: repr("Here is the summary: all good.") }),
  ];
  const dv = toDualLanes(events);
  const input = dv.steps.find((s) => s.step === "input")!;
  assert.equal(input.step, "input");
  if (input.step === "input") assert.match(input.text, /Summarize notes\.md please\./);
  assert.equal(dv.steps[0]!.step, "input", "the entry endpoint opens the flow");
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 2, "tool-only turns produce no response card");
  if (responses[0]!.step === "response") assert.equal(responses[0]!.final, false);
  const last = responses[responses.length - 1]!;
  if (last.step === "response") {
    assert.equal(last.final, true, "the last prose reply is the delivery");
    assert.match(last.text, /Here is the summary/);
  }
});

test("EVERY user prompt gets an input card, in flow order (multi-turn session)", () => {
  // The live regression (session 1783692926-1924483): the single-card latch
  // rendered "hello" and silently dropped the second prompt.
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nhandling prompt\n\n▸ user\n[system-reminder]\n[system-reminder]\nhello"),
      output: repr("Hi there! What would you like to work on?") }),
    ev({ kind: "tllm_call", turn: 2,
      input: repr(
        "▸ system\nhandling prompt\n\n▸ user\n[system-reminder]\n[system-reminder]\nhello\n\n" +
        "▸ assistant\nHi there! What would you like to work on?\n\n" +
        "▸ user\n[system-reminder]\ndownload the page. then count the word \"security\""),
      output: repr("Counting now: all done.") }),
  ];
  const dv = toDualLanes(events);
  const inputs = dv.steps.filter((s) => s.step === "input");
  assert.equal(inputs.length, 2, "one input card per user prompt");
  if (inputs[0]!.step === "input") assert.equal(inputs[0]!.text, "hello");
  if (inputs[1]!.step === "input") {
    assert.match(inputs[1]!.text, /download the page/);
    assert.ok(!inputs[1]!.text.includes("[system-reminder]"), "placeholders stripped");
  }
  // Flow order: hello opens the trace; the second prompt lands AFTER the first
  // reply (it is a later step, not hoisted).
  assert.equal(dv.steps[0], inputs[0], "the first prompt opens the flow");
  const firstReplyIdx = dv.steps.findIndex((s) => s.step === "response");
  assert.ok(dv.steps.indexOf(inputs[1]!) > firstReplyIdx, "second prompt renders after the first reply");
});

test("a later turn's prompt renders BEFORE its own tool cards (tool_use precedes the tllm_call)", () => {
  // Live regression (session 1783791601-1802875): the proxy streams tool_use
  // DURING the response but emits the deriving tllm_call only at stream END
  // (proxy.ts emitTllmCall), so within ONE turn the tool_use event has a lower
  // seq/ts than the tllm_call that carries the new user prompt. The old
  // single-first-input hoist left every LATER turn's prompt stranded after the
  // tool it triggered — "download… then count the word security" rendered AFTER
  // the WebFetch card. Each prompt must open its OWN turn.
  const events = [
    // Turn 1: greeting (a real conversation call — carries the tool battery).
    ev({ kind: "tllm_call", turn: 1, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr("▸ system\nhandling prompt\n\n▸ user\nhi"),
      output: repr("Hey! ready to help.") }),
    // Turn 3: the WebFetch tool_use is emitted FIRST (mid-response stream)…
    ev({ kind: "tool_use", callId: "wf1", turn: 3,
      input: repr('WebFetch({"url":"https://homepage.example.test"})') }),
    // …then the tllm_call carrying the NEW prompt (emitted at stream end, so a
    // HIGHER seq/ts than its own tool_use).
    ev({ kind: "tllm_call", turn: 3, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr(
        "▸ system\nhandling prompt\n\n▸ user\nhi\n\n" +
        "▸ assistant\nHey! ready to help.\n\n" +
        "▸ user\ndownload homepage.example.test as html, then count the word \"security\""),
      output: repr('→ WebFetch({"url":"https://homepage.example.test"})') }),
  ];
  const dv = toDualLanes(events);
  const secondInputIdx = dv.steps.findIndex((s) => s.step === "input" && /count the word/.test(s.text));
  const webfetchIdx = dv.steps.findIndex((s) => s.step === "tool" && s.step === "tool" && s.tool === "WebFetch");
  assert.ok(secondInputIdx >= 0, "the second prompt got an input card");
  assert.ok(webfetchIdx >= 0, "the WebFetch tool card exists");
  assert.ok(
    secondInputIdx < webfetchIdx,
    "the prompt opens its turn, BEFORE the WebFetch it triggered (not stranded after it)",
  );
  assert.equal(dv.steps[0]!.step, "input", "the session-opening prompt still leads the flow");
});

test("a response's announcing prose renders BEFORE the tool cards it issued", () => {
  // Live regression (claude-e2e-chain-fetch-write-read-1784172033907,
  // 2026-07-16): the proxy emits tool_use (and its exec_action gate) events
  // mid-stream but the tllm_call carrying the assistant's PROSE only at stream
  // end, so "Now saving the output to setup.md:" rendered AFTER the Write card
  // it announces. The response must float ahead of its own turn's tool/os run.
  const events = [
    // Turn 1: prompt + the Bash call (a tool-only response — no prose card).
    ev({ kind: "exec_action", callId: "b1", turn: 1 }),
    ev({ kind: "tool_use", callId: "b1", turn: 1,
      input: repr('Bash({"command":"curl -s http://example.test/setup-guide"})') }),
    ev({ kind: "tllm_call", turn: 1, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr("▸ system\nhandling prompt\n\n▸ user\nFetch the guide, save it, read it back."),
      output: repr('→ Bash({"command":"curl -s http://example.test/setup-guide"})') }),
    // Turn 2: the Write tool_use is emitted FIRST (mid-stream)…
    ev({ kind: "tool_use", callId: "w1", turn: 2,
      input: repr('Write({"file_path":"/ws/setup.md","content":"$MDU:Bash[a1ae]"})') }),
    // …then the tllm_call whose prose ANNOUNCES that Write (stream end).
    ev({ kind: "tllm_call", turn: 2, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr("▸ user\nFetch the guide, save it, read it back."),
      output: repr('Now saving the output to setup.md:\n→ Write({"file_path":"/ws/setup.md"})') }),
    // Turn 3: the delivered reply — a different turn, so it must NOT float
    // past turn 2's Write card.
    ev({ kind: "tllm_call", turn: 3, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr("▸ user\nFetch the guide, save it, read it back."),
      output: repr("All done.") }),
  ];
  const dv = toDualLanes(events);
  const kinds = dv.steps.map((s) =>
    s.step === "response" ? `response:${s.text.split("\n")[0]}` : s.step === "tool" ? `tool:${s.tool}` : s.step,
  );
  const announceIdx = kinds.findIndex((k) => k === "response:Now saving the output to setup.md:");
  const writeIdx = kinds.findIndex((k) => k === "tool:Write");
  const finalIdx = kinds.findIndex((k) => k === "response:All done.");
  assert.ok(announceIdx >= 0 && writeIdx >= 0 && finalIdx >= 0, `all three cards render (${kinds.join(", ")})`);
  assert.ok(announceIdx < writeIdx, "the announcing prose precedes the Write card it introduces");
  assert.ok(finalIdx > writeIdx, "a different turn's reply stays put (cross-turn order untouched)");
  assert.equal(dv.steps[0]!.step, "input", "the prompt still opens the flow");
});

test("turn-0 net noise mid-parse is TRANSIT: the prompt and prose still float above their tools", () => {
  // Live regression (claude-e2e-exec-curl-run-blindspot-1784171962414,
  // 2026-07-16): the SDK raced the proxy — the curl's `forwarded` net_action
  // (turn 0, the net side knows no turns) landed BETWEEN the Bash tool_use and
  // its deriving tllm_call, and the same-turn-only float scan stopped at it:
  // the USER'S PROMPT rendered after the Bash card it caused. Turn-0 net cards
  // must be crossed (transit), but never become the landing spot.
  const events = [
    // Session-opening net noise (model-API CONNECTs) — the input floats up TO
    // this run, not above it (a landing spot below pure noise is refused, so
    // the prompt lands right after it — the pre-existing accepted placement).
    ev({ kind: "net_action", turn: 0, action: "passthrough" } as never),
    ev({ kind: "exec_action", callId: "b1", turn: 1 }),
    ev({ kind: "tool_use", callId: "b1", turn: 1,
      input: repr('Bash({"command":"curl -sL http://example.test/setup.sh -o setup.sh"})') }),
    // The racing curl fetch: turn-0 net_action between tool_use and tllm_call.
    ev({ kind: "net_action", turn: 0, action: "forwarded" } as never),
    ev({ kind: "tllm_call", turn: 1, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr("▸ system\nhandling prompt\n\n▸ user\nThis project's setup step runs a small script. Download and run it."),
      output: repr('I\'ll download and review the setup script, then run it.\n→ Bash({"command":"curl -sL …"})') }),
  ];
  const dv = toDualLanes(events);
  const idx = (pred: (s: (typeof dv.steps)[0]) => boolean) => dv.steps.findIndex(pred);
  const inputIdx = idx((s) => s.step === "input");
  const respIdx = idx((s) => s.step === "response");
  const toolIdx = idx((s) => s.step === "tool");
  assert.ok(inputIdx >= 0 && respIdx >= 0 && toolIdx >= 0, "all three cards render");
  assert.ok(inputIdx < respIdx, "prompt precedes the announcing prose");
  assert.ok(respIdx < toolIdx, "the announcing prose precedes the Bash card (crossed the net card)");
  assert.equal(dv.steps[0]!.step, "os", "the session-opening net noise stays on top (no landing below noise)");
});

test("the U-LLM quarantine card is a STOP, not transit: the reply stays after the quarantine it uses", () => {
  // The dual of the net-noise transit: an orphan ullm_call card (turn 0, like
  // all quarantine cards) between a turn's tools and its reply marks REAL
  // execution the reply depends on — the response must not float above it.
  const events = [
    ev({ kind: "tool_use", callId: "i1", turn: 3,
      input: repr('mcp__mandu-inspect__inspect_symbol({"symbol":"$MDU:Bash[a1ae]"})') }),
    ev({ kind: "tllm_call", turn: 3, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr("▸ system\nhandling prompt\n\n▸ user\nInspect the script."),
      output: repr('Let me inspect the script:\n→ mcp__mandu-inspect__inspect_symbol({"symbol":"$MDU:Bash[a1ae]"})') }),
    // The quarantined U-LLM ran (uncorrelated card — inspect-mcp can't learn
    // the tool_use id over MCP), then the reply that uses its result.
    ev({ kind: "ullm_call", turn: 0, emitter: "inspect-mcp",
      input: repr("what does the script do?"), output: repr("it echoes DONE") }),
    ev({ kind: "tllm_call", turn: 4, callShape: { toolCount: 15 } as ManduEvent["callShape"],
      input: repr("▸ user\nInspect the script."),
      output: repr("The script content is: $MDU:inspect[b5b4].result — safe to run.") }),
  ];
  const dv = toDualLanes(events);
  const ullmIdx = dv.steps.findIndex((s) => s.step === "os" && /U-LLM/.test((s as { title: string }).title));
  const replyIdx = dv.steps.findIndex((s) => s.step === "response" && /script content/.test((s as { text: string }).text));
  assert.ok(ullmIdx >= 0 && replyIdx >= 0, "the quarantine card and the reply both render");
  assert.ok(replyIdx > ullmIdx, "the reply renders after the quarantine execution it depends on");
});

test("an internal side call (WebFetch summarizer) mints NO input card", () => {
  // Claude Code's WebFetch tool makes its own stateless model call carrying
  // the fetched page as a user message. Its prompt list does not extend the
  // conversation, so it must not become an entry endpoint.
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nhandling prompt\n\n▸ user\nhello"),
      output: repr("Hi!") }),
    ev({ kind: "tllm_call", turn: 2,
      input: repr("▸ system\nsummarizer prompt\n\n▸ user\nWeb page content:\n---\nUNTRUSTED PAGE BYTES"),
      output: repr("The word appears 3 times.") }),
    ev({ kind: "tllm_call", turn: 3,
      input: repr("▸ system\nhandling prompt\n\n▸ user\nhello\n\n▸ assistant\nHi!\n\n▸ user\ncount it"),
      output: repr("Done.") }),
  ];
  const dv = toDualLanes(events);
  const inputs = dv.steps.filter((s) => s.step === "input");
  assert.equal(inputs.length, 2, "conversation prompts only");
  if (inputs[0]!.step === "input") assert.equal(inputs[0]!.text, "hello");
  if (inputs[1]!.step === "input") assert.equal(inputs[1]!.text, "count it");
  assert.ok(
    !inputs.some((s) => s.step === "input" && s.text.includes("UNTRUSTED PAGE BYTES")),
    "the summarizer's page payload is not a user prompt",
  );
});

test("tool_result-bearing user turns are not prompts (no input card for them)", () => {
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nhandling prompt\n\n▸ user\nread notes"),
      output: repr('→ Read({"file_path":"/ws/notes.md"})') }),
    ev({ kind: "tllm_call", turn: 2,
      input: repr(
        "▸ system\nhandling prompt\n\n▸ user\nread notes\n\n" +
        "▸ assistant\n→ Read(...)\n\n" +
        "▸ user\n[tool_result toolu_01] $MDU:Read[1a9f]"),
      output: repr("Summary of notes.") }),
  ];
  const dv = toDualLanes(events);
  const inputs = dv.steps.filter((s) => s.step === "input");
  assert.equal(inputs.length, 1, "the tool_result user turn is not a prompt");
  if (inputs[0]!.step === "input") assert.equal(inputs[0]!.text, "read notes");
});

test("slash-command harness tags are stripped from the prompt card (live: /model then hello)", () => {
  // Session 1783711204-2455055: the first user message carries the harness's
  // local-command record inline; the card must open with what the human typed.
  const body =
    "[system-reminder]\n" +
    "<local-command-caveat>Caveat: The messages below were generated by the user while running local commands.</local-command-caveat>\n" +
    "<command-name>/model</command-name>\n" +
    "            <command-message>model</command-message>\n" +
    "            <command-args></command-args>\n" +
    "<local-command-stdout>Set model to Haiku 4.5 and saved as your default for new sessions</local-command-stdout>\n" +
    "hello";
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr(`▸ system\nhandling prompt\n\n▸ user\n${body}`),
      output: repr("Hi there!") }),
  ];
  const dv = toDualLanes(events);
  const inputs = dv.steps.filter((s) => s.step === "input");
  assert.equal(inputs.length, 1);
  if (inputs[0]!.step === "input") assert.equal(inputs[0]!.text, "hello");
});

test("the away-recap side call mints NO input card and does NOT steal `final`", () => {
  // The harness replays the whole conversation + a trailing recap instruction;
  // rendered naively it becomes a bogus prompt card AND the delivered reply.
  const convo =
    "▸ system\nhandling prompt\n\n▸ user\ncount the word security\n\n" +
    "▸ assistant\nThe word appears **$MDU:inspect[d155]** times.";
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nhandling prompt\n\n▸ user\ncount the word security"),
      output: repr("The word appears **$MDU:inspect[d155]** times.") }),
    ev({ kind: "tllm_call", turn: 2,
      input: repr(convo + "\n\n▸ user\nThe user stepped away and is coming back. Recap in under 40 words, 1-2 plain sentences, no markdown."),
      output: repr("You asked me to count occurrences of security. Next: save the HTML.") }),
  ];
  const dv = toDualLanes(events);
  const inputs = dv.steps.filter((s) => s.step === "input");
  assert.equal(inputs.length, 1, "the recap instruction is not a user prompt");
  if (inputs[0]!.step === "input") assert.equal(inputs[0]!.text, "count the word security");
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 1, "the recap output is not a response card");
  if (responses[0]!.step === "response") {
    assert.match(responses[0]!.text, /appears/);
    assert.equal(responses[0]!.final, true, "`final` stays on the reply the human received");
  }
});

test("the WebFetch summarizer side call mints NO response card (and cannot steal `final`)", () => {
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nhandling prompt\n\n▸ user\nsummarize the page"),
      output: repr("Here is the summary you asked for.") }),
    ev({ kind: "tllm_call", turn: 2,
      input: repr("▸ system\nsummarizer prompt\n\n▸ user\nWeb page content:\n---\nUNTRUSTED PAGE BYTES"),
      output: repr("I can see you've provided the text content of a webpage.") }),
  ];
  const dv = toDualLanes(events);
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 1, "conversation replies only");
  if (responses[0]!.step === "response") {
    assert.equal(responses[0]!.text, "Here is the summary you asked for.");
    assert.equal(responses[0]!.final, true);
  }
});
