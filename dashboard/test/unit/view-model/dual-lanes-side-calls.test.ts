/**
 * dual-lanes-side-calls.test.ts — toDualLanes chokepoint attribution
 * (symbolizedBy/desymbolizedBy/quarantinedBy), the U-LLM correlate pre-pass,
 * and the side-call classification that keeps harness calls (typeahead, quota
 * probe, recap, summarizer) out of the conversation lane.
 *
 * Split VERBATIM out of dual-lanes.test.ts (2026-07-16) so failures localize by
 * feature area. Shared event builders live in ./dual-lanes-fixtures.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { correlateUllmCalls, toDualLanes } from "../../../src/view-model.js";

import { ev, repr, READ_SYM } from "./dual-lanes-fixtures.js";

test("the rewrite TECHNIQUE is recorded: symbolizedBy from the symbolize/tool_result emitter", () => {
  const symOut = repr("$MDU:Read[1a9f]", "RAW NOTES", [READ_SYM]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/ws/notes.md"})') }),
    ev({ kind: "symbolize", callId: "c1", output: symOut }),
    ev({ kind: "tool_result", callId: "c1", output: symOut, policy: { trust: "UNTRUSTED" } }),
    ev({ kind: "desymbolize", callId: "c1", emitter: "arbiter" as never, input: symOut, policy: { usage: "allow" } }),
  ];
  const dv = toDualLanes(events);
  const t = dv.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.symbolizedBy, "anthropic-proxy", "the up-band names the model-context chokepoint");
  assert.equal(t.desymbolizedBy, "arbiter", "the down-band names the resolving component");
});

test("an MCP-named inspect tool is quarantine, attributed to inspect-mcp", () => {
  const MCP_TOOL = "mcp__mandu-inspect__inspect_symbol";
  const wrap = {
    name: "$MDU:inspect[ee19]", tool: MCP_TOOL, field: null,
    origin: null, value: "$MDU:inspect[c3d4].result", derivedFrom: undefined, lineRange: undefined,
  };
  const events = [
    ev({ kind: "tool_use", callId: "i1", input: repr(`${MCP_TOOL}({"symbol":"$MDU:Read[1a9f]"})`) }),
    ev({ kind: "tool_result", callId: "i1", output: repr("$MDU:inspect[ee19]", "$MDU:inspect[c3d4].result", [wrap]), policy: { trust: "UNTRUSTED" } }),
  ];
  const dv = toDualLanes(events);
  const t = dv.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.quarantine, true, "mcp__<server>__inspect_symbol renders as the U-LLM card");
  assert.equal(t.quarantinedBy, "inspect-mcp");
  assert.equal(t.symbolizedBy, "anthropic-proxy");
});

test("a correlated ullm_call records quarantinedBy from its emitter", () => {
  const events = [
    ev({ kind: "tool_use", callId: "i1", input: repr('inspect_symbol({"symbol":"$MDU:Read[1a9f]"})') }),
    ev({ kind: "ullm_call", callId: "i1", view: "Quarantine", emitter: "inspect-mcp" as never,
      input: repr("$MDU:Read[1a9f]", "RAW NOTES", [READ_SYM]),
      output: repr("$MDU:inspect[c3d4].result", "the summary", []) }),
  ];
  const dv = toDualLanes(events);
  const t = dv.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.quarantine, true);
  assert.equal(t.quarantinedBy, "inspect-mcp");
});

test("correlate pre-pass end result: an ORPHAN ullm_call folds into the inspect tool card — no standalone U-LLM box", () => {
  // The live gap: inspect-mcp emits ullm_call with callId null / turn 0 (MCP
  // hides the invoking tool_use id), so the fold below could never fire and an
  // orphan "U-LLM (quarantined)" OS card rendered. toSessionViewModel now runs
  // correlateUllmCalls over the trace first; this proves the folded end result.
  const MCP_TOOL = "mcp__mandu-inspect__inspect_symbol";
  const events = [
    ev({ kind: "tool_use", callId: "toolu_017za", turn: 7,
      input: repr(`${MCP_TOOL}({"symbol":"$MDU:WebFetch[5227]","instruction":"Count occurrences."})`) }),
    ev({ kind: "ullm_call", turn: 0, view: "Quarantine", emitter: "inspect-mcp" as never,
      input: repr("$MDU:WebFetch[5227]", "<full raw web page summary>"),
      output: repr("$MDU:inspect[3021].result", "6") }),
  ];
  // Control — WITHOUT the pre-pass the fold cannot fire: the orphan box renders.
  const before = toDualLanes(events);
  assert.ok(
    before.steps.some((s) => s.step === "os" && s.title === "U-LLM (quarantined) · inspect-mcp"),
    "control: an uncorrelated ullm_call renders the orphan standalone card",
  );
  // WITH the pre-pass (as toSessionViewModel applies it):
  const dv = toDualLanes(correlateUllmCalls(events));
  assert.ok(!dv.steps.some((s) => s.step === "os"), "NO standalone U-LLM (quarantined) OS card");
  const tools = dv.steps.filter((s) => s.step === "tool");
  assert.equal(tools.length, 1, "one inspect tool card carries the whole quarantine run");
  const t = tools[0]!;
  if (t.step !== "tool") return;
  assert.equal(t.quarantine, true);
  assert.equal(t.quarantinedBy, "inspect-mcp", "attributed from the ullm_call emitter");
  assert.equal(t.turn, 7, "the card keeps the tool_use turn (adopted by the orphan too)");
  assert.equal(t.resultHuman, "6", "the U-LLM answer fills the card's HumanView result");
});

test("inspect_symbol is a quarantine (U-LLM) crossing; its arg symbols fill the down band", () => {
  const events = [
    ev({ kind: "symbolize", callId: "r1", output: repr("$MDU:Read[1a9f]", "RAW NOTES", [READ_SYM]) }),
    ev({ kind: "tool_result", callId: "r1", output: repr("$MDU:Read[1a9f]", "RAW NOTES", [READ_SYM]), policy: { trust: "UNTRUSTED" } }),
    ev({ kind: "tool_use", callId: "i1", input: repr('inspect_symbol({"symbols":"[\\"$MDU:Read[1a9f]\\"]","prompt":"Summarize."})') }),
    ev({ kind: "tool_result", callId: "i1", output: repr("$MDU:inspect_symbol[0961]", "the summary", []), policy: { trust: "UNTRUSTED" } }),
  ];
  const dv = toDualLanes(events);
  const t = dv.steps.find((s) => s.step === "tool" && (s as { tool?: string }).tool === "inspect_symbol")!;
  if (t.step !== "tool") return;
  assert.equal(t.quarantine, true);
  assert.equal(t.crossing, true);
  assert.equal(t.downSyms.length, 1, "the symbol referenced in the args is the down-band mapping");
  assert.equal(t.downSyms[0]!.name, "$MDU:Read[1a9f]");
  assert.equal(t.downSyms[0]!.value, "RAW NOTES", "resolved from the session symbol table");
});

// ── Side calls must not pollute the conversation lane (the session-1783675777
// bug): Claude Code's typeahead SUGGESTION call outputs PROSE, so the JSON-blob
// check alone let it become the LAST response card — stealing `final` (the
// delivery zone + §4.2c deep reveal) from the reply the human actually got. ──

test("a typeahead SUGGESTION side call never steals the delivery from the real reply", () => {
  const INSPECT_SYM = {
    name: "$MDU:inspect[c3dc].result", tool: "inspect_symbol", field: "result",
    origin: "$MDU:Bash[bfaa]", value: "10", derivedFrom: "$MDU:Bash[bfaa]",
  };
  const events = [
    ev({ kind: "tllm_call", turn: 8,
      input: repr("▸ system\nCC prompt\n\n▸ user\nthen count the word, security"),
      output: repr('The word "security" appears **$MDU:inspect[c3dc].result** times.',
        null, [INSPECT_SYM]) }),
    // The typeahead predictor: the conversation transcript plus a trailing
    // "[SUGGESTION MODE: …]" user instruction, answered with a predicted prompt.
    ev({ kind: "tllm_call", turn: 9,
      input: repr("▸ system\nCC prompt\n\n▸ user\nthen count the word, security\n\n▸ user\n[SUGGESTION MODE: Suggest what the user might naturally type next into Claude Code.]\n\nFIRST: Look at the user's recent messages."),
      output: repr("show the lines with security") }),
  ];
  const dv = toDualLanes(events);
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 1, "the suggestion side call produces NO response card");
  const r = responses[0]!;
  if (r.step !== "response") return;
  assert.match(r.text, /appears \*\*\$MDU:inspect\[c3dc\]\.result\*\*/);
  assert.equal(r.final, true, "the reply the human received keeps the delivery zone");
  assert.equal(r.symbols[0]?.name, "$MDU:inspect[c3dc].result");
  assert.equal(r.symbols[0]?.value, "10", "the delivery band resolves the count");
});

test("the startup quota probe seeds neither the input endpoint nor a response card", () => {
  const events = [
    // Claude Code's startup probe: a lone "quota" prompt, max_tokens=1 → "I".
    ev({ kind: "tllm_call", turn: 0,
      input: repr("▸ system\n[Mandu IPI handling prompt]\n\n▸ user\nquota"),
      output: repr("I") }),
    // The real first turn: injected context collapses to literal
    // [system-reminder] placeholder lines ahead of what the human typed.
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nCC prompt\n\n▸ user\n[system-reminder]\n[system-reminder]\nhello"),
      output: repr("Hey! I'm ready to help.") }),
  ];
  const dv = toDualLanes(events);
  const input = dv.steps.find((s) => s.step === "input")!;
  if (input.step !== "input") return;
  assert.equal(input.text, "hello", "the entry endpoint is the human's prompt, placeholders stripped");
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 1, 'the probe\'s one-token "I" is not a response card');
});

test('a REAL user prompt "quota" (full reply, not a one-token probe) keeps rendering', () => {
  const events = [
    ev({ kind: "tllm_call", turn: 0,
      input: repr("▸ system\nCC prompt\n\n▸ user\nquota"),
      output: repr("Your quota resets at midnight UTC.") }),
  ];
  const dv = toDualLanes(events);
  const input = dv.steps.find((s) => s.step === "input");
  assert.ok(input && input.step === "input" && input.text === "quota");
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 1, "a real reply to a real prompt renders");
});

// ── The session-1783733223 bugs: a quota probe whose upstream 429'd escapes the
// ≤8-char output check (its output is the proxy's no-model-response explainer)
// and stole the delivery zone; and the reply-filter's uncorrelated desymbolize
// frames rendered as bare, unexplained "desymbolize" cards. ──

test("a 429'd quota probe (no-model-response explainer) is still a side call", () => {
  const events = [
    ev({ kind: "tllm_call", turn: 6,
      input: repr("▸ system\nCC prompt\n\n▸ user\ncount the word security on the page"),
      output: repr("$MDU:WebFetch[cd10]") }),
    // The startup probe, rate-limited upstream: the proxy emits its explainer
    // instead of the one-token reply — it must not become the delivered reply.
    ev({ kind: "tllm_call", turn: 0,
      input: repr("▸ system\n[Mandu IPI handling prompt]\n\n▸ user\nquota"),
      output: repr("⚠ no model response — upstream HTTP 429 (rate-limited): rate_limit_error: Error") }),
  ];
  const dv = toDualLanes(events);
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 1, "the errored probe mints no response card");
  const r = responses[0]!;
  if (r.step !== "response") return;
  assert.equal(r.text, "$MDU:WebFetch[cd10]");
  assert.equal(r.final, true, "the reply the human received keeps the delivery zone");
  assert.ok(!dv.steps.some((s) => s.step === "input" && s.text === "quota"),
    "the probe seeds no input card");
});

test("an errored REAL turn renders the explainer but never takes the delivery zone", () => {
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nCC prompt\n\n▸ user\nhello"),
      output: repr("Hey! I'm ready to help.") }),
    ev({ kind: "tllm_call", turn: 2,
      input: repr("▸ system\nCC prompt\n\n▸ user\nhello\n\n▸ user\nnow refactor it"),
      output: repr("⚠ no model response — upstream HTTP 529 (overloaded)") }),
  ];
  const dv = toDualLanes(events);
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 2, "the explainer still renders — the blank turn stays explained");
  const [reply, explainer] = responses;
  if (reply!.step !== "response" || explainer!.step !== "response") return;
  assert.equal(reply!.final, true, "delivery stays on the reply the human actually received");
  assert.match(explainer!.text, /no model response/);
  assert.equal(explainer!.final, false);
});

test("a tool-less request (callShape.toolCount 0) is a side call STRUCTURALLY — no string match needed", () => {
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nCC prompt\n\n▸ user\nhello"),
      output: repr("Hey! I'm ready to help.") }),
    // A future harness side call with a never-seen prompt shape: the proxy
    // recorded that the request carried NO tools, so it cannot be the agent
    // conversation loop — no input card, no response card, no stolen final.
    ev({ kind: "tllm_call", turn: 0,
      callShape: { toolCount: 0, maxTokens: 512, userMessages: 1 },
      input: repr("▸ system\nbrand-new harness prompt\n\n▸ user\nDo the new background thing."),
      output: repr("Here is my background answer.") }),
  ];
  const dv = toDualLanes(events);
  const responses = dv.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 1, "the tool-less call mints no response card");
  if (responses[0]!.step === "response") assert.equal(responses[0]!.final, true);
  assert.equal(dv.calls.length, 2);
  assert.equal(dv.calls[0]!.cls, "conversation");
  assert.equal(dv.calls[1]!.cls, "side", "toolCount 0 classifies as side without a string heuristic");
});

test("calls classification: conversation / side / unknown, prose flag on unknowns only when prose renders", () => {
  const events = [
    ev({ kind: "tllm_call", turn: 1,
      input: repr("▸ system\nCC prompt\n\n▸ user\nhello"),
      output: repr("Hey!") }),
    // Non-extending prose call, no callShape, no known string shape → unknown.
    ev({ kind: "tllm_call", turn: 0,
      input: repr("▸ system\nweird\n\n▸ user\nsomething else entirely"),
      output: repr("Surprise prose.") }),
    // The quota probe → side (string shape).
    ev({ kind: "tllm_call", turn: 0,
      input: repr("▸ system\n[Mandu IPI handling prompt]\n\n▸ user\nquota"),
      output: repr("I") }),
  ];
  const dv = toDualLanes(events);
  assert.deepEqual(dv.calls.map((c) => c.cls), ["conversation", "unknown", "side"]);
  assert.deepEqual(dv.calls.map((c) => c.prose), [true, true, false]);
});

test("uncorrelated reply-filter desymbolize frames fold into ONE explanatory user-reply card", () => {
  const frame = "[2J[H● $MDU:WebFetch[cd10]\r\n❯ ";
  const mk = () => ev({
    kind: "desymbolize", view: "HumanView", emitter: "reply-filter",
    input: repr(frame),
    output: { symbolized: frame, original: "● the original reply\r\n❯ ", differs: true, symbols: [] },
  });
  const dv = toDualLanes([mk(), mk(), mk()]);
  const os = dv.steps.filter((s) => s.step === "os");
  assert.equal(os.length, 1, "identical consecutive repaint frames fold");
  const o = os[0]!;
  if (o.step !== "os") return;
  assert.equal(o.repeats, 3);
  assert.equal(o.title, "user reply · reply-filter", "the card names the egress surface, not a bare kind");
  assert.match(o.note ?? "", /\$MDU:WebFetch\[cd10\]/, "the note names the resolved symbol");
});

// ── plan 11 D6: the endpoint that served a quarantined call ─────────────────

test("plan 11 D6: a correlated ullm_call's endpoint lands on the inspect step (readBy)", () => {
  const MCP_TOOL = "mcp__mandu-inspect__inspect_symbol";
  const events = [
    ev({ kind: "tool_use", callId: "toolu_1", turn: 3,
      input: repr(`${MCP_TOOL}({"symbol":"$MDU:localmodel_Read[5227]","instruction":"Summarize."})`) }),
    ev({ kind: "ullm_call", turn: 0, view: "Quarantine", emitter: "inspect-mcp" as never,
      input: repr("$MDU:localmodel_Read[5227]", "the contract"),
      output: repr("$MDU:localmodel_inspect[3021].result", "a summary"),
      endpoint: { name: "ollama", location: "local" } }),
  ];
  const dv = toDualLanes(correlateUllmCalls(events));
  const t = dv.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.deepEqual(t.readBy, { name: "ollama", location: "local" });
});

test("plan 11 D6: an orphan U-LLM card names its endpoint; without the field the title is unchanged", () => {
  const card = (extra: Record<string, unknown>) => toDualLanes([
    ev({ kind: "ullm_call", turn: 0, view: "Quarantine", emitter: "inspect-mcp" as never,
      input: repr("$MDU:Read[1a9f]", "RAW"), output: repr("$MDU:inspect[c3d4].result", "x"), ...extra }),
  ]).steps.find((s) => s.step === "os")!;
  const local = card({ endpoint: { name: "ollama", location: "local" } });
  if (local.step !== "os") return;
  assert.equal(local.title, "U-LLM (quarantined) · inspect-mcp · ollama (local model)");
  assert.deepEqual(local.readBy, { name: "ollama", location: "local" });
  const ext = card({ endpoint: { name: "default", location: "external" } });
  if (ext.step !== "os") return;
  assert.equal(ext.title, "U-LLM (quarantined) · inspect-mcp · default (external model)");
  const old = card({});
  if (old.step !== "os") return;
  assert.equal(old.title, "U-LLM (quarantined) · inspect-mcp");
  assert.equal("readBy" in old, false);
});

test("plan 11 D6: an uncorrelated inspect step still names its reader, joined by the answer token", () => {
  const events = [
    ev({ kind: "tool_use", callId: "i9", input: repr('inspect_symbol({"symbol":"$MDU:Read[1a9f]"})') }),
    ev({ kind: "ullm_call", turn: 0, view: "Quarantine", emitter: "inspect-mcp" as never,
      input: repr("$MDU:Read[1a9f]", "RAW"), output: repr("$MDU:inspect[c3d4].result", "x"),
      endpoint: { name: "default", location: "external" } }),
    ev({ kind: "tool_result", callId: "i9", output: repr(JSON.stringify({ result_symbol: "$MDU:inspect[c3d4].result" })), policy: { trust: "TRUSTED" } }),
  ];
  const t = toDualLanes(events).steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.deepEqual(t.readBy, { name: "default", location: "external" });
});
