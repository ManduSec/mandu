/**
 * paired-rows.test.ts — §4.2f the paired-rows projection (view-model/
 * paired-rows.ts): turns per prompt, one row per step, the background fold,
 * the protection-mode signal, and the right-hand originals (local collapse +
 * the arbiter deep reveal). Pure: events → toSessionViewModel → vm.paired.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { toSessionViewModel, revealPairedOriginals, type PairedModel, type PairedToolRow } from "../../../src/view-model.js";

const INV = { invariant: { violatedInvariant: false } };
let seq = 0;
function ev(over: Record<string, unknown>): Record<string, unknown> {
  seq++;
  return {
    id: "e" + seq, sessionId: "s", seq, turn: 1, ts: `2026-09-26T10:00:${String(seq).padStart(2, "0")}.000Z`,
    callId: null, parentId: null, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, ...INV, ...over,
  };
}
const repr = (symbolized: string, original: string | null = null, symbols: unknown[] = []) =>
  ({ symbolized, original, differs: original !== null && original !== symbolized, symbols });
const prompt = (text: string, out = "") =>
  ev({ kind: "tllm_call", input: repr(`▸ user\n${text}`), output: out ? repr(out) : null });
const paired = (events: Record<string, unknown>[]): PairedModel =>
  toSessionViewModel("s", events as never).paired;
const rows = (p: PairedModel) => p.turns.flatMap((t) => t.rows);

test("turns: one per prompt, a leading setup turn only when something happened before it", () => {
  const p = paired([
    ev({ kind: "net_action", turn: 0, action: "tunneled", destination: "api.anthropic.com:443" }),
    prompt("first question", "first answer"),
    { ...prompt("first question\n▸ assistant\nfirst answer\n▸ user\nsecond question", "second answer"), turn: 2 },
  ]);
  assert.equal(p.turns.length, 3, "setup + two prompts");
  assert.equal(p.turns[0]!.inputId, null);
  assert.deepEqual(p.turns[0]!.background.map((b) => b.category), ["connections"]);
  assert.deepEqual(p.turns[0]!.background[0]!.labels, ["api.anthropic.com"], "the :443 suffix is dropped");
  assert.ok(p.turns[1]!.inputId && p.turns[2]!.inputId);
  assert.deepEqual(rows(p).map((r) => r.row), ["reply", "reply"], "each turn's last AI message is its reply");

  const bare = paired([prompt("hi", "hello")]);
  assert.equal(bare.turns.length, 1, "no setup turn when nothing preceded the prompt");
});

test("reply vs note: only the LAST AI message of a turn is the reply; a compaction summary is an aside", () => {
  const p = paired([
    prompt("do it", "I'll read the file first."),
    ev({ kind: "tllm_call", input: repr("▸ user\ndo it"), output: repr("<analysis>\nlong recap\n</analysis>\n<summary>\nrecap\n</summary>") }),
    ev({ kind: "tllm_call", input: repr("▸ user\ndo it"), output: repr("Done.") }),
  ]);
  assert.deepEqual(rows(p).map((r) => r.row), ["note", "aside", "reply"]);
  const aside = rows(p).find((r) => r.row === "aside") as { chars: number };
  assert.ok(aside.chars > 20);
});

test("a masked result: the row carries the local deep original; a trusted one is 'same on both sides'", () => {
  const INNER = "$MDU:Read[d9ce].notes.md";
  const TWIN = `1\t${INNER}\n2\t`;
  const p = paired([
    // fs-sync birth (before the prompt): the inner original is in the session.
    ev({ kind: "symbolize", turn: 0, emitter: "fs-sync", callId: null, boundary: "filesystem",
      output: repr(INNER, "TODO: ship it", [{ name: INNER, tool: "Read", field: "notes.md", origin: "/ws/notes.md", value: "TODO: ship it" }]) }),
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/ws/agentview/notes.md"})') }),
    ev({ kind: "tool_result", callId: "c1", policy: { trust: "UNTRUSTED", reason: "fail-closed" },
      output: repr("$MDU:Read[f435]", TWIN, [{ name: "$MDU:Read[f435]", tool: "Read", field: null, origin: null, value: TWIN }]) }),
    ev({ kind: "tool_use", callId: "c2", input: repr('Write({"file_path":"/ws/x"})') }),
    ev({ kind: "tool_result", callId: "c2", policy: { trust: "TRUSTED", reason: "schema rule" }, output: repr("File created.", "File created.") }),
    prompt("read notes.md", "Here: $MDU:Read[f435]"),
  ]);
  const setup = rows(p).find((r) => r.row === "setup") as { files: string[] };
  assert.deepEqual(setup.files, ["notes.md"], "the setup row names FILES (the symbol's field), not tokens");
  const [read, write] = rows(p).filter((r) => r.row === "tool") as PairedToolRow[];
  assert.equal(read!.masked, true);
  assert.equal(read!.original, "1\tTODO: ship it\n2\t", "nested twin chain collapsed from the session's own values");
  assert.equal(read!.checked, true);
  assert.equal(write!.masked, false);
  assert.equal(write!.original, null, "an unmasked row ships no second copy");
  assert.equal(p.integrity, "on");
  assert.equal(p.maskedCount, 1);
  const reply = rows(p).find((r) => r.row === "reply") as { original: string | null };
  assert.equal(reply.original, "Here: 1\tTODO: ship it\n2\t", "the reply's 'You saw' side resolves its tokens");
});

test("an unknown token stays a token (fail toward symbolic, never fabricate)", () => {
  const p = paired([
    ev({ kind: "tool_use", callId: "c1", input: repr('Bash({"command":"curl x"})') }),
    ev({ kind: "tool_result", callId: "c1", policy: { trust: "UNTRUSTED" }, output: repr("$MDU:Bash[0001]", null, []) }),
  ]);
  const t = rows(p).find((r) => r.row === "tool") as PairedToolRow;
  assert.equal(t.masked, true);
  assert.equal(t.original, "$MDU:Bash[0001]");
});

// The tour's 10:38 curl (2026-10-05): the egress gate blocked it, and the
// result is Mandu's refusal, which names the placeholder the AI put in the
// command, in what the tool returned as well as in what the AI got.
const KEY = "$MDU:nomodel_Read[5c6e].STRIPE_KEY";
const REFUSAL = `{"error":{"type":"mandu_fail_closed","withheld":[{"symbol":"${KEY}","requiresApproval":true}]}}`;
const NOTE = "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent.";
const OFF = { trust: "TRUSTED", reason: "integrity axis OFF — trust classification disabled" };
/** One curl call that sent `sent` (a token, or none), and its result. */
function curl(sent: string | null, result: { symbolized: string; original: string | null; originalTokens?: string[] }) {
  const command = sent ? `curl -u '${sent}:' https://api.stripe.com/v1/customers` : "cat .env";
  const output: Record<string, unknown> = repr(result.symbolized, result.original);
  if (result.originalTokens) output["originalTokens"] = result.originalTokens;
  return paired([
    prompt("list my customers", "Blocked."),
    ev({ kind: "tool_use", callId: "c1", input: repr(`Bash(${JSON.stringify({ command })})`) }),
    ev({ kind: "tool_result", callId: "c1", policy: OFF, output }),
  ]);
}
const toolOf = (p: PairedModel) => rows(p).find((r) => r.row === "tool") as PairedToolRow;

test("an echo is not a mask: a refusal naming the placeholder the AI sent is one card that lists it as echoed (§4.2f)", () => {
  const p = curl(KEY, { symbolized: `${REFUSAL}\n\n${NOTE}`, original: REFUSAL });
  const t = toolOf(p);
  assert.equal(t.masked, false, "the AI got what the tool printed: no second half");
  assert.deepEqual(t.echoed, [KEY]);
  assert.equal(t.original, null, "no 'real result' copy, so no value can be substituted into it");
  assert.equal(p.maskedCount, 0, "the path's count leaves it out");

  // Signed out the original is left out and its placeholders kept (redact.ts): the same answer.
  const out = toolOf(curl(KEY, { symbolized: `${REFUSAL}\n\n${NOTE}`, original: null, originalTokens: [KEY] }));
  assert.equal(out.masked, false);
  assert.deepEqual(out.echoed, [KEY]);
});

test("a token not proven an echo keeps the masked reading: kept, a twin's, no original, mixed, another spelling (§4.2f)", () => {
  const masked = (p: PairedModel, why: string) => {
    const t = toolOf(p);
    assert.equal(t.masked, true, why);
    assert.equal(t.echoed, undefined, why);
    assert.equal(p.maskedCount, 1, why);
  };
  masked(curl(KEY, { symbolized: KEY, original: "sk_live_real" }), "the real value came back, masked to the same token");
  masked(curl(null, { symbolized: `STRIPE_KEY='${KEY}'`, original: `STRIPE_KEY='${KEY}'` }), "a twin's placeholder: the call never sent it");
  masked(curl(KEY, { symbolized: REFUSAL, original: null }), "no original recorded: as before");
  masked(curl(KEY, { symbolized: `${REFUSAL}\n$MDU:nomodel_Bash[c3c3]`, original: `${REFUSAL}\nAPI_KEY=sk-live` }), "an echo beside a kept token");
  // A spelling only the inspector's wider grammar matches (a hash that is not hex) is never taken for an echo.
  const ODD = "$MDU:nomodel_Read[zz12]";
  masked(curl(ODD, { symbolized: `refused ${ODD}`, original: `refused ${ODD}` }), "an unproven spelling");
});

test("secrets mode: the integrity-OFF reason marks the session and every row unchecked", () => {
  const off = { trust: "TRUSTED", reason: "integrity axis OFF — trust classification disabled" };
  const p = paired([
    ev({ kind: "tool_use", callId: "c1", input: repr('Bash({"command":"git status"})') }),
    ev({ kind: "tool_result", callId: "c1", policy: off, output: repr("master", "master") }),
  ]);
  assert.equal(p.integrity, "off");
  assert.equal((rows(p)[0] as PairedToolRow).checked, false);
  assert.equal(paired([prompt("hi", "hello")]).integrity, "unknown", "no tool results → unknown, never a claim");
});

test("secrets mode: a secret the proxy masked by provenance is unchecked too, and never makes the session integrity-on (§4.2)", () => {
  // The tour's 10:42 Read (2026-10-05): the anthropic-proxy records the
  // arbiter's integrity-OFF reason behind its provenance prefix. The row
  // drew a green TRUSTED and, with no recorded mode, the session read as
  // integrity-on ("untrusted results reached the AI only as masked tokens").
  const TOK = "$MDU:nomodel_Read[aa74]";
  const provenance = { trust: "TRUSTED", reason: "secret content (no-model) symbolized by provenance: integrity axis OFF — trust classification disabled", confidentiality: "no-model" };
  const read = (callId: string, policy: unknown) => [
    ev({ kind: "tool_use", callId, input: repr('Read({"file_path":"/w/deploy/staging.conf"})') }),
    ev({ kind: "tool_result", callId, policy, output: repr(TOK, 'token = "ghp_x"', [{ name: TOK, tool: "Read", field: null, origin: "/w/deploy/staging.conf" }]) }),
  ];
  const alone = paired(read("c1", provenance));
  assert.equal(toolOf(alone).masked, true);
  assert.equal(toolOf(alone).checked, false, "masked as a secret, never judged: not TRUSTED");
  assert.equal(alone.integrity, "off", "no recorded mode: a masked secret does not make the session integrity-on");
  // The tour's order: plain integrity-OFF results first, then the masked one.
  const tour = paired([
    ev({ kind: "tool_use", callId: "c0", input: repr('Bash({"command":"git status"})') }),
    ev({ kind: "tool_result", callId: "c0", policy: OFF, output: repr("master", "master") }),
    ...read("c1", provenance),
  ]);
  assert.equal(tour.integrity, "off");
  assert.deepEqual(rows(tour).filter((r) => r.row === "tool").map((r) => (r as PairedToolRow).checked), [false, false]);
  // Only that prefix: a reason that merely mentions the phrase is a classification.
  for (const reason of [
    "trusted command; integrity axis OFF was not consulted",
    "origin rule: secret content (no-model) symbolized by provenance: integrity axis OFF",
  ]) {
    const p = paired(read("c2", { trust: "TRUSTED", reason }));
    assert.equal(toolOf(p).checked, true, reason);
    assert.equal(p.integrity, "on", reason);
  }
});

test("recorded protection: the launcher's posture event decides the mode; inference is only the fallback", () => {
  const posture = (protection: unknown) =>
    ev({ kind: "launch_posture", turn: 0, view: "HumanView", boundary: "shell", emitter: "launcher", protection });
  const classified = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Bash({"command":"git status"})') }),
    ev({ kind: "tool_result", callId: "c1", policy: { trust: "TRUSTED", reason: "trusted command" }, output: repr("master", "master") }),
  ];
  // Recorded secrets mode wins over a classified result (which would infer "on").
  const rec = paired([posture({ mode: "secrets", integrity: false, confidentiality: true, reported: true }), ...classified]);
  assert.equal(rec.integrity, "off");
  assert.equal(rec.mode, "secrets");
  // Even with no tool results, a recorded mode is a statement, not "unknown".
  const quiet = paired([posture({ mode: "full", integrity: true, confidentiality: true, reported: true }), prompt("hi", "hello")]);
  assert.equal(quiet.integrity, "on");
  assert.equal(quiet.mode, "full");
  // Not reported by the arbiter, malformed, or absent → inferred, mode null.
  for (const p of [
    paired([posture({ mode: "secrets", integrity: false, confidentiality: true, reported: false }), ...classified]),
    paired([posture({ mode: "bogus", integrity: false, reported: true }), ...classified]),
    paired([posture(undefined), ...classified]),
    paired(classified),
  ]) {
    assert.equal(p.integrity, "on");
    assert.equal(p.mode, null);
  }
});

test("a Codex exchange (openai-proxy transcript, 2026-09-26): the typed prompt opens the turn and the answer is its reply", () => {
  const SYM = "$MDU:exec_command[a1b2]";
  const codex = (over: Record<string, unknown>) => ev({ emitter: "openai-proxy", callShape: { toolCount: 3, maxTokens: null, userMessages: 3 }, ...over });
  const ctx = "▸ system\n[Mandu IPI handling prompt]\nYou are Codex.\n\n▸ system\n<environment_context>\n  <cwd>/ws</cwd>\n</environment_context>\n\n▸ user\nSummarize notes.md";
  const p = paired([
    codex({ kind: "tllm_call", input: repr(ctx), output: repr('→ exec_command({"cmd":"cat notes.md"})') }),
    codex({ kind: "tool_use", callId: "call_1", input: repr('exec_command({"cmd":"cat notes.md"})') }),
    // The proxy numbers turns per exchange: the result rides the NEXT request.
    codex({ kind: "tool_result", turn: 2, callId: "call_1", policy: { trust: "UNTRUSTED", reason: "fail-closed" },
      output: repr(SYM, "buy milk", [{ name: SYM, tool: "exec_command", field: null, origin: "cat notes.md", value: "buy milk" }]) }),
    codex({ kind: "tllm_call", turn: 2, input: repr(`${ctx}\n\n▸ assistant\n→ exec_command({"cmd":"cat notes.md"})\n\n▸ user\n[tool_result call_1]\n${SYM}`),
      output: repr(`The notes say: ${SYM}`) }),
  ]);
  const turn = p.turns.find((t) => t.inputId !== null);
  assert.ok(turn, "the typed prompt opens a turn (the context blocks do not)");
  assert.equal(p.turns.filter((t) => t.inputId !== null).length, 1);
  assert.deepEqual(turn!.rows.map((r) => r.row), ["tool", "reply"]);
  const reply = turn!.rows.find((r) => r.row === "reply") as { original: string | null };
  assert.equal(reply.original, "The notes say: buy milk");
});

test("background fold: bookkeeping folds per turn; decisions stay inline", () => {
  const p = paired([
    prompt("go", "ok"),
    ev({ kind: "net_action", turn: 0, action: "tunneled", destination: "mcp-proxy.anthropic.com:443" }),
    ev({ kind: "net_action", turn: 0, action: "forwarded", destination: "example.test" }),
    ev({ kind: "net_action", turn: 0, action: "blocked", destination: "evil.example", policy: { usage: "deny" } }),
    ev({ kind: "path_rewrite", rewrite: { direction: "reverse", tool: null, field: null, human: "/h", agent: "/a" } }),
    ev({ kind: "desymbolize", turn: 0, emitter: "reply-filter", input: repr("$MDU:Read[1]") }),
    ev({ kind: "exec_action", callId: "zz", boundary: "shell", policy: { usage: "allow" } }),
    ev({ kind: "exec_action", callId: "zy", boundary: "shell", policy: { usage: "deny" } }),
    ev({ kind: "ullm_call", view: "Quarantine", emitter: "inspect-mcp" }),
  ]);
  const t = p.turns[p.turns.length - 1]!;
  const cats = Object.fromEntries(t.background.map((b) => [b.category, b]));
  assert.equal(cats["connections"]!.count, 2, "allowed connections fold");
  assert.deepEqual(cats["connections"]!.labels, ["mcp-proxy.anthropic.com", "example.test"]);
  assert.equal(cats["paths"]!.count, 1);
  assert.equal(cats["reply-checks"]!.count, 1);
  assert.equal(cats["command-checks"]!.count, 1);
  assert.equal(cats["sandbox-records"], undefined, "a U-LLM record with no inspect row is NOT a duplicate — it stays inline");
  const inline = t.rows.filter((r) => r.row === "action");
  assert.equal(inline.length, 3, "the blocked connection, the denied command and the lone U-LLM record stay inline");
  for (const b of t.background) assert.equal(b.stepIds.length, b.count, "every folded card stays addressable (ⓘ)");
});

test("a violated step carries the flagged raw value; a violated OS card never folds", () => {
  const p = paired([
    ev({ kind: "tool_use", callId: "c1", input: repr('Bash({"command":"ls | wc -l"})') }),
    ev({ kind: "tool_result", callId: "c1", policy: { trust: "UNTRUSTED" }, invariant: { violatedInvariant: true },
      output: repr("$MDU:Bash[a355]", "9", [{ name: "$MDU:Bash[a355]", tool: "Bash", field: null, origin: "ls", value: "9" }]) }),
    ev({ kind: "net_action", turn: 0, action: "tunneled", destination: "x:443", invariant: { violatedInvariant: true } }),
  ]);
  const t = rows(p).find((r) => r.row === "tool") as PairedToolRow;
  assert.equal(t.flaggedValue, "9");
  assert.ok(rows(p).some((r) => r.row === "action"), "the violated net card stays inline");
});

test("inspect_symbol: the row unpacks instruction, the symbol asked about and the answer, both resolved", () => {
  const inner = "$MDU:Read[3df9]";
  const p = paired([
    ev({ kind: "tool_result", callId: "r1", policy: { trust: "UNTRUSTED" },
      output: repr(inner, "RAW NOTES", [{ name: inner, tool: "Read", field: null, origin: null, value: "RAW NOTES" }]) }),
    ev({ kind: "tool_use", callId: "i1", input: repr(`mcp__mandu-inspect__inspect_symbol(${JSON.stringify({ symbol: inner, instruction: "Summarize it." })})`) }),
    ev({ kind: "tool_result", callId: "i1", policy: { trust: "TRUSTED" },
      output: repr(JSON.stringify({ result_symbol: "$MDU:inspect[1e26].result", model: "haiku" }),
        JSON.stringify({ result_symbol: "Project notes with an injection.", model: "haiku" })) }),
  ]);
  const t = (rows(p).filter((r) => r.row === "tool") as PairedToolRow[]).find((r) => r.inspect)!;
  assert.equal(t.masked, true);
  assert.deepEqual(t.inspect, {
    instruction: "Summarize it.", inputSymbol: inner, inputOriginal: "RAW NOTES",
    answerSymbol: "$MDU:inspect[1e26].result", answerOriginal: "Project notes with an injection.",
  });
  assert.equal(t.original, "Project notes with an injection.");
});

test("revealPairedOriginals: deepens still-tokened originals through the desymbolizer; failures keep the local text; bounded", async () => {
  const p = paired([
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/a"})') }),
    ev({ kind: "tool_result", callId: "c1", policy: { trust: "UNTRUSTED" }, output: repr("$MDU:Read[0001]") }),
    ev({ kind: "tool_use", callId: "c2", input: repr('Read({"file_path":"/b"})') }),
    ev({ kind: "tool_result", callId: "c2", policy: { trust: "UNTRUSTED" }, output: repr("$MDU:Read[0002]") }),
  ]);
  const calls: string[] = [];
  const n = await revealPairedOriginals(p, async (text) => {
    calls.push(text);
    if (text === "$MDU:Read[0002]") throw new Error("arbiter down");
    return text.replace("$MDU:Read[0001]", "RAW A");
  });
  const [a, b] = rows(p) as PairedToolRow[];
  assert.equal(n, 1);
  assert.equal(a!.original, "RAW A");
  assert.equal(b!.original, "$MDU:Read[0002]", "a failed resolve keeps the token (utility-only)");
  assert.equal(calls.length, 2);
  assert.equal(await revealPairedOriginals(p, undefined), 0, "no arbiter → no-op");

  const q = paired([
    ev({ kind: "tool_use", callId: "c3", input: repr('Read({"file_path":"/c"})') }),
    ev({ kind: "tool_result", callId: "c3", policy: { trust: "UNTRUSTED" }, output: repr("$MDU:Read[0003]") }),
    ev({ kind: "tool_use", callId: "c4", input: repr('Read({"file_path":"/d"})') }),
    ev({ kind: "tool_result", callId: "c4", policy: { trust: "UNTRUSTED" }, output: repr("$MDU:Read[0004]") }),
  ]);
  let used = 0;
  await revealPairedOriginals(q, async (t) => { used++; return t + "!"; }, 1);
  assert.equal(used, 1, "the budget caps round trips");
});

test("the OS fold never merges different decisions: an allowed then a denied command stay two cards", () => {
  const vm = toSessionViewModel("s", [
    ev({ kind: "exec_action", callId: "a1", boundary: "shell", policy: { usage: "allow" } }),
    ev({ kind: "exec_action", callId: "a2", boundary: "shell", policy: { usage: "deny" } }),
    ev({ kind: "exec_action", callId: "a3", boundary: "shell", policy: { usage: "deny" } }),
  ] as never);
  const os = vm.dualLanes.steps.filter((s) => s.step === "os") as Array<{ usage: string | null; repeats: number }>;
  assert.deepEqual(os.map((s) => [s.usage, s.repeats]), [["allow", 1], ["deny", 2]], "identical denials still fold; allow ≠ deny");
});

// ── plan 11 D6: which model read the datum (the ullm_call's `endpoint`) ─────

function inspectSession(ullm: Record<string, unknown> | null): PairedToolRow {
  const inner = "$MDU:localmodel_Read[3df9]";
  const answer = "$MDU:localmodel_inspect[1e26].result";
  const events = [
    ev({ kind: "tool_result", callId: "r1", policy: { trust: "UNTRUSTED" },
      output: repr(inner, "THE CONTRACT", [{ name: inner, tool: "Read", field: null, origin: null, value: "THE CONTRACT" }]) }),
    ev({ kind: "tool_use", callId: "i1", input: repr(`mcp__mandu-inspect__inspect_symbol(${JSON.stringify({ symbol: inner, instruction: "Summarize it." })})`) }),
    // inspect-mcp emits its ullm_call with callId null: the endpoint is
    // joined to the inspect row by the answer token.
    ...(ullm ? [ev({ kind: "ullm_call", view: "Quarantine", emitter: "inspect-mcp", input: repr(inner, "THE CONTRACT"), output: repr(answer, "A short summary."), ...ullm })] : []),
    ev({ kind: "tool_result", callId: "i1", policy: { trust: "TRUSTED" },
      output: repr(JSON.stringify({ result_symbol: answer }), JSON.stringify({ result_symbol: "A short summary." })) }),
  ];
  return (rows(paired(events)).filter((r) => r.row === "tool") as PairedToolRow[]).find((r) => r.inspect)!;
}

test("plan 11 D6: an inspect row names the model that read it: your own model, or the helper", () => {
  const local = inspectSession({ endpoint: { name: "ollama", location: "local" } });
  assert.deepEqual(local.inspect!.readBy, { name: "ollama", location: "local" });
  assert.equal(local.inspect!.readByWords, "read by your own model (ollama)");
  const helper = inspectSession({ endpoint: { name: "default", location: "external" } });
  assert.equal(helper.inspect!.readByWords, "read by the helper");
});

test("plan 11 D6: an inspect event without `endpoint` (an older inspect-mcp) renders exactly as before", () => {
  for (const r of [inspectSession({}), inspectSession(null)]) {
    assert.equal("readBy" in r.inspect!, false);
    assert.equal("readByWords" in r.inspect!, false);
    assert.equal(r.inspect!.answerOriginal, "A short summary.");
  }
});

// ── The sandboxed reader's card: every shape an agent forwards (inspect-answer.ts) ──

/** One reader call: the AI's result `agent`, the original `human`, under `tool`. */
function readerRow(agent: string, human: string | null = agent, tool = "mcp__mandu-inspect__inspect_symbol", ullm = false): PairedToolRow | undefined {
  const inner = "$MDU:Read[3df9]";
  const answer = "$MDU:inspect[1e26].result";
  const events = [
    ev({ kind: "tool_result", callId: "r1", policy: { trust: "UNTRUSTED" },
      output: repr(inner, "RAW NOTES", [{ name: inner, tool: "Read", field: null, origin: null, value: "RAW NOTES" }]) }),
    ev({ kind: "tool_use", callId: "i1", input: repr(`${tool}(${JSON.stringify({ symbol: inner, instruction: "Summarize it." })})`) }),
    // A record no correlation attaches to the call (its callId is no call's,
    // its input not the bare symbol): only the answer token joins its model.
    ...(ullm ? [ev({ kind: "ullm_call", view: "Quarantine", emitter: "inspect-mcp", callId: "elsewhere", input: repr(`Summarize it.\n${inner}`, "RAW NOTES"), output: repr(answer, "A short summary."), endpoint: { name: "ollama", location: "local" } })] : []),
    ev({ kind: "tool_result", callId: "i1", policy: { trust: "TRUSTED" }, output: repr(agent, human) }),
  ];
  return (rows(paired(events)).filter((r) => r.row === "tool") as PairedToolRow[]).find((r) => r.stepId.endsWith("i1"));
}

test("inspect_symbol: every shape the arbiter keeps draws the reader's card, and what came after the answer stays on the AI's side", () => {
  const A = "$MDU:inspect[1e26].result";
  const env = JSON.stringify({ result_symbol: A, model: "claude-haiku-4-5", content_kind: "as_requested" });
  const budget = "<system-reminder>\n<total_tokens>91234 tokens left</total_tokens>\n</system-reminder>";
  const shapes: Array<[string, string, string | undefined]> = [
    ["the envelope", env, undefined],
    ["the bare token (the MCP content text)", A, undefined],
    ["the token, then the envelope", `${A}${env}`, undefined],
    ["the envelope, then a kept reminder", `${env}\n\n${budget}`, budget],
    ["the envelope, then a masked reminder (a live session's shape)", `${env}\n\n\n\n$MDU:inspect[5a3a]`, "$MDU:inspect[5a3a]"],
  ];
  for (const [what, agent, tail] of shapes) {
    const r = readerRow(agent)!;
    assert.equal(r.masked, true, what);
    assert.equal(r.inspect?.answerSymbol, A, what);
    assert.equal(r.inspect?.instruction, "Summarize it.", what);
    assert.equal(r.inspect?.inputOriginal, "RAW NOTES", what);
    assert.equal(r.inspect?.tail, tail, what);
    assert.equal("tail" in r.inspect!, tail !== undefined, `${what}: no tail key without a tail`);
  }
  // The original side's envelope holds the answer itself, behind its own tail.
  const r = readerRow(`${env}\n\n${budget}`, `${JSON.stringify({ result_symbol: "A short summary." })}\n\n${budget}`)!;
  assert.equal(r.inspect?.answerOriginal, "A short summary.");
  assert.equal(r.original, "A short summary.");
});

test("inspect_symbol: OpenCode's spelling draws the reader's card; another name, an error or prose does not", () => {
  const env = JSON.stringify({ result_symbol: "$MDU:inspect[1e26].result" });
  for (const tool of ["mandu-inspect_inspect_symbol", "mcp__mandu_inspect__inspect_symbol", "mandu-inspect__inspect_symbol", "inspect_symbol"]) {
    assert.equal(readerRow(env, env, tool)?.inspect?.answerSymbol, "$MDU:inspect[1e26].result", tool);
  }
  assert.equal(readerRow(env, env, "other_inspect_symbol")?.inspect, null, "another server's tool of a like name");
  for (const agent of ["inspect_symbol: unknown symbol $MDU:Read[3df9]", "$MDU:inspect[5a3a]", `Here: ${env}`]) {
    const r = readerRow(agent)!;
    assert.equal(r.inspect?.answerSymbol, null, agent);
    assert.equal(r.masked, false, `${agent}: drawn as before`);
  }
});

test("plan 11 D6: the reader's model is joined by the answer token whatever shape carried it, under any of Mandu's spellings", () => {
  const A = "$MDU:inspect[1e26].result";
  for (const agent of [`${JSON.stringify({ result_symbol: A })}\n\n\n\n$MDU:inspect[5a3a]`, A, `${A}${JSON.stringify({ result_symbol: A })}`]) {
    for (const tool of ["mcp__mandu-inspect__inspect_symbol", "mandu-inspect_inspect_symbol"]) {
      const r = readerRow(agent, agent, tool, true)!;
      assert.deepEqual(r.inspect?.readBy, { name: "ollama", location: "local" }, `${tool}: ${agent}`);
      assert.equal(r.inspect?.readByWords, "read by your own model (ollama)", `${tool}: ${agent}`);
    }
  }
});
