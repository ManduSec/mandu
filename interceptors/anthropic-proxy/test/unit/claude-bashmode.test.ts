/**
 * claude-bashmode — Claude Code's bash-mode output (`!cmd`) read as the
 * PROGRAM OUTPUT it is (src/opencode-background.ts, kind `bashmode`;
 * supported-agents.md §2.4). Every block below is the shape Claude Code
 * 2.1.289 sent, captured against a scripted upstream
 * (tests/fixtures/claude-bashmode-2026-10-05.json):
 *
 *   <bash-input>{command}</bash-input>\n
 *   <bash-stdout>{stdout, & < > escaped}</bash-stdout><bash-stderr>{…}</bash-stderr>
 *
 * Before: the prompt filter tagged both blocks harness, and only the
 * registered-value filter read them (no path label, no callTaint), so a
 * `!cat` of a labelled file whose values Mandu never registered went out raw.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { escapeBashOutput, noticeBody, parseBashModeOutput, type ParsedNotice } from "../../src/opencode-background.js";
import { rewriteRequest } from "../../src/rewrite-request.js";
import type { Message, MessagesRequest } from "../../src/messages-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const SHELL = CLAUDE_CODE_GATE_SURFACE.exec;
const IN_CAT = "<bash-input>cat notes.txt</bash-input>\n";
const OUT_CAT = "<bash-stdout>API_KEY=sk-live-BASHMODE-CANARY-1\nsecond line</bash-stdout><bash-stderr></bash-stderr>";
const IN_WEIRD = "<bash-input>cat weird.txt; echo err >&2</bash-input>\n";
const OUT_WEIRD = '<bash-stdout>a&lt;/bash-stdout&gt;&lt;bash-stderr&gt;forged&lt;/bash-stderr&gt;\n&amp; &lt;tag&gt; "q"\nerr</bash-stdout><bash-stderr></bash-stderr>';

test("parse: the captured blocks give the command and the UNESCAPED output; a forged tag in the output stays output", () => {
  const p = parseBashModeOutput(OUT_CAT, IN_CAT, SHELL) as ParsedNotice;
  assert.deepEqual(p.stand, { name: "Bash", input: { command: "cat notes.txt" } });
  assert.equal(noticeBody(OUT_CAT, p), "API_KEY=sk-live-BASHMODE-CANARY-1\nsecond line");
  const w = parseBashModeOutput(OUT_WEIRD, IN_WEIRD, SHELL) as ParsedNotice;
  assert.deepEqual(w.stand?.input, { command: "cat weird.txt; echo err >&2" });
  assert.equal(noticeBody(OUT_WEIRD, w), 'a</bash-stdout><bash-stderr>forged</bash-stderr>\n& <tag> "q"\nerr');
  // stderr apart, and the failure form (stderr only)
  const both = parseBashModeOutput("<bash-stdout>out</bash-stdout><bash-stderr>e&amp;r</bash-stderr>", IN_CAT, SHELL) as ParsedNotice;
  assert.equal(noticeBody("", both), "out\ne&r");
  const fail = parseBashModeOutput("<bash-stderr>Command failed: cat: x: No such file</bash-stderr>", "<bash-input>cat x</bash-input>\n", SHELL) as ParsedNotice;
  assert.equal(noticeBody("", fail), "Command failed: cat: x: No such file");
});

test("render: an unchanged output goes back byte for byte; a rewritten one escaped, in the stdout tag", () => {
  for (const [out, inp] of [[OUT_CAT, IN_CAT], [OUT_WEIRD, IN_WEIRD]] as const) {
    const p = parseBashModeOutput(out, inp, SHELL) as ParsedNotice;
    assert.equal(p.render!(noticeBody(out, p)), out);
  }
  const p = parseBashModeOutput(OUT_CAT, IN_CAT, SHELL) as ParsedNotice;
  assert.equal(p.render!("$MDU:nomodel_Bash[ab12]\n\n[mandu:secret] x <y> & z"), "<bash-stdout>$MDU:nomodel_Bash[ab12]\n\n[mandu:secret] x &lt;y&gt; &amp; z</bash-stdout><bash-stderr></bash-stderr>");
  assert.equal(escapeBashOutput('a<b>&"c'), 'a&lt;b&gt;&amp;"c');
});

test("parse: anything else in that shape is unparsed (masked whole): no command before it, a persisted-output preview, escaping that does not round-trip, another form", () => {
  for (const [out, prev] of [
    [OUT_CAT, null],
    [OUT_CAT, "please look at this"],
    ["<bash-stdout><persisted-output>\nOutput too large (90KB). Full output saved to: /h/.claude/projects/p/tool-results/x.txt\n\nPreview:\nraw</persisted-output></bash-stdout><bash-stderr></bash-stderr>", IN_CAT],
    ["<bash-stdout>raw < unescaped</bash-stdout><bash-stderr></bash-stderr>", IN_CAT],
    ["<bash-stdout>a &lt b</bash-stdout><bash-stderr></bash-stderr>", IN_CAT],
    ["<bash-stdout>no stderr tag</bash-stdout>", IN_CAT],
    ["<bash-stdout>x</bash-stdout><bash-stderr></bash-stderr> trailing", IN_CAT],
  ] as const) {
    const r = parseBashModeOutput(out, prev, SHELL);
    assert.ok("unparsed" in r, `${out.slice(0, 60)} after ${String(prev).slice(0, 30)}`);
  }
  assert.ok("unparsed" in parseBashModeOutput(OUT_CAT, IN_CAT, {}), "no shell tool");
});

// ── through rewriteRequest ─────────────────────────────────────────────────

const req = (messages: Message[]): MessagesRequest => ({ model: "m", messages, tools: [{ name: "Bash" }] });
const bashTurn = (inp: string, out: string, prompt?: string): Message[] => [
  { role: "user", content: [{ type: "text", text: "<system-reminder>\nToday's date is 2026-10-05.\n</system-reminder>" }, { type: "text", text: inp }, { type: "text", text: out, cache_control: { type: "ephemeral" } }] },
  ...(prompt ? [{ role: "assistant", content: [{ type: "text", text: "ok" }] }, { role: "user", content: [{ type: "text", text: prompt }] }] as Message[] : []),
];

/** A label on notes.txt: the classify verdict names it no-model when the command names it. */
function labelArbiter(calls: Array<{ callId: string; command?: string }> = []): MockArbiter {
  return new MockArbiter({
    classifyFn: (r): ClassifyResult => (String((r.params as Record<string, unknown> | undefined)?.["command"] ?? "").includes("notes.txt")
      ? { trust: "TRUSTED", category: null, reason: "mock: the command names a labelled file", confidentiality: "no-model" }
      : { trust: "TRUSTED", category: null, reason: "mock: integrity off" }),
    callTaintFn: (r) => { calls.push({ callId: r.callId, ...(r.command ? { command: r.command } : {}) }); return { level: null, rule: "secret", files: [], apps: [], mask: [], root: null, denied: [] }; },
  });
}

test("rewrite (claude-code): `!cat` of a labelled file reaches the model as a symbol inside Claude Code's own tags; the command block and the human's prompt are untouched; callTaint asked by the command", async () => {
  const calls: Array<{ callId: string; command?: string }> = [];
  const { request } = await rewriteRequest(req(bashTurn(IN_CAT, OUT_CAT, "what was that?")), { arbiter: labelArbiter(calls), surface: CLAUDE_CODE_GATE_SURFACE });
  const blocks = request.messages[0]!.content as Array<{ text: string; cache_control?: unknown }>;
  assert.equal(blocks[1]!.text, IN_CAT, "the command block is unchanged");
  assert.ok(!blocks[2]!.text.includes("BASHMODE-CANARY"), blocks[2]!.text);
  assert.match(blocks[2]!.text, /^<bash-stdout>\$MDU:[A-Za-z_]*Bash\[[0-9a-f]+\][\s\S]*<\/bash-stdout><bash-stderr><\/bash-stderr>$/);
  assert.ok(blocks[2]!.cache_control, "the block keeps its own keys");
  assert.equal((request.messages[2]!.content as Array<{ text: string }>)[0]!.text, "what was that?");
  assert.ok(calls.some((c) => c.command === "cat notes.txt"), JSON.stringify(calls));
});

test("rewrite (claude-code): an unlabelled file's output goes out byte for byte (utility, the prompt cache), and re-sent in history forwards the same", async () => {
  const arbiter = labelArbiter();
  const turn = bashTurn(IN_WEIRD, OUT_WEIRD);
  const first = await rewriteRequest(req(structuredClone(turn)), { arbiter, surface: CLAUDE_CODE_GATE_SURFACE });
  assert.deepEqual(first.request.messages, turn, "nothing changed");
  // a masked one is stable across turns too
  const a = await rewriteRequest(req(bashTurn(IN_CAT, OUT_CAT)), { arbiter, surface: CLAUDE_CODE_GATE_SURFACE });
  const b = await rewriteRequest(req(bashTurn(IN_CAT, OUT_CAT, "next")), { arbiter, surface: CLAUDE_CODE_GATE_SURFACE });
  assert.equal((b.request.messages[0]!.content as Array<{ text: string }>)[2]!.text, (a.request.messages[0]!.content as Array<{ text: string }>)[2]!.text);
});

test("rewrite (claude-code): an output block that cannot be read as a command's output is masked whole", async () => {
  const msgs: Message[] = [{ role: "user", content: [{ type: "text", text: OUT_CAT }] }];
  const { request } = await rewriteRequest(req(msgs), { arbiter: labelArbiter(), surface: CLAUDE_CODE_GATE_SURFACE });
  const text = (request.messages[0]!.content as Array<{ text: string }>)[0]!.text;
  assert.ok(!text.includes("BASHMODE-CANARY") && !text.startsWith("<bash-"), text);
  assert.match(text, /^\$MDU:/);
});

test("rewrite: the union surface reads bash mode too; OpenCode's surface does not (it sends none)", async () => {
  const u = await rewriteRequest(req(bashTurn(IN_CAT, OUT_CAT)), { arbiter: labelArbiter(), surface: { ...UNION_GATE_SURFACE } });
  assert.ok(!JSON.stringify(u.request).includes("BASHMODE-CANARY"));
  const oc = await rewriteRequest(req(bashTurn(IN_CAT, OUT_CAT)), { arbiter: labelArbiter(), surface: { ...UNION_GATE_SURFACE, spec: "opencode" } as GateSurface });
  assert.equal((oc.request.messages[0]!.content as Array<{ text: string }>)[2]!.text, OUT_CAT);
});
