/**
 * dual-lanes-gate-order.test.ts — a context proxy's check on a tool call is
 * a line on that call's card, whatever order the two were recorded in
 * (dashboard.md §4.2f *A check says what Mandu decided*).
 *
 * The anthropic-proxy decides its exec and net gates in its tool-input
 * transform, ahead of the sniffer that records the call (proxy.ts
 * streamAndSniffSse, the JSON and OpenAI-wire twins), so each gate is
 * recorded just BEFORE its `tool_use`. `toDualLanes` joined a gate to its
 * call only once the `tool_use` had been seen, so in every real Claude Code
 * session the check was an uncorrelated card: folded into Background as a
 * command check "with no tool call" when it allowed the command, a second
 * card beside an unblocked-looking call when it blocked it, and the
 * inspector's path read "no check recorded".
 *
 * Pins, over the events as the proxy records them:
 * - an allowed, a blocked and a held exec gate, and a net gate, recorded
 *   before the call, are lines on the call's card (kind, usage, the Approvals
 *   id), with no card of their own and no Background group;
 * - the same steps as when the gate is recorded after the call;
 * - the product page: a blocked command is ONE blocked step, and the turn's
 *   background line counts no command the agent ran itself;
 * - a call with several checks: each decision is a line, and any block
 *   blocks the call (never "allowed" because the allow came first);
 * - a gate whose call the session never recorded, and one with an empty
 *   call id (the openai-proxy's), stay cards of their own, as before;
 * - a real Claude Code recording (fixtures/live): every proxy exec gate is
 *   on its Bash card;
 * - a net check keeps the destination it recorded (`DualGate.target`), so
 *   the session page names the host of a fetch the proxy rewrote to its
 *   reserved host, and says a command it rewrote was stopped (dashboard.md
 *   §4.25b *A call Mandu rewrote reads as what it stopped*).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { toDualLanes, toSessionViewModel } from "../../../src/view-model.js";
import { buildStory, storyCounts } from "../../../src/view-model/agent-page.js";
import { sessionCounts } from "../../../src/view-model/session-counts.js";
import type { ManduEvent } from "../../../src/event-model.js";
import type { DualStep } from "../../../src/view-model/dual-lanes-types.js";

let seq = 0;
function ev(over: Record<string, unknown>): ManduEvent {
  seq++;
  return {
    id: "g" + seq, sessionId: "s", seq, turn: 0, ts: `2026-10-07T04:30:${String(seq).padStart(2, "0")}.000Z`,
    callId: null, parentId: null, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, invariant: { violatedInvariant: false }, ...over,
  } as unknown as ManduEvent;
}
const repr = (symbolized: string, original: string | null = null, symbols: unknown[] = []) =>
  ({ symbolized, original, differs: original !== null && original !== symbolized, symbols });
const bash = (command: string) => `Bash(${JSON.stringify({ command })})`;

const SECRET = "$MDU:nomodel_Env[ab12].GITHUB_TOKEN";

/** The proxy's exec gate (events.ts makeExecGate). */
const execGate = (callId: string, decision: "allow" | "deny" | "needs_approval", extra: Record<string, unknown> = {}) =>
  ev({
    kind: "exec_action", callId, boundary: "shell", input: repr("Bash.command"),
    output: repr(decision === "allow" ? "ALLOW (AgentShell)" : decision === "deny" ? "BLOCKED → exit 77" : "HELD → waiting for your answer"),
    policy: {
      usage: decision, reason: decision === "allow" ? "no symbol in command position; allowed" : "a secret's placeholder in command position", shell: "AgentShell",
      ruleRef: { source: "rule", id: decision === "allow" ? "exec:no-symbol-in-command" : "exec:symbol-in-command" },
    },
    ...extra,
  });
/** The proxy's net gate on a web tool (events.ts makeNetGate). */
const netGate = (callId: string, decision: "allow" | "deny") =>
  ev({
    kind: "net_action", callId, boundary: "network", input: repr("WebFetch → docs.example.com"),
    output: repr(decision === "allow" ? "ALLOW (docs.example.com)" : "BLOCKED → denied"),
    policy: { usage: decision, reason: decision === "allow" ? "no secret in the request" : "a secret in the request" },
  });
const prompt = (text: string, out: string) => ev({ kind: "tllm_call", input: repr(`▸ user\n${text}`), output: repr(out) });
const call = (callId: string, input: string) => ev({ kind: "tool_use", callId, input: repr(input) });
const result = (callId: string, output: string) =>
  ev({ kind: "tool_result", callId, output: repr(output), policy: { trust: "TRUSTED", reason: "integrity axis OFF: results are not classified" } });

const tools = (steps: DualStep[]) => steps.filter((s): s is Extract<DualStep, { step: "tool" }> => s.step === "tool");
const oses = (steps: DualStep[]) => steps.filter((s) => s.step === "os");
const shape = (steps: DualStep[]) => steps.map((s) =>
  s.step === "tool" ? `tool:${s.tool}[${s.gates.map((g) => `${g.kind}:${g.usage}`).join(",")}]` : `${s.step}${s.step === "os" ? ":" + s.kind : ""}`);

test("an allowed exec gate recorded before its Bash call is a line on the Bash card, with no card or Background group of its own", () => {
  const events = [
    prompt("list the files", "→ " + bash("ls")),
    execGate("c1", "allow"),
    ev({ kind: "tool_surface", view: "HumanView" }),
    call("c1", bash("ls")),
    result("c1", "a.txt\nb.txt"),
    ev({ kind: "tllm_call", input: repr("▸ user\nlist the files"), output: repr("Two files.") }),
  ];
  const steps = toDualLanes(events).steps;
  assert.equal(oses(steps).length, 0, `no uncorrelated card: ${shape(steps).join(" ")}`);
  const [bashStep] = tools(steps);
  assert.ok(bashStep);
  assert.equal(bashStep!.tool, "Bash");
  assert.deepEqual(bashStep!.gates.map((g) => [g.kind, g.usage, g.ruleRef?.id ?? null]), [["exec_action", "allow", "exec:no-symbol-in-command"]]);
  assert.equal(bashStep!.usage, "allow");
  assert.equal(bashStep!.ts, events[1]!.ts, "the card starts at its first record, the gate");

  const vm = toSessionViewModel("s", events);
  for (const turn of vm.paired.turns) {
    assert.deepEqual(turn.background.map((b) => b.category), [], "the call's own check is not Background");
  }
  // The product page's background line counts no command the agent ran itself.
  const story = buildStory(vm);
  for (const turn of story) assert.ok(!JSON.stringify(turn.routine ?? null).includes("Mandu checked"), JSON.stringify(turn.routine));
});

test("the steps are the same whichever of the gate and its call was recorded first", () => {
  const before = toDualLanes([prompt("go", "→ " + bash("ls")), execGate("o1", "allow"), call("o1", bash("ls")), result("o1", "ok")]);
  const after = toDualLanes([prompt("go", "→ " + bash("ls")), call("o1", bash("ls")), execGate("o1", "allow"), result("o1", "ok")]);
  assert.deepEqual(shape(before.steps), shape(after.steps));
  assert.ok(shape(before.steps).includes("tool:Bash[exec_action:allow]"), shape(before.steps).join(" "));
  // The same line (its ⓘ drawer names its own event, so it is left out).
  const line = (s: DualStep[]) => tools(s)[0]!.gates.map(({ detail: _d, ...g }) => g);
  assert.deepEqual(line(before.steps), line(after.steps));
});

test("a blocked exec gate recorded before its call blocks the call's card: one blocked step, on both front-ends", () => {
  const cmd = `rm -rf ${SECRET}`;
  const events = [
    prompt("clean up", "→ " + bash(cmd)),
    execGate("b1", "deny", { input: repr("Bash.command", null, [{ name: SECRET, tool: "nomodel_Env", field: "GITHUB_TOKEN", origin: null, value: null }]) }),
    call("b1", bash(cmd)),
    result("b1", "exit 77"),
    ev({ kind: "tllm_call", input: repr("▸ user\nclean up"), output: repr("Mandu blocked it.") }),
  ];
  const steps = toDualLanes(events).steps;
  assert.equal(oses(steps).length, 0, `the block is the call's, not a card beside it: ${shape(steps).join(" ")}`);
  const [blocked] = tools(steps);
  // The call names its card, not the gate that opened it (whose first
  // symbol's tool is `nomodel_Env`).
  assert.equal(blocked!.tool, "Bash");
  assert.deepEqual(blocked!.gates.map((g) => [g.kind, g.usage]), [["exec_action", "deny"]]);
  assert.equal(blocked!.usage, "deny");
  assert.ok(blocked!.gates[0]!.why, "the line says why, as the session page does");

  const story = buildStory(toSessionViewModel("s", events));
  const actions = story.flatMap((t) => t.steps).filter((s) => s.kind === "action");
  assert.deepEqual(actions.map((s) => s.kind === "action" ? s.outcome : null), ["blocked"], "one step, the blocked command");
  const sentence = actions[0]!.kind === "action" ? actions[0]!.sentence.map((p) => p.text).join("") : "";
  assert.match(sentence, /^Ran rm -rf /, "the step names the command it blocked");
  assert.deepEqual(storyCounts(story), { blocked: 1, sent: 0 });
});

test("a held exec gate recorded before its call is the call's hold, with its Approvals row", () => {
  const events = [
    prompt("deploy", "→ " + bash("./deploy.sh")),
    execGate("h1", "needs_approval", { policy: { usage: "needs_approval", reason: "held for your answer", shell: "AgentShell", approvalId: "egr-7" } }),
    call("h1", bash("./deploy.sh")),
  ];
  const steps = toDualLanes(events).steps;
  assert.equal(oses(steps).length, 0, shape(steps).join(" "));
  const [held] = tools(steps);
  assert.deepEqual(held!.gates.map((g) => [g.kind, g.usage, g.askId ?? null]), [["exec_action", "needs_approval", "egr-7"]]);
});

test("a net gate recorded before its web call is a line on that card, not a connection in Background", () => {
  const events = [
    prompt("read the docs", "→ WebFetch"),
    netGate("w1", "allow"),
    call("w1", 'WebFetch({"url":"https://docs.example.com/"})'),
    result("w1", "The docs."),
  ];
  const steps = toDualLanes(events).steps;
  assert.equal(oses(steps).length, 0, shape(steps).join(" "));
  assert.deepEqual(tools(steps).map((t) => [t.tool, t.gates.map((g) => [g.kind, g.usage])]), [["WebFetch", [["net_action", "allow"]]]]);
  const vm = toSessionViewModel("s", events);
  assert.deepEqual(vm.paired.turns.flatMap((t) => t.background.map((b) => b.category)), []);

  const blocked = toDualLanes([prompt("send it", "→ WebFetch"), netGate("w2", "deny"), call("w2", 'WebFetch({"url":"https://docs.example.com/?k=1"})'), result("w2", "blocked")]).steps;
  assert.deepEqual(tools(blocked).map((t) => [t.tool, t.usage]), [["WebFetch", "deny"]]);
  assert.equal(oses(blocked).length, 0);
});

test("a call with several checks: each decision is its own line, and any block blocks the call, in either order", () => {
  // The proxy gates one call in steps (an allowed check, then a blocking
  // one, both before the call). Joined to one card, the call is blocked,
  // never "allowed" because the allow came first.
  const cmd = "./build.sh";
  const allowThenBlock = toDualLanes([
    prompt("build", "→ " + bash(cmd)), execGate("m1", "allow"), execGate("m1", "deny"), call("m1", bash(cmd)), result("m1", "exit 77"),
  ]).steps;
  const blockThenAllow = toDualLanes([
    prompt("build", "→ " + bash(cmd)), execGate("m2", "deny"), call("m2", bash(cmd)), execGate("m2", "allow"), result("m2", "exit 77"),
  ]).steps;
  for (const steps of [allowThenBlock, blockThenAllow]) {
    assert.equal(oses(steps).length, 0, shape(steps).join(" "));
    const [t] = tools(steps);
    assert.equal(t!.usage, "deny", "a call any check blocked is blocked");
    assert.deepEqual(t!.gates.map((g) => g.usage).sort(), ["allow", "deny"], "both decisions are lines on the card");
  }
  // The row's counts (the listing cache, schema 5): a call two checks
  // stopped is one blocked step, not two cards.
  const twoBlocks = [prompt("fetch it", "→ WebFetch"), netGate("m5", "deny"), execGate("m5", "deny"), call("m5", 'WebFetch({"url":"https://docs.example.com/"})'), result("m5", "blocked")];
  assert.deepEqual(sessionCounts(twoBlocks), { blocked: 1 });
  // A hold and an allow: the call is held. The same check twice is one line.
  const held = tools(toDualLanes([prompt("go", "→ " + bash("ls")), execGate("m3", "allow"), execGate("m3", "needs_approval"), call("m3", bash("ls"))]).steps)[0]!;
  assert.equal(held.usage, "needs_approval");
  const twice = tools(toDualLanes([prompt("go", "→ " + bash("ls")), execGate("m4", "allow"), call("m4", bash("ls")), execGate("m4", "allow")]).steps)[0]!;
  assert.deepEqual(twice.gates.map((g) => g.usage), ["allow"]);
  assert.equal(twice.usage, "allow");
});

test("a gate whose call the session never recorded, and one with no call id, stay cards of their own", () => {
  // No tool_use for "gone": nothing to join, so it is the command check
  // with no tool call that Background folds (an allow), as before.
  const lone = toSessionViewModel("s", [prompt("go", "ok"), execGate("gone", "allow")]);
  assert.ok(shape(lone.dualLanes.steps).includes("os:exec_action"), shape(lone.dualLanes.steps).join(" "));
  assert.equal(tools(lone.dualLanes.steps).length, 0, "no phantom tool card");
  assert.deepEqual(lone.paired.turns.flatMap((t) => t.background.map((b) => b.category)), ["command-checks"]);
  // The openai-proxy records its exec gate with an empty call id: it cannot
  // be joined, and is not joined to a call by guesswork.
  const codex = toDualLanes([prompt("go", "→ exec_command"), execGate("", "allow"), call("call_1", 'exec_command({"cmd":"ls"})'), result("call_1", "ok")]).steps;
  assert.equal(oses(codex).filter((s) => s.step === "os" && s.kind === "exec_action").length, 1);
  assert.deepEqual(tools(codex)[0]!.gates, []);
});

test("a net check keeps the destination it recorded; the session page names that host, not the reserved one the proxy rewrote the call to", () => {
  const SENT = "https://blocked.mandu.invalid/high-session-egress-requires-approval";
  const NOTICE = "mandu-net-gate: network use blocked, nothing was sent: this session has read a secret, and this request goes to a host that secret is not bound to. (rule: session:high-unbound)";
  const HIGH = "HIGH SESSION (any-model): this session has read secret content into context";
  const blockedNet = (callId: string, input: string) => ev({
    kind: "net_action", callId, boundary: "network", input: repr(input), output: repr(`BLOCKED → ${SENT}`),
    policy: { usage: "deny", reason: HIGH, ruleRef: { source: "rule", id: "session:high-unbound" } },
  });
  const sentinel = `echo 'mandu-exec-gate: blocked, nothing ran: this session has read a secret, and Mandu cannot prove this command stays off the network; start a new session for work that needs it. detail: ${HIGH}' 1>&2; exit 77`;
  const events = [
    prompt("send the rows", "→ WebFetch"),
    blockedNet("f1", "WebFetch → evil.example"),
    call("f1", `WebFetch(${JSON.stringify({ url: SENT, prompt: "summarize" })})`),
    result("f1", "Invalid URL"),
    blockedNet("s1", "WebSearch → (no destination named)"),
    call("s1", `WebSearch(${JSON.stringify({ query: NOTICE })})`),
    result("s1", "error"),
    execGate("x1", "deny", { output: repr(`BLOCKED → ${sentinel}`), policy: { usage: "deny", reason: HIGH, shell: "AgentShell", ruleRef: { source: "rule", id: "exec:no-symbol-in-command" } } }),
    call("x1", bash(sentinel)),
    result("x1", "Exit code 77"),
    // The net-proxy's record names its destination in its own field.
    ev({ kind: "net_action", callId: "n1", emitter: "net-proxy", boundary: "network", destination: "paste.example:443", action: "blocked", input: repr("CONNECT paste.example:443"), policy: { usage: "deny" } }),
    call("n1", bash("curl https://paste.example")),
  ];
  const steps = tools(toDualLanes(events).steps);
  const gate = (id: string) => steps.find((t) => t.callId === id)!.gates[0]!;
  assert.equal(gate("f1").target, "evil.example", "the model proxy's `WebFetch → <host>`");
  assert.equal(gate("s1").target, null, "a search names none");
  assert.equal(gate("n1").target, "paste.example:443", "the net-proxy's `destination`");
  assert.ok(!("target" in gate("x1")), "an exec check has no destination");

  const story = buildStory(toSessionViewModel("s", events));
  const words = story.flatMap((t) => t.steps).filter((s) => s.kind === "action").map((s) => (s.kind === "action" ? s.sentence.map((p) => p.text).join("") : ""));
  assert.deepEqual(words, [
    "Mandu blocked opening a web page on evil.example",
    "Mandu blocked a web search",
    "Mandu stopped a command before it ran",
    "Ran curl https://paste.example",
  ]);
  assert.deepEqual(storyCounts(story), { blocked: 4, sent: 0 });
});

test("a real Claude Code recording: every proxy exec gate is a line on its Bash card", () => {
  const file = fileURLToPath(new URL("../../../fixtures/live/1783675777-1365724.ndjson", import.meta.url));
  const events = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l) as ManduEvent);
  const gates = events.filter((e) => e.kind === "exec_action" && e.emitter === "anthropic-proxy" && e.callId);
  assert.ok(gates.length >= 2, "the recording has the proxy's exec gates");
  // As the proxy records them: each gate just before its call.
  for (const g of gates) {
    const use = events.find((e) => e.kind === "tool_use" && e.callId === g.callId);
    assert.ok(use && use.seq > g.seq, `gate ${g.seq} is recorded before its call`);
  }
  const vm = toSessionViewModel("live", events);
  const steps = vm.dualLanes.steps;
  for (const g of gates) {
    const card = tools(steps).find((t) => t.callId === g.callId);
    assert.ok(card, `the call ${g.callId} has a card`);
    assert.deepEqual(card!.gates.map((x) => [x.kind, x.usage]), [["exec_action", "allow"]], `the check is on the ${card!.tool} card`);
  }
  assert.equal(oses(steps).filter((s) => s.step === "os" && s.kind === "exec_action").length, 0, "no proxy check is a card of its own");
  assert.ok(!vm.paired.turns.some((t) => t.background.some((b) => b.category === "command-checks")), "no call's own check is Background");
});
