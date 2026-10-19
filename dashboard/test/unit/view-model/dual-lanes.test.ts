/**
 * dual-lanes.test.ts — unit tests for toDualLanes (view-model §4.2c): the
 * dual-lane-mode step builder and its DEDUPLICATION contract.
 *
 * The de-verbosity fix under test: the stateless Messages API re-sends the whole
 * conversation every turn, so the proxy re-emits tool_result / symbolize /
 * path_rewrite for the SAME callId once per subsequent model call. toDualLanes
 * must fold those repeats into ONE step (with a `repeats` count) instead of
 * stacking guard rows — the "three output-guards for one read()" bug.
 *
 * Feature areas split across siblings (2026-07-16, bodies VERBATIM): endpoint +
 * ordering rules in dual-lanes-endpoints.test.ts, attribution/quarantine/side
 * calls in dual-lanes-side-calls.test.ts; shared builders in
 * ./dual-lanes-fixtures.ts.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toDualLanes } from "../../../src/view-model.js";

import { ev, repr, READ_SYM } from "./dual-lanes-fixtures.js";

test("history re-sends fold: 3× tool_result + 3× symbolize for one callId → ONE step, repeats=3", () => {
  const symOut = repr("$MDU:Read[1a9f]", "RAW NOTES", [READ_SYM]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/ws/notes.md"})') }),
    // Turn 2..4: the same result re-guarded on every later model call.
    ev({ kind: "symbolize", callId: "c1", turn: 2, output: symOut }),
    ev({ kind: "tool_result", callId: "c1", turn: 2, output: symOut, policy: { trust: "UNTRUSTED", reason: "fail-closed" } }),
    ev({ kind: "symbolize", callId: "c1", turn: 3, output: symOut }),
    ev({ kind: "tool_result", callId: "c1", turn: 3, output: symOut, policy: { trust: "UNTRUSTED" } }),
    ev({ kind: "symbolize", callId: "c1", turn: 4, output: symOut }),
    ev({ kind: "tool_result", callId: "c1", turn: 4, output: symOut, policy: { trust: "UNTRUSTED" } }),
  ];
  const dv = toDualLanes(events);
  const tools = dv.steps.filter((s) => s.step === "tool");
  assert.equal(tools.length, 1, "one step per tool call, not per re-emission");
  const t = tools[0]!;
  assert.equal(t.step, "tool");
  if (t.step !== "tool") return;
  assert.equal(t.repeats, 3, "the fold count discloses the re-sends");
  assert.equal(t.trust, "UNTRUSTED");
  assert.equal(t.crossing, true, "an untrusted result crosses the wall");
  assert.equal(t.readsTwin, false, "a real HumanView read (raw original, no rewrite) is NOT a twin read");
  assert.equal(t.upSyms.length, 1, "one symbol↔raw mapping in the up band");
  assert.equal(t.upSyms[0]!.value, "RAW NOTES");
  assert.equal(t.resultAgent, "$MDU:Read[1a9f]");
  assert.equal(t.resultHuman, "RAW NOTES");
  assert.equal(t.origin, "/ws/notes.md");
  assert.ok(dv.collapsedCount >= 4, "the folded duplicates are counted");
});

test("re-minted symbol NAMES for the same value fold (arbiter mints a fresh hash per turn)", () => {
  const mk = (name: string) => repr(name, "RAW NOTES", [{ ...READ_SYM, name }]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/ws/notes.md"})') }),
    ev({ kind: "symbolize", callId: "c1", output: mk("$MDU:Read[1a9f]") }),
    ev({ kind: "tool_result", callId: "c1", output: mk("$MDU:Read[1a9f]"), policy: { trust: "UNTRUSTED" } }),
    ev({ kind: "symbolize", callId: "c1", output: mk("$MDU:Read[4026]") }),
    ev({ kind: "symbolize", callId: "c1", output: mk("$MDU:Read[a124]") }),
  ];
  const dv = toDualLanes(events);
  const t = dv.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.upSyms.length, 1, "same VALUE re-symbolized under new names → one band entry");
  assert.equal(t.upSyms[0]!.name, "$MDU:Read[1a9f]", "the first minted name wins");
});

test("a TRUSTED result does NOT cross: single AgentView step, no bands", () => {
  const out = repr("notes.md\nREADME.md", "notes.md\nREADME.md");
  const events = [
    ev({ kind: "tool_use", callId: "g1", input: repr('Glob({"pattern":"**/*.md"})') }),
    ev({ kind: "tool_result", callId: "g1", output: out, policy: { trust: "TRUSTED", reason: "schema rule: literal TRUSTED" } }),
  ];
  const dv = toDualLanes(events);
  const t = dv.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.crossing, false);
  assert.equal(t.trust, "TRUSTED");
  assert.equal(t.upSyms.length, 0);
  assert.equal(t.tool, "Glob");
});

test("path_rewrite events attach to their tool call and identical re-applications fold", () => {
  const fwd = {
    direction: "forward" as const, tool: "Read", field: "file_path",
    human: "/home/u/ws/a.md", agent: "/tmp/agentview/a.md",
  };
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/home/u/ws/a.md"})') }),
    ev({ kind: "path_rewrite", callId: "c1", rewrite: fwd }),
    ev({ kind: "path_rewrite", callId: "c1", rewrite: { ...fwd, direction: "reverse" } }),
    // A later turn re-applies the same reverse rewrite on the echoed history.
    ev({ kind: "path_rewrite", callId: "c1", rewrite: { ...fwd, direction: "reverse" } }),
    ev({ kind: "tool_result", callId: "c1", output: repr("ok", "ok"), policy: { trust: "TRUSTED" } }),
  ];
  const dv = toDualLanes(events);
  const t = dv.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.pathRewrites.length, 2, "one forward + one reverse (deduped)");
  const forward = t.pathRewrites.find((p) => p.direction === "forward")!;
  assert.equal(forward.human, "/home/u/ws/a.md");
  assert.equal(forward.agent, "/tmp/agentview/a.md");
  assert.equal(forward.repeats, 1);
  const reverse = t.pathRewrites.find((p) => p.direction === "reverse")!;
  assert.equal(reverse.repeats, 2, "the re-applied reverse rewrite folds with a count");
  // A trusted call with path rewrites still renders them (rewrite ⊥ trust).
  assert.equal(t.crossing, false);
});

// ── twin reads: an fs dual-view read hits the AgentView twin, NOT the raw file ──
// The agent's CWD is the AgentView worktree, whose files were already symbolized
// ON DISK by the fs chokepoint. So an untrusted workspace read gets a SYMBOL back
// (there is no raw HumanView data at read time — it crossed earlier, on disk).
// Such a read must NOT render as a "HumanView (Original) executes" crossing (that
// put a HumanView label on an agentview-dir path); `readsTwin` marks it so the
// renderer keeps it a single AgentView card. Two independent detectors:

test("twin read (own result already a symbol): readsTwin, non-crossing, still UNTRUSTED", () => {
  // The tool's OWN `original` result is the twin's on-disk content — itself a
  // symbol — the tell-tale that this was a read of a symbolized twin, not raw data.
  const twinOnDisk = "1\t$MDU:Read[f63e].notes.md\n2\t";
  const outer = { name: "$MDU:Read[9b8a]", tool: "Read", field: null, origin: null, value: twinOnDisk };
  const out = repr("$MDU:Read[9b8a]", twinOnDisk, [outer]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/tmp/dv/ws/agentview/notes.md"})') }),
    ev({ kind: "symbolize", callId: "c1", output: out }),
    ev({ kind: "tool_result", callId: "c1", output: out, policy: { trust: "UNTRUSTED", reason: "fail-closed" } }),
  ];
  const t = toDualLanes(events).steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.trust, "UNTRUSTED", "the twin's content is still untrusted-classified");
  assert.equal(t.readsTwin, true, "an already-symbolized own result marks a twin read");
  assert.equal(t.crossing, false, "a twin read did NOT cross the wall at read time — no HumanView (Original) card");
});

test("twin read (ViewMap path rewrite alone): readsTwin from the rewrite even without a symbol original", () => {
  const rw = {
    direction: "reverse" as const, tool: "Read", field: "file_path",
    human: "/ws/notes.md", agent: "/tmp/dv/ws/agentview/notes.md",
  };
  const out = repr("$MDU:Read[9b8a]", null, [
    { name: "$MDU:Read[9b8a]", tool: "Read", field: null, origin: null, value: null },
  ]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/tmp/dv/ws/agentview/notes.md"})') }),
    ev({ kind: "path_rewrite", callId: "c1", rewrite: rw }),
    ev({ kind: "tool_result", callId: "c1", output: out, policy: { trust: "UNTRUSTED" } }),
  ];
  const t = toDualLanes(events).steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.readsTwin, true, "a ViewMap rewrite (path translated to the twin) alone marks a twin read");
  assert.equal(t.crossing, false, "so it renders as an AgentView card, not a crossing");
});

test("a quarantine (U-LLM) call is never mis-tagged as a twin read", () => {
  // inspect_symbol's own result can be a symbol too, but it OWNS the U-LLM card —
  // readsTwin must exclude it so it keeps crossing (the Quarantine lane).
  const out = repr("$MDU:inspect[ee19]", "wrapped $MDU:Read[1a9f]", [
    { name: "$MDU:inspect[ee19]", tool: "inspect_symbol", field: null, origin: null, value: "wrapped" },
  ]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('inspect_symbol({"symbol":"$MDU:Read[1a9f]"})') }),
    ev({ kind: "ullm_call", callId: "c1", view: "Quarantine", output: out }),
    ev({ kind: "tool_result", callId: "c1", output: out, policy: { trust: "UNTRUSTED" } }),
  ];
  const t = toDualLanes(events).steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.quarantine, true);
  assert.equal(t.readsTwin, false, "quarantine is excluded from twin detection");
  assert.equal(t.crossing, true, "the U-LLM call still crosses into the Quarantine lane");
});

test("an uncorrelated path_rewrite (no callId) becomes a standalone step, not lost", () => {
  const events = [
    ev({ kind: "path_rewrite", rewrite: { direction: "reverse", tool: null, field: "content", human: "/h", agent: "/a" } }),
  ];
  const dv = toDualLanes(events);
  assert.equal(dv.steps.length, 1);
  assert.equal(dv.steps[0]!.step, "os");
});

test("consecutive identical net_actions fold into one right-lane card with a count", () => {
  const mk = () => ev({
    kind: "net_action", boundary: "network", emitter: "net-supervisor",
    ...( { action: "passthrough", destination: "api.anthropic.com:443", note: "model-API host excluded (tunnel)" } as object),
  });
  const events = [mk(), mk(), mk(),
    ev({ kind: "net_action", boundary: "network", emitter: "net-supervisor",
      ...({ action: "tunneled", destination: "mcp.example:443" } as object) })];
  const dv = toDualLanes(events);
  const os = dv.steps.filter((s) => s.step === "os");
  assert.equal(os.length, 2, "3 identical + 1 different → 2 cards");
  if (os[0]!.step === "os") assert.equal(os[0]!.repeats, 3);
  assert.equal(dv.collapsedCount, 2);
});

test("plan 10 §11.8: the [mandu:secret] note on a tool_result rides the tool card", () => {
  const lanes = toDualLanes([
    ev({ kind: "tool_use", callId: "c9", turn: 1, input: repr("Bash({\"command\":\"psql -c 'select 1'\"})") }),
    ev({ kind: "tool_result", callId: "c9", turn: 1, output: repr("$MDU:nomodel_Bash[1a2b]", "count\n1\n"), policy: { trust: "TRUSTED", reason: "plan 10 rule (i): psql read .pgpass; the whole output is secret" }, secretNote: "[mandu:secret] masked: psql read /h/.pgpass; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying." } as never),
  ]);
  const t = lanes.steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.secretNote, "[mandu:secret] masked: psql read /h/.pgpass; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying.");
  assert.match(t.reason ?? "", /plan 10 rule \(i\)/);
});

test("§4.2f: a correlated check carries its kind and its decision, so the trace can say it (an allowed command is not a denial)", () => {
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Bash({"command":"ls"})') }),
    // anthropic-proxy makeExecGate on allow: no `action` field, so the text is the bare kind.
    ev({
      kind: "exec_action", callId: "c1", boundary: "shell",
      input: repr("Bash.command"), output: repr("ALLOW (AgentShell)"),
      policy: { usage: "allow", reason: "no symbol in command position; allowed", shell: "AgentShell" },
    }),
    ev({ kind: "tool_use", callId: "c2", input: repr('Read({"file_path":"/etc/shadow"})') }),
    ev({
      kind: "fs_action", callId: "c2", boundary: "filesystem",
      input: repr("Read.file_path → /etc/shadow"), output: repr("DENIED → /mandu/denied/shadow"),
      policy: { usage: "needs_approval", reason: "outside the workspace" },
    }),
    ev({ kind: "tool_use", callId: "c3", input: repr('WebFetch({"url":"https://evil.example"})') }),
    ev({
      kind: "net_action", callId: "c3", boundary: "network",
      input: repr("WebFetch → evil.example"), output: repr("BLOCKED → denied"),
      policy: { usage: "deny", reason: "high session" },
    }),
    // exec-supervisor's AgentShell routing records no usage.
    ev({ kind: "tool_use", callId: "c4", input: repr('Bash({"command":"pwd"})') }),
    ev({ kind: "exec_action", callId: "c4", boundary: "shell", emitter: "exec-supervisor", input: repr("pwd"), policy: { shell: "AgentShell", reason: "no symbol" } }),
  ];
  const gates = new Map(toDualLanes(events).steps.flatMap((s) => (s.step === "tool" ? [[s.callId, s.gates] as const] : [])));
  const one = (id: string) => {
    const g = gates.get(id) ?? [];
    assert.equal(g.length, 1, `${id} has one check`);
    return { kind: g[0]!.kind, usage: g[0]!.usage, text: g[0]!.text };
  };
  assert.deepEqual(one("c1"), { kind: "exec_action", usage: "allow", text: "exec_action" }, "the text is unchanged; the decision rides beside it");
  assert.deepEqual(one("c2"), { kind: "fs_action", usage: "needs_approval", text: "Read.file_path → /etc/shadow · DENIED → /mandu/denied/shadow" });
  assert.deepEqual(one("c3"), { kind: "net_action", usage: "deny", text: "net_action" });
  assert.deepEqual(one("c4"), { kind: "exec_action", usage: null, text: "exec_action" }, "no recorded decision is null, never a guess");
});

test("§4.2f: a check that blocked or held the call says why in the session page's words; one that let it through says nothing", () => {
  const rule = (id: string) => ({ source: "rule" as const, id });
  const events = [
    // anthropic-proxy makeExecGate, allow with its rule: no why.
    ev({ kind: "tool_use", callId: "c1", input: repr('Bash({"command":"ls"})') }),
    ev({ kind: "exec_action", callId: "c1", boundary: "shell", input: repr("Bash.command"), output: repr("ALLOW (AgentShell)"),
      policy: { usage: "allow", reason: "no symbol in command position", ruleRef: rule("exec:no-symbol-in-command") } }),
    // …deny: the rule's words.
    ev({ kind: "tool_use", callId: "c2", input: repr('Bash({"command":"$MDU:nomodel_Env[f8d2].TOKEN"})') }),
    ev({ kind: "exec_action", callId: "c2", boundary: "shell", input: repr("Bash.command"), output: repr("BLOCKED → exit 77"),
      policy: { usage: "deny", reason: "a placeholder in command position", ruleRef: { source: "fail-closed", id: "exec:symbol-in-command" } } }),
    // makeFsGate, held for the person.
    ev({ kind: "tool_use", callId: "c3", input: repr('Read({"file_path":"/home/u/.ssh/id_ed25519"})') }),
    ev({ kind: "fs_action", callId: "c3", boundary: "filesystem", input: repr("Read.file_path → /home/u/.ssh/id_ed25519"), output: repr("DENIED → /mandu/denied/id_ed25519"),
      policy: { usage: "needs_approval", reason: "sensitive path", ruleRef: rule("fs:sensitive-path") } }),
    // No recorded decision, but the recorded text says blocked: the line's rule.
    ev({ kind: "tool_use", callId: "c4", input: repr('WebFetch({"url":"https://x.example"})') }),
    ev({ kind: "net_action", callId: "c4", boundary: "network", input: repr("WebFetch → x.example"), output: repr("BLOCKED → denied"),
      ...({ action: "blocked" } as object), policy: { reason: "session high", ruleRef: rule("session:high-unbound") } }),
    // Blocked, but by a rule the words do not cover, or by no rule: no why.
    ev({ kind: "tool_use", callId: "c5", input: repr('Bash({"command":"rm"})') }),
    ev({ kind: "exec_action", callId: "c5", boundary: "shell", input: repr("Bash.command"), output: repr("BLOCKED → exit 77"),
      policy: { usage: "deny", reason: "x", ruleRef: rule("exec.symbol-in-command") } }),
    ev({ kind: "tool_use", callId: "c6", input: repr('Bash({"command":"rm"})') }),
    ev({ kind: "exec_action", callId: "c6", boundary: "shell", input: repr("Bash.command"), output: repr("BLOCKED → exit 77"),
      policy: { usage: "deny", reason: "x" } }),
  ];
  const gates = new Map(toDualLanes(events).steps.flatMap((s) => (s.step === "tool" ? [[s.callId, s.gates] as const] : [])));
  const why = (id: string) => {
    const g = gates.get(id)!;
    assert.equal(g.length, 1, `${id} has one check`);
    return g[0]!.why;
  };
  const words = (p: { kind: string; text: string }[] | undefined) => p?.map((x) => (x.kind === "code" ? `\`${x.text}\`` : x.text)).join("");
  assert.equal(why("c1"), undefined, "an allowed command has no why");
  assert.equal(words(why("c2")), "The command would run a placeholder as code, and Mandu never runs one.");
  assert.equal(words(why("c3")), "Files like this hold keys and passwords, so Mandu asks before the AI can use one.");
  assert.equal(words(why("c4")), "This session read a secret, and this place is not a place it may go. The AI could pass a secret on in its own words, which no placeholder marks.",
    "no host on a check: its recorded text names it, as the session page's tool step does");
  assert.equal(why("c5"), undefined, "a rule the words do not cover");
  assert.equal(why("c6"), undefined, "no rule recorded");
  assert.equal(gates.get("c2")![0]!.text, "exec_action", "the check's text is unchanged");
});

test("§4.2f: an OS step that blocked or held a send says why with its recorded host; a send let out, a flagged step and no rule say nothing", () => {
  const KEY = "$MDU:nomodel_Read[5c6e].STRIPE_KEY";
  const net = (over: Record<string, unknown>, policy: Record<string, unknown>, violated = false) => ev({
    kind: "net_action", boundary: "network", emitter: "net-supervisor", input: repr("POST /v1/customers"),
    ...(over as object), policy: policy as never, invariant: { violatedInvariant: violated },
  });
  const unbound = { source: "rule", id: "egress:secret-unbound" };
  const steps = toDualLanes([
    net({ action: "blocked", destination: "api.stripe.com:443", withheld: [{ symbol: KEY }] }, { usage: "deny", ruleRef: unbound }),
    net({ action: "forwarded", destination: "api.stripe.com:443", resolved: [KEY] }, { usage: "allow", ruleRef: { source: "rule", id: "egress:secret-bound" } }),
    net({ action: "held", destination: "paste.example", withheld: [KEY, "$MDU:nomodel_Env[aa11].PASTE_KEY"] }, { usage: "needs_approval", ruleRef: unbound }),
    net({ action: "blocked", destination: "evil.example" }, { usage: "deny", ruleRef: unbound }, true),
    net({ action: "blocked", destination: "other.example" }, { usage: "deny" }),
  ]).steps.filter((s) => s.step === "os");
  assert.equal(steps.length, 5);
  const words = (p: { kind: string; text: string }[] | undefined) => p?.map((x) => (x.kind === "code" ? `\`${x.text}\`` : x.text)).join("");
  const [blocked, sent, held, flagged, bare] = steps as Extract<(typeof steps)[number], { step: "os" }>[];
  assert.equal(words(blocked!.why), "No rule lets this secret go to `api.stripe.com`. Mandu sends a secret only where a rule lets it go, or with your OK.");
  assert.deepEqual(blocked!.why!.filter((p) => p.kind === "code").map((p) => p.text), ["api.stripe.com"], "the host is code, its port left out");
  assert.equal(sent!.why, undefined, "a send let out has no why");
  assert.equal(words(held!.why), "No rule lets one of these secrets go to `paste.example`. Mandu sends a secret only where a rule lets it go, or with your OK.");
  assert.equal(flagged!.why, undefined, "a flagged step is told by its flag");
  assert.equal(bare!.why, undefined, "no rule, no why");
  assert.ok(!JSON.stringify(steps.map((s) => s.why ?? null)).includes("$MDU:"), "a why never carries a token");
});

test("§4.2f: a check or an OS step that stopped something and filed an Approvals row carries the row's id; one that let it through, a flagged step and an id of another shape carry none", () => {
  const unbound = { source: "rule" as const, id: "egress:secret-unbound" };
  const KEY = "$MDU:nomodel_Read[5c6e].STRIPE_KEY";
  const net = (over: Record<string, unknown>, policy: Record<string, unknown>, violated = false) => ev({
    kind: "net_action", boundary: "network", emitter: "net-supervisor", input: repr("GET /v1/customers"),
    ...(over as object), policy: policy as never, invariant: { violatedInvariant: violated },
  });
  const steps = toDualLanes([
    // The tour's 10:38 block: the net-proxy stamps the row the arbiter queued.
    net({ action: "blocked", destination: "api.stripe.com", withheld: [KEY] }, { usage: "deny", ruleRef: unbound, approvalId: "egr-1" }),
    net({ action: "held", destination: "paste.example", withheld: [KEY] }, { usage: "needs_approval", ruleRef: unbound, approvalId: "egr-2" }),
    // Let through: an id on it names no ask (a verdict's join is its ruleRef).
    net({ action: "forwarded", destination: "api.stripe.com", resolved: [KEY] }, { usage: "allow", approvalId: "egr-3" }),
    net({ action: "blocked", destination: "evil.example" }, { usage: "deny", ruleRef: unbound, approvalId: "egr-4" }, true),
    net({ action: "blocked", destination: "odd.example" }, { usage: "deny", ruleRef: unbound, approvalId: "egr 5\"><b>" }),
    net({ action: "blocked", destination: "other.example" }, { usage: "deny", ruleRef: unbound }),
    // A check on a tool card: the model proxy's fs gate held the Read and filed a row.
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/home/u/.ssh/id_ed25519"})') }),
    ev({ kind: "fs_action", callId: "c1", boundary: "filesystem", input: repr("Read.file_path → /home/u/.ssh/id_ed25519"), output: repr("DENIED → /mandu/denied/id_ed25519"),
      policy: { usage: "needs_approval", reason: "sensitive path", ruleRef: { source: "rule", id: "fs:sensitive-path" }, approvalId: "egr-6" } }),
    ev({ kind: "tool_use", callId: "c2", input: repr('Bash({"command":"ls"})') }),
    ev({ kind: "exec_action", callId: "c2", boundary: "shell", input: repr("Bash.command"), output: repr("ALLOW (AgentShell)"),
      policy: { usage: "allow", reason: "no symbol in command position", approvalId: "egr-7" } }),
  ]).steps;
  const os = steps.filter((s) => s.step === "os") as Extract<(typeof steps)[number], { step: "os" }>[];
  assert.deepEqual(os.map((s) => s.askId ?? null), ["egr-1", "egr-2", null, null, null, null],
    "blocked and held carry their row; let out, flagged, a malformed id and none carry nothing");
  const gate = (callId: string) => (steps.find((s) => s.step === "tool" && s.callId === callId) as Extract<(typeof steps)[number], { step: "tool" }>).gates[0]!;
  assert.equal(gate("c1").askId, "egr-6", "a held check on a tool card carries its row");
  assert.equal(gate("c2").askId, undefined, "a check that let the call through carries none");
  assert.equal(gate("c2").why, undefined, "…and still no why");
});
