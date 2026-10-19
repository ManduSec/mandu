/**
 * session-health.test — the per-session health verdict (session-health.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveHealth, SECRETS_FIX, SECRETS_SENTENCE, TOOL_CANNOT_RUN_RE } from "../../src/session-health.js";
import type { ManduEvent } from "../../src/event-model.js";

let n = 0;
function ev(kind: string, extra: Record<string, unknown> = {}): ManduEvent {
  n++;
  return {
    id: `e${n}`, sessionId: "s", turn: n, ts: new Date(1700000000000 + n * 1000).toISOString(), seq: n,
    callId: null, parentId: null, kind: kind as ManduEvent["kind"], view: "HumanView", boundary: "shell",
    emitter: "launcher", input: null, output: null, invariant: { violatedInvariant: false },
    ...extra,
  } as ManduEvent;
}
const posture = (live: string[], dropped: string[] = []) => ev("launch_posture", { live, dropped });
const turn = () => ev("tllm_call", { callShape: { toolCount: 12 }, output: { symbolized: "Berlin.", original: null, differs: false, symbols: [] } });
const sideCall = () => ev("tllm_call", { callShape: { toolCount: 0 }, output: { symbolized: "title", original: null, differs: false, symbols: [] } });
const toolResult = (orig: string, tool = "Bash", callId = `c${++n}`) => ev("tool_result", { tool, callId, input: { symbolized: "$MDU:Bash[ab12]", original: orig, differs: true, symbols: [] } });

test("no launch_posture → null (a proxy-only or test trace is not graded)", () => {
  assert.equal(deriveHealth([turn(), turn()]), null);
});

test("ok: full posture, pty relay, turns, known tools, exit 0", () => {
  const h = deriveHealth([
    posture(["fs", "net-proxy", "exec-box", "reply-filter"]),
    ev("relay_mode", { mode: "pty" }),
    ev("client_info", { clientVersion: "2.1.258" }),
    ev("tool_surface", { names: ["Read", "Bash"], unknown: [] }),
    sideCall(), turn(), turn(),
    ev("session_exit", { code: 0 }),
  ])!;
  assert.equal(h.verdict, "ok");
  assert.equal(h.turns, 2);
  assert.equal(h.relay, "pty");
  assert.equal(h.clientVersion, "2.1.258");
  assert.equal(h.exitCode, 0);
  assert.deepEqual(h.reasons, []);
});

test("degraded: a dropped rung, an unknown tool, or a command that could not run — the session still works", () => {
  const dropped = deriveHealth([posture(["fs"], ["mandu: service 'net-proxy' is on by default but failed to start: port busy"]), turn()])!;
  assert.equal(dropped.verdict, "degraded");
  assert.match(dropped.reasons[0]!, /net-proxy/);
  const unknown = deriveHealth([posture(["fs"]), ev("tool_surface", { names: ["Read", "NewTool"], unknown: ["NewTool"] }), turn()])!;
  assert.equal(unknown.verdict, "degraded");
  assert.deepEqual(unknown.unknownTools, ["NewTool"]);
  const failing = deriveHealth([posture(["fs"]), ev("exec_action"), ev("exec_action"), toolResult("Exit code 126\nbwrap: --disable-userns requires --unshare-user"), turn()])!;
  assert.equal(failing.verdict, "degraded");
  assert.equal(failing.toolFailures, 1);
});

test("broken: passthrough relay, no completed turn, or every command run failing", () => {
  const pass = deriveHealth([posture(["fs"]), ev("relay_mode", { mode: "passthrough" }), turn()])!;
  assert.equal(pass.verdict, "broken");
  assert.match(pass.reasons[0]!, /PASSTHROUGH/);
  const noTurn = deriveHealth([posture(["fs"]), sideCall(), sideCall(), ev("session_exit", { code: 0 })])!;
  assert.equal(noTurn.verdict, "broken");
  assert.match(noTurn.reasons[0]!, /never completed a conversation turn/);
  const allFail = deriveHealth([posture(["fs"]), ev("exec_action"), toolResult("Exit code 127\nbash: python3: command not found"), turn()])!;
  assert.equal(allFail.verdict, "broken");
  assert.equal(allFail.reasons[0], "every command run (1) could not execute");
});

test("broken while the reply filter's lookups fail (relay_mode.resolveFailure, the S8 miss); ok again once a plain record follows", () => {
  const why = "human-plane: 'desymbolize' returns originals and is accepted only on the human socket (or the admin channel), never on the data socket";
  const down = deriveHealth([posture(["fs"]), ev("relay_mode", { mode: "pty" }), ev("relay_mode", { mode: "pty", resolveFailure: why }), turn()])!;
  assert.equal(down.verdict, "broken");
  assert.equal(down.relay, "pty", "the relay still runs; only its lookups fail");
  assert.equal(down.relayFailure, why);
  assert.match(down.reasons[0]!, /cannot resolve placeholders \(human-plane: 'desymbolize'.*symbols stay opaque/);
  const up = deriveHealth([posture(["fs"]), ev("relay_mode", { mode: "pty", resolveFailure: why }), ev("relay_mode", { mode: "pty" }), turn()])!;
  assert.equal(up.verdict, "ok", up.reasons.join("; "));
  assert.equal(up.relayFailure, undefined);
});

test("a --version / quit-only launch (exit 0, no model call) is NOT broken; a non-zero exit with no model call is", () => {
  const quiet = deriveHealth([posture(["fs", "reply-filter"]), ev("relay_mode", { mode: "pipe" }), ev("session_exit", { code: 0 })])!;
  assert.equal(quiet.verdict, "ok");
  assert.match(quiet.reasons[0]!, /no model call/);
  const died = deriveHealth([posture(["fs"]), ev("session_exit", { code: 1 })])!;
  assert.equal(died.verdict, "broken");
});

test("the tool-failure scan reads only EXEC tool outputs, and counts one failing call once", () => {
  // A secret twin's bytes (tool nomodel_Read) that happen to say "command not found" are not a tool failure.
  const secret = deriveHealth([posture(["fs"]), ev("symbolize", { tool: "nomodel_Read", input: { symbolized: "$MDU:nomodel_Read[1]", original: "# bash: foo: command not found\n", differs: true, symbols: [] } }), turn()])!;
  assert.equal(secret.toolFailures, 0);
  assert.equal(secret.verdict, "ok");
  // The same failing Bash call seen as symbolize AND tool_result → one failure.
  const once = deriveHealth([
    posture(["fs"]), ev("exec_action"), ev("exec_action"),
    ev("symbolize", { tool: "Bash", callId: "same", input: { symbolized: "$MDU:Bash[1]", original: "Exit code 126\nbwrap: x", differs: true, symbols: [] } }),
    toolResult("Exit code 126\nbwrap: x", "Bash", "same"),
    turn(),
  ])!;
  assert.equal(once.toolFailures, 1);
  assert.equal(once.verdict, "degraded");
});

// ── the recorded shape (dashboard.md §4.21, 2026-10-07) ───────────────────────
// The proxies record a result with its call id only: no `tool` field, the
// text in `output` (anthropic-proxy / openai-proxy events.ts makeToolResult).
// The call's tool is on its `tool_use` event, `Name({args})`.

const toolUse = (name: string, callId: string, args: Record<string, unknown> = {}) =>
  ev("tool_use", { emitter: "anthropic-proxy", callId, input: { symbolized: `${name}(${JSON.stringify(args)})`, original: null, differs: false, symbols: [] } });
const recorded = (text: string, callId: string) =>
  ev("tool_result", { emitter: "anthropic-proxy", callId, output: { symbolized: text, original: text, differs: false, symbols: [] } });

test("the recorded shape: a result that names no tool is a command run when its call is one (it was never counted before)", () => {
  const events = [
    posture(["fs", "exec-box"]),
    toolUse("Bash", "toolu_a", { command: "python3 build.py" }), ev("exec_action", { callId: "toolu_a" }),
    recorded("Exit code 127\n/bin/bash: line 1: python3: command not found", "toolu_a"),
    toolUse("Bash", "toolu_b", { command: "ls" }), ev("exec_action", { callId: "toolu_b" }),
    recorded("README.md\nsrc\n", "toolu_b"),
    // the same failing result, re-sent with the next request: one failure
    recorded("Exit code 127\n/bin/bash: line 1: python3: command not found", "toolu_a"),
    turn(),
  ];
  assert.ok(events.every((e) => !("tool" in e)), "the shape the proxies write: no tool field");
  const h = deriveHealth(events)!;
  assert.equal(h.toolFailures, 1);
  assert.equal(h.verdict, "degraded");
  assert.equal(h.reasons[0], "1 command run could not execute (exit 126/127, sandbox or lookup failure)");
  const all = deriveHealth([posture(["fs"]), toolUse("Bash", "toolu_c"), ev("exec_action", { callId: "toolu_c" }), recorded("Exit code 126\nbwrap: Can't mount proc on /newroot/proc: Operation not permitted", "toolu_c"), turn()])!;
  assert.equal(all.verdict, "broken");
  assert.equal(all.reasons[0], "every command run (1) could not execute");
});

test("the reasons say what the check counts: command runs, one or several, never a \"tool run\" (dashboard.md §4.21)", () => {
  // Only command results are read, so a failed Read or WebFetch is never
  // counted: "tool" would claim what the check does not measure.
  const run = (id: string, command: string, text: string) =>
    [toolUse("Bash", id, { command }), ev("exec_action", { callId: id }), recorded(text, id)];
  const two = deriveHealth([
    posture(["fs"]),
    ...run("toolu_1", "python3 a.py", "Exit code 127\n/bin/bash: line 1: python3: command not found"),
    ...run("toolu_2", "./run.sh", "Exit code 126\n/bin/bash: line 1: ./run.sh: Permission denied"),
    ...run("toolu_3", "ls", "README.md\n"),
    toolUse("Read", "toolu_4", { file_path: "gone.md" }), recorded("<tool_use_error>File does not exist.</tool_use_error>", "toolu_4"),
    turn(),
  ])!;
  assert.equal(two.toolFailures, 2);
  assert.equal(two.verdict, "degraded");
  assert.deepEqual(two.reasons, ["2 command runs could not execute (exit 126/127, sandbox or lookup failure)"]);
  const every = deriveHealth([
    posture(["fs"]),
    ...run("toolu_5", "python3 a.py", "Exit code 127\n/bin/bash: line 1: python3: command not found"),
    ...run("toolu_6", "make", "Exit code 127\n/bin/bash: line 1: make: command not found"),
    turn(),
  ])!;
  assert.equal(every.verdict, "broken");
  assert.deepEqual(every.reasons, ["every command run (2) could not execute"]);
  for (const r of [...two.reasons, ...every.reasons]) assert.doesNotMatch(r, /\btool\b/, r);
});

test("every supported agent's command tools are read (tool-family.ts), and no other tool's text is", () => {
  const failing = "Exit code 127\nbash: deploy: command not found";
  for (const tool of ["Bash", "Monitor", "bash", "shell", "shell_command", "exec_command", "local_shell", "exec"]) {
    const h = deriveHealth([posture(["fs"]), toolUse(tool, "c1", { command: "deploy" }), ev("exec_action"), ev("exec_action"), recorded(failing, "c1"), turn()])!;
    assert.equal(h.toolFailures, 1, tool);
    assert.equal(h.verdict, "degraded", tool);
  }
  for (const tool of ["Read", "read", "read_file", "Grep", "WebFetch", "web_fetch", "mcp__docs__search", "NewTool"]) {
    const h = deriveHealth([posture(["fs"]), toolUse(tool, "c1", { file_path: "notes.md" }), recorded(failing, "c1"), turn()])!;
    assert.equal(h.toolFailures, 0, `${tool}: a file or page that says "command not found" is not a failed run`);
  }
  // A result whose call was never seen is not counted (no tool, no guess).
  assert.equal(deriveHealth([posture(["fs"]), recorded(failing, "unseen"), turn()])!.toolFailures, 0);
});

test("a call known only from the transcript (`→ Name(…)` before its `[tool_result <id>]`) names the result's tool", () => {
  const transcript = (name: string) => ev("tllm_call", {
    callShape: { toolCount: 9 },
    input: { symbolized: `▸ user\nbuild it\n\n▸ assistant\n→ ${name}({"cmd":"make"})\n\n▸ user\n[tool_result call_t1]\nExit code: 127\n`, original: null, differs: false, symbols: [] },
    output: { symbolized: "It failed.", original: null, differs: false, symbols: [] },
  });
  const failing = "Exit code: 127\nWall time: 0.0 seconds\nOutput:\n/bin/bash: line 1: make: command not found\n";
  assert.equal(deriveHealth([posture(["fs"]), ev("exec_action"), ev("exec_action"), transcript("shell_command"), recorded(failing, "call_t1")])!.toolFailures, 1);
  assert.equal(deriveHealth([posture(["fs"]), transcript("read_file"), recorded(failing, "call_t1")])!.toolFailures, 0);
});

test("TOOL_CANNOT_RUN_RE: Codex's result heads for exit 126/127, and no other exit code", () => {
  const head = (status: string) => `Chunk ID: 9a3f\nWall time: 0.0123 seconds\n${status}\nOriginal token count: 4\nOutput:\n`;
  for (const s of [
    `${head("Process exited with code 126")}`, // unified exec (agent-result-head.ts)
    `${head("Process exited with code 127")}`,
    "Exit code: 126\nWall time: 0.1 seconds\nOutput:\n", // the classic shell
    "Script failed (exit code 127)\nWall time 0.2 seconds\nOutput:\n", // the script cell
  ]) assert.ok(TOOL_CANNOT_RUN_RE.test(s), s);
  for (const s of [
    `${head("Process exited with code 0")}ok\n`,
    `${head("Process exited with code 1")}FAILED: 2 tests\n`,
    `${head("Process exited with code 1260")}`,
    "Exit code: 2\nWall time: 0.1 seconds\nOutput:\ngrep: no matches\n",
    "Script failed (exit code 1)\nOutput:\nTraceback (most recent call last)\n",
    "mandu-exec-gate: blocked, nothing ran: this session has read a secret\nExit code 77",
  ]) assert.ok(!TOOL_CANNOT_RUN_RE.test(s), s);
});

test("TOOL_CANNOT_RUN_RE: the shapes seen live, and not an ordinary failing command", () => {
  for (const s of ["Exit code 126\nbwrap: loopback: Failed to create NETLINK_ROUTE socket", "Exit code 1\nbwrap: Can't mount proc on /newroot/proc: Operation not permitted", "bash: python3: command not found"]) {
    assert.ok(TOOL_CANNOT_RUN_RE.test(s), s);
  }
  assert.ok(!TOOL_CANNOT_RUN_RE.test("Exit code 1\nTraceback (most recent call last): assert False"), "a command that ran and failed is not 'cannot run'");
  assert.ok(!TOOL_CANNOT_RUN_RE.test("Exit code 2\ngrep: no matches"));
});

// ── secret posture (rootless-confinement-ubuntu-2404.md §3.4) ─────────────────

const GATED_NOTICE = "mandu: secrets are GATED, not confined, on this host.\n  Ubuntu restricts unprivileged user namespaces (AppArmor).\n  Programs the agent runs can still read your credential files.";

test("gated secrets: AMBER (degraded), never broken; one honest reason + the fix, not the raw multi-line banner", () => {
  const h = deriveHealth([
    ev("launch_posture", { live: ["fs", "reply-filter"], dropped: [GATED_NOTICE], secrets: { posture: "gated", gap: "apparmor-userns" } }),
    ev("relay_mode", { mode: "pty" }), turn(), ev("session_exit", { code: 0 }),
  ])!;
  assert.equal(h.verdict, "degraded", "a known host condition is amber, not the red incident state");
  assert.deepEqual(h.secrets, { posture: "gated", gap: "apparmor-userns", sentence: SECRETS_SENTENCE.gated, fix: "mandu setup" });
  assert.equal(h.reasons.length, 1);
  assert.match(h.reasons[0]!, /secrets are gated, not confined/);
  assert.match(h.reasons[0]!, /can still read your credential files/);
  assert.match(h.reasons[0]!, /`mandu setup`/);
  assert.ok(!h.reasons[0]!.includes("\n"), "the tooltip reason is one line");
});

test("bind-only (no file guard, finding 7): gated AMBER with no one-command fix; the reason names the partial layer and what it misses", () => {
  const notice = "mandu: secrets are GATED, not confined, on this host.\n  Mandu's file guard (mandu-net-guard) is not available here.\n  A mount layer still puts a placeholder over each credential file found at launch; a file replaced while the agent runs is not covered.";
  for (const gap of ["no-guard", "guard-off"] as const) {
    const h = deriveHealth([ev("launch_posture", { live: ["fs"], dropped: [notice], secrets: { posture: "gated", gap } }), ev("relay_mode", { mode: "pty" }), turn()])!;
    assert.equal(h.verdict, "degraded");
    assert.deepEqual(h.secrets, { posture: "gated", gap, sentence: SECRETS_SENTENCE.gated });
    assert.equal(h.reasons.length, 1);
    assert.match(h.reasons[0]!, /mount layer still puts a placeholder/);
    assert.match(h.reasons[0]!, /a file replaced while the AI runs is readable/);
    assert.match(h.reasons[0]!, gap === "guard-off" ? /turned off/ : /not available/);
    assert.doesNotMatch(h.reasons[0]!, /Upgrade once/);
  }
});

test("gated with no available fix (userns-off / arbiter) offers none; confined stays ok; an old launcher's event has no secrets field", () => {
  const gated = deriveHealth([ev("launch_posture", { live: [], dropped: [GATED_NOTICE], secrets: { posture: "gated", gap: "userns-off" } })])!;
  assert.equal(gated.secrets?.fix, undefined);
  assert.doesNotMatch(gated.reasons[0]!, /Upgrade once/);
  const confined = deriveHealth([ev("launch_posture", { live: ["fs"], dropped: [], secrets: { posture: "confined" } }), ev("relay_mode", { mode: "pty" }), turn()])!;
  assert.equal(confined.verdict, "ok");
  assert.equal(confined.secrets?.posture, "confined");
  assert.match(confined.secrets!.sentence, /get a placeholder copy of each credential file, never the real one/);
  assert.equal(deriveHealth([posture(["fs"])])!.secrets, undefined);
  // a malformed posture value is ignored, never rendered
  assert.equal(deriveHealth([ev("launch_posture", { live: [], dropped: [], secrets: { posture: "super-safe" } })])!.secrets, undefined);
});

test("PARITY: the dashboard's posture sentences + fixes equal the launcher's single source", async () => {
  // Loaded by URL: the launcher is a separate package outside this tsconfig's rootDir.
  const src = new URL("../../../launcher/src/confinement-posture.ts", import.meta.url).href;
  const { gapExplanation, POSTURE_SENTENCE, POSTURES, HOST_GAPS } = (await import(src)) as {
    gapExplanation: (gap: string) => { fix: string | null };
    POSTURE_SENTENCE: Record<string, string>;
    POSTURES: Array<"confined" | "read-blocked" | "gated">;
    HOST_GAPS: readonly string[];
  };
  for (const p of POSTURES) assert.equal(SECRETS_SENTENCE[p], POSTURE_SENTENCE[p], p);
  // §4.25d: a rule sends a secret with no question asked, so the gated
  // sentence names it instead of promising an OK for every send.
  assert.match(SECRETS_SENTENCE.gated, /a secret is sent out only where a rule or your OK allows/);
  assert.doesNotMatch(SECRETS_SENTENCE.gated, /without your OK/);
  // EVERY gap the launcher can name (incl. the bind-only no-guard / guard-off
  // of sandbox-security-review finding 7), from its own list.
  assert.ok(HOST_GAPS.includes("no-guard") && HOST_GAPS.includes("guard-off"));
  for (const gap of HOST_GAPS) {
    assert.equal(SECRETS_FIX[gap] ?? null, gapExplanation(gap).fix, gap);
  }
  for (const gap of Object.keys(SECRETS_FIX)) assert.ok(HOST_GAPS.includes(gap), `the dashboard names a gap the launcher does not: ${gap}`);
});
