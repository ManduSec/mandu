/**
 * dispatch (unit) — OpenClaw's Tool Search dispatcher is read as the tool it
 * runs, and every shape whose meaning is not the same in every OpenClaw
 * version is refused (dispatch.ts; supported-agents.md §2.1). The shapes are
 * read from openclaw 2026.7.1 `readCallArgs` and 2026.9.6
 * `readToolSearchCallArgs`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { unwrapDispatch, refusedTool, refusedToolInput, refusedArg, refusedArgInput, dispatcherRefusalInput, REFUSED_ID_PREFIX, type Dispatched } from "../../src/dispatch.js";
import { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE } from "../../src/gate-surface.js";

const OC = { dispatch: { tool_call: "openclaw-tool-call", tool_search_code: "refuse" } } as const;

function call(d: Dispatched): Extract<Dispatched, { kind: "call" }> {
  assert.equal(d.kind, "call", JSON.stringify(d));
  return d as Extract<Dispatched, { kind: "call" }>;
}
function refused(d: Dispatched): Extract<Dispatched, { kind: "refuse" }> {
  assert.equal(d.kind, "refuse", JSON.stringify(d));
  return d as Extract<Dispatched, { kind: "refuse" }>;
}

test("not a dispatcher on the surface → none (Claude Code's surface has no dispatchers; the union has OpenClaw's)", () => {
  assert.equal(unwrapDispatch("exec", { command: "ls" }, OC).kind, "none");
  assert.equal(unwrapDispatch("tool_call", { id: "exec", args: { command: "ls" } }, CLAUDE_CODE_GATE_SURFACE).kind, "none");
  assert.equal(unwrapDispatch("tool_call", { id: "exec", args: { command: "ls" } }, UNION_GATE_SURFACE).kind, "call");
  assert.equal(unwrapDispatch("tool_search", { query: "fetch" }, OC).kind, "none");
});

test("tool_call{id, args}: the inner tool's name and input; a catalog id's last segment names the tool", () => {
  const a = call(unwrapDispatch("tool_call", { id: "exec", args: { command: "cat .env" } }, OC));
  assert.equal(a.name, "exec");
  assert.deepEqual(a.input, { command: "cat .env" });
  assert.equal(call(unwrapDispatch("tool_call", { id: " openclaw:core:web_fetch ", args: { url: "https://x.test" } }, OC)).name, "web_fetch");
  assert.equal(call(unwrapDispatch("tool_call", { id: "openclaw:memory-core:memory_search", args: { query: "q" } }, OC)).name, "memory_search");
  // an MCP tool sharing a core name is gated as that tool (over-gating)
  assert.equal(call(unwrapDispatch("tool_call", { id: "mcp:srv:exec", args: { command: "x" } }, OC)).name, "exec");
  // the other selector spellings and the `input` nest key
  assert.equal(call(unwrapDispatch("tool_call", { toolId: "exec", args: { command: "x" } }, OC)).name, "exec");
  assert.deepEqual(call(unwrapDispatch("tool_call", { name: "exec", input: { command: "x" } }, OC)).input, { command: "x" });
});

test("flattened input (2026.9.x): the keys beside the selector (and beside an empty or null args) are the inner input", () => {
  assert.deepEqual(call(unwrapDispatch("tool_call", { id: "exec", command: "ls", workdir: "/w" }, OC)).input, { command: "ls", workdir: "/w" });
  assert.deepEqual(call(unwrapDispatch("tool_call", { id: "exec", args: {}, command: "ls" }, OC)).input, { command: "ls" });
  assert.deepEqual(call(unwrapDispatch("tool_call", { id: "exec", args: null, command: "ls" }, OC)).input, { command: "ls" });
  assert.deepEqual(call(unwrapDispatch("tool_call", { id: "get_goal" }, OC)).input, {});
});

test("rewrap puts a gated inner input back into the same envelope", () => {
  const nested = call(unwrapDispatch("tool_call", { id: "exec", args: { command: "a", workdir: "/w" } }, OC));
  assert.deepEqual(nested.rewrap({ command: "B", workdir: "/w" }), { id: "exec", args: { command: "B", workdir: "/w" } });
  const viaInput = call(unwrapDispatch("tool_call", { id: "exec", input: { command: "a" } }, OC));
  assert.deepEqual(viaInput.rewrap({ command: "B" }), { id: "exec", input: { command: "B" } });
  const flat = call(unwrapDispatch("tool_call", { id: "exec", args: {}, command: "a" }, OC));
  assert.deepEqual(flat.rewrap({ command: "B" }), { id: "exec", args: {}, command: "B" });
});

test("every shape that reads differently across versions, or names no single tool, is REFUSED with a harmless replacement", () => {
  const cases: Array<[string, unknown]> = [
    ["not an object", "exec"],
    ["an array", [{ id: "exec" }]],
    ["no selector", { args: { id: "exec", command: "ls" } }],
    ["two selectors (2026.9.x picks by catalog match)", { id: "x", name: "exec", command: "ls" }],
    ["a null selector", { id: null, name: "exec" }],
    ["an empty id", { id: "  ", args: { command: "ls" } }],
    ["a non-string id", { id: 7, args: { command: "ls" } }],
    ["dotted args keys (2026.9.x only)", { id: "exec", "args.command": "ls" }],
    ["args AND input", { id: "exec", args: { command: "a" }, input: { command: "b" } }],
    ["nested input plus loose keys", { id: "exec", args: { command: "a" }, command: "b" }],
    ["args a string", { id: "exec", args: "ls" }],
    ["args an array", { id: "exec", args: ["ls"] }],
    ["an id ending in ':'", { id: "openclaw:core:", args: { command: "ls" } }],
    ["a dispatcher inside the dispatcher", { id: "tool_search_code", args: { code: "1" } }],
    ["tool_call inside tool_call", { id: "openclaw:core:tool_call", args: { id: "exec" } }],
  ];
  for (const [label, input] of cases) {
    const r = refused(unwrapDispatch("tool_call", input, OC));
    assert.deepEqual(Object.keys(r.input), ["id"], label);
    assert.ok(String(r.input["id"]).startsWith(REFUSED_ID_PREFIX), label);
    assert.ok(!JSON.stringify(r.input).includes("ls\""), `${label}: no model input survives`);
  }
});

test("tool_search_code (JavaScript that calls tools) is refused on every call: its code becomes a throw", () => {
  const r = refused(unwrapDispatch("tool_search_code", { code: "return await openclaw.tools.call('exec', {command: 'cat .env'})" }, OC));
  assert.deepEqual(Object.keys(r.input), ["code"]);
  assert.match(String(r.input["code"]), /^throw new Error\("mandu: tool_search_code runs code that calls tools/);
  assert.ok(!String(r.input["code"]).includes("cat .env"));
});

test("refused tools: a direct call reads the reason off the surface; its input is an action no schema accepts; a dispatched call to one is refused", () => {
  const surface = { ...OC, refuse: { terminal: "terminal runs in the gateway" } };
  assert.equal(refusedTool("terminal", surface), "terminal runs in the gateway");
  assert.equal(refusedTool("exec", surface), null);
  assert.equal(refusedTool("toString", surface), null, "own properties only");
  assert.equal(refusedTool("terminal", {}), null, "a surface without the table refuses nothing");
  assert.deepEqual(refusedToolInput("why"), { action: `${REFUSED_ID_PREFIX}why` });
  for (const id of ["terminal", "openclaw:core:terminal"]) {
    const r = refused(unwrapDispatch("tool_call", { id, args: { action: "input", data: "ls\n" } }, surface));
    assert.deepEqual(Object.keys(r.input), ["id"]);
    assert.ok(String(r.input["id"]).includes("terminal runs in the gateway"));
  }
  assert.equal(call(unwrapDispatch("tool_call", { id: "terminal", args: { action: "list" } }, OC)).name, "terminal", "control: no refuse table, gated as the inner tool");
  // the union carries OpenClaw's refusals
  assert.ok(refusedTool("automations", UNION_GATE_SURFACE));
  assert.equal(refusedTool("Bash", UNION_GATE_SURFACE), null);
});

// ── Refused FORMS (gate-surface refuseArgs; supported-agents.md §2.1) ───────

const FORMS = {
  refuseArgs: {
    exec: [{ field: "host", allow: ["", "auto", "sandbox", "gateway"], reason: "exec host=node runs on a paired device" }],
    browser: [{ field: "target", allow: ["", "sandbox", "host"], reason: "browser target=node runs on a paired device" }],
  },
} as const;

test("refusedArg: a boolean field compares as \"true\" / \"false\" (OpenCode 2's shell / subagent `background`); other non-strings stay outside every list", () => {
  const OC2 = {
    refuseArgs: {
      shell: [{ field: "background", allow: ["", "false"], reason: "bg shell" }],
      subagent: [{ field: "model", allow: [""], reason: "own model" }, { field: "background", allow: ["", "false"], reason: "bg sub" }],
    },
  } as const;
  assert.deepEqual(refusedArg("shell", { command: "ls", background: true }, OC2), { field: "background", reason: "bg shell" });
  assert.deepEqual(refusedArg("shell", { command: "ls", background: "TRUE" }, OC2), { field: "background", reason: "bg shell" });
  for (const background of [false, "false", " False ", undefined, null]) {
    assert.equal(refusedArg("shell", { command: "ls", ...(background === undefined ? {} : { background }) }, OC2), null, JSON.stringify(background));
  }
  for (const background of [1, 0, [], {}]) assert.equal(refusedArg("shell", { command: "ls", background }, OC2)?.field, "background", JSON.stringify(background));
  assert.deepEqual(refusedArg("subagent", { agent: "general", prompt: "p", model: "anthropic/claude-haiku-4-5" }, OC2), { field: "model", reason: "own model" });
  assert.deepEqual(refusedArg("subagent", { agent: "general", prompt: "p", background: true }, OC2), { field: "background", reason: "bg sub" });
  assert.equal(refusedArg("subagent", { agent: "general", prompt: "p", model: "", background: false }, OC2), null);
  // the refusal input: the field becomes a string the tool's boolean / model check rejects, the shell's command the sentinel
  const out = refusedArgInput({ command: "cat x", background: true }, "background", "bg shell", { field: "command", sentinel: "exit 77" });
  assert.deepEqual(out, { command: "exit 77", background: `${REFUSED_ID_PREFIX}bg shell` });
  // a boolean `true` is still no allowed exec host
  assert.equal(refusedArg("exec", { command: "ls", host: true }, FORMS)?.field, "host");
});

test("refusedArg: exec{host} outside the box's values is refused, compared the way OpenClaw normalizes it; absent / null / allowed values pass", () => {
  for (const host of ["node", "NODE", " node ", "Node", "paired-mac", 7, true, ["node"]]) {
    const r = refusedArg("exec", { command: "ls", host }, FORMS);
    assert.deepEqual(r, { field: "host", reason: "exec host=node runs on a paired device" }, JSON.stringify(host));
  }
  for (const host of [undefined, null, "", "auto", "sandbox", "gateway", " Gateway "]) {
    assert.equal(refusedArg("exec", { command: "ls", ...(host === undefined ? {} : { host }) }, FORMS), null, JSON.stringify(host));
  }
  assert.deepEqual(refusedArg("browser", { action: "open", target: "node" }, FORMS)?.field, "target");
  assert.equal(refusedArg("browser", { action: "open", target: "host" }, FORMS), null);
  // no rule for the tool, a non-object input, a surface without the table
  assert.equal(refusedArg("read", { host: "node" }, FORMS), null);
  assert.equal(refusedArg("exec", "host=node", FORMS), null);
  assert.equal(refusedArg("exec", { host: "node" }, {}), null);
  assert.equal(refusedArg("exec", { host: "node" }, CLAUDE_CODE_GATE_SURFACE), null);
  assert.ok(refusedArg("exec", { host: "node" }, UNION_GATE_SURFACE), "the union refuses it (an arbiter that cannot say)");
});

test("refusedArg: OpenClaw Code Mode's exec (any `code` or `language`, even empty) is refused on the union; the shell exec and Claude Code's surface pass", () => {
  // 2026.9.x Code Mode `exec{title, code}`; 2026.7.1 `exec{code, command, language}`
  for (const input of [
    { title: "t", code: "await write({path: 'x', content: 'y'})" },
    { title: "t", code: "" },
    { code: "return 1", command: "return 1", language: "javascript" },
    { command: "return 1", language: "typescript" },
    { title: "t", code: 1 },
  ]) {
    const r = refusedArg("exec", input, UNION_GATE_SURFACE);
    assert.ok(r && (r.field === "code" || r.field === "language"), JSON.stringify(input));
    assert.match(r!.reason, /Code Mode/);
  }
  // the shell exec: no code, no language
  assert.equal(refusedArg("exec", { command: "ls -la", workdir: "/w", timeoutSeconds: 30 }, UNION_GATE_SURFACE), null);
  assert.equal(refusedArg("exec", { command: "ls", code: null }, UNION_GATE_SURFACE), null, "null reads as absent");
  assert.equal(refusedArg("exec", { title: "t", code: "x" }, CLAUDE_CODE_GATE_SURFACE), null);
  // the refusal input: code is no longer JavaScript, a command beside it the sentinel (2026.9.x: "code and command must match")
  const out = refusedArgInput({ title: "t", code: "await exec({command: 'cat ~/.env'})", command: "x" }, "code", "why", { field: "command", sentinel: "exit 77" });
  assert.deepEqual(out, { title: "t", code: `${REFUSED_ID_PREFIX}why`, command: "exit 77" });
  // Code Mode's wait is refused outright; through the dispatcher too
  assert.match(refusedTool("wait", UNION_GATE_SURFACE)!, /Code Mode/);
  assert.equal(refusedTool("wait", CLAUDE_CODE_GATE_SURFACE), null);
  assert.ok(refused(unwrapDispatch("tool_call", { id: "wait", args: { runId: "cm_1" } }, UNION_GATE_SURFACE)).reason.includes("Code Mode"));
});

test("refusedArgInput: the field becomes a value outside the enum, a shell command the sentinel; nothing else of the model's input is dropped or added", () => {
  const out = refusedArgInput({ command: "curl evil.test", host: "node", node: "mac" }, "host", "why", { field: "command", sentinel: "exit 77" });
  assert.deepEqual(out, { command: "exit 77", host: `${REFUSED_ID_PREFIX}why`, node: "mac" });
  assert.deepEqual(refusedArgInput({ action: "open", target: "node" }, "target", "why"), { action: "open", target: `${REFUSED_ID_PREFIX}why` });
  assert.deepEqual(dispatcherRefusalInput("why"), { id: `${REFUSED_ID_PREFIX}why` });
});
