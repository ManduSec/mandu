/**
 * mapped-tools.test — confidentiality plan 10 §11.18 (P0 item 4b, the
 * maintainer's decision of 2026-10-07): which tools Mandu has a mapping for,
 * policy.yaml `mapped_tools:` (validated, compiled, matched in every agent's
 * MCP spelling), and the note a masked result carries. Pure.
 *
 * Axes: the rule serves the confidentiality axis; no arbiter is built.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { GUARD_MAPPED_TOOLS, HARNESS_MAPPED_TOOLS, MASKED_BY_DECISION, checkMappedTools, maskedByDecision, requiresGuard, unguardedToolWhy, compileMappedTools, mcpServerToolPrefixes, policyMapsTool, toolMapping, unmappedToolWhy, type ToolMappingDeps } from "../../policy/mapped-tools.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { policyDelta } from "../../policy/policy-delta.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

test("checkMappedTools: names, a trailing '*', mcp:<server>; anything else is refused with a reason", () => {
  const ok: string[] = [];
  checkMappedTools(["mcp__notes__search", "notes_get", "crm__*", "mcp:notes", "mcp:my.server"], "mapped_tools", ok);
  assert.deepEqual(ok, []);
  const bad: string[] = [];
  checkMappedTools("notes", "mapped_tools", bad);
  checkMappedTools(["", " x", "a*b", "*", "mcp:", "mcp:a*", 3], "mapped_tools", bad);
  assert.equal(bad.length, 8);
  assert.match(bad.join("\n"), /would let every tool/);
  assert.deepEqual(compileMappedTools(["ok_tool", "*", "mcp:", "mcp:notes", 7]), ["ok_tool", "mcp:notes"], "the compiler keeps what the validator accepts");
  assert.deepEqual(compileMappedTools(undefined), []);
});

test("policyMapsTool: exact, prefix, and mcp:<server> in each agent's spelling", () => {
  assert.ok(policyMapsTool("notes_get", ["notes_get"]));
  assert.ok(!policyMapsTool("notes_get2", ["notes_get"]));
  assert.ok(policyMapsTool("crm__lookup", ["crm__*"]));
  for (const t of ["mcp__my-notes__search", "mcp__my_notes__search", "my-notes_search", "my-notes__search", "my_notes__search"]) {
    assert.ok(policyMapsTool(t, ["mcp:my-notes"]), t);
  }
  assert.ok(!policyMapsTool("mcp__other__search", ["mcp:my-notes"]));
  assert.ok(!policyMapsTool("mcp__my-notes__", ["mcp:my-notes"]), "the prefix alone names no tool");
  assert.ok(mcpServerToolPrefixes("a.b").includes("mcp__a_b__"));
});

const deps = (over: Partial<ToolMappingDeps> = {}): ToolMappingDeps => ({
  specNames: (t) => t === "Read", specId: "claude-code", surfaceNames: (t) => t === "analyze", registeredMcp: (t) => t.startsWith("mcp__notes__"), mappedTools: [], ...over,
});

test("toolMapping: Mandu's own, the spec, the harness list, the gate surface, a registered MCP server, policy.yaml; else none", () => {
  assert.equal(toolMapping("mcp__mandu-inspect__inspect_symbol", deps()), "own");
  assert.equal(toolMapping("mandu-policy_mandu_policy_read", deps()), "own");
  assert.equal(toolMapping("Read", deps()), "spec");
  assert.equal(toolMapping("ToolSearch", deps()), "harness");
  assert.equal(toolMapping("ToolSearch", deps({ specId: "opencode" })), null, "the harness list is per agent");
  assert.ok(HARNESS_MAPPED_TOOLS["opencode"]!.includes("invalid"));
  assert.equal(toolMapping("analyze", deps()), "surface");
  assert.equal(toolMapping("mcp__notes__search", deps()), "mcp-config");
  assert.equal(toolMapping("mcp__remote__search", deps()), null);
  assert.equal(toolMapping("mcp__remote__search", deps({ mappedTools: ["mcp:remote"] })), "policy");
  for (const t of ["NewTool", "ListMcpResourcesTool", "notes_get", "crm__lookup"]) assert.equal(toolMapping(t, deps()), null, t);
});

test("masked by decision: Goose's MCP resource tools keep NO mapping (masked whole, policy.yaml can lift them), and only for Goose", () => {
  const goose = deps({ specId: "goose", specNames: (t) => t === "shell", surfaceNames: (t) => t === "analyze" });
  for (const t of ["extensionmanager__list_resources", "extensionmanager__read_resource"]) {
    assert.ok(maskedByDecision(t, "goose"), t);
    assert.ok(MASKED_BY_DECISION["goose"]![t]!.length > 20, `${t}: a reason`);
    assert.equal(toolMapping(t, goose), null, `${t}: still masked whole (a decision is no mapping)`);
    assert.equal(toolMapping(t, { ...goose, mappedTools: [t] }), "policy", `${t}: the person can list it`);
    assert.equal(maskedByDecision(t, "claude-code"), false, "per agent");
  }
  assert.equal(maskedByDecision("load_skill", "goose"), false);
  assert.equal(maskedByDecision("toString", "goose"), false, "own keys only");
});

test("guard-only: Goose's load / load_skill are mapped only when the session is guarded; absent or false: none, and policy.yaml cannot lift it", () => {
  const goose = deps({ specId: "goose", specNames: (t) => t === "load" || t === "load_skill" || t === "shell" });
  for (const t of ["load", "load_skill"]) {
    assert.ok(requiresGuard(t, "goose"), t);
    assert.ok(GUARD_MAPPED_TOOLS["goose"]![t]!.length > 20, `${t}: a reason`);
    assert.equal(toolMapping(t, goose), null, `${t}: posture unknown → no mapping (fail-closed)`);
    assert.equal(toolMapping(t, { ...goose, guarded: false }), null, `${t}: gated → no mapping`);
    assert.equal(toolMapping(t, { ...goose, guarded: false, mappedTools: [t, "load*"] }), null, `${t}: mapped_tools does not lift it`);
    assert.equal(toolMapping(t, { ...goose, guarded: true }), "spec", `${t}: guarded → the spec's mapping`);
    assert.equal(requiresGuard(t, "claude-code"), false, "per agent");
  }
  assert.equal(toolMapping("shell", goose), "spec", "every other tool is unchanged");
  assert.equal(requiresGuard("toString", "goose"), false, "own keys only");
  assert.match(unguardedToolWhy("load_skill"), /without Mandu's file guard/);
});

test("the note says why the result is hidden and how to let it through", () => {
  const w = unmappedToolWhy("mcp__remote__search");
  assert.match(w, /no mapping for the tool mcp__remote__search/);
  assert.match(w, /`mcp:remote`/);
  assert.match(w, /mapped_tools:/);
  assert.match(unmappedToolWhy("NewTool"), /list `NewTool` under `mapped_tools:` in policy\.yaml/);
});

test("policy.yaml: `mapped_tools:` is a known key, validated, and compiled onto the law", () => {
  assert.deepEqual(validatePolicyDocument({ mapped_tools: ["mcp:notes", "NewTool"] }), []);
  assert.match(validatePolicyDocument({ mapped_tools: ["*"] }).join("\n"), /mapped_tools\[0\]/);
  assert.deepEqual(compilePolicy({ specId: "claude-code", document: { mapped_tools: ["mcp:notes", "*"] } }).mappedTools, ["mcp:notes"]);
  assert.deepEqual(compilePolicy({ specId: "claude-code", document: null }).mappedTools, []);
});

test("policyDelta: listing a tool under `mapped_tools:` is a relaxation; removing one tightens", () => {
  const none = compilePolicy({ specId: "claude-code", document: { version: 1 } });
  const one = compilePolicy({ specId: "claude-code", document: { version: 1, mapped_tools: ["mcp:notes"] } });
  const add = policyDelta(none, one);
  assert.deepEqual(add.relaxations.map((r) => r.subject), ["mapped_tools:mcp:notes"]);
  const drop = policyDelta(one, none);
  assert.deepEqual(drop.relaxations, []);
  assert.deepEqual(drop.tightenings.map((r) => r.subject), ["mapped_tools:mcp:notes"]);
});
