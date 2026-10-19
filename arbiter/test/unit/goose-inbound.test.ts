/**
 * goose-inbound — the Goose trust spec (policy/goose-inbound.ts), held to the
 * tools[] captured from real goose 1.53.0 requests
 * (test/fixtures/goose-tool-surface-2026-10-05.json), and Mandu's own MCP
 * tools under Goose's `<extension key>__<tool>` spelling.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { GOOSE_INBOUND_SPEC } from "../../policy/goose-inbound.js";
import {
  INBOUND_SPEC_IDS,
  bindSessionSpec,
  clearSessionSpecs,
  getToolInboundSpec,
  inboundSpecNamesInput,
  unknownToolNames,
} from "../../policy/tool-inbound.js";
import { MCP_INBOUND_SPEC } from "../../policy/claude-code-inbound.js";
import { INSPECT_TOOL_SPELLINGS, isManduDeclassifyTool, isManduInspectTool } from "../../policy/inspect-tool.js";
import { isManduPolicyTool } from "../../policy/policy-tool.js";
import { destinationKind } from "../../policy/tool-outbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the spec tables are axis-independent

afterEach(() => clearSessionSpecs());

const capture = JSON.parse(readFileSync(new URL("../fixtures/goose-tool-surface-2026-10-05.json", import.meta.url), "utf8")) as Record<string, Record<string, string[]>>;
const DEFAULT_SURFACE = Object.keys(capture["1.53.0"]!);
const ALL_CAPTURED = new Set<string>();
for (const [k, v] of Object.entries(capture)) if (k !== "__doc__") for (const t of Object.keys(v)) ALL_CAPTURED.add(t);

/** The captured default tools the spec leaves unmapped on purpose, with why
 *  (goose-inbound.ts, DELIBERATELY UNMAPPED): the in-process readers the gate
 *  surface reads (their input is scanned), the tools refused on every call,
 *  and the two masked whole by decision. Each fails closed UNTRUSTED; none
 *  is drift (the toolSurface op's answer, test/component/tool-surface.test.ts). */
const UNMAPPED_BY_DESIGN = new Set([
  "analyze", "read_image",
  "apps__create_app", "apps__delete_app", "apps__iterate_app",
  "extensionmanager__list_resources", "extensionmanager__manage_extensions",
  "extensionmanager__read_resource",
]);

test("goose is a registered spec id", () => {
  assert.ok(INBOUND_SPEC_IDS.includes("goose"));
});

test("every mapped tool is a captured 1.53.0 tool (a name off the wire, not from docs)", () => {
  for (const tool of Object.keys(GOOSE_INBOUND_SPEC)) assert.ok(ALL_CAPTURED.has(tool), `${tool} is not on the captured wire`);
});

test("the default surface: mapped exactly where the spec says, and the rest is the declared unmapped set (the session-health list names them)", () => {
  bindSessionSpec("g", "goose");
  const unknown = unknownToolNames(DEFAULT_SURFACE, "g");
  assert.deepEqual(new Set(unknown), UNMAPPED_BY_DESIGN);
  for (const t of DEFAULT_SURFACE) {
    if (!UNMAPPED_BY_DESIGN.has(t)) assert.ok(getToolInboundSpec(t, "g"), t);
  }
});

test("postures: the shell and a subagent's answer are UNTRUSTED; write/edit echoes, tree's names and the todo list are TRUSTED metadata", () => {
  const schemaOf = (t: string): unknown => (GOOSE_INBOUND_SPEC[t] as { schema?: unknown }).schema;
  assert.equal(schemaOf("shell"), "UNTRUSTED");
  assert.equal(schemaOf("delegate"), "UNTRUSTED");
  // recipe, agent and skill bodies are workspace files; a background task's
  // result is a subagent's answer; the registry listings carry descriptions
  // whoever configured the entry wrote (Claude Code's Skill / TaskOutput)
  for (const t of ["load", "load_skill", "apps__list_apps", "extensionmanager__search_available_extensions"]) assert.equal(schemaOf(t), "UNTRUSTED", t);
  for (const t of ["write", "edit", "tree", "todo__todo_write"]) assert.equal(schemaOf(t), "TRUSTED", t);
  // every entry is a whole-result literal: every Goose result is one string on the wire
  for (const t of Object.keys(GOOSE_INBOUND_SPEC)) assert.equal(typeof schemaOf(t), "string", `${t}: no field schema`);
});

test("the spec is session-keyed: Goose's names classify only for a session bound to goose; Claude Code's names are unknown there", () => {
  bindSessionSpec("g", "goose");
  assert.equal(getToolInboundSpec("shell"), undefined, "the claude-code default does not know shell");
  assert.ok(getToolInboundSpec("shell", "g"));
  assert.equal(getToolInboundSpec("Bash", "g"), undefined);
  assert.equal(getToolInboundSpec("Read", "g"), undefined);
});

test("Mandu's own MCP tools under Goose's spelling: inspect, declassify and the policy tools are recognized, look-alikes are not", () => {
  bindSessionSpec("g", "goose");
  assert.ok(INSPECT_TOOL_SPELLINGS.includes("mandu-inspect__inspect_symbol"));
  assert.ok(isManduInspectTool("mandu-inspect__inspect_symbol"));
  assert.ok(isManduDeclassifyTool("mandu-inspect__declassify_symbol"));
  for (const b of ["mandu_policy_read", "mandu_policy_test", "mandu_policy_propose"]) assert.ok(isManduPolicyTool(`mandu-policy__${b}`), b);
  assert.equal(getToolInboundSpec("mandu-inspect__inspect_symbol", "g"), MCP_INBOUND_SPEC);
  assert.equal(getToolInboundSpec("mandu-inspect__declassify_symbol", "g"), MCP_INBOUND_SPEC);
  assert.deepEqual(unknownToolNames(["shell", "mandu-inspect__inspect_symbol", "mandu-inspect__declassify_symbol", "mandu-policy__mandu_policy_read"], "g"), []);
  // the input scan stays on for declassify, as on every agent
  assert.equal(inboundSpecNamesInput("mandu-inspect__declassify_symbol", "g"), false);
  // a third party's MCP tool, or a near miss, is not Mandu's
  for (const t of ["acme__inspect_symbol", "mandu-inspect___inspect_symbol", "mandu_inspect__inspect_symbol", "mandu-policy__mandu_policy_write"]) {
    assert.equal(getToolInboundSpec(t, "g"), undefined, t);
  }
});

test("the outbound map: only the shell's command resolves; the Agent File System tools and read_image keep symbols symbolic", () => {
  bindSessionSpec("g-out", "goose");
  assert.equal(destinationKind("shell", "command", "g-out"), "resolve");
  for (const [tool, field] of [["write", "path"], ["write", "content"], ["edit", "after"], ["tree", "path"], ["read_image", "source"], ["delegate", "instructions"], ["brand_new_goose_tool", "x"]] as const) {
    assert.equal(destinationKind(tool, field, "g-out"), "not_resolve", `${tool}.${field}`);
  }
});
