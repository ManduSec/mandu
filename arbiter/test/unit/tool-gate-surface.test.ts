/**
 * tool-gate-surface — the per-agent gate tables (policy/tool-gate-surface.ts)
 * and the `gateSurface` IPC op.
 *
 * The OpenCode / OpenClaw tables are pinned against the tools[] CAPTURED from
 * a real request on opencode 1.18.32 / openclaw 2026.6.35
 * (test/fixtures/agent-tool-schemas-2026-09-27.json): keying a field the agent
 * does not send is a silent gate miss, the exact regression the table closes.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CLAUDE_CODE_GATE_SURFACE,
  GOOSE_GATE_SURFACE,
  OPENCLAW_GATE_SURFACE,
  OPENCODE_GATE_SURFACE,
  UNION_GATE_SURFACE,
  gateSurfaceFor,
  gateSurfaceForSpec,
  unionSurfaces,
} from "../../policy/tool-gate-surface.js";
import { INBOUND_SPEC_IDS, bindSessionSpec, clearSessionSpecs, getToolInboundSpec } from "../../policy/tool-inbound.js";
import { OPENCLAW_AGENT_INBOUND_SPEC } from "../../policy/openclaw-inbound.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // the IPC leg builds an arbiter; the tables are axis-independent

afterEach(() => clearSessionSpecs());

const here = dirname(fileURLToPath(import.meta.url));
const wire = JSON.parse(readFileSync(join(here, "..", "fixtures", "agent-tool-schemas-2026-09-27.json"), "utf8")) as {
  opencode: { tools: Record<string, string[]> };
  openclaw: { tools: Record<string, string[]> };
};

/** OpenClaw's later captures (2026.7.1, 2026.9.6 with and without Tool
 *  Search): a tool the 2026.6.35 capture lacks is pinned against the newest
 *  build that advertises it. */
const openclawLater = JSON.parse(readFileSync(join(here, "..", "fixtures", "openclaw-tool-surface-2026-09-27.json"), "utf8")) as Record<string, Record<string, string[]>>;
for (const [build, tools] of Object.entries(openclawLater)) {
  if (build === "__doc__") continue;
  for (const [tool, fields] of Object.entries(tools)) wire.openclaw.tools[tool] ??= fields;
}

/** OpenCode 2 (npm `@opencode/cli` 2.0.23, captured 2026-10-05): one table
 *  serves both generations, so the OpenCode wire the table is pinned against
 *  is 1.18.32's and 2.0.23's together (a tool both send keeps every field
 *  either sends: `read.filePath` from 1.x, `read.path` from 2.x). */
const opencode2Capture = JSON.parse(readFileSync(join(here, "..", "fixtures", "opencode2-tool-surface-2026-10-05.json"), "utf8")) as Record<string, unknown>;
const opencode2Wire = opencode2Capture["2.0.23"] as Record<string, string[]>;
const opencode1Wire: Record<string, string[]> = { ...wire.opencode.tools };
for (const [tool, fields] of Object.entries(opencode2Wire)) {
  wire.opencode.tools[tool] = [...new Set([...(wire.opencode.tools[tool] ?? []), ...fields])];
}

/** Tools a table maps that the captured build did not advertise, with why. */
const NOT_IN_CAPTURE: Record<string, string> = {
  // (opencode:websearch was here: registry-conditional and off in 1.18.32;
  // OpenCode 2.0.23 advertises it by default, so the merged wire has it.)
};

function everyField(table: typeof OPENCODE_GATE_SURFACE): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const [t, f] of Object.entries(table.exec)) out.push([t, f]);
  for (const [t, f] of Object.entries(table.execOutput)) if (t !== "process") out.push([t, f]);
  for (const [t, n] of Object.entries(table.net)) {
    if (n.destination) out.push([t, n.destination]);
    out.push([t, n.symbols]);
    for (const f of n.alsoDestinations ?? []) out.push([t, f]);
  }
  for (const [t, p] of Object.entries(table.paths)) for (const f of p.fields) out.push([t, f]);
  for (const [t, p] of Object.entries(table.patch)) out.push([t, p.field]);
  return out;
}

/** Path fields a table reads that no captured or package-read surface lists,
 *  with why. */
const FIELD_NOT_IN_CAPTURE: Record<string, string> = {
  "openclaw:read.file_path": "the alias read accepts (openclaw-inbound.ts header), not in the schema",
  "openclaw:write.file_path": "the same alias on write",
  "openclaw:edit.file_path": "the same alias on edit",
};

for (const [agent, table] of [["opencode", OPENCODE_GATE_SURFACE], ["openclaw", OPENCLAW_GATE_SURFACE]] as const) {
  test(`${agent}: every tool and field the gate table reads (net, further destinations, paths, patch) is on the captured wire`, () => {
    const tools = wire[agent].tools;
    for (const [tool, field] of everyField(table)) {
      if (NOT_IN_CAPTURE[`${agent}:${tool}`]) continue;
      if (FIELD_NOT_IN_CAPTURE[`${agent}:${tool}.${field}`]) continue;
      assert.ok(tools[tool], `${agent} advertised no tool '${tool}'`);
      assert.ok(tools[tool]!.includes(field), `${agent} ${tool} has no input field '${field}' (captured: ${tools[tool]!.join(", ")})`);
    }
  });
}

test("openclaw `process` (a background exec session's output) is an exec-output tool: no command field on the wire, so the command read is simply absent", () => {
  assert.ok(wire.openclaw.tools["process"], "captured");
  assert.ok(!wire.openclaw.tools["process"]!.includes("command"));
  assert.equal(OPENCLAW_GATE_SURFACE.execOutput["process"], "command");
});

/** Gated tools the inbound spec leaves unmapped on purpose: they read local
 *  files named in reference arrays, and only an unmapped tool gets the input
 *  scan that raises its result's level for every labeled path it names
 *  (openclaw-inbound.ts, DELIBERATELY UNMAPPED). The path gate reads those
 *  arrays too since 2026-09-29, but only absolute (or placeable) paths and
 *  only with the view map, so the scan stays. */
const GATED_BUT_UNMAPPED = new Set([
  "openclaw-agent:pdf", "openclaw-agent:image_generate", "openclaw-agent:music_generate", "openclaw-agent:video_generate",
  // Goose's in-process file readers (goose-inbound.ts, DELIBERATELY UNMAPPED)
  "goose:analyze", "goose:read_image", "goose:computercontroller__docx_tool", "goose:computercontroller__xlsx_tool",
  "goose:computercontroller__pdf_tool", "goose:summarize__summarize",
]);

test("every gated tool of an agent is also a tool its inbound spec maps (the gate and the trust spec name the same agent)", () => {
  for (const [spec, table] of [["opencode", OPENCODE_GATE_SURFACE], ["openclaw-agent", OPENCLAW_GATE_SURFACE], ["goose", GOOSE_GATE_SURFACE]] as const) {
    bindSessionSpec("s", spec);
    for (const tool of [...Object.keys(table.exec), ...Object.keys(table.net), ...Object.keys(table.paths)]) {
      if (GATED_BUT_UNMAPPED.has(`${spec}:${tool}`)) {
        assert.equal(getToolInboundSpec(tool, "s"), undefined, `${spec}: ${tool} stays unmapped`);
        continue;
      }
      assert.ok(getToolInboundSpec(tool, "s"), `${spec}: ${tool} has no inbound rule`);
    }
    clearSessionSpecs();
  }
});

test("Claude Code: the constants the proxy hard-coded before the table moved here, plus Monitor and TaskOutput (plan 10 §11.12)", () => {
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.exec, { Bash: "command", Monitor: "command" });
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.execOutput, { Bash: "command", BashOutput: "command", TaskOutput: "command", Monitor: "command" });
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.net, {
    WebFetch: { destination: "url", symbols: "url" },
    WebSearch: { destination: null, symbols: "query" },
  });
  assert.deepEqual(Object.keys(CLAUDE_CODE_GATE_SURFACE.paths).sort(), ["Edit", "Glob", "Grep", "LS", "MultiEdit", "NotebookEdit", "Read", "Write"]);
});

test("session resolution: bound spec first, else the process-global spec (the same resolution classify uses)", () => {
  assert.equal(gateSurfaceFor().spec, "claude-code");
  assert.equal(gateSurfaceFor("unbound").spec, "claude-code");
  bindSessionSpec("oc", "opencode");
  bindSessionSpec("ocl", "openclaw-agent");
  assert.deepEqual(gateSurfaceFor("oc").exec, { bash: "command", shell: "command" });
  assert.deepEqual(gateSurfaceFor("ocl").exec, { exec: "command" });
  assert.deepEqual(gateSurfaceFor("ocl").paths["read"], { fields: ["path", "file_path"], mode: "read" });
});

test("FAIL-CLOSED default: a spec with no gate table gets the union, a superset of every agent's table", () => {
  for (const id of INBOUND_SPEC_IDS) {
    const s = gateSurfaceForSpec(id);
    assert.equal(s.spec, id);
  }
  for (const id of ["fail-closed", "agentdojo"] as const) {
    const s = gateSurfaceForSpec(id);
    for (const table of [CLAUDE_CODE_GATE_SURFACE, OPENCODE_GATE_SURFACE, OPENCLAW_GATE_SURFACE]) {
      for (const [t, f] of Object.entries(table.exec)) assert.equal(s.exec[t], f, `${id}: exec ${t}`);
      for (const t of Object.keys(table.net)) assert.ok(s.net[t], `${id}: net ${t}`);
      for (const [t, p] of Object.entries(table.paths)) {
        for (const f of p.fields) assert.ok(s.paths[t]!.fields.includes(f), `${id}: ${t}.${f}`);
      }
    }
  }
});

test("union merge: fields accumulate per tool, a mode conflict resolves to write, a checkable destination wins over none", () => {
  const u = unionSurfaces(
    { exec: {}, execOutput: {}, net: { f: { destination: null, symbols: "q", alsoDestinations: ["a"] } }, paths: { read: { fields: ["filePath"], mode: "read" } }, dispatch: { d: "openclaw-tool-call" }, refuse: {}, refuseArgs: { x: [{ field: "host", allow: ["a", "b"], reason: "r1" }] }, stdin: {}, patch: {} },
    { exec: {}, execOutput: {}, net: { f: { destination: "url", symbols: "url", alsoDestinations: ["a", "b"], block: "refuse" } }, paths: { read: { fields: ["path"], mode: "write", refs: "media" } }, dispatch: { d: "refuse" }, refuse: {}, refuseArgs: { x: [{ field: "host", allow: ["b"], reason: "r2" }] }, stdin: { p: "openclaw-process" }, patch: { ap: { field: "input", format: "apply-patch" } } },
  );
  // every further destination either names is checked; media references are read where either reads them
  assert.deepEqual(u.net["f"]!.alsoDestinations, ["a", "b"]);
  assert.equal(u.paths["read"]!.refs, "media");
  assert.deepEqual(u.patch, { ap: { field: "input", format: "apply-patch" } });
  assert.deepEqual(u.paths["read"], { fields: ["filePath", "path"], mode: "write", refs: "media" });
  // a whole-input refusal on a block wins over a field rewrite
  assert.deepEqual(u.net["f"], { destination: "url", symbols: "q", alsoDestinations: ["a", "b"], block: "refuse" });
  // every agent's form rules apply (together: only "b" passes both)
  assert.deepEqual(u.refuseArgs["x"]!.map((r) => r.reason), ["r1", "r2"]);
  assert.equal(u.stdin["p"], "openclaw-process");
  assert.deepEqual(UNION_GATE_SURFACE.paths["read"]!.fields, ["filePath", "path", "file_path"]);
  // two agents dispatching one name differently: the stricter reading wins
  assert.equal(u.dispatch["d"], "refuse");
});

test("OpenClaw's Tool Search dispatcher is a dispatch entry (supported-agents.md §2.1): tool_call is unwrapped, tool_search_code refused; only Goose's and OpenCode 2's code mode also dispatch", () => {
  assert.deepEqual(OPENCLAW_GATE_SURFACE.dispatch, { tool_call: "openclaw-tool-call", tool_search_code: "refuse" });
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.dispatch, {});
  assert.deepEqual(OPENCODE_GATE_SURFACE.dispatch, { execute: "refuse" });
  assert.deepEqual(UNION_GATE_SURFACE.dispatch, { ...OPENCODE_GATE_SURFACE.dispatch, ...OPENCLAW_GATE_SURFACE.dispatch, ...GOOSE_GATE_SURFACE.dispatch });
  assert.deepEqual(gateSurfaceForSpec("openclaw-agent").dispatch, OPENCLAW_GATE_SURFACE.dispatch);
  // every dispatcher the captured surfaces advertise is in the table
  const captured = JSON.parse(readFileSync(new URL("../fixtures/openclaw-tool-surface-2026-09-27.json", import.meta.url), "utf8")) as Record<string, unknown>;
  for (const [ver, tools] of Object.entries(captured)) {
    if (ver === "__doc__") continue;
    for (const t of Object.keys(tools as object)) {
      if (t === "tool_call" || t === "tool_search_code") assert.ok(OPENCLAW_GATE_SURFACE.dispatch[t], `${ver}: ${t}`);
    }
  }
});

test("the gateSurface op over real IPC answers the session's bound spec (read-only, data plane)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gate-surface-ipc-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "s.sqlite"), eventDir: join(tmp, "events"), log: () => {} });
  await server.listen();
  const c = new ArbiterClient(socketPath);
  await c.connect();
  try {
    assert.equal((await c.gateSurface()).spec, "claude-code");
    await c.setSessionSpec({ sessionKey: "ipc-oc", spec: "opencode" });
    const s = await c.gateSurface("ipc-oc");
    assert.equal(s.spec, "opencode");
    assert.deepEqual(s.net["webfetch"], { destination: "url", symbols: "url" });
    // an unknown spec binds fail-closed, whose surface is the union
    await c.setSessionSpec({ sessionKey: "ipc-x", spec: "no-such-agent" });
    const x = await c.gateSurface("ipc-x");
    assert.equal(x.spec, "fail-closed");
    assert.equal(x.exec["bash"], "command");
    assert.equal(x.exec["Bash"], "command");
  } finally {
    c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** Why `{action: "mandu-refused: …"}` fails each refused tool's schema (read
 *  from 2026.7.1 / 2026.9.6; the field must be on the captured or
 *  package-read surface). OpenClaw validates every call against the tool's
 *  schema before it runs (validateToolArguments). */
const REFUSAL_FAILS: Record<string, { field: string; why: "action enum" | "required" | "no extra keys" }> = {
  terminal: { field: "action", why: "action enum" },
  automations: { field: "action", why: "action enum" },
  cron: { field: "action", why: "action enum" },
  gateway: { field: "action", why: "action enum" },
  plugins: { field: "action", why: "action enum" },
  secrets: { field: "action", why: "action enum" },
  portal: { field: "action", why: "action enum" },
  nodes: { field: "action", why: "action enum" },
  computer: { field: "action", why: "action enum" },
  mobile_ui: { field: "action", why: "action enum" },
  canvas: { field: "action", why: "action enum" },
  sessions_send: { field: "message", why: "required" },
  sessions_spawn: { field: "task", why: "required" },
  openclaw: { field: "message", why: "required" },
  github_publish: { field: "title", why: "no extra keys" },
  // Code Mode's resume tool (2026.7.1, 2026.9.6 and 2026.9.9 captures): the
  // refusal's input has no runId ("must have required properties runId",
  // observed on 2026.9.9).
  wait: { field: "runId", why: "required" },
};

test("openclaw: every refused tool is on a captured or package-read surface, with the field that makes the refusal's input fail its schema; conversations_send/turn are net tools on `message`", () => {
  assert.deepEqual(Object.keys(OPENCLAW_GATE_SURFACE.refuse).sort(), Object.keys(REFUSAL_FAILS).sort());
  for (const tool of Object.keys(OPENCLAW_GATE_SURFACE.refuse)) {
    assert.ok(wire.openclaw.tools[tool], `${tool} advertised by a captured build or read from the package`);
    assert.ok(wire.openclaw.tools[tool]!.includes(REFUSAL_FAILS[tool]!.field), `${tool} takes ${REFUSAL_FAILS[tool]!.field}`);
    assert.ok(OPENCLAW_GATE_SURFACE.refuse[tool]!.length > 20, "the reason is words the model can act on");
  }
  assert.deepEqual(OPENCLAW_GATE_SURFACE.net["conversations_send"], { destination: null, symbols: "message" });
  assert.deepEqual(OPENCLAW_GATE_SURFACE.net["conversations_turn"], { destination: null, symbols: "message" });
  // the union refuses what any agent refuses; Claude Code and OpenCode refuse nothing
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.refuse, {});
  assert.deepEqual(OPENCODE_GATE_SURFACE.refuse, {});
  assert.deepEqual(UNION_GATE_SURFACE.refuse, { ...OPENCLAW_GATE_SURFACE.refuse, ...GOOSE_GATE_SURFACE.refuse });
  assert.deepEqual(unionSurfaces(CLAUDE_CODE_GATE_SURFACE, { ...OPENCODE_GATE_SURFACE, refuse: { x: "a" } }).refuse, { x: "a" });
});

test("openclaw: exec{host} and browser{target} are refused outside the box's values; the fields are on the wire", () => {
  assert.deepEqual(OPENCLAW_GATE_SURFACE.refuseArgs["exec"]!.map((r) => [r.field, [...r.allow]]),
    [["host", ["", "auto", "sandbox", "gateway"]], ["code", []], ["language", []]]);
  assert.deepEqual(OPENCLAW_GATE_SURFACE.refuseArgs["browser"]!.map((r) => [r.field, [...r.allow]]), [["target", ["", "sandbox", "host"]]]);
  assert.ok(wire.openclaw.tools["exec"]!.includes("host"));
  assert.ok(wire.openclaw.tools["browser"]!.includes("target"));
  for (const rules of Object.values(OPENCLAW_GATE_SURFACE.refuseArgs)) {
    for (const r of rules) assert.ok(!r.allow.includes("node"), "node is never an allowed value");
  }
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.refuseArgs, {});
  assert.deepEqual(UNION_GATE_SURFACE.refuseArgs, { ...OPENCODE_GATE_SURFACE.refuseArgs, ...OPENCLAW_GATE_SURFACE.refuseArgs, ...GOOSE_GATE_SURFACE.refuseArgs });
});

test("openclaw Code Mode: exec{code} / exec{language} are refused by form, on fields only Code Mode's exec has; wait is refused outright", () => {
  const shell = openclawLater["2026.9.9"]!["exec"]!;
  const code99 = openclawLater["2026.9.9+codeMode=true"]!;
  const code96 = openclawLater["2026.9.6+codeMode=true"]!;
  const code71 = openclawLater["2026.7.1+codeMode=true"]!;
  // Code Mode's surface: exec + wait in place of the tools (2026.9.x keeps
  // sessions_yield and view_image beside them)
  assert.deepEqual(Object.keys(code71).sort(), ["exec", "wait"]);
  assert.deepEqual(Object.keys(code99).sort(), ["exec", "sessions_yield", "view_image", "wait"]);
  assert.deepEqual(code96, code99);
  const rules = OPENCLAW_GATE_SURFACE.refuseArgs["exec"]!;
  const empty = rules.filter((r) => r.allow.length === 0).map((r) => r.field);
  assert.deepEqual(empty, ["code", "language"]);
  for (const f of empty) {
    assert.ok(!shell.includes(f), `the shell exec never sends ${f}: refusing it costs a shell call nothing`);
    assert.ok(!(openclawLater["2026.9.6"]!["exec"]!).includes(f));
  }
  assert.ok(code99["exec"]!.includes("code") && code71["exec"]!.includes("code"), "every Code Mode exec takes code");
  assert.ok(code71["exec"]!.includes("language"), "2026.7.1's takes language (and command, its alias for code)");
  for (const r of rules.filter((x) => x.allow.length === 0)) assert.match(r.reason, /Code Mode/);
  assert.ok(Object.hasOwn(OPENCLAW_GATE_SURFACE.refuse, "wait"));
  assert.match(OPENCLAW_GATE_SURFACE.refuse["wait"]!, /Code Mode/);
  // only OpenClaw refuses a tool named wait
  assert.ok(!Object.hasOwn(GOOSE_GATE_SURFACE.refuse, "wait") && !Object.hasOwn(OPENCODE_GATE_SURFACE.refuse, "wait"));
});

test("openclaw 2026.9.9: every tool it advertises, in each Tool Search mode and in Code Mode, has an inbound rule, is refused (outright or by form), or is a dispatcher", () => {
  const handled = (t: string): boolean =>
    OPENCLAW_AGENT_INBOUND_SPEC[t] !== undefined ||
    Object.hasOwn(OPENCLAW_GATE_SURFACE.refuse, t) ||
    Object.hasOwn(OPENCLAW_GATE_SURFACE.dispatch, t);
  for (const build of ["2026.9.9", "2026.9.9+toolSearch=false", "2026.9.9+toolSearch=directory", "2026.9.9+codeMode=true", "2026.9.6+codeMode=true", "2026.7.1+codeMode=true"]) {
    const tools = openclawLater[build];
    assert.ok(tools, `${build} captured`);
    const missing = Object.keys(tools).filter((t) => !handled(t));
    assert.deepEqual(missing, [], `unhandled on ${build}: ${missing.join(", ")}`);
  }
  // what 2026.9.9 adds over 2026.9.6: presence (toolSearch false), read-only
  // gateway presence whose names and activity remote clients report
  const added = Object.keys(openclawLater["2026.9.9+toolSearch=false"]!).filter((t) => !openclawLater["2026.9.6+toolSearch=false"]![t]);
  assert.deepEqual(added, ["presence"]);
  assert.deepEqual(OPENCLAW_AGENT_INBOUND_SPEC["presence"], { schema: "UNTRUSTED" });
  assert.equal(OPENCLAW_GATE_SURFACE.net["presence"], undefined, "presence sends nothing");
});

test("openclaw: process types into a background exec session (stdin table), and its typed fields are on the wire", () => {
  assert.deepEqual(OPENCLAW_GATE_SURFACE.stdin, { process: "openclaw-process" });
  for (const f of ["data", "text", "literal", "keys", "hex"]) assert.ok(wire.openclaw.tools["process"]!.includes(f), f);
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.stdin, {});
  assert.deepEqual(UNION_GATE_SURFACE.stdin, { process: "openclaw-process" });
});

test("openclaw: the full-profile senders are net tools whose block refuses the whole input", () => {
  for (const tool of ["message", "show_widget", "x_search", "code_execution", "image_generate", "music_generate", "video_generate", "tts", "pdf", "browser"]) {
    assert.equal(OPENCLAW_GATE_SURFACE.net[tool]?.block, "refuse", tool);
    assert.equal(UNION_GATE_SURFACE.net[tool]?.block, "refuse", `union ${tool}`);
  }
  assert.equal(OPENCLAW_GATE_SURFACE.net["browser"]!.destination, "targetUrl");
  // the tools the proxy already rewrote by field keep that behavior
  for (const tool of ["web_fetch", "web_search", "conversations_send"]) assert.equal(OPENCLAW_GATE_SURFACE.net[tool]!.block, undefined, tool);
  assert.equal(CLAUDE_CODE_GATE_SURFACE.net["WebSearch"]!.block, undefined);
});

// ── the gate-surface residue (supported-agents.md §5.5 item 4, closed 2026-09-29) ──

test("residue: apply_patch's input is a patch the proxy parses; only OpenClaw has one, and the union carries it", () => {
  assert.deepEqual(OPENCLAW_GATE_SURFACE.patch, { apply_patch: { field: "input", format: "apply-patch" } });
  assert.deepEqual(wire.openclaw.tools["apply_patch"], ["input"], "the captured schema: one text field");
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.patch, {});
  assert.deepEqual(OPENCODE_GATE_SURFACE.patch, {});
  assert.deepEqual(UNION_GATE_SURFACE.patch, OPENCLAW_GATE_SURFACE.patch);
  assert.deepEqual(gateSurfaceForSpec("fail-closed").patch, OPENCLAW_GATE_SURFACE.patch, "a session with no table gets it too");
});

test("residue: the shell's working directory is a path read (exec.workdir, bash.workdir), never a write the derived label would stamp", () => {
  assert.deepEqual(OPENCLAW_GATE_SURFACE.paths["exec"], { fields: ["workdir"], mode: "read" });
  assert.deepEqual(OPENCODE_GATE_SURFACE.paths["bash"], { fields: ["workdir"], mode: "read" });
  assert.ok(wire.openclaw.tools["exec"]!.includes("workdir"));
  assert.ok(wire.opencode.tools["bash"]!.includes("workdir"));
  assert.deepEqual(OPENCODE_GATE_SURFACE.paths["shell"], { fields: ["workdir"], mode: "read" }, "OpenCode 2's shell");
  assert.ok(opencode2Wire["shell"]!.includes("workdir"));
  // the shell stays the exec gate's (its command field unchanged)
  assert.equal(OPENCLAW_GATE_SURFACE.exec["exec"], "command");
  assert.equal(OPENCODE_GATE_SURFACE.exec["bash"], "command");
  assert.deepEqual(UNION_GATE_SURFACE.paths["exec"], { fields: ["workdir"], mode: "read" });
  assert.deepEqual(UNION_GATE_SURFACE.paths["bash"], { fields: ["workdir"], mode: "read" });
});

test("residue: image and view_image send each reference to a provider (no destination) and fetch its URLs (further destinations); their local references are media paths", () => {
  assert.deepEqual(OPENCLAW_GATE_SURFACE.net["image"], { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" });
  assert.deepEqual(OPENCLAW_GATE_SURFACE.net["view_image"], { destination: null, symbols: "prompt", alsoDestinations: ["path", "paths"], block: "refuse" });
  assert.deepEqual(OPENCLAW_GATE_SURFACE.paths["image"], { fields: ["image", "images"], mode: "read", refs: "media" });
  assert.deepEqual(OPENCLAW_GATE_SURFACE.paths["view_image"], { fields: ["path", "paths"], mode: "read", refs: "media" });
  for (const f of ["prompt", "image", "images"]) assert.ok(wire.openclaw.tools["image"]!.includes(f), `image.${f}`);
  for (const f of ["prompt", "path", "paths"]) assert.ok(wire.openclaw.tools["view_image"]!.includes(f), `view_image.${f}`);
});

test("residue: browser reads `url` when targetUrl is absent (a further destination) and uploads the local files in `paths` (an array path field)", () => {
  assert.deepEqual(OPENCLAW_GATE_SURFACE.net["browser"], { destination: "targetUrl", symbols: "targetUrl", alsoDestinations: ["url"], block: "refuse" });
  assert.deepEqual(OPENCLAW_GATE_SURFACE.paths["browser"], { fields: ["path", "paths"], mode: "write" });
  for (const f of ["targetUrl", "url", "path", "paths"]) assert.ok(wire.openclaw.tools["browser"]!.includes(f), `browser.${f}`);
  assert.deepEqual(UNION_GATE_SURFACE.net["browser"]!.alsoDestinations, ["url"]);
});

test("residue: the gateSurface op answers the new fields over real IPC (the proxy's parser reads them off this wire)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gate-surface-residue-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "s.sqlite"), eventDir: join(tmp, "events"), log: () => {} });
  await server.listen();
  const c = new ArbiterClient(socketPath);
  await c.connect();
  try {
    await c.setSessionSpec({ sessionKey: "ipc-ocl", spec: "openclaw-agent" });
    const s = await c.gateSurface("ipc-ocl");
    assert.deepEqual(s.patch, { apply_patch: { field: "input", format: "apply-patch" } });
    assert.deepEqual(s.net["image"]!.alsoDestinations, ["image", "images"]);
    assert.equal(s.paths["image"]!.refs, "media");
    assert.deepEqual(s.paths["exec"], { fields: ["workdir"], mode: "read" });
    const cc = await c.gateSurface();
    assert.deepEqual(cc.patch, {}, "Claude Code has no patch tool");
  } finally {
    c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── follow-up: the media tools' arrays, and the relative-path base ───────────

test("pdf and the media generators: every reference field, string and array, is a media path and a further destination (fields on the package-read surface)", () => {
  const want: Record<string, string[]> = {
    pdf: ["pdf", "pdfs"],
    image_generate: ["image", "images"],
    music_generate: ["image", "images"],
    video_generate: ["image", "images", "video", "videos", "audioRef", "audioRefs"],
  };
  for (const [tool, fields] of Object.entries(want)) {
    assert.deepEqual(OPENCLAW_GATE_SURFACE.paths[tool], { fields, mode: "read", refs: "media" }, tool);
    assert.deepEqual(OPENCLAW_GATE_SURFACE.net[tool]!.alsoDestinations, fields, tool);
    assert.equal(OPENCLAW_GATE_SURFACE.net[tool]!.destination, null, `${tool}: the provider leg names no destination`);
    for (const f of fields) assert.ok(wire.openclaw.tools[tool]!.includes(f), `${tool}.${f}`);
  }
});

test("relativeBase: OpenCode and OpenClaw (its workspace, pinned to the launch directory) resolve relative paths against the launch directory; Claude Code and the union claim no base", () => {
  assert.equal(OPENCODE_GATE_SURFACE.relativeBase, "launch");
  assert.equal(OPENCLAW_GATE_SURFACE.relativeBase, "launch", "the launcher names the directory only where it pins the workspace");
  assert.equal(CLAUDE_CODE_GATE_SURFACE.relativeBase, undefined, "follows the shell's cd");
  assert.equal(UNION_GATE_SURFACE.relativeBase, undefined);
  assert.equal(gateSurfaceForSpec("opencode").relativeBase, "launch");
  assert.equal(gateSurfaceForSpec("openclaw-agent").relativeBase, "launch");
  assert.equal(gateSurfaceForSpec("fail-closed").relativeBase, undefined);
  assert.equal(unionSurfaces(OPENCODE_GATE_SURFACE).relativeBase, "launch", "one agent that claims it");
  assert.equal(unionSurfaces(OPENCODE_GATE_SURFACE, OPENCLAW_GATE_SURFACE).relativeBase, "launch", "both claim it");
  assert.equal(unionSurfaces(OPENCODE_GATE_SURFACE, CLAUDE_CODE_GATE_SURFACE).relativeBase, undefined, "any agent without it: unknown");
  assert.equal(unionSurfaces().relativeBase, undefined);
});

test("replyMedia: only OpenClaw attaches files its reply names (`MEDIA:` lines, fixtures/openclaw-media-lines-2026-10-17.json); a resolved surface always says (null for none), and the union reads every reply", () => {
  const fixture = JSON.parse(readFileSync(join(here, "..", "fixtures", "openclaw-media-lines-2026-10-17.json"), "utf8")) as { builds: string[] };
  assert.deepEqual(fixture.builds, ["2026.7.1", "2026.9.9"]);
  assert.equal(OPENCLAW_GATE_SURFACE.replyMedia, "openclaw-media-lines");
  for (const t of [CLAUDE_CODE_GATE_SURFACE, OPENCODE_GATE_SURFACE, GOOSE_GATE_SURFACE]) assert.equal(t.replyMedia, undefined);
  assert.equal(gateSurfaceForSpec("openclaw-agent").replyMedia, "openclaw-media-lines");
  assert.equal(gateSurfaceForSpec("openclaw").replyMedia, "openclaw-media-lines");
  assert.equal(gateSurfaceForSpec("claude-code").replyMedia, null, "an explicit none, so the proxy can tell it from an older arbiter");
  assert.equal(gateSurfaceForSpec("opencode").replyMedia, null);
  assert.equal(JSON.parse(JSON.stringify(gateSurfaceForSpec("goose"))).replyMedia, null, "null survives the wire");
  assert.equal(UNION_GATE_SURFACE.replyMedia, "openclaw-media-lines");
  assert.equal(gateSurfaceForSpec("fail-closed").replyMedia, "openclaw-media-lines", "a session no table names: every reply is read");
  assert.equal(unionSurfaces(CLAUDE_CODE_GATE_SURFACE, OPENCODE_GATE_SURFACE).replyMedia, undefined);
});

// ── Goose (goose 1.53.0, captured 2026-10-05; supported-agents.md §5.6) ──────

/** Every capture entry of goose-tool-surface-2026-10-05.json merged: the
 *  default surface, a subagent's, each opt-in builtin's additions, code mode,
 *  and the U-LLM mount. */
const gooseCapture = JSON.parse(readFileSync(join(here, "..", "fixtures", "goose-tool-surface-2026-10-05.json"), "utf8")) as Record<string, Record<string, string[]>>;
const gooseWire: Record<string, string[]> = {};
for (const [build, tools] of Object.entries(gooseCapture)) {
  if (build === "__doc__") continue;
  for (const [tool, fields] of Object.entries(tools)) gooseWire[tool] ??= fields;
}

/** Goose tools a table names that no captured surface advertises, with why. */
const GOOSE_NOT_IN_CAPTURE: Record<string, string> = {
  scheduler__manage_schedule: "the scheduler extension advertises no tool under run or session (hidden; it needs `serve --enable-scheduler`); refused by name in case a later build does",
  computercontroller__computer_control: "macOS-only (computercontroller/mod.rs cfg(target_os = \"macos\")); the capture ran on Linux",
};

test("goose: every tool and field the gate table reads is on the captured 1.53.0 wire", () => {
  for (const [tool, field] of everyField(GOOSE_GATE_SURFACE)) {
    assert.ok(gooseWire[tool], `goose advertised no tool '${tool}'`);
    assert.ok(gooseWire[tool]!.includes(field), `goose ${tool} has no input field '${field}' (captured: ${gooseWire[tool]!.join(", ")})`);
  }
  for (const [tool, rules] of Object.entries(GOOSE_GATE_SURFACE.refuseArgs)) {
    for (const r of rules) assert.ok(gooseWire[tool]!.includes(r.field), `goose ${tool}.${r.field}`);
  }
  for (const tool of Object.keys(GOOSE_GATE_SURFACE.dispatch)) assert.ok(gooseWire[tool], `goose dispatcher ${tool} is captured`);
});

test("goose: the shell is the exec tool and its output the exec-output class; there is no file-read tool to map", () => {
  assert.deepEqual(GOOSE_GATE_SURFACE.exec, { shell: "command" });
  assert.deepEqual(GOOSE_GATE_SURFACE.execOutput, { shell: "command" });
  assert.deepEqual(gooseWire["shell"], ["command", "timeout_secs"]);
  for (const t of Object.keys(gooseWire)) assert.ok(!/^(read|read_file|cat|view)$/.test(t), `${t}: an unexpected file reader`);
  assert.equal(GOOSE_GATE_SURFACE.relativeBase, "launch");
  assert.equal(gateSurfaceForSpec("goose").relativeBase, "launch");
});

test("goose: read_image is a net tool on `source` and a media path read on the same field", () => {
  assert.deepEqual(GOOSE_GATE_SURFACE.net, { read_image: { destination: "source", symbols: "source" } });
  assert.deepEqual(GOOSE_GATE_SURFACE.paths["read_image"], { fields: ["source"], mode: "read", refs: "media" });
  assert.deepEqual(UNION_GATE_SURFACE.net["read_image"], { destination: "source", symbols: "source" });
});

test("goose: code mode's execute_typescript is refused as a dispatcher (decision D4); list_functions and get_function_details only read", () => {
  assert.deepEqual(GOOSE_GATE_SURFACE.dispatch, { execute_typescript: "refuse" });
  assert.deepEqual(gooseWire["execute_typescript"], ["code", "tool_graph"]);
  assert.ok(!gooseWire["execute_bash"], "1.53.0 has no execute_bash");
  assert.equal(UNION_GATE_SURFACE.dispatch["execute_typescript"], "refuse");
});

/** Why `{action: "mandu-refused: …"}` fails each refused Goose tool (probed
 *  on 1.53.0 for the captured ones: apps "Missing or invalid 'prd'" /
 *  "'name'", manage_extensions "unknown variant"; the orchestrator's
 *  required fields from the captured schema; delete_app probed on 1.53.0
 *  and 1.54.0 on 2026-10-09: "Error: Missing or invalid 'name'", the
 *  desktop's default app still there). */
const GOOSE_REFUSAL_FAILS: Record<string, string> = {
  extensionmanager__manage_extensions: "action",
  apps__create_app: "prd",
  apps__iterate_app: "name",
  apps__delete_app: "name",
  orchestrator__start_agent: "working_dir",
  orchestrator__send_message: "message",
  orchestrator__interrupt_agent: "session_id",
};

test("goose: every refused tool is captured (or explained), with the field that makes the refusal input fail; the reasons are words the model can act on", () => {
  assert.deepEqual(Object.keys(GOOSE_GATE_SURFACE.refuse).sort(), [...Object.keys(GOOSE_REFUSAL_FAILS), ...Object.keys(GOOSE_NOT_IN_CAPTURE)].sort());
  for (const [tool, field] of Object.entries(GOOSE_REFUSAL_FAILS)) {
    assert.ok(gooseWire[tool], `${tool} captured`);
    assert.ok(gooseWire[tool]!.includes(field), `${tool} takes ${field}`);
  }
  for (const tool of Object.keys(GOOSE_NOT_IN_CAPTURE)) assert.ok(!gooseWire[tool], `${tool}: now captured, move it to GOOSE_REFUSAL_FAILS`);
  for (const r of Object.values(GOOSE_GATE_SURFACE.refuse)) assert.ok(r.length > 20);
  // the harmless reads of the same extensions stay callable
  for (const t of ["apps__list_apps", "extensionmanager__search_available_extensions", "orchestrator__list_sessions", "orchestrator__view_session"]) {
    assert.ok(!GOOSE_GATE_SURFACE.refuse[t], t);
  }
});

test("goose: a delegate naming a provider or a source is refused; every other delegate runs, its working_dir gated as a read", () => {
  assert.deepEqual(GOOSE_GATE_SURFACE.refuseArgs["delegate"]!.map((r) => [r.field, [...r.allow]]), [["provider", [""]], ["source", [""]]]);
  assert.deepEqual(GOOSE_GATE_SURFACE.paths["delegate"], { fields: ["working_dir"], mode: "read" });
  for (const f of ["provider", "source", "working_dir", "instructions"]) assert.ok(gooseWire["delegate"]!.includes(f), f);
  assert.deepEqual(UNION_GATE_SURFACE.refuseArgs["delegate"], GOOSE_GATE_SURFACE.refuseArgs["delegate"]);
});

test("goose: the U-LLM mount's captured spelling is the one inspect-tool.ts recognizes", () => {
  const mount = gooseCapture["1.53.0 --with-extension mandu-inspect:<cmd>"]!;
  assert.deepEqual(Object.keys(mount).sort(), ["mandu-inspect__declassify_symbol", "mandu-inspect__inspect_symbol"]);
});

test("goose: the gateSurface op answers the Goose table for a session bound to `goose`", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gate-surface-goose-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "s.sqlite"), eventDir: join(tmp, "events"), log: () => {} });
  await server.listen();
  const c = new ArbiterClient(socketPath);
  await c.connect();
  try {
    await c.setSessionSpec({ sessionKey: "ipc-goose", spec: "goose" });
    const s = await c.gateSurface("ipc-goose");
    assert.equal(s.spec, "goose");
    assert.deepEqual(s.exec, { shell: "command" });
    assert.deepEqual(s.dispatch, { execute_typescript: "refuse" });
    assert.deepEqual(s.refuseArgs["delegate"]!.map((r) => r.field), ["provider", "source"]);
    assert.equal(s.relativeBase, "launch");
  } finally {
    c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── OpenCode 2 (2.0.23, captured 2026-10-05; supported-agents.md §2.3) ──────

test("opencode 2: every advertised tool is gated, mapped by the inbound spec, or refused; only `execute` (code mode) is unknown to the spec, and it is a refusing dispatcher", () => {
  bindSessionSpec("oc2", "opencode");
  const names = Object.keys(opencode2Wire);
  assert.deepEqual([...names].sort(), ["edit", "execute", "glob", "grep", "question", "read", "shell", "skill", "subagent", "webfetch", "websearch", "write"]);
  for (const t of names) {
    if (t === "execute") continue;
    assert.ok(getToolInboundSpec(t, "oc2"), `${t} has an inbound rule`);
  }
  assert.equal(getToolInboundSpec("execute", "oc2"), undefined, "execute stays unmapped (fail-closed UNTRUSTED)");
  assert.equal(OPENCODE_GATE_SURFACE.dispatch["execute"], "refuse");
  assert.deepEqual(opencode2Wire["execute"], ["code"], "the refusal input {code: …} is the tool's own shape");
  // a subagent's child session advertises a subset of the main surface (no question, no subagent)
  const child = opencode2Capture["2.0.23 subagent"] as Record<string, string[]>;
  for (const [t, f] of Object.entries(child)) assert.deepEqual(f, opencode2Wire[t], `child ${t}`);
  assert.ok(!child["subagent"] && !child["question"]);
});

test("opencode 2: the renamed tools keep OpenCode 1's gates (shell is bash, `path` is filePath), in one table for both", () => {
  assert.equal(OPENCODE_GATE_SURFACE.exec["shell"], "command");
  assert.equal(OPENCODE_GATE_SURFACE.execOutput["shell"], "command");
  assert.equal(OPENCODE_GATE_SURFACE.exec["bash"], "command", "OpenCode 1 still gated");
  for (const [tool, mode] of [["read", "read"], ["write", "write"], ["edit", "write"]] as const) {
    assert.deepEqual(OPENCODE_GATE_SURFACE.paths[tool], { fields: ["filePath", "path"], mode }, tool);
    assert.ok(opencode1Wire[tool]!.includes("filePath") && !opencode1Wire[tool]!.includes("path"), `1.x ${tool} sends filePath`);
    assert.ok(opencode2Wire[tool]!.includes("path") && !opencode2Wire[tool]!.includes("filePath"), `2.x ${tool} sends path`);
  }
  for (const tool of ["glob", "grep"]) assert.ok(opencode2Wire[tool]!.includes("path"), `2.x ${tool}.path`);
  assert.deepEqual(OPENCODE_GATE_SURFACE.net["webfetch"], { destination: "url", symbols: "url" });
  assert.deepEqual(OPENCODE_GATE_SURFACE.net["websearch"], { destination: null, symbols: "query" });
  // question, skill and subagent name no path, URL or command: no gate reads
  // them (the inbound spec classifies their results; subagent's forms are refuseArgs)
  for (const t of ["question", "skill", "subagent"]) {
    for (const k of ["exec", "net", "paths"] as const) assert.equal(OPENCODE_GATE_SURFACE[k][t], undefined, `${k} ${t}`);
  }
  assert.equal(OPENCODE_GATE_SURFACE.relativeBase, "launch");
});

test("opencode 2: background shells and subagents and a subagent's own model are refused forms; each field is on the 2.x wire; false passes", () => {
  const rules = (t: string): Array<[string, string[]]> => OPENCODE_GATE_SURFACE.refuseArgs[t]!.map((r) => [r.field, [...r.allow]]);
  assert.deepEqual(rules("shell"), [["background", ["", "false"]]]);
  assert.deepEqual(rules("subagent"), [["model", [""]], ["background", ["", "false"]]]);
  for (const [tool, list] of Object.entries(OPENCODE_GATE_SURFACE.refuseArgs)) {
    for (const r of list) {
      assert.ok(opencode2Wire[tool]!.includes(r.field), `${tool}.${r.field} is on the wire`);
      assert.ok(r.reason.length > 40, "the reason is words the model can act on");
    }
  }
  // why background is refused: the capture shows its output arriving as a USER TEXT, not a tool_result
  const results = opencode2Capture["__results__"] as Array<{ tool: string; input?: Record<string, unknown>; content: unknown }>;
  const notes = results.filter((r) => r.tool === "(user text: background notification)").map((r) => String(r.content));
  assert.ok(notes.some((n) => n.startsWith("<shell id=") && n.includes("bgdone")), "a background shell's output came back as user text");
  assert.ok(notes.some((n) => n.startsWith("<subagent sessionID=") && n.includes("subagent says hi")), "a background subagent's answer too");
  // and why a refused model value fails the call without running a child session
  const refusedModel = results.find((r) => r.tool === "subagent" && String(r.input?.["model"] ?? "").startsWith("mandu-refused: "));
  assert.match(String(refusedModel?.content), /Invalid model/);
  // the code-mode refusal's shape: a thrown error is the whole result
  const thrown = results.find((r) => r.tool === "execute" && String(r.input?.["code"]).startsWith("throw new Error("));
  assert.equal(thrown?.content, "Error: mandu: refused here");
});

test("opencode 2: the union (a session with no table) carries OpenCode 2's names, forms and dispatcher too", () => {
  const u = gateSurfaceForSpec("fail-closed");
  assert.equal(u.exec["shell"], "command");
  assert.deepEqual(u.paths["shell"], { fields: ["workdir"], mode: "read" });
  assert.ok(u.paths["read"]!.fields.includes("path") && u.paths["read"]!.fields.includes("filePath"));
  assert.equal(u.dispatch["execute"], "refuse");
  assert.deepEqual(u.refuseArgs["subagent"]!.map((r) => r.field), ["model", "background"]);
  assert.deepEqual(u.refuseArgs["shell"]!.map((r) => r.field), ["background"]);
});

// ── Claude Code 2.1.292: DesignSync uploads local files (supported-agents.md §2) ──

/** DesignSync's tool definition as 2.1.292 advertised it (captured against a
 *  stub upstream that errors every request; no key, no model). */
const designSync = JSON.parse(readFileSync(join(here, "..", "fixtures", "claude-design-sync-tool-2026-10-07.json"), "utf8")) as {
  name: string;
  input_schema: {
    required: string[];
    additionalProperties: boolean;
    properties: Record<string, { enum?: string[]; items?: { properties: Record<string, unknown>; additionalProperties: boolean } }>;
  };
};

const CC_UPLOAD = {
  DesignSync: "claude-design-sync", Artifact: "claude-artifact", ArtifactData: "claude-artifact-data", ArtifactComments: "claude-artifact-comments",
};

test("DesignSync is Claude Code's upload tool; the fields the proxy reads are on the captured 2.1.292 wire, and its refusal input fails the schema", () => {
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.upload, CC_UPLOAD);
  assert.equal(designSync.name, "DesignSync");
  const props = designSync.input_schema.properties;
  // the methods upload-gate.ts reads, the plan's base, each file's local path and inline bytes
  for (const m of ["finalize_plan", "write_files"]) assert.ok(props["method"]!.enum!.includes(m), m);
  assert.ok(props["localDir"], "finalize_plan names the directory uploads read from");
  assert.ok(props["planId"]);
  const file = props["files"]!.items!;
  for (const f of ["path", "localPath", "data", "encoding"]) assert.ok(f in file.properties, `files[].${f}`);
  assert.equal(file.additionalProperties, false);
  // `{action: "mandu-refused: …"}` names no method and an unknown key: rejected, nothing sent
  assert.deepEqual(designSync.input_schema.required, ["method"]);
  assert.equal(designSync.input_schema.additionalProperties, false);
  assert.ok(!("action" in props));
});

const OPENCLAW_UPLOAD = {
  message: "openclaw-message",
  view_image: "openclaw-media", image: "openclaw-media", pdf: "openclaw-media",
  image_generate: "openclaw-media", music_generate: "openclaw-media", video_generate: "openclaw-media",
  browser: "openclaw-browser-upload",
};

test("the union (a session with no table) carries Claude Code's and OpenClaw's upload kinds; OpenCode and Goose have no upload tool", () => {
  assert.deepEqual(gateSurfaceForSpec("fail-closed").upload, { ...CC_UPLOAD, ...OPENCLAW_UPLOAD });
  for (const t of [OPENCODE_GATE_SURFACE, GOOSE_GATE_SURFACE]) assert.deepEqual(t.upload ?? {}, {});
  assert.deepEqual(gateSurfaceForSpec("claude-code").upload, CC_UPLOAD);
  assert.deepEqual(OPENCLAW_GATE_SURFACE.upload, OPENCLAW_UPLOAD);
  assert.deepEqual(gateSurfaceForSpec("openclaw-agent").upload, OPENCLAW_UPLOAD);
});

// ── OpenClaw's tools that send a local file (supported-agents.md §2.1, "Tools that send a local file") ──

const senders = JSON.parse(readFileSync(join(here, "..", "fixtures", "openclaw-local-file-senders-2026-10-17.json"), "utf8")) as {
  message: { sendSchemaProps: string[]; BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS: string[]; STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS: string[] };
  view_image: { params: string[] };
  image: { params: string[] };
};

test("openclaw upload kinds: each sender is a tool the tables already gate, a media tool's references are its media path fields, and a block refuses the whole input", () => {
  for (const [tool, kind] of Object.entries(OPENCLAW_UPLOAD)) {
    // the net entry refuses the whole input on a block, so a refused upload
    // (`{action: "mandu-refused: …"}`) is the same shape a net block sends
    assert.equal(OPENCLAW_GATE_SURFACE.net[tool]?.block, "refuse", `${tool}: net block refuses whole`);
    if (kind === "openclaw-media") {
      const p = OPENCLAW_GATE_SURFACE.paths[tool];
      assert.ok(p && p.refs === "media" && p.fields.length > 0, `${tool}: its references are media path fields`);
    }
  }
  assert.ok(OPENCLAW_GATE_SURFACE.paths["browser"]!.fields.includes("paths"), "browser upload reads `paths`");
  // the captured schemas carry the reference fields the proxy reads
  assert.deepEqual(OPENCLAW_GATE_SURFACE.paths["view_image"]!.fields.filter((f) => !senders.view_image.params.includes(f)), []);
  assert.deepEqual(OPENCLAW_GATE_SURFACE.paths["image"]!.fields.filter((f) => !senders.image.params.includes(f)), []);
  // message: `media` and `attachments` are schema props; the loader reads
  // the six source params besides (the proxy's openclawUploadRefs pins the rest)
  for (const f of ["media", "attachments", "buffer"]) assert.ok(senders.message.sendSchemaProps.includes(f), f);
  assert.ok(senders.message.BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS.includes("media"));
  assert.ok(senders.message.STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS.includes("media"));
});

// ── OpenCode 1's registry-conditional websearch (read statically from 1.18.13) ──

test("opencode 1 websearch: the field the net gate reads is in the shape read from the 1.18.13 binary, and no field names a destination", () => {
  const ws = JSON.parse(readFileSync(join(here, "..", "fixtures", "opencode-websearch-2026-10-17.json"), "utf8")) as {
    tool: string; params: string[]; required: string[]; destinations: string[];
  };
  assert.equal(ws.tool, "websearch");
  const entry = OPENCODE_GATE_SURFACE.net["websearch"]!;
  assert.deepEqual(entry, { destination: null, symbols: "query" });
  assert.ok(ws.params.includes(entry.symbols) && ws.required.includes(entry.symbols));
  // the hosts are picked by OpenCode (per session), not named by any input field
  for (const p of ws.params) assert.ok(!/url|host|endpoint/i.test(p), p);
  assert.deepEqual(ws.destinations.sort(), ["mcp.exa.ai", "search.parallel.ai"]);
  // OpenCode 2.0.23 sends the same `query`
  assert.ok(opencode2Wire["websearch"]!.includes("query"));
});

// ── Claude Code's interactive Artifact tools (supported-agents.md §2, "Claude Code 2.1.295") ──

/** The five interactive-only tools as 2.1.290 to 2.1.295 advertised them
 *  (the TUI against a stub upstream that errors every request; no key, no
 *  model; the definitions identical in each). */
type CapturedTool = {
  name: string;
  description: string;
  input_schema: {
    required?: string[];
    properties: Record<string, { enum?: string[]; type?: string; anyOf?: unknown[]; items?: { properties: Record<string, unknown> } }>;
  };
};
const artifactTools = JSON.parse(readFileSync(join(here, "..", "fixtures", "claude-artifact-tools-2026-10-09.json"), "utf8")) as CapturedTool[];
const captured = (name: string): CapturedTool => {
  const t = artifactTools.find((x) => x.name === name);
  assert.ok(t, `${name} is in the capture`);
  return t;
};

test("Artifact, ArtifactData, ArtifactComments: the fields the proxy reads are on the captured wire, and each refusal input fails the schema", () => {
  assert.deepEqual(artifactTools.map((t) => t.name).sort(), ["Artifact", "ArtifactComments", "ArtifactData", "EndConversation", "SendFeedback"]);
  // every upload tool takes `action` from an enum: `{action: "mandu-refused: …"}` is rejected, nothing is sent
  for (const name of ["Artifact", "ArtifactData", "ArtifactComments"]) {
    const action = captured(name).input_schema.properties["action"];
    assert.ok(action?.enum && action.enum.length > 0, `${name}.action is an enum`);
    assert.ok(!action.enum.some((v) => v.startsWith("mandu-refused")));
    assert.ok(/claude\.ai/.test(JSON.stringify(captured(name))), `${name} talks to claude.ai`);
  }
  // Artifact: publish reads the page, the supporting files (list or map) against root
  const art = captured("Artifact").input_schema.properties;
  assert.ok(art["action"]!.enum!.includes("publish"));
  for (const f of ["file_path", "files", "root"]) assert.ok(art[f], `Artifact.${f}`);
  assert.equal((art["files"]!.anyOf ?? []).length, 2, "files: a list of {path} or a map of published path → source");
  // ArtifactData: set/update/batch read a local JSON file by file_path
  const data = captured("ArtifactData").input_schema.properties;
  for (const a of ["set", "update", "batch"]) assert.ok(data["action"]!.enum!.includes(a), a);
  assert.ok(data["file_path"]);
  assert.ok("file_path" in data["writes"]!.items!.properties, "writes[].file_path");
  // ArtifactComments sends reply text, no local file
  const com = captured("ArtifactComments").input_schema.properties;
  assert.ok(com["action"]!.enum!.includes("reply"));
  assert.ok(com["text"] && !("file_path" in com));
  // EndConversation and SendFeedback send nothing off the machine (a local feedback draft)
  assert.deepEqual(Object.keys(captured("EndConversation").input_schema.properties), []);
  assert.match(captured("SendFeedback").description, /QUEUED LOCALLY/);
});
