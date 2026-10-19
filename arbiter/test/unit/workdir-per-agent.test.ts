/**
 * workdir-per-agent.test — a `workdir` is believed only on a tool whose AGENT
 * acts on it (2026-10-11, confidentiality.md §6).
 *
 * `callWorkdir` reads a shell call's relative path tokens in the directory
 * the call runs in, so a human label there decides them, in either
 * direction. It used to key that on the tool NAME: `exec_command` and
 * `shell` took their `workdir` param. Goose's tool is also named `shell`, but
 * it has no `workdir` (`shell{command, timeout_secs}`, a `bash -c` in the
 * launch directory), so a `workdir` a Goose model wrote into its call was a
 * claim nothing acted on, and the arbiter believed it, over the directory
 * the kernel had recorded for the call's shell:
 *
 *   - `cat .env` with `workdir` = the directory of a file the human labelled
 *     public (`test/fixtures/.env`): the workspace's secret `.env` took the
 *     public label and reached the model raw;
 *   - `cat vault/k.txt` with `workdir: "/"` in a bound call: the human's
 *     no-model label on the workspace's `vault/` was never looked up.
 *
 * Now the session's gate surface names which of its agent's tools honour a
 * `workdir` (GateSurface `workdir`): Codex's `exec_command` and argv `shell`,
 * OpenCode's `bash` / `shell`; Goose's none. Any other `workdir` is ignored
 * and the kernel's start directory is read instead (else none).
 *
 * Stack twin: tests/stack/relative-read-public-label.test.ts (the forged
 * Goose call over the real arbiter and anthropic-proxy).
 *
 * Run: npx tsx --test test/unit/workdir-per-agent.test.ts
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { callWorkdir, honoursWorkdir, labelForClassify, type LabelLookup, type WorkdirTools } from "../../policy/secret-catalog.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import {
  CLAUDE_CODE_GATE_SURFACE,
  CODEX_WORKDIR_TOOLS,
  GOOSE_GATE_SURFACE,
  OPENCLAW_GATE_SURFACE,
  OPENCODE_GATE_SURFACE,
  UNION_GATE_SURFACE,
  gateSurfaceForSpec,
  unionSurfaces,
} from "../../policy/tool-gate-surface.js";
import { createEngineBackedPolicy, sessionWorkdirTools } from "../../policy/policy-interface.js";
import { bindSessionSpec, clearSessionSpecs } from "../../policy/tool-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality derivation is the code under test

const HOME = "/home/u";
const WS = "/home/u/proj";
const FIXTURES = `${WS}/test/fixtures`;
const here = dirname(fileURLToPath(import.meta.url));

function lookupOver(...rows: Array<Partial<PathLabel> & { path: string }>): LabelLookup {
  const m = new Map<string, PathLabel>();
  for (const r of rows) {
    m.set(r.path, { path: r.path, confidentiality: r.confidentiality ?? "no-model", bindings: [], recursive: r.recursive ?? true, source: "user", updatedAt: 1 });
  }
  return (p) => resolvePathLabel(p, m, HOME);
}

const PUBLIC_FIXTURE = { path: `${FIXTURES}/.env`, confidentiality: "public" as const, recursive: false };
const VAULT = { path: `${WS}/vault`, confidentiality: "no-model" as const, recursive: true };
const GOOSE: WorkdirTools = GOOSE_GATE_SURFACE.workdir!;
/** What the arbiter believed before: every `shell` / `exec_command` workdir. */
const BY_NAME: WorkdirTools = { exec_command: "always", shell: "always" };

/** A Goose `shell` call as the classify handler hands it to the policy:
 *  `callStartDir` only for a call the recorder bound. */
const gooseShell = (command: string, workdir: string, callStartDir?: string, workdirTools: WorkdirTools = GOOSE) =>
  ({ tool: "shell", origin: command, params: { command, workdir }, workdirTools, ...(callStartDir !== undefined ? { callStartDir } : {}) });

afterEach(() => clearSessionSpecs());

// ── the per-agent tables ──────────────────────────────────────────────────────

test("honoursWorkdir: by the agent's table and the call's shape, never by the tool name alone", () => {
  assert.equal(honoursWorkdir("exec_command", { cmd: "x" }, CODEX_WORKDIR_TOOLS), true);
  assert.equal(honoursWorkdir("shell", { command: ["bash", "-lc", "x"] }, CODEX_WORKDIR_TOOLS), true, "Codex's classic shell: an argv command");
  assert.equal(honoursWorkdir("shell", { command: "cat .env" }, CODEX_WORKDIR_TOOLS), false, "a string command is not Codex's shell");
  assert.equal(honoursWorkdir("shell", { command: [] }, CODEX_WORKDIR_TOOLS), false);
  assert.equal(honoursWorkdir("shell", { command: ["bash", 7] }, CODEX_WORKDIR_TOOLS), false);
  assert.equal(honoursWorkdir("shell", undefined, CODEX_WORKDIR_TOOLS), false);
  assert.equal(honoursWorkdir("shell", { command: "cat .env" }, GOOSE), false, "Goose's shell has no workdir");
  assert.equal(honoursWorkdir("shell", { command: ["bash", "-lc", "x"] }, GOOSE), false, "whatever its shape");
  assert.equal(honoursWorkdir("shell", { command: "ls" }, OPENCODE_GATE_SURFACE.workdir!), true, "OpenCode 2's shell runs in its workdir");
  assert.equal(honoursWorkdir("bash", { command: "ls" }, OPENCODE_GATE_SURFACE.workdir!), true, "OpenCode 1's bash too");
  assert.equal(honoursWorkdir("exec", { command: "ls" }, OPENCLAW_GATE_SURFACE.workdir ?? {}), false, "OpenClaw's exec falls back elsewhere when the directory is missing");
  assert.equal(honoursWorkdir("Bash", { command: "ls" }, CLAUDE_CODE_GATE_SURFACE.workdir!), false);
  assert.equal(honoursWorkdir("toString", { command: "ls" }, CODEX_WORKDIR_TOOLS), false, "an inherited name is no entry");
  assert.equal(honoursWorkdir("exec_command", { cmd: "x" }, {}), false, "no table: nothing believed");
});

test("the gate surfaces: Goose honours no workdir, Claude Code's table carries Codex's, a session with no table believes only what every agent honours", () => {
  assert.deepEqual(GOOSE_GATE_SURFACE.workdir, {});
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.workdir, CODEX_WORKDIR_TOOLS);
  assert.deepEqual(gateSurfaceForSpec("goose").workdir, {});
  assert.deepEqual(gateSurfaceForSpec("claude-code").workdir, { exec_command: "always", shell: "argv" });
  assert.deepEqual(gateSurfaceForSpec("opencode").workdir, { bash: "always", shell: "always" });
  assert.deepEqual(UNION_GATE_SURFACE.workdir, {}, "the union of every agent: Goose's shell and OpenClaw honour none");
  assert.deepEqual(gateSurfaceForSpec("fail-closed").workdir, {});
  assert.deepEqual(unionSurfaces(CLAUDE_CODE_GATE_SURFACE, OPENCODE_GATE_SURFACE).workdir, { shell: "argv" }, "both honour shell: the stricter shape");
  assert.deepEqual(unionSurfaces(CLAUDE_CODE_GATE_SURFACE).workdir, CODEX_WORKDIR_TOOLS);
  assert.deepEqual(unionSurfaces().workdir, {});
});

test("every agent table's workdir tool has a `workdir` on its captured wire; Goose's captured shell has none", () => {
  const goose = JSON.parse(readFileSync(join(here, "..", "fixtures", "goose-tool-surface-2026-10-05.json"), "utf8")) as Record<string, Record<string, string[]>>;
  for (const [build, tools] of Object.entries(goose)) {
    if (build === "__doc__" || tools["shell"] === undefined) continue;
    assert.ok(!tools["shell"].includes("workdir"), `goose ${build}: shell has no workdir (${tools["shell"].join(", ")})`);
  }
  assert.deepEqual(goose["1.53.0"]!["shell"], ["command", "timeout_secs"]);
  const oc2 = JSON.parse(readFileSync(join(here, "..", "fixtures", "opencode2-tool-surface-2026-10-05.json"), "utf8")) as Record<string, Record<string, string[]>>;
  const oc1 = JSON.parse(readFileSync(join(here, "..", "fixtures", "agent-tool-schemas-2026-09-27.json"), "utf8")) as { opencode: { tools: Record<string, string[]> } };
  const opencodeWire: Record<string, string[]> = { ...oc1.opencode.tools, ...oc2["2.0.23"] };
  for (const tool of Object.keys(OPENCODE_GATE_SURFACE.workdir!)) {
    assert.ok(opencodeWire[tool]?.includes("workdir"), `opencode ${tool} has a workdir on the wire`);
  }
});

test("sessionWorkdirTools: the session's own agent's table; an unbound session the boot spec's (Claude Code's, which carries Codex's)", () => {
  bindSessionSpec("s-goose", "goose");
  bindSessionSpec("s-oc", "opencode");
  assert.deepEqual(sessionWorkdirTools({ sessionKey: "s-goose" }), {});
  assert.deepEqual(sessionWorkdirTools({ sessionKey: "s-oc" }), { bash: "always", shell: "always" });
  assert.deepEqual(sessionWorkdirTools({ sessionKey: "s-codex" }), CODEX_WORKDIR_TOOLS);
  assert.deepEqual(sessionWorkdirTools({}), CODEX_WORKDIR_TOOLS);
});

// ── the forged workdir, in the derivation ─────────────────────────────────────

test("callWorkdir: a Goose call's workdir is never its base; the kernel's directory is", () => {
  assert.equal(callWorkdir("shell", { command: "cat .env", workdir: FIXTURES }, undefined, WS, GOOSE), WS);
  assert.equal(callWorkdir("shell", { command: "cat .env", workdir: FIXTURES }, undefined, undefined, GOOSE), undefined);
  assert.equal(callWorkdir("shell", { command: "cat .env", workdir: FIXTURES }, "/s", undefined, GOOSE), undefined, "Codex's session default is not Goose's");
  assert.equal(callWorkdir("shell", { command: "cat .env", workdir: FIXTURES }, undefined, WS, BY_NAME), FIXTURES, "the pre-fix reading: the claim beat the kernel");
});

test("Goose: `cat .env` with a workdir forged to the public fixture's directory stays masked, bound or not", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(gooseShell("cat .env", FIXTURES, WS), HOME, lk).level, "no-model", "bound: read where it ran");
  assert.equal(labelForClassify(gooseShell("cat .env", FIXTURES), HOME, lk).level, "no-model", "unbound: the catalog's verdict");
  // the pre-fix reading, pinned so the test proves the fix
  assert.equal(labelForClassify(gooseShell("cat .env", FIXTURES, WS, BY_NAME), HOME, lk).level, "public");
  assert.equal(labelForClassify(gooseShell("cat .env", FIXTURES, undefined, BY_NAME), HOME, lk).level, "public");
});

test("Goose: a bound read under the human's no-model label stays masked whatever workdir the model names", () => {
  const lk = lookupOver(VAULT);
  for (const forged of ["/", "/tmp", FIXTURES, `${HOME}/elsewhere`]) {
    assert.equal(labelForClassify(gooseShell("cat vault/k.txt", forged, WS), HOME, lk).level, "no-model", forged);
  }
  assert.equal(labelForClassify(gooseShell("cat vault/k.txt", "/", WS, BY_NAME), HOME, lk).level, "public", "the pre-fix reading");
});

test("Goose: utility is the kernel's directory's, not the claim's (the public fixture read where it ran is public)", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(gooseShell("cat test/fixtures/.env", "/", WS), HOME, lk).level, "public");
  assert.equal(labelForClassify(gooseShell("cat test/fixtures/.env", WS), HOME, lk).level, "no-model", "unbound, a workdir naming the right place is still only a claim");
});

test("Codex and OpenCode keep the workdir they act on", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  const codexShell = { tool: "shell", origin: "cat .env", params: { command: ["bash", "-lc", "cat .env"], workdir: FIXTURES }, workdirTools: CODEX_WORKDIR_TOOLS };
  assert.equal(labelForClassify(codexShell, HOME, lk).level, "public", "Codex runs it in the fixture directory: that file is the public one");
  const exec = { tool: "exec_command", origin: "cat .env", params: { cmd: "cat .env", workdir: FIXTURES }, workdirTools: CODEX_WORKDIR_TOOLS, callStartDir: WS };
  assert.equal(labelForClassify(exec, HOME, lk).level, "public");
  const oc2 = { tool: "shell", origin: "cat .env", params: { command: "cat .env", workdir: FIXTURES }, workdirTools: OPENCODE_GATE_SURFACE.workdir! };
  assert.equal(labelForClassify(oc2, HOME, lk).level, "public");
});

// ── the engine wrapper: the session's table, never the request's ─────────────

test("classify: a Goose session's forged workdir is not believed; a lost binding (the boot spec) does not believe it either; a caller cannot send a table", () => {
  bindSessionSpec("s-goose", "goose");
  const lk = lookupOver(PUBLIC_FIXTURE, VAULT);
  const policy = createEngineBackedPolicy({ confidentiality: true, integrity: false, labelLookup: lk });
  const ask = (sessionKey: string, command: string, workdir: string, extra: Record<string, unknown> = {}) =>
    policy.classify({ tool: "shell", value: "API_KEY=x", boundary: "model_context", origin: command, sessionKey, params: { command, workdir }, ...extra } as Parameters<typeof policy.classify>[0]);
  assert.equal(ask("s-goose", "cat .env", FIXTURES).confidentiality, "no-model");
  assert.equal(ask("s-goose", "cat vault/k.txt", "/", { callStartDir: WS }).confidentiality, "no-model");
  assert.equal(ask("s-unbound", "cat .env", FIXTURES).confidentiality, "no-model", "a string-command shell in a session with no binding");
  assert.equal(ask("s-goose", "cat .env", FIXTURES, { workdirTools: { shell: "always" } }).confidentiality, "no-model", "a table in the request is ignored");
  // Goose's own reading still works: the kernel's directory decides
  assert.equal(ask("s-goose", "cat test/fixtures/.env", "/", { callStartDir: WS }).confidentiality, "public");
});
