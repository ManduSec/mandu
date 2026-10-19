/**
 * unmapped-tool-mask (unit) — confidentiality plan 10 §11.18 (P0 item 4b,
 * the maintainer's decision of 2026-10-07) in the anthropic-proxy's request
 * rewrite, which serves Claude Code, OpenCode, OpenClaw and Goose: every
 * result of a tool that is not the agent's shell is asked about
 * (`callTaint{unmappedTool}`), and a tool the arbiter has no mapping for is
 * masked WHOLE (one symbol) whatever the session read, with the arbiter's
 * note on why and how to let it through. MASTER: a tool with no command and
 * no `mcp__` prefix was never asked, and reached the model raw.
 *
 * The mock plays the arbiter's answer (server.ts callTaint): empty for a
 * tool it has a mapping for (KNOWN), `evidence: "unmapped"` for any other.
 *
 * Axes: `secrets`, stated through the mock (classify TRUSTED with no level,
 * integrity off; callTaint as the arbiter answers it with the
 * confidentiality axis on).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, McpServerTaintWire } from "../../src/arbiter-client.js";
import { CLAUDE_CODE_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const ROWS = "card | 4411-5522-6633-7744";
const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
const why = (tool: string): string => `Mandu has no mapping for the tool ${tool}, so its whole result is hidden from the AI: it may carry a secret no check of Mandu's can see. To let it through, list \`${tool}\` under \`mapped_tools:\` in policy.yaml`;
const UNMAPPED = (tool: string): CallTaintWire => ({ ...EMPTY, level: "no-model", evidence: "unmapped", why: why(tool) });
const trusted = () => ({ trust: "TRUSTED" as const, category: null, reason: "mock: integrity off" });

function arbiterKnowing(known: readonly string[], extra: { mcpServerTaintFn?: () => McpServerTaintWire } = {}) {
  const asked: Array<{ tool?: string; command?: string }> = [];
  const arbiter = new MockArbiter({
    classifyFn: trusted,
    ...extra,
    callTaintFn: (r) => {
      asked.push({ tool: r.unmappedTool, command: r.command });
      return r.unmappedTool !== undefined && !known.includes(r.unmappedTool) ? UNMAPPED(r.unmappedTool) : EMPTY;
    },
  });
  return { arbiter, asked };
}

function turn(name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-sonnet-5",
    messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => JSON.stringify((r.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);

const OPENCODE: GateSurface = { ...CLAUDE_CODE_GATE_SURFACE, spec: "opencode", exec: { bash: "command" }, execOutput: { bash: "command" }, net: {}, paths: { read: { fields: ["filePath"], mode: "read" } } };
const GOOSE: GateSurface = { ...CLAUDE_CODE_GATE_SURFACE, spec: "goose", exec: { shell: "command" }, execOutput: { shell: "command" }, net: {}, paths: {} };

test("Claude Code: a tool with no mapping is masked whole in a session that read nothing; a tool the spec names is asked and forwarded", async () => {
  for (const name of ["NewTool", "ListMcpResourcesTool", "McpResourceRead"]) {
    const { arbiter, asked } = arbiterKnowing(["Read"]);
    const { request } = await rewriteRequest(turn(name, { q: "x" }, ROWS), { arbiter, sessionKey: "s" });
    // MASTER: raw (no command, no `mcp__` prefix: never asked; the resource tools only with a raw read)
    assert.ok(!forwarded(request).includes("4411-5522"), `${name}: CONFIDENTIALITY: a tool Mandu has no mapping for reached the model raw`);
    assert.match(forwarded(request), /\$MDU:/);
    assert.match(forwarded(request), new RegExp(`no mapping for the tool ${name}.*mapped_tools`));
    assert.deepEqual(asked, [{ tool: name, command: undefined }]);
  }
  const { arbiter, asked } = arbiterKnowing(["Read"]);
  const read = await rewriteRequest(turn("Read", { file_path: "/w/a.md" }, ROWS), { arbiter, sessionKey: "s" });
  assert.ok(forwarded(read.request).includes("4411-5522"), "a tool the spec names: forwarded");
  assert.deepEqual(asked, [{ tool: "Read", command: undefined }]);
});

test("Claude Code: an MCP tool of no registered server is masked whole; a clean registered server is not asked; a tainted one is masked", async () => {
  const verdict = (v: McpServerTaintWire["verdict"]) => (): McpServerTaintWire => ({ verdict: v, candidates: v === "clean" ? 1 : 0, level: v === "tainted" ? "no-model" : null, files: v === "tainted" ? ["/h/.npmrc"] : [], apps: v === "tainted" ? ["node"] : [], ...(v === "unmapped" ? {} : { server: "store" }) });
  const un = arbiterKnowing([], { mcpServerTaintFn: verdict("unmapped") });
  const masked = await rewriteRequest(turn("mcp__remote__search", { q: "x" }, ROWS), { arbiter: un.arbiter, sessionKey: "s" });
  assert.ok(!forwarded(masked.request).includes("4411-5522"), "CONFIDENTIALITY: an unmapped MCP tool's result reached the model raw");
  assert.match(forwarded(masked.request), /mcp__remote__search/);
  const clean = arbiterKnowing([], { mcpServerTaintFn: verdict("clean") });
  const raw = await rewriteRequest(turn("mcp__store__get", { key: "rows" }, ROWS), { arbiter: clean.arbiter, sessionKey: "s" });
  assert.ok(forwarded(raw.request).includes("4411-5522"), "a server proven clean is forwarded");
  assert.deepEqual(clean.asked, []);
  const dirty = arbiterKnowing([], { mcpServerTaintFn: verdict("tainted") });
  const t = await rewriteRequest(turn("mcp__store__get", { key: "rows" }, ROWS), { arbiter: dirty.arbiter, sessionKey: "s" });
  assert.ok(!forwarded(t.request).includes("4411-5522"));
});

test("OpenCode and Goose: an MCP or extension tool no config named is masked whole; the spec's tools are forwarded; the shell keeps its process ask", async () => {
  const oc = arbiterKnowing(["read"]);
  const mcp = await rewriteRequest(turn("notes_get", { key: "rows" }, ROWS), { arbiter: oc.arbiter, sessionKey: "s", surface: OPENCODE });
  assert.ok(!forwarded(mcp.request).includes("4411-5522"), "CONFIDENTIALITY: an OpenCode MCP tool's result reached the model raw");
  const read = await rewriteRequest(turn("read", { filePath: "/w/a.md" }, ROWS), { arbiter: oc.arbiter, sessionKey: "s", surface: OPENCODE });
  assert.ok(forwarded(read.request).includes("4411-5522"));
  const sh = arbiterKnowing([]);
  await rewriteRequest(turn("bash", { command: "ls" }, "a.txt"), { arbiter: sh.arbiter, sessionKey: "s", surface: OPENCODE });
  assert.deepEqual(sh.asked, [{ tool: undefined, command: "ls" }], "the shell is asked about its process tree, never as unmapped");
  const g = arbiterKnowing(["shell", "analyze"]);
  const ext = await rewriteRequest(turn("crm__lookup", { id: "7" }, ROWS), { arbiter: g.arbiter, sessionKey: "s", surface: GOOSE });
  assert.ok(!forwarded(ext.request).includes("4411-5522"), "CONFIDENTIALITY: a Goose extension's result reached the model raw");
  const an = await rewriteRequest(turn("analyze", { path: "/w" }, ROWS), { arbiter: g.arbiter, sessionKey: "s", surface: GOOSE });
  assert.ok(forwarded(an.request).includes("4411-5522"), "a tool the gate surface maps is forwarded");
});

test("fail-closed: an ask that throws masks; an answer with no note still says how to let it through", async () => {
  const broken = new MockArbiter({ classifyFn: trusted, callTaintFn: () => { throw new Error("socket closed"); } });
  const thrown = await rewriteRequest(turn("NewTool", { q: "x" }, ROWS), { arbiter: broken, sessionKey: "s" });
  assert.ok(!forwarded(thrown.request).includes("4411-5522"), "a throw masks");
  const bare = new MockArbiter({ classifyFn: trusted, callTaintFn: () => ({ ...EMPTY, level: "no-model", evidence: "unmapped" }) });
  const b = await rewriteRequest(turn("NewTool", { q: "x" }, ROWS), { arbiter: bare, sessionKey: "s" });
  assert.ok(!forwarded(b.request).includes("4411-5522"));
  assert.match(forwarded(b.request), /mapped_tools/);
});
