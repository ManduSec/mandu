/**
 * unmapped-tool-mask.test.ts — confidentiality plan 10 §11.18 (P0 item 4b,
 * the maintainer's decision of 2026-10-07) over the real IPC: `callTaint`
 * with an `unmappedTool` answers `evidence: "unmapped"` (masked whole at
 * `no-model`, with the note) for a tool the arbiter has no mapping for,
 * whatever the session read, and empty for a tool it has one for: the
 * session's spec, its harness list, its gate surface, Mandu's own tools,
 * policy.yaml `mapped_tools:`; a registered MCP server and a proxy-named
 * built-in keep the session rule. With the confidentiality axis off nothing
 * is masked. MASTER: every unmapped tool with no command got an empty answer.
 *
 * Axes stated per server: `secrets`, and `off` for the control.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { compilePolicy, resetCurrentPolicyForTests, swapCurrentPolicy } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

afterEach(() => { resetCurrentPolicyForTests("claude-code"); });

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-unmapped-"));
  const sock = join(dir, "a.sock");
  const human = join(dir, "human", "h.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const h = new ArbiterClient(human); await h.connect();
  return { data, h, done: async () => { data.close(); h.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

let n = 0;
const ask = (c: ArbiterClient, tool: string, session: string, extra: { builtin?: boolean; command?: string } = {}) =>
  c.callTaint(`call-${++n}`, { unmappedTool: tool, session, ...extra });

test("Claude Code: a tool with no mapping is masked whole in a session that read nothing; the spec's, the harness's and Mandu's own are not", async () => {
  const k = await stack(true);
  try {
    for (const tool of ["NewTool", "ListMcpResourcesTool", "ReadMcpResourceTool", "mcp__remote__search"]) {
      const r = await ask(k.h, tool, "s-cc");
      // MASTER: { level: null } (no command, no raw read in the session)
      assert.equal(r.evidence, "unmapped", `${tool}: ${JSON.stringify(r)}`);
      assert.equal(r.level, "no-model");
      assert.match(r.why ?? "", new RegExp(`no mapping for the tool ${tool}.*mapped_tools`));
    }
    for (const tool of ["Read", "Grep", "WebFetch", "ToolSearch", "mcp__mandu-inspect__inspect_symbol", "mcp__mandu-policy__mandu_policy_read", "mcp__mandu-inspect__declassify_symbol"]) {
      const r = await ask(k.h, tool, "s-cc");
      assert.equal(r.level, null, `${tool}: ${JSON.stringify(r)}`);
      assert.equal(r.evidence, undefined, tool);
    }
  } finally { await k.done(); }
});

test("a registered MCP server and a proxy-named built-in keep the session rule; policy.yaml `mapped_tools:` lets a tool through", async () => {
  const k = await stack(true);
  try {
    await k.h.registerMcpServers("s-reg", [{ name: "notes", command: "notes-mcp", args: [] }]);
    const reg = await ask(k.h, "mcp__notes__search", "s-reg");
    assert.equal(reg.level, null, "registered: no raw read in the session, nothing to mask");
    assert.notEqual(reg.evidence, "unmapped");
    await k.h.taintProcessSecret({ procKey: "psql-1", path: "/h/.pgpass", level: "no-model", app: "psql", session: "s-reg" });
    assert.equal((await ask(k.h, "mcp__notes__search", "s-reg")).evidence, "session", "registered: the session rule (§11.13 (c))");
    assert.equal((await ask(k.h, "wait", "s-reg", { builtin: true })).evidence, "session", "a built-in keeps the session rule");
    assert.equal((await ask(k.h, "wait", "s-reg")).evidence, "unmapped", "not named a built-in: no mapping");

    swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: { mapped_tools: ["NewTool", "mcp:remote"] } }));
    for (const tool of ["NewTool", "mcp__remote__search"]) {
      const r = await ask(k.h, tool, "s-reg");
      assert.equal(r.level, null, `${tool} listed: ${JSON.stringify(r)}`);
    }
    assert.equal((await ask(k.h, "OtherTool", "s-reg")).evidence, "unmapped");
  } finally { await k.done(); }
});

test("each agent's session: its spec and gate surface map its own tools; an MCP or extension tool is masked whole", async () => {
  const k = await stack(true);
  try {
    const cases: Array<[string, string[], string[]]> = [
      ["opencode", ["read", "bash", "webfetch", "invalid", "mandu-inspect_inspect_symbol"], ["notes_get", "leaktool"]],
      ["goose", ["shell", "tree", "analyze", "read_image", "summarize__summarize", "list_functions", "mandu-policy__mandu_policy_read"], ["crm__lookup", "memory__retrieve_memories", "extensionmanager__read_resource"]],
      ["openclaw-agent", ["read", "exec", "tool_search", "browser"], ["plugin_lookup"]],
    ];
    for (const [spec, mapped, unmapped] of cases) {
      const session = `s-${spec}`;
      assert.equal((await k.data.setSessionSpec({ sessionKey: session, spec, requestedBy: "unmapped-tool-mask" })).bound, spec);
      for (const tool of mapped) assert.notEqual((await ask(k.h, tool, session)).evidence, "unmapped", `${spec} ${tool}`);
      for (const tool of unmapped) assert.equal((await ask(k.h, tool, session)).evidence, "unmapped", `${spec} ${tool}`);
    }
  } finally { await k.done(); }
});

test("the confidentiality axis off: nothing is masked for being unmapped", async () => {
  stateAxes("off");
  const k = await stack(false);
  try {
    const r = await ask(k.h, "NewTool", "s-off");
    assert.equal(r.level, null);
    assert.equal(r.evidence, undefined);
  } finally { await k.done(); stateAxes("secrets"); }
});
