/**
 * unmapped-exec-taint.test.ts — plan 10 §11.12 over the real IPC: `callTaint`
 * with `unmappedTool` (the proxies' backstop for a tool whose input carries a
 * command but that no gate surface knows as a shell).
 *
 *   - axis OFF, or a tool the session's spec maps: an EMPTY answer (the
 *     mapped tool keeps its own legs and its releases);
 *   - the guard tied the command to a tree: that tree's taint, `evidence:
 *     "tree"`;
 *   - no tree: every raw secret read of the SESSION, rule `secret`,
 *     `evidence: "session"`; a session with none has nothing to mask.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-unmapped-exec-"));
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  return { c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("an unmapped tool whose command the guard tied to a tree: the tree's taint, evidence tree", async () => {
  const k = await stack(true);
  try {
    // plan 10 §11.18: a server the launcher registered (a tool of no
    // registered server is masked whole before any of this, see below)
    for (const s of ["su", "sv"]) await k.c.registerMcpServers(s, [{ name: "box", command: "box-mcp", args: [] }]);
    // the proxy gates each call before the agent runs it (plan 13 D9
    // follow-up: the command it records there is what binds the call)
    await k.c.execGate({ command: "psql -c 'select 1'", sessionKey: "su", callId: "call_u1" });
    await k.c.recordExecRoot({ procKey: "u-sh-1", argv: ["/bin/sh", "-c", "psql -c 'select 1'"], session: "su", callRoot: true });
    await k.c.processLineage({ childKey: "u-psql-2", parentKey: "u-sh-1" });
    await k.c.taintProcessSecret({ procKey: "u-psql-2", path: "/h/.pgpass", level: "no-model", app: "psql", session: "su" });
    const t = await k.c.callTaint("call_u1", { command: "psql -c 'select 1'", session: "su", unmappedTool: "mcp__box__run_command" });
    assert.equal(t.evidence, "tree");
    assert.equal(t.root, "u-sh-1");
    assert.equal(t.level, "no-model");
    assert.deepEqual(t.files, ["/h/.pgpass"]);
    // a tree that read nothing, bound by the call-root recorder (the agent's
    // own child ran it): no level, evidence tree (nothing to mask)
    await k.c.execGate({ command: "ls", sessionKey: "su", callId: "call_u2" });
    await k.c.recordExecRoot({ procKey: "u-sh-3", argv: ["/bin/sh", "-c", "ls"], session: "su", callRoot: true });
    const clean = await k.c.callTaint("call_u2", { command: "ls", session: "su", unmappedTool: "mcp__box__run_command" });
    assert.equal(clean.evidence, "tree");
    assert.equal(clean.level, null);
    // plan 13 D7: a clean tree found only by a guess (no agent child ran the
    // command: an MCP server's own shell) proves nothing about the call in a
    // session holding a raw read: the session decides (fail-closed)
    await k.c.recordExecRoot({ procKey: "u-sh-5", argv: ["/bin/sh", "-c", "date"], session: "su" });
    const guessed = await k.c.callTaint("call_u3", { command: "date", session: "su", unmappedTool: "mcp__box__run_command" });
    assert.equal(guessed.evidence, "session");
    assert.equal(guessed.level, "no-model");
    // …and in a session holding none, the guessed tree answers as before
    await k.c.recordExecRoot({ procKey: "v-sh-1", argv: ["/bin/sh", "-c", "date"], session: "sv" });
    const quiet = await k.c.callTaint("call_v1", { command: "date", session: "sv", unmappedTool: "mcp__box__run_command" });
    assert.equal(quiet.evidence, "tree");
    assert.equal(quiet.level, null);
  } finally { await k.done(); }
});

test("no tree: the session's raw reads decide, rule secret; another session's never count; none ⇒ nothing", async () => {
  const k = await stack(true);
  try {
    // `builtin`: a tool the proxy names one of its agent's own (plan 10
    // §11.18); without it the tool has no mapping and is masked whole
    assert.equal((await k.c.callTaint("call_n0", { command: "print(1)", session: "sa", unmappedTool: "python_exec" })).evidence, "unmapped");
    const none = await k.c.callTaint("call_n1", { command: "print(open('notes').read())", session: "sa", unmappedTool: "python_exec", builtin: true });
    assert.equal(none.evidence, "session");
    assert.equal(none.level, null, "no raw read in the session: every process got the twin");
    await k.c.taintProcessSecret({ procKey: "a-psql-1", path: "/h/.pgpass", level: "any-model", app: "psql", session: "sa" });
    await k.c.taintProcessSecret({ procKey: "b-gh-1", path: "/h/.config/gh/hosts.yml", level: "no-model", app: "gh", session: "sb" });
    const t = await k.c.callTaint("call_n2", { command: "print(1)", session: "sa", unmappedTool: "python_exec", builtin: true });
    assert.equal(t.evidence, "session");
    assert.equal(t.root, null);
    assert.equal(t.level, "any-model");
    assert.equal(t.rule, "secret", "no app rule speaks for output no tree attributes");
    assert.deepEqual(t.files, ["/h/.pgpass"]);
  } finally { await k.done(); }
});

test("a tool the session's spec maps, or the axis OFF: an empty answer, whatever the tree says", async () => {
  const k = await stack(true);
  try {
    await k.c.recordExecRoot({ procKey: "m-sh-1", argv: ["/bin/sh", "-c", "cat .env"], session: "sm" });
    await k.c.taintProcessSecret({ procKey: "m-sh-1", path: "/h/.env", level: "no-model", app: "sh", session: "sm" });
    const mapped = await k.c.callTaint("call_m1", { command: "cat .env", session: "sm", unmappedTool: "Workflow" });
    assert.deepEqual(mapped, { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] });
    // the same call without `unmappedTool` is the mapped leg (Bash): the tree answers
    assert.equal((await k.c.callTaint("call_m2", { command: "cat .env", session: "sm" })).level, "no-model");
  } finally { await k.done(); }
  const off = await stack(false);
  try {
    await off.c.taintProcessSecret({ procKey: "o-1", path: "/h/.env", level: "no-model", app: "sh", session: "so" });
    const t = await off.c.callTaint("call_o1", { command: "x", session: "so", unmappedTool: "python_exec" });
    assert.equal(t.level, null);
    assert.equal(t.evidence, undefined);
  } finally { await off.done(); }
});

test("§11.13: an MCP tool asked with no command gets the session's answer; Mandu's own tools (policy, inspect, declassify) answer empty", async () => {
  const k = await stack(true);
  try {
    await k.c.registerMcpServers("smc", [{ name: "store", command: "store-mcp", args: [] }]);
    await k.c.taintProcessSecret({ procKey: "mc-psql-1", path: "/h/.pgpass", level: "no-model", app: "psql", session: "smc" });
    // a third-party MCP tool of a registered server, no command (an MCP
    // server is a store a cell can write to)
    const store = await k.c.callTaint("call_mc1", { session: "smc", unmappedTool: "mcp__store__get" });
    assert.equal(store.evidence, "session");
    assert.equal(store.level, "no-model");
    // a cell's session fold: `exec`, a call id of its own, no command
    const fold = await k.c.callTaint("call_cell#cell", { session: "smc", unmappedTool: "exec", builtin: true });
    assert.equal(fold.level, "no-model");
    // Mandu's own tools, in Codex's spelling: empty whatever the session read
    const empty = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
    for (const tool of ["mcp__mandu_policy__mandu_policy_read", "mcp__mandu_inspect__inspect_symbol", "mcp__mandu_inspect__declassify_symbol"]) {
      assert.deepEqual(await k.c.callTaint(`call_${tool}`, { session: "smc", unmappedTool: tool }), empty, tool);
    }
  } finally { await k.done(); }
});
