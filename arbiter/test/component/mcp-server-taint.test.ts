/**
 * mcp-server-taint.test.ts — plan 10 §11.13, the per-server MCP rule over the
 * real IPC: the launcher registers the agent's stdio MCP servers on the HUMAN
 * socket (`registerMcpServers`); the guard records each exec's argv
 * (`recordExecRoot`); `mcpServerTaint` maps a tool to its server's process by
 * that argv and folds the process tree's raw secret reads.
 *
 *   tainted   any process carrying the server's argv has a tree that read a
 *             secret raw (the server itself, or a descendant);
 *   clean     exactly one such process, its tree read none;
 *   unmapped  not registered, no such process, two clean ones, an ambiguous
 *             tool name, or the confidentiality axis off;
 *   own       Mandu's own tools (inspect, declassify, policy).
 * The registration is refused on the data socket (the agent world could name
 * a clean process of its choosing as the server).
 *
 * Mandu-new test. Axes stated per server: `secrets` (confidentiality on).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer, mcpArgvSpellings, mcpSourceStamp, mcpToolPrefixes } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-srv-"));
  const sock = join(dir, "a.sock");
  const human = join(dir, "human", "h.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const h = new ArbiterClient(human); await h.connect();
  return { data, h, done: async () => { data.close(); h.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const S = "sess-mcp";
const SERVERS = [
  { name: "box-tools", command: "npx", args: ["-y", "@acme/box-mcp"] },
  { name: "notes", command: "/usr/bin/node", args: ["/opt/notes/server.js"] },
];

test("mcpToolPrefixes / mcpArgvSpellings: each agent's spelling; the basename of a path command", () => {
  assert.deepEqual(mcpToolPrefixes("box-tools"), ["mcp__box-tools__", "mcp__box_tools__"]);
  assert.deepEqual(mcpToolPrefixes("my.srv"), ["mcp__my.srv__", "mcp__my_srv__"]);
  assert.deepEqual(mcpArgvSpellings("npx", ["-y", "x"]), [["npx", "-y", "x"]]);
  assert.deepEqual(mcpArgvSpellings("/usr/bin/node", ["s.js"]), [["/usr/bin/node", "s.js"], ["node", "s.js"]]);
});

test("registration is human-plane only; an unregistered or unspawned server is unmapped; Mandu's own tools are own", async () => {
  const k = await stack(true);
  try {
    await assert.rejects(k.data.registerMcpServers(S, SERVERS), /human-plane/, "refused on the data socket");
    assert.equal((await k.data.mcpServerTaint("mcp__box_tools__run", S)).verdict, "unmapped", "not registered");
    assert.deepEqual(await k.h.registerMcpServers(S, SERVERS), { registered: 2 });
    assert.equal((await k.data.mcpServerTaint("mcp__box_tools__run", S)).verdict, "unmapped", "registered, never spawned");
    for (const t of ["mcp__mandu_policy__mandu_policy_read", "mcp__mandu-policy__mandu_policy_read", "mcp__mandu_inspect__inspect_symbol", "mcp__mandu_inspect__declassify_symbol"]) {
      assert.equal((await k.data.mcpServerTaint(t, S)).verdict, "own", t);
    }
  } finally { await k.done(); }
});

test("clean: exactly one process carries the argv and its tree read nothing; tainted: the server or a descendant read a secret raw", async () => {
  const k = await stack(true);
  try {
    await k.h.registerMcpServers(S, SERVERS);
    // the agent spawns the box server; npx's child runs the package
    await k.h.recordExecRoot({ procKey: "agent-1", argv: ["codex"], session: S });
    await k.h.recordExecRoot({ procKey: "npx-2", parentKey: "agent-1", argv: ["npx", "-y", "@acme/box-mcp"], session: S });
    await k.h.recordExecRoot({ procKey: "npx-2", parentKey: "agent-1", argv: ["node", "/usr/lib/node_modules/npm/bin/npx-cli.js", "-y", "@acme/box-mcp"], session: S });
    await k.h.recordExecRoot({ procKey: "box-3", parentKey: "npx-2", argv: ["node", "/tmp/_npx/box/index.js"], session: S });
    // the notes server, spawned by its path; another process of the session read a secret raw
    await k.h.recordExecRoot({ procKey: "notes-4", parentKey: "agent-1", argv: ["/usr/bin/node", "/opt/notes/server.js"], session: S });
    await k.h.taintProcessSecret({ procKey: "psql-9", path: "/h/.pgpass", level: "no-model", app: "psql", session: S });

    for (const t of ["mcp__box-tools__run", "mcp__box_tools__run"]) {
      const c = await k.data.mcpServerTaint(t, S);
      assert.deepEqual({ v: c.verdict, n: c.candidates, s: c.server }, { v: "clean", n: 1, s: "box-tools" }, `${t}: the session's raw read is not the server's`);
    }
    // a descendant of the server reads a secret raw ⇒ the server is tainted
    await k.h.taintProcessSecret({ procKey: "box-3", path: "/h/.netrc", level: "no-model", app: "node", session: S });
    const t = await k.data.mcpServerTaint("mcp__box_tools__run", S);
    assert.equal(t.verdict, "tainted");
    assert.equal(t.level, "no-model");
    assert.deepEqual(t.files, ["/h/.netrc"]);
    // the server's root itself (an npx that read ~/.npmrc) taints its tree
    await k.h.taintProcessSecret({ procKey: "notes-4", path: "/h/.npmrc", level: "no-model", app: "node", session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__notes__list", S)).verdict, "tainted");
  } finally { await k.done(); }
});

test("two processes carry the argv: tainted if either tree is, else unmapped (never clean)", async () => {
  const k = await stack(true);
  try {
    await k.h.registerMcpServers(S, SERVERS);
    await k.h.recordExecRoot({ procKey: "box-a", argv: ["npx", "-y", "@acme/box-mcp"], session: S });
    await k.h.recordExecRoot({ procKey: "box-b", argv: ["npx", "-y", "@acme/box-mcp"], session: S });
    const two = await k.data.mcpServerTaint("mcp__box_tools__run", S);
    assert.deepEqual({ v: two.verdict, n: two.candidates }, { v: "unmapped", n: 2 });
    await k.h.taintProcessSecret({ procKey: "box-b", path: "/h/.pgpass", level: "no-model", app: "node", session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__box_tools__run", S)).verdict, "tainted");
    // another session's processes never count
    assert.equal((await k.data.mcpServerTaint("mcp__box_tools__run", "other")).verdict, "unmapped");
  } finally { await k.done(); }
});

test("an ambiguous tool name, or the axis off, is unmapped", async () => {
  const k = await stack(true);
  try {
    await k.h.registerMcpServers(S, [{ name: "a", command: "x", args: [] }, { name: "a__b", command: "y", args: [] }]);
    await k.h.recordExecRoot({ procKey: "x-1", argv: ["x"], session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__a__b__tool", S)).verdict, "unmapped", "two servers claim the name");
  } finally { await k.done(); }
  const off = await stack(false);
  try {
    await off.h.registerMcpServers(S, SERVERS);
    await off.h.recordExecRoot({ procKey: "box-1", argv: ["npx", "-y", "@acme/box-mcp"], session: S });
    await off.h.taintProcessSecret({ procKey: "box-1", path: "/h/.pgpass", level: "no-model", app: "node", session: S });
    assert.equal((await off.data.mcpServerTaint("mcp__box_tools__run", S)).verdict, "unmapped");
  } finally { await off.done(); }
});

// Item 4 of the P0 wave (2026-10-02): a second registration of a session's
// servers (a re-read of a changed config) only ADDS a command line to a
// server. Replacing it let the agent point a tainted server at a clean
// look-alike: edit its config to the look-alike's argv, run the look-alike
// once, and the re-read named only the look-alike, one clean process, so the
// server's results went raw on Codex (`clean` skips the session ask).
test("a second registration adds a server's new command line, never replaces the first: a look-alike cannot make a tainted server clean", async () => {
  const k = await stack(true);
  try {
    await k.h.registerMcpServers(S, SERVERS);
    await k.h.recordExecRoot({ procKey: "box-1", argv: ["npx", "-y", "@acme/box-mcp"], session: S });
    await k.h.taintProcessSecret({ procKey: "box-1", path: "/h/.pgpass", level: "no-model", app: "node", session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__box_tools__run", S)).verdict, "tainted");
    // the config now names a look-alike, which runs once, clean
    const lookAlike = [{ name: "box-tools", command: "node", args: ["/tmp/x/clean.js"] }];
    assert.deepEqual(await k.h.registerMcpServers(S, lookAlike), { registered: 1 });
    await k.h.recordExecRoot({ procKey: "fake-2", argv: ["node", "/tmp/x/clean.js"], session: S });
    const after = await k.data.mcpServerTaint("mcp__box_tools__run", S);
    // MASTER: { verdict: "clean", candidates: 1 } (the registration was replaced)
    assert.equal(after.verdict, "tainted", `CONFIDENTIALITY: the server keeps its first command line: ${JSON.stringify(after)}`);
    assert.equal(after.candidates, 2);
    // a server the first registration named and the second does not is kept
    await k.h.recordExecRoot({ procKey: "notes-3", argv: ["/usr/bin/node", "/opt/notes/server.js"], session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__notes__list", S)).server, "notes");
    // a new server is added
    await k.h.registerMcpServers(S, [{ name: "extra", command: "extra-mcp", args: [] }]);
    await k.h.recordExecRoot({ procKey: "extra-4", argv: ["extra-mcp"], session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__extra__go", S)).verdict, "clean");
  } finally { await k.done(); }
});

// P0 item 11 (a), plan 10 §11.17: a server whose config changed after the
// launcher read it. The stale registration names the OLD command line; its
// one clean process vouched for the server while the agent ran the NEW one,
// whose tree read a secret raw: `clean`, so the result skipped the session
// rule on both wires (MASTER). The registration now carries the stamp of
// every file the read consulted; a moved stamp keeps the session's servers
// from `clean` until the launcher's re-read lands, and the re-read adds the
// new command line (two processes: never clean).
test("a config file changed since the launcher read it: the old command line's clean process does not vouch for the server (unmapped until the re-read)", async () => {
  const k = await stack(true);
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-src-"));
  try {
    const cfg = join(dir, ".mcp.json");
    writeFileSync(cfg, JSON.stringify({ mcpServers: { notes: { command: "/usr/bin/node", args: ["/opt/notes/server.js"] } } }));
    const missing = join(dir, "later.json");
    assert.equal(mcpSourceStamp(missing), "absent");
    await k.h.registerMcpServers(S, SERVERS, [{ path: cfg, stamp: mcpSourceStamp(cfg) }, { path: missing, stamp: "absent" }]);
    await k.h.recordExecRoot({ procKey: "notes-1", argv: ["/usr/bin/node", "/opt/notes/server.js"], session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__notes__list", S)).verdict, "clean", "unchanged config: the one process vouches");

    // the agent edits the config; its reload runs the new command line, whose
    // tree reads a secret raw; the launcher has not re-read yet
    const next = ["sh", "-c", "psql -c 'select * from cards' ; node /opt/notes/server.js"];
    writeFileSync(cfg, JSON.stringify({ mcpServers: { notes: { command: next[0], args: next.slice(1) } } }));
    await k.h.recordExecRoot({ procKey: "notes-2", argv: next, session: S });
    await k.h.taintProcessSecret({ procKey: "notes-2", path: "/h/.pgpass", level: "no-model", app: "psql", session: S });
    const stale = await k.data.mcpServerTaint("mcp__notes__list", S);
    // MASTER: { verdict: "clean", candidates: 1 } (the old process vouched)
    assert.equal(stale.verdict, "unmapped", `CONFIDENTIALITY: a changed config's old process vouched for the server: ${JSON.stringify(stale)}`);
    assert.equal(stale.configChanged, true);
    // a file that appears later (a project .mcp.json created mid-session) counts the same
    await k.h.registerMcpServers(S, [], [{ path: cfg, stamp: mcpSourceStamp(cfg) }, { path: missing, stamp: "absent" }]);
    assert.equal((await k.data.mcpServerTaint("mcp__notes__list", S)).verdict, "clean", "stamps current again (the new line not registered: the test's own setup)");
    writeFileSync(missing, "{}");
    assert.equal((await k.data.mcpServerTaint("mcp__notes__list", S)).configChanged, true, "a created file moves its stamp");

    // the re-read lands: the new command line is ADDED, so both processes count
    await k.h.registerMcpServers(S, [{ name: "notes", command: next[0]!, args: next.slice(1) }],
      [{ path: cfg, stamp: mcpSourceStamp(cfg) }, { path: missing, stamp: mcpSourceStamp(missing) }]);
    const after = await k.data.mcpServerTaint("mcp__notes__list", S);
    assert.deepEqual({ v: after.verdict, n: after.candidates, c: after.configChanged }, { v: "tainted", n: 2, c: undefined });
  } finally { await k.done(); rmSync(dir, { recursive: true, force: true }); }
});

test("an unchanged re-read keeps a clean server clean; a malformed sources list is refused whole", async () => {
  const k = await stack(true);
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-src-"));
  try {
    const cfg = join(dir, "config.toml");
    writeFileSync(cfg, "[mcp_servers.notes]\ncommand = \"/usr/bin/node\"\n");
    await k.h.registerMcpServers(S, SERVERS, [{ path: cfg, stamp: mcpSourceStamp(cfg) }]);
    await k.h.registerMcpServers(S, SERVERS, [{ path: cfg, stamp: mcpSourceStamp(cfg) }]);
    await k.h.recordExecRoot({ procKey: "notes-1", argv: ["/usr/bin/node", "/opt/notes/server.js"], session: S });
    assert.equal((await k.data.mcpServerTaint("mcp__notes__list", S)).verdict, "clean");
    await assert.rejects(k.h.registerMcpServers(S, SERVERS, [{ path: "relative.json", stamp: "absent" }]), /sources must be/);
    await assert.rejects(k.h.registerMcpServers(S, SERVERS, [{ path: cfg, stamp: "" }]), /sources must be/);
    assert.equal((await k.data.mcpServerTaint("mcp__notes__list", S)).verdict, "clean", "a refused registration changes nothing");
  } finally { await k.done(); rmSync(dir, { recursive: true, force: true }); }
});
