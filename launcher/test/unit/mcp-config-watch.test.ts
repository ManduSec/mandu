/**
 * mcp-config-watch.test — plan 10 §11.17 (P0 item 11 (a)): the launcher
 * follows the agent's MCP config through the session.
 *
 *   readMcpConfig   every file the read consulted (present or not), each
 *                   stamped BEFORE it was read; relative paths left out; a
 *                   list over the arbiter's cap ends in a source no stamp
 *                   matches (the check never passes on a cut list);
 *   watchMcpConfig  a moved stamp ⇒ a re-read registered with its new
 *                   sources (also when the config now names no server, once
 *                   something was registered); an unmoved one ⇒ no call; a
 *                   failed registration ⇒ retried on the next check, one
 *                   WARNING at most; nothing ever mapped and nothing now ⇒
 *                   no call;
 *   mapLaunchMcpServers  the watch only for Claude Code and Codex with a
 *                   human socket, never with the axis off; a real file
 *                   edited on disk re-registers through the real stamp.
 *
 * Pure over injected readFile / stamp / call, except the last test (a temp
 * dir, the real stamp). No arbiter is built, so no axes are stated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MCP_SOURCES_MAX,
  mapLaunchMcpServers,
  mcpSourceStamp,
  readMcpConfig,
  watchMcpConfig,
  type McpLaunchPlan,
} from "../../src/mcp-server-config.js";

const HOME = "/home/u";
const CWD = "/work/proj";

function world(initial: Record<string, string>) {
  const fs: Record<string, string> = { ...initial };
  const gen: Record<string, number> = {};
  const order: string[] = [];
  return {
    fs,
    order,
    write(p: string, text: string | null): void {
      if (text === null) delete fs[p];
      else fs[p] = text;
      gen[p] = (gen[p] ?? 0) + 1;
    },
    readFile: (p: string): string | null => { order.push(`read ${p}`); return p in fs ? fs[p]! : null; },
    stamp: (p: string): string => { order.push(`stamp ${p}`); return p in fs ? `g${gen[p] ?? 0}` : "absent"; },
  };
}

test("readMcpConfig: every consulted file with its stamp, stamped before it is read; relative paths left out", () => {
  const w = world({ "/home/u/.claude.json": JSON.stringify({ mcpServers: { gh: { command: "gh-mcp" } } }) });
  const r = readMcpConfig({ target: "claude", home: HOME, humanCwd: CWD, agentCwd: CWD, managedMcpFile: "/m.json", readFile: w.readFile, stamp: w.stamp, agentArgv: ["--mcp-config", "rel.json"] });
  assert.deepEqual(r.servers.map((s) => s.name), ["gh"]);
  assert.deepEqual(r.sources, [
    { path: "/home/u/.claude.json", stamp: "g0" },
    { path: "/work/proj/.mcp.json", stamp: "absent" },
    { path: "/m.json", stamp: "absent" },
    { path: "/home/u/.claude/plugins/installed_plugins.json", stamp: "absent" },
    { path: "/work/proj/rel.json", stamp: "absent" },
  ]);
  const i = w.order.indexOf("read /home/u/.claude.json");
  assert.ok(i > 0 && w.order[i - 1] === "stamp /home/u/.claude.json", "stamped before read");
  // codex: one file
  const c = readMcpConfig({ target: "codex", home: HOME, humanCwd: CWD, agentCwd: CWD, readFile: w.readFile, stamp: w.stamp });
  assert.deepEqual(c.sources, [{ path: "/home/u/.codex/config.toml", stamp: "absent" }]);
  // another agent: nothing read
  assert.deepEqual(readMcpConfig({ target: "opencode", home: HOME, humanCwd: CWD, agentCwd: CWD, readFile: w.readFile, stamp: w.stamp }), { servers: [], sources: [] });
});

test("readMcpConfig: over the arbiter's cap, the list ends in a source no stamp matches", () => {
  const plugins: Record<string, unknown> = {};
  for (let i = 0; i < MCP_SOURCES_MAX; i++) plugins[`p${i}@m`] = [{ installPath: `/p/${i}` }];
  const w = world({ "/home/u/.claude/plugins/installed_plugins.json": JSON.stringify({ plugins }) });
  const r = readMcpConfig({ target: "claude", home: HOME, humanCwd: CWD, agentCwd: CWD, managedMcpFile: "/m.json", readFile: w.readFile, stamp: w.stamp });
  assert.equal(r.sources.length, MCP_SOURCES_MAX);
  assert.deepEqual(r.sources[r.sources.length - 1], { path: "/", stamp: "overflow" });
  assert.notEqual(mcpSourceStamp("/"), "overflow");
});

test("watchMcpConfig: a moved stamp re-reads and registers the new servers and sources; an unmoved one sends nothing", async () => {
  const w = world({ "/home/u/.codex/config.toml": '[mcp_servers.notes]\ncommand = "node"\nargs = ["/opt/notes.js"]\n' });
  const input = { target: "codex", home: HOME, humanCwd: CWD, agentCwd: CWD, readFile: w.readFile, stamp: w.stamp };
  const calls: Array<Record<string, unknown>> = [];
  const watch = watchMcpConfig(input, readMcpConfig(input), "/h.sock", "sess", {
    registered: true, log: () => {},
    call: async (_s, op, a) => { calls.push({ op, ...a }); return { registered: (a["servers"] as unknown[]).length }; },
  });
  assert.equal(await watch.checkNow(), false);
  assert.equal(calls.length, 0, "unchanged: nothing sent");
  w.write("/home/u/.codex/config.toml", '[mcp_servers.notes]\ncommand = "sh"\nargs = ["-c", "psql; node /opt/notes.js"]\n');
  assert.equal(await watch.checkNow(), true);
  assert.deepEqual(calls, [{
    op: "registerMcpServers", sessionKey: "sess",
    servers: [{ name: "notes", command: "sh", args: ["-c", "psql; node /opt/notes.js"] }],
    sources: [{ path: "/home/u/.codex/config.toml", stamp: "g1" }],
  }]);
  assert.equal(await watch.checkNow(), false, "the new stamp is the watch's now");
  // the config now names no server: the stamps are still replaced
  w.write("/home/u/.codex/config.toml", "");
  assert.equal(await watch.checkNow(), true);
  assert.deepEqual(calls[1], { op: "registerMcpServers", sessionKey: "sess", servers: [], sources: [{ path: "/home/u/.codex/config.toml", stamp: "g2" }] });
});

test("watchMcpConfig: a file created mid-session counts; a failed registration is retried with one WARNING; nothing ever mapped and nothing now sends nothing", async () => {
  const w = world({});
  const input = { target: "claude", home: HOME, humanCwd: CWD, agentCwd: CWD, managedMcpFile: "/m.json", readFile: w.readFile, stamp: w.stamp };
  let fail = true;
  const calls: unknown[] = [];
  const logs: string[] = [];
  const watch = watchMcpConfig(input, readMcpConfig(input), "/h.sock", "sess", {
    log: (m) => logs.push(m),
    call: async (_s, _op, a) => { calls.push(a); if (fail) throw new Error("socket closed"); return { registered: 1 }; },
  });
  // an unrelated file appears, naming no server: nothing to replace
  w.write("/m.json", "{}");
  assert.equal(await watch.checkNow(), false);
  assert.equal(calls.length, 0);
  // the project's .mcp.json is created with a server
  w.write("/work/proj/.mcp.json", JSON.stringify({ mcpServers: { late: { command: "late-mcp" } } }));
  assert.equal(await watch.checkNow(), false, "the registration failed");
  assert.equal(await watch.checkNow(), false, "retried, failed again");
  assert.equal(calls.length, 2);
  assert.equal(logs.length, 1, "one WARNING per session");
  fail = false;
  assert.equal(await watch.checkNow(), true, "retried until it lands");
  assert.deepEqual((calls[2] as { servers: unknown }).servers, [{ name: "late", command: "late-mcp", args: [] }]);
});

const PLAN: McpLaunchPlan = {
  target: "claude", scopeId: "s-1", humanCwd: CWD, cwd: CWD, arbiterHumanSock: "/run/h.sock",
  effectiveAxes: { integrity: false, confidentiality: true },
} as McpLaunchPlan;

test("mapLaunchMcpServers: a watch for Claude Code and Codex with a human socket; none for another agent, without a socket, or with the axis off", async () => {
  const deps = { home: HOME, readFile: () => null, stamp: () => "absent", call: async () => ({ registered: 0 }), log: () => {} };
  assert.notEqual((await mapLaunchMcpServers(PLAN, {}, deps)).watch, null);
  assert.notEqual((await mapLaunchMcpServers({ ...PLAN, target: "codex" }, {}, deps)).watch, null);
  assert.equal((await mapLaunchMcpServers({ ...PLAN, target: "opencode" }, {}, deps)).watch, null);
  assert.equal((await mapLaunchMcpServers({ ...PLAN, arbiterHumanSock: null } as McpLaunchPlan, {}, deps)).watch, null);
  assert.deepEqual(await mapLaunchMcpServers({ ...PLAN, effectiveAxes: { integrity: false, confidentiality: false } } as McpLaunchPlan, {}, deps), { registration: null, watch: null });
});

test("mapLaunchMcpServers over real files: an edit on disk moves the real stamp and the watch registers the new command line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-watch-"));
  try {
    const cfg = join(dir, ".mcp.json");
    writeFileSync(cfg, JSON.stringify({ mcpServers: { notes: { command: "node", args: ["/opt/notes.js"] } } }));
    const calls: Array<Record<string, unknown>> = [];
    const { registration, watch } = await mapLaunchMcpServers({ ...PLAN, humanCwd: dir, cwd: dir } as McpLaunchPlan, { CLAUDE_CONFIG_DIR: dir }, {
      home: dir, call: async (_s, _o, a) => { calls.push(a); return { registered: (a["servers"] as unknown[]).length }; }, log: () => {},
    });
    assert.deepEqual(registration, { status: "registered", registered: 1 });
    const first = (calls[0]!["sources"] as Array<{ path: string; stamp: string }>).find((x) => x.path === cfg)!;
    assert.equal(first.stamp, mcpSourceStamp(cfg));
    assert.equal(await watch!.checkNow(), false);
    writeFileSync(cfg, JSON.stringify({ mcpServers: { notes: { command: "sh", args: ["-c", "node /opt/notes.js"] } } }));
    assert.equal(await watch!.checkNow(), true);
    assert.deepEqual(calls[1]!["servers"], [{ name: "notes", command: "sh", args: ["-c", "node /opt/notes.js"] }]);
    watch!.stop();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
