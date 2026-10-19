/**
 * mcp-server-config.test — the agent's configured STDIO MCP servers (plan 10
 * §11.13): every source both agents read, the entries that are not local
 * processes (url / http / sse) skipped, malformed files contributing
 * nothing, Mandu's own servers left out, args validated; and their
 * registration on the arbiter's HUMAN plane (never the data socket), skipped
 * without one, never fatal.
 *
 * Pure tests over an injected readFile and call, except the last ones, which
 * read real files from a temp dir and answer on a real Unix socket. No
 * arbiter is built, so no axes are stated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MANDU_OWN_MCP_SERVERS,
  defaultManagedMcpFile,
  configuredMcpServers,
  parseTomlDocument,
  TomlScalar,
  registerLaunchMcpServers,
  registerMcpServers,
  type ConfiguredMcpServer,
  type McpLaunchPlan,
} from "../../src/mcp-server-config.js";
import { MANDU_POLICY_SERVER } from "../../src/services/mcp.js";
import { ndjsonCall } from "../../src/secret-setup.js";

const HOME = "/home/u";
const HUMAN = "/work/proj";
const AGENT = "/home/u/.mandu/view/proj-abc/agent";

const files = (m: Record<string, string>) => (p: string): string | null => (p in m ? m[p]! : null);
const strip = (xs: ConfiguredMcpServer[]) => xs.map(({ name, command, args }) => ({ name, command, args }));

// ---- claude ----------------------------------------------------------------

test("claude: user, local (both cwds) and project (both cwds) scopes, in that order, each tagged with its source", () => {
  const got = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
    readFile: files({
      [`${HOME}/.claude.json`]: JSON.stringify({
        mcpServers: { github: { type: "stdio", command: "npx", args: ["-y", "@mcp/github"] } },
        projects: {
          [HUMAN]: { mcpServers: { db: { command: "/usr/bin/db-mcp" } } },
          [AGENT]: { mcpServers: { db: { command: "/usr/bin/db-mcp", args: ["--agent"] } } },
          "/elsewhere": { mcpServers: { other: { command: "nope" } } },
        },
      }),
      [`${HUMAN}/.mcp.json`]: JSON.stringify({ mcpServers: { fs: { command: "node", args: ["fs.js"] } } }),
      [`${AGENT}/.mcp.json`]: JSON.stringify({ mcpServers: { fs: { command: "node", args: ["fs2.js"] } } }),
    }),
  });
  assert.deepEqual(strip(got), [
    { name: "github", command: "npx", args: ["-y", "@mcp/github"] },
    { name: "db", command: "/usr/bin/db-mcp", args: [] },
    { name: "db", command: "/usr/bin/db-mcp", args: ["--agent"] },
    { name: "fs", command: "node", args: ["fs.js"] },
    { name: "fs", command: "node", args: ["fs2.js"] },
  ]);
  assert.deepEqual(got.map((s) => s.source), [
    `${HOME}/.claude.json#mcpServers`,
    `${HOME}/.claude.json#projects[${HUMAN}].mcpServers`,
    `${HOME}/.claude.json#projects[${AGENT}].mcpServers`,
    `${HUMAN}/.mcp.json#mcpServers`,
    `${AGENT}/.mcp.json#mcpServers`,
  ]);
});

test("claude: CLAUDE_CONFIG_DIR holds .claude.json instead of HOME", () => {
  const read = files({
    "/cfg/.claude.json": JSON.stringify({ mcpServers: { a: { command: "a-mcp" } } }),
    [`${HOME}/.claude.json`]: JSON.stringify({ mcpServers: { b: { command: "b-mcp" } } }),
  });
  const got = configuredMcpServers({ target: "claude", home: HOME, claudeConfigDir: "/cfg", humanCwd: HUMAN, agentCwd: AGENT, readFile: read });
  assert.deepEqual(got.map((s) => s.name), ["a"]);
  const empty = configuredMcpServers({ target: "claude", home: HOME, claudeConfigDir: "", humanCwd: HUMAN, agentCwd: AGENT, readFile: read });
  assert.deepEqual(empty.map((s) => s.name), ["b"], "an empty CLAUDE_CONFIG_DIR is unset");
});

test("claude: one cwd (no AgentView) is read once, not twice", () => {
  const got = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: HUMAN,
    readFile: files({
      [`${HOME}/.claude.json`]: JSON.stringify({ projects: { [HUMAN]: { mcpServers: { db: { command: "db" } } } } }),
      [`${HUMAN}/.mcp.json`]: JSON.stringify({ mcpServers: { fs: { command: "fs" } } }),
    }),
  });
  assert.deepEqual(got.map((s) => s.name), ["db", "fs"]);
});

test("claude: url / http / sse / ws entries (no local process) are skipped; type stdio or absent is kept", () => {
  const got = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
    readFile: files({
      [`${HOME}/.claude.json`]: JSON.stringify({
        mcpServers: {
          remote: { type: "http", url: "https://mcp.example/v1" },
          events: { type: "sse", url: "https://mcp.example/sse" },
          sock: { type: "ws", url: "wss://mcp.example" },
          urlOnly: { url: "https://mcp.example/x", command: "decoy" },
          httpWithCommand: { type: "http", command: "decoy" },
          local: { type: "stdio", command: "local-mcp" },
          plain: { command: "plain-mcp" },
        },
      }),
    }),
  });
  assert.deepEqual(got.map((s) => s.name), ["local", "plain"]);
});

test("args: absent → []; an array of strings is kept; anything else skips the entry; command must be a non-empty string", () => {
  const got = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
    readFile: files({
      [`${HUMAN}/.mcp.json`]: JSON.stringify({
        mcpServers: {
          noArgs: { command: "x" },
          okArgs: { command: "x", args: ["a", "b c", ""] },
          numArg: { command: "x", args: ["a", 1] },
          strArgs: { command: "x", args: "a b" },
          objArgs: { command: "x", args: { 0: "a" } },
          nullArgs: { command: "x", args: null },
          noCmd: { args: ["a"] },
          emptyCmd: { command: "" },
          arrCmd: { command: ["x"] },
          notObj: "x",
          nullEntry: null,
        },
      }),
    }),
  });
  assert.deepEqual(strip(got), [
    { name: "noArgs", command: "x", args: [] },
    { name: "okArgs", command: "x", args: ["a", "b c", ""] },
  ]);
});

test("Mandu's own servers (mandu-inspect, mandu-policy) are left out, for both agents", () => {
  assert.ok(MANDU_OWN_MCP_SERVERS.includes(MANDU_POLICY_SERVER), "the list names services/mcp.ts's policy server");
  assert.ok(MANDU_OWN_MCP_SERVERS.includes("mandu-inspect"));
  const claude = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
    readFile: files({
      [`${HOME}/.claude.json`]: JSON.stringify({ mcpServers: { "mandu-inspect": { command: "node" }, "mandu-policy": { command: "node" }, gh: { command: "gh-mcp" } } }),
    }),
  });
  assert.deepEqual(claude.map((s) => s.name), ["gh"]);
  const codex = configuredMcpServers({
    target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
    readFile: files({
      [`${HOME}/.codex/config.toml`]: '[mcp_servers.mandu-inspect]\ncommand = "node"\n[mcp_servers."mandu-policy"]\ncommand = "node"\n[mcp_servers.gh]\ncommand = "gh-mcp"\n',
    }),
  });
  assert.deepEqual(codex.map((s) => s.name), ["gh"]);
});

test("claude: malformed or unreadable files contribute nothing; the other sources still count", () => {
  const got = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
    readFile: files({
      [`${HOME}/.claude.json`]: "{ not json",
      [`${HUMAN}/.mcp.json`]: JSON.stringify(["mcpServers"]),
      [`${AGENT}/.mcp.json`]: JSON.stringify({ mcpServers: { ok: { command: "ok" } } }),
    }),
  });
  assert.deepEqual(got.map((s) => s.name), ["ok"]);
  for (const bad of ["null", "42", '"s"', JSON.stringify({ mcpServers: [] }), JSON.stringify({ mcpServers: { a: { command: "x" } }, projects: [] }), JSON.stringify({ projects: { [HUMAN]: "x" } })]) {
    const r = configuredMcpServers({ target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: HUMAN, readFile: files({ [`${HOME}/.claude.json`]: bad }) });
    assert.ok(r.length <= 1, bad);
  }
  const throwing = configuredMcpServers({ target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: AGENT, readFile: () => { throw new Error("EIO"); } });
  assert.deepEqual(throwing, [], "a reader that throws contributes nothing and never escapes");
});

test("a __proto__ server name is an ordinary entry, never the prototype", () => {
  const got = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
    readFile: files({ [`${HUMAN}/.mcp.json`]: '{"mcpServers":{"__proto__":{"command":"p"}}}' }),
  });
  assert.deepEqual(strip(got), [{ name: "__proto__", command: "p", args: [] }]);
});

// ---- codex -----------------------------------------------------------------

const CODEX_TOML = `
model = "gpt-5" # the model
approval_policy = "on-request"

[projects."/work/proj"]
trust_level = "trusted"

[mcp_servers.github]
command = "npx"
args = [
  "-y",          # a comment inside
  "@modelcontextprotocol/server-github",
]
env = { GITHUB_TOKEN = "x", "A.B" = 'y' }
startup_timeout_sec = 20
enabled = true

[mcp_servers.github.env_extra]
FOO = "bar"

[mcp_servers."docs server"]
command = '/opt/docs mcp'
args = ["--root=C:\\\\x", "tab\\there", "\\u00e9"]

[mcp_servers.remote]
url = "https://mcp.example/v1"
bearer_token_env_var = "TOKEN"

[mcp_servers.badargs]
command = "x"
args = ["a", 1]

[mcp_servers.noargs]
command = "solo"

[profiles.fast]
model = "gpt-5-mini"
`;

test("codex: [mcp_servers.<name>] tables (bare and quoted names, multi-line args, sub-tables) are read; url entries and bad args skipped", () => {
  const got = configuredMcpServers({ target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: AGENT, readFile: files({ [`${HOME}/.codex/config.toml`]: CODEX_TOML }) });
  assert.deepEqual(strip(got), [
    { name: "github", command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] },
    { name: "docs server", command: "/opt/docs mcp", args: ["--root=C:\\x", "tab\there", "é"] },
    { name: "noargs", command: "solo", args: [] },
  ]);
  assert.ok(got.every((s) => s.source === `${HOME}/.codex/config.toml#mcp_servers`));
});

test("codex: CODEX_HOME replaces ~/.codex; an empty one is unset", () => {
  const read = files({
    "/ch/config.toml": '[mcp_servers.a]\ncommand = "a"\n',
    [`${HOME}/.codex/config.toml`]: '[mcp_servers.b]\ncommand = "b"\n',
  });
  assert.deepEqual(configuredMcpServers({ target: "codex", home: HOME, codexHome: "/ch", humanCwd: HUMAN, agentCwd: AGENT, readFile: read }).map((s) => s.name), ["a"]);
  assert.deepEqual(configuredMcpServers({ target: "codex", home: HOME, codexHome: "", humanCwd: HUMAN, agentCwd: AGENT, readFile: read }).map((s) => s.name), ["b"]);
});

test("codex: the other TOML spellings of the same table (inline tables, dotted keys) are read too", () => {
  const text = [
    "[mcp_servers]",
    'inl = { command = "i", args = ["1"] }',
    'dot.command = "d"',
    'dot.args = ["2", "3"]',
    "",
    "[mcp_servers.multi]",
    'command = """',
    'multi-cmd"""',
    "args = ['''lit\\eral''']",
  ].join("\n");
  const got = configuredMcpServers({ target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: AGENT, readFile: files({ [`${HOME}/.codex/config.toml`]: text }) });
  assert.deepEqual(strip(got), [
    { name: "inl", command: "i", args: ["1"] },
    { name: "dot", command: "d", args: ["2", "3"] },
    { name: "multi", command: "multi-cmd", args: ["lit\\eral"] },
  ]);
});

test("codex: a file the reader cannot read contributes nothing (no partial reading)", () => {
  for (const bad of [
    '[mcp_servers.a]\ncommand = "a"\n[mcp_servers.b\ncommand = "b"\n', // unterminated header
    '[mcp_servers.a]\ncommand = "a\n', // unterminated string
    '[mcp_servers.a]\ncommand = "a"\ncommand = "b"\n', // duplicate key
    '[mcp_servers.a]\ncommand = "a" trailing\n', // junk after a value
    '[mcp_servers.a]\nargs = ["x"\n', // unterminated array
    '[mcp_servers.a]\ncommand = "\\q"\n', // bad escape
    '[mcp_servers.a]\ncommand = "\\U0011FFFF"\n', // code point out of range
    "mcp_servers = 3\n[mcp_servers.a]\ncommand = \"a\"\n", // a table over a value
  ]) {
    assert.equal(parseTomlDocument(bad), null, bad);
    assert.deepEqual(configuredMcpServers({ target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: AGENT, readFile: files({ [`${HOME}/.codex/config.toml`]: bad }) }), [], bad);
  }
  assert.deepEqual(configuredMcpServers({ target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: AGENT, readFile: files({}) }), [], "no file");
  assert.deepEqual(configuredMcpServers({ target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: AGENT, readFile: files({ [`${HOME}/.codex/config.toml`]: "mcp_servers = [1, 2]\n" }) }), [], "not a table");
});

test("parseTomlDocument: CRLF, arrays of tables, comments, scalars and a __proto__ key stay in their place", () => {
  const doc = parseTomlDocument('a = 1\r\n[[t]]\r\nx = true # c\r\n[[t]]\r\nx = false\r\n"__proto__" = 2000-01-01 10:00:00\r\n');
  assert.ok(doc !== null);
  assert.ok(doc["a"] instanceof TomlScalar && doc["a"].raw === "1", "a number is not a string");
  const t = doc["t"] as Array<Record<string, unknown>>;
  assert.deepEqual(t.map((e) => e["x"]), [true, false]);
  assert.equal(Object.getPrototypeOf({}), Object.prototype, "no prototype was touched");
  assert.equal(Object.prototype.hasOwnProperty.call(t[1], "__proto__"), true, "__proto__ is an own key of the second [[t]]");
  assert.equal((t[1]!["__proto__"] as TomlScalar).raw, "2000-01-01 10:00:00");
});

test("other targets have no configured servers", () => {
  for (const target of ["opencode", "openclaw", "shell", "other"]) {
    assert.deepEqual(configuredMcpServers({
      target, home: HOME, humanCwd: HUMAN, agentCwd: AGENT,
      readFile: files({ [`${HOME}/.claude.json`]: JSON.stringify({ mcpServers: { a: { command: "a" } } }) }),
    }), []);
  }
});

test("the real filesystem: absent files contribute nothing; present ones are read", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-cfg-"));
  try {
    assert.deepEqual(configuredMcpServers({ target: "claude", home: join(dir, "nohome"), humanCwd: join(dir, "nocwd"), agentCwd: join(dir, "nocwd") }), []);
    assert.deepEqual(configuredMcpServers({ target: "codex", home: "/dev/null/nohome", humanCwd: "/dev/null/x", agentCwd: "/dev/null/x" }), []);
    mkdirSync(join(dir, "proj"));
    writeFileSync(join(dir, "proj", ".mcp.json"), JSON.stringify({ mcpServers: { fs: { command: "fs-mcp", args: ["."] } } }));
    mkdirSync(join(dir, ".codex"));
    writeFileSync(join(dir, ".codex", "config.toml"), '[mcp_servers.gh]\ncommand = "gh"\nargs = ["mcp"]\n');
    assert.deepEqual(strip(configuredMcpServers({ target: "claude", home: dir, humanCwd: join(dir, "proj"), agentCwd: join(dir, "proj") })), [{ name: "fs", command: "fs-mcp", args: ["."] }]);
    assert.deepEqual(strip(configuredMcpServers({ target: "codex", home: dir, humanCwd: dir, agentCwd: dir })), [{ name: "gh", command: "gh", args: ["mcp"] }]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- registration ----------------------------------------------------------

const SERVERS: ConfiguredMcpServer[] = [
  { name: "gh", command: "npx", args: ["-y", "gh"], source: "/h/.claude.json#mcpServers" },
  { name: "gh", command: "npx", args: ["-y", "gh2"], source: "/p/.mcp.json#mcpServers" },
];

test("registerMcpServers: one call on the HUMAN socket with {sessionKey, servers: {name, command, args}}", async () => {
  const calls: Array<{ sock: string; op: string; args: Record<string, unknown> }> = [];
  const logs: string[] = [];
  const r = await registerMcpServers("/run/h/human.sock", "sess-1", SERVERS, {
    call: async (sock, op, args) => { calls.push({ sock, op, args }); return { registered: 2 }; },
    log: (m) => logs.push(m),
  });
  assert.deepEqual(r, { status: "registered", registered: 2 });
  assert.deepEqual(calls, [{
    sock: "/run/h/human.sock",
    op: "registerMcpServers",
    args: { sessionKey: "sess-1", servers: [{ name: "gh", command: "npx", args: ["-y", "gh"] }, { name: "gh", command: "npx", args: ["-y", "gh2"] }] },
  }]);
  assert.deepEqual(logs, []);
});

test("registerMcpServers: no human socket → nothing sent, one note naming the fallback", async () => {
  for (const sock of [null, undefined, ""]) {
    const logs: string[] = [];
    let called = false;
    const r = await registerMcpServers(sock, "s", SERVERS, { call: async () => { called = true; return {}; }, log: (m) => logs.push(m) });
    assert.deepEqual(r, { status: "skipped" });
    assert.equal(called, false);
    assert.equal(logs.length, 1);
    assert.match(logs[0]!, /^WARNING: mandu: MCP servers not mapped \(gh\): .*no human-plane socket; their results fall back to the session rule$/);
  }
});

test("registerMcpServers: a failed call or a bad answer warns once and never throws", async () => {
  const cases: Array<() => Promise<unknown>> = [
    async () => { throw new Error("unknown op registerMcpServers"); },
    async () => null,
    async () => ({ registered: "2" }),
    async () => "ok",
  ];
  for (const call of cases) {
    const logs: string[] = [];
    const r = await registerMcpServers("/h.sock", "s", SERVERS, { call, log: (m) => logs.push(m) });
    assert.equal(r.status, "failed");
    assert.equal(logs.length, 1);
    assert.match(logs[0]!, /^WARNING: mandu: MCP servers not mapped \(gh\): .+; their results fall back to the session rule$/);
  }
});

test("registerMcpServers: no servers → no call and no note", async () => {
  const logs: string[] = [];
  let called = false;
  const r = await registerMcpServers("/h.sock", "s", [], { call: async () => { called = true; return { registered: 0 }; }, log: (m) => logs.push(m) });
  assert.deepEqual(r, { status: "none" });
  assert.equal(called, false);
  assert.deepEqual(logs, []);
});

const PLAN: McpLaunchPlan = {
  target: "claude", scopeId: "1700000000-42", humanCwd: HUMAN, cwd: AGENT,
  arbiterHumanSock: "/run/user/7/mandu/human/i.sock",
  effectiveAxes: { integrity: false, confidentiality: true },
};
const LAUNCH_FILES = files({
  "/cfg/.claude.json": JSON.stringify({ mcpServers: { gh: { command: "gh-mcp" } } }),
  [`${AGENT}/.mcp.json`]: JSON.stringify({ mcpServers: { fs: { command: "fs-mcp", args: ["/"] } } }),
  "/ch/config.toml": '[mcp_servers.cx]\ncommand = "cx"\n',
});

test("registerLaunchMcpServers: confidentiality on → the plan's scopeId, human socket, cwds and env's config dirs", async () => {
  const calls: Array<{ sock: string; op: string; args: Record<string, unknown> }> = [];
  const stamp = (p: string): string => `st:${p}`;
  const r = await registerLaunchMcpServers(PLAN, { CLAUDE_CONFIG_DIR: "/cfg", CODEX_HOME: "/ch" }, {
    home: HOME, readFile: LAUNCH_FILES, stamp,
    call: async (sock, op, args) => { calls.push({ sock, op, args }); return { registered: 2 }; },
    log: () => {},
  });
  assert.deepEqual(r, { status: "registered", registered: 2 });
  // §11.17: every file the read consulted, present or not, with its stamp
  // The managed file is the platform's (/Library/Application Support/ClaudeCode on macOS).
  const consulted = ["/cfg/.claude.json", "/work/proj/.mcp.json", `${AGENT}/.mcp.json`, defaultManagedMcpFile(), "/cfg/plugins/installed_plugins.json"];
  assert.deepEqual(calls, [{
    sock: PLAN.arbiterHumanSock!, op: "registerMcpServers",
    args: {
      sessionKey: "1700000000-42", servers: [{ name: "gh", command: "gh-mcp", args: [] }, { name: "fs", command: "fs-mcp", args: ["/"] }],
      sources: consulted.map((path) => ({ path, stamp: stamp(path) })),
    },
  }]);
  const codex: Array<Record<string, unknown>> = [];
  await registerLaunchMcpServers({ ...PLAN, target: "codex" }, { CODEX_HOME: "/ch" }, {
    home: HOME, readFile: LAUNCH_FILES, stamp, call: async (_s, _o, a) => { codex.push(a); return { registered: 1 }; }, log: () => {},
  });
  assert.deepEqual(codex, [{ sessionKey: "1700000000-42", servers: [{ name: "cx", command: "cx", args: [] }], sources: [{ path: "/ch/config.toml", stamp: "st:/ch/config.toml" }] }]);
});

test("registerLaunchMcpServers: confidentiality off → nothing read, nothing sent", async () => {
  let called = false;
  let read = false;
  for (const plan of [
    { ...PLAN, effectiveAxes: { integrity: false, confidentiality: false } },
    { ...PLAN, effectiveAxes: undefined, confidentiality: false },
  ] as McpLaunchPlan[]) {
    const r = await registerLaunchMcpServers(plan, {}, {
      home: HOME, readFile: (p) => { read = true; return LAUNCH_FILES(p); },
      call: async () => { called = true; return { registered: 0 }; }, log: () => {},
    });
    assert.equal(r, null);
  }
  assert.equal(called, false);
  assert.equal(read, false);
});

test("registerLaunchMcpServers: without a human socket it never falls back to another socket", async () => {
  const logs: string[] = [];
  let called = false;
  const r = await registerLaunchMcpServers({ ...PLAN, arbiterHumanSock: null }, { CLAUDE_CONFIG_DIR: "/cfg" }, {
    home: HOME, readFile: LAUNCH_FILES, call: async () => { called = true; return { registered: 1 }; }, log: (m) => logs.push(m),
  });
  assert.deepEqual(r, { status: "skipped" });
  assert.equal(called, false);
  assert.equal(logs.length, 1);
});

test("registerMcpServers over a real Unix socket with the launcher's ndjsonCall: the wire shape, and a refusal is non-fatal", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-reg-"));
  const sock = join(dir, "human.sock");
  const seen: unknown[] = [];
  let refuse = false;
  const server = createServer((c) => {
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const req = JSON.parse(buf.slice(0, nl)) as { id: unknown; op: string };
      seen.push(req);
      const reply = refuse
        ? { id: req.id, ok: false, error: "unknown op: registerMcpServers" }
        : { id: req.id, ok: true, result: { registered: 2 } };
      c.end(JSON.stringify(reply) + "\n");
    });
  });
  server.listen(sock);
  await once(server, "listening");
  try {
    const logs: string[] = [];
    const deps = { call: (s: string, op: string, args: Record<string, unknown>) => ndjsonCall<unknown>(s, op, args, 5_000), log: (m: string) => logs.push(m) };
    assert.deepEqual(await registerMcpServers(sock, "sess", SERVERS, deps), { status: "registered", registered: 2 });
    assert.equal(logs.length, 0);
    // The launcher's NDJSON request carries the body's fields beside `op`.
    const { id: _id, ...req } = seen[0] as Record<string, unknown>;
    assert.deepEqual(req, { op: "registerMcpServers", sessionKey: "sess", servers: SERVERS.map(({ name, command, args }) => ({ name, command, args })) });
    refuse = true;
    const r = await registerMcpServers(sock, "sess", SERVERS, deps);
    assert.equal(r.status, "failed");
    assert.equal(logs.length, 1);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- 2026-10-02: the sources plan 10 §11.13 listed as unmapped ----------------

test("claude: the managed file, every installed plugin's servers (named plugin:<plugin>:<server>, ${CLAUDE_PLUGIN_ROOT} put in) and --mcp-config files and JSON are read", () => {
  const P = "/home/u/.claude/plugins/cache/mkt/db-tools/1.2.0";
  const Q = "/home/u/.claude/plugins/cache/mkt/notes/0.1.0";
  const read = files({
    [defaultManagedMcpFile()]: JSON.stringify({ mcpServers: { corp: { command: "/opt/corp/mcp", args: ["--stdio"] }, web: { type: "http", url: "https://x" } } }),
    "/home/u/.claude/plugins/installed_plugins.json": JSON.stringify({ version: 2, plugins: {
      "db-tools@mkt": [{ scope: "user", installPath: P, version: "1.2.0" }],
      "notes@mkt": [{ scope: "project", projectPath: HUMAN, installPath: Q }],
    } }),
    [`${P}/.mcp.json`]: JSON.stringify({ mcpServers: { db: { command: "${CLAUDE_PLUGIN_ROOT}/bin/db", args: ["--config", "${CLAUDE_PLUGIN_ROOT}/c.json"] } } }),
    [`${Q}/.claude-plugin/plugin.json`]: JSON.stringify({ name: "notes", mcpServers: ["./mcp/servers.json", { inline: { command: "node", args: ["${CLAUDE_PLUGIN_ROOT}/i.js"] } }, "https://example.test/x.mcpb"] }),
    [`${Q}/mcp/servers.json`]: JSON.stringify({ store: { command: "python3", args: ["-m", "store"] } }),
    "/work/proj/extra.json": JSON.stringify({ mcpServers: { extra: { command: "extra-mcp", args: [] } } }),
  });
  const got = strip(configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: HUMAN, readFile: read,
    agentArgv: ["--model", "opus", "--mcp-config", "extra.json", '{"mcpServers":{"inl":{"command":"inl-mcp","args":["a"]}}}', "--print", "--mcp-config=/nope.json", "-p", "hi"],
  }));
  assert.deepEqual(got, [
    { name: "corp", command: "/opt/corp/mcp", args: ["--stdio"] },
    { name: "plugin:db-tools:db", command: `${P}/bin/db`, args: ["--config", `${P}/c.json`] },
    { name: "plugin:notes:store", command: "python3", args: ["-m", "store"] },
    { name: "plugin:notes:inline", command: "node", args: [`${Q}/i.js`] },
    { name: "extra", command: "extra-mcp", args: [] },
    { name: "inl", command: "inl-mcp", args: ["a"] },
  ]);
  // installed_plugins.json v1, and a CLAUDE_CONFIG_DIR that moves ~/.claude
  const v1 = strip(configuredMcpServers({
    target: "claude", home: HOME, claudeConfigDir: "/cfg", humanCwd: HUMAN, agentCwd: HUMAN, managedMcpFile: "/none",
    readFile: files({
      "/cfg/plugins/installed_plugins.json": JSON.stringify({ version: 1, plugins: { "old": { installPath: "/p/old" } } }),
      "/p/old/.mcp.json": JSON.stringify({ srv: { command: "old-mcp" } }),
    }),
  }));
  assert.deepEqual(v1, [{ name: "plugin:old:srv", command: "old-mcp", args: [] }]);
});

test("claude: malformed plugin registries, manifests and --mcp-config values contribute nothing", () => {
  const got = configuredMcpServers({
    target: "claude", home: HOME, humanCwd: HUMAN, agentCwd: HUMAN, managedMcpFile: "/m.json",
    agentArgv: ["--mcp-config", "{not json", "--mcp-config"],
    readFile: files({
      "/m.json": "nope",
      "/home/u/.claude/plugins/installed_plugins.json": JSON.stringify({ plugins: { "a@m": [{ installPath: 7 }], "b@m": "x", "@m": [{ installPath: "/p" }] } }),
    }),
  });
  assert.deepEqual(got, []);
});

test("codex: -c / --config mcp_servers overrides on the agent's argv add servers and lay a changed command line over the file's (both kept)", () => {
  const read = files({ "/home/u/.codex/config.toml": `[mcp_servers.box]\ncommand = "npx"\nargs = ["-y", "@acme/box"]\n` });
  const got = strip(configuredMcpServers({
    target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: HUMAN, readFile: read,
    agentArgv: [
      "-c", 'mcp_servers.box.args=["-y", "@acme/box@2"]',
      "--config", "mcp_servers.raw.command=raw-mcp",
      "--config=mcp_servers.tbl={command = \"tbl-mcp\", args = [\"x\"]}",
      "-cmcp_servers.dotted.command=\"dotted\"",
      "-c", "model=\"o3\"",
      "exec", "do it",
    ],
  }));
  assert.deepEqual(got, [
    { name: "box", command: "npx", args: ["-y", "@acme/box"] },
    { name: "box", command: "npx", args: ["-y", "@acme/box@2"] },
    { name: "raw", command: "raw-mcp", args: [] },
    { name: "tbl", command: "tbl-mcp", args: ["x"] },
    { name: "dotted", command: "dotted", args: [] },
  ]);
  // no config file: the overrides alone
  assert.deepEqual(strip(configuredMcpServers({ target: "codex", home: HOME, humanCwd: HUMAN, agentCwd: HUMAN, readFile: files({}), agentArgv: ["-c", "mcp_servers.solo.command=\"solo\""] })), [{ name: "solo", command: "solo", args: [] }]);
});
