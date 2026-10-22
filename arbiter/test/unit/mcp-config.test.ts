/**
 * mcp-config — the MCP and editor config files of the default catalog
 * (secret-discovery.md §2.10, 2026-10-21): which files they are and who
 * reads each, the server entries in each format (JSON with positions,
 * Codex's TOML with its inline tables), the values the twin masks and the
 * ones it keeps, the Authorization credential's wire mark, the content
 * decision that labels a config, the walk's MCP pass and its per-launch
 * tag (`agentConfig`: the launched agent's own config, left readable), the
 * wire grant of a HOME editor config (never `.claude.json`, Codex's
 * `config.toml` or a workspace file), and a session's exempt paths.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  codexTomlReading, mcpConfigKind, mcpConfigReader, mcpHomeConfigPaths, mcpServerEntries, mcpUrlHost, parseJsonPositions,
} from "../../policy/mcp-config.js";
import { CONTENT_RULE, mcpConfigCandidate, mcpConfigCredential } from "../../policy/found-labels.js";
import { extractSecretSpans, renderStructuredTwin } from "../../policy/secret-extract.js";
import { discoverSecretsReport, parseSessionLogins, sessionLoginPaths, sessionMcpConfigPaths } from "../../policy/secret-discovery.js";
import { getSymbolEntry, loadSymbolMap, wireGrantOf } from "../../symbol-table/symbol-table.js";
import { registerSecret, wireReleaseScheme } from "../../secret-registry/registry.js";
import type { LabelLookup } from "../../policy/secret-catalog.js";

// Canaries: each a credential by its shape, none a real one.
const GH = "ghp_MCPCFGgithubCANARY0123456789abcdefAB";
const BRAVE = "BSAmcpcfgBraveCANARY7x9Q2w";
const LINEAR = "lin_api_MCPCFGlinearCANARY9z8y7x6w5v";
const XKEY = "xk-MCPCFG-header-CANARY-4f9e";
const OPAQUE = "Zq8Wx7Ec6Rv5Tb4Yn3MCPCFG";
const PGPW = "Tiger9LilyMCPCFG";
const NOTION = "ntn_MCPCFGnotionCANARY0123456789ab";
const RAWS = [GH, BRAVE, LINEAR, XKEY, OPAQUE, PGPW, NOTION];

/** A Claude Code / Cursor / Claude Desktop shaped config. */
const MCP_JSON = `${JSON.stringify({
  mcpServers: {
    github: { command: "docker", args: ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: GH } },
    brave: { command: "npx", args: ["-y", "@brave/brave-search-mcp-server"], env: { BRAVE_API_KEY: BRAVE, NODE_ENV: "production" } },
    notion: { command: "npx", args: ["-y", "@notionhq/notion-mcp-server"], env: { OPENAPI_MCP_HEADERS: `{"Authorization": "Bearer ${NOTION}", "Notion-Version": "2022-06-28"}` } },
    pg: { command: "npx", args: ["-y", "@modelcontextprotocol/server-postgres", `postgresql://app:${PGPW}@db.internal/prod`] },
    linear: { type: "http", url: "https://mcp.linear.app/mcp", headers: { Authorization: `Bearer ${LINEAR}`, "Content-Type": "application/json" } },
    custom: { type: "sse", url: "http://mcp.example.test:8080/sse", headers: { "X-API-Key": XKEY } },
    opaque: { command: "uvx", args: ["mcp-server-x"], env: { SERVICE: OPAQUE, DEBUG: "1" } },
    reference: { command: "npx", args: ["-y", "server"], env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" } },
  },
}, null, 2)}\n`;

/** Codex's config.toml: tables, sub-tables, a dotted key, one-line inline tables. */
const CODEX_TOML = `model = "o3"

[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "${GH}", LOG = "info" }

[mcp_servers.linear]
url = "https://mcp.linear.app/mcp"
bearer_token = "${LINEAR}"
env_http_headers = { "X-Org" = "LINEAR_ORG" }

[mcp_servers.brave.env]
BRAVE_API_KEY = "${BRAVE}"

[mcp_servers.opaque]
command = "uvx"
env.SERVICE = "${OPAQUE}"

[projects."/home/u/proj"]
trust_level = "trusted"
`;

test("mcpConfigKind names the MCP configs by their names, and mcpConfigReader the agent that reads each in its own process", () => {
  const kinds: Array<[string, string | null]> = [
    ["/h/.claude.json", "claude"], ["/h/cfg/.claude.json", "claude"],
    ["/w/p/.mcp.json", "claude-project"], ["/h/.mcp.json", "claude-project"],
    ["/h/.cursor/mcp.json", "cursor"], ["/w/p/.cursor/mcp.json", "cursor"],
    ["/w/p/.vscode/mcp.json", "vscode"], ["/h/.config/Code/User/mcp.json", "vscode"], ["/h/Library/Application Support/Code/User/mcp.json", "vscode"],
    ["/h/.config/Claude/claude_desktop_config.json", "claude-desktop"], ["/h/Library/Application Support/Claude/claude_desktop_config.json", "claude-desktop"],
    ["/h/.codeium/windsurf/mcp_config.json", "windsurf"],
    ["/h/.codex/config.toml", "codex"],
    ["/w/p/mcp.json", null], ["/w/p/.vscode/settings.json", null], ["/w/p/config.toml", null], ["/h/.codex-work/config.toml", null],
    ["/w/p/claude_desktop_config.json", null], ["/w/p/.claude/settings.json", null],
  ];
  for (const [p, k] of kinds) assert.equal(mcpConfigKind(p), k, p);
  assert.equal(mcpConfigReader("claude"), "claude");
  assert.equal(mcpConfigReader("claude-project"), "claude");
  assert.equal(mcpConfigReader("codex"), "codex");
  for (const k of ["cursor", "vscode", "claude-desktop", "windsurf"] as const) assert.equal(mcpConfigReader(k), null, `${k}: no supported agent reads it in its own process`);
});

test("mcpHomeConfigPaths: the per-user places, and where CLAUDE_CONFIG_DIR and CODEX_HOME move Claude Code's and Codex's (absolute only)", () => {
  const ps = mcpHomeConfigPaths("/home/u", { CLAUDE_CONFIG_DIR: "/srv/claude", CODEX_HOME: "relative/codex" });
  for (const p of ["/home/u/.claude.json", "/home/u/.cursor/mcp.json", "/home/u/.config/Claude/claude_desktop_config.json", "/home/u/.codex/config.toml", "/srv/claude/.claude.json"]) assert.ok(ps.includes(p), p);
  assert.ok(!ps.some((p) => p.includes("relative")), "a relative CODEX_HOME counts for nothing");
  assert.equal(new Set(ps).size, ps.length);
});

test("parseJsonPositions: JSON and JSONC with offsets inside the quotes; anything else is null", () => {
  const text = '{\n  // VS Code writes comments\n  "servers": { "a": { "env": { "K": "v\\"x" }, }, },\n  /* and trailing commas */\n}\n';
  const root = parseJsonPositions(text);
  assert.equal(root?.t, "obj");
  const entries = mcpServerEntries("/w/.vscode/mcp.json", text)!;
  assert.equal(entries.length, 1);
  const v = entries[0]!.values[0]!;
  assert.equal(text.slice(v.start, v.end), 'v\\"x', "the raw text between the quotes, escapes as written");
  for (const bad of ["", "{", '{"a": }', '{"a": "b" "c": 1}', '["x"', '{"a": "line\nbreak"}', "{} trailing"]) assert.equal(parseJsonPositions(bad), null, JSON.stringify(bad));
  let deep = "";
  for (let i = 0; i < 80; i++) deep += "[";
  assert.equal(parseJsonPositions(deep + "]".repeat(80)), null, "nested past the depth bound");
});

test("mcpServerEntries (JSON): every server map (mcpServers, servers, mcp.servers, a .claude.json project's), stdio or http by its url or type", () => {
  const claudeJson = JSON.stringify({
    numStartups: 4,
    mcpServers: { u: { command: "a", env: { K: "1" } } },
    projects: { "/home/u/proj": { mcpServers: { l: { type: "http", url: "https://mcp.x.test/m", headers: { Authorization: "Bearer t" } } } } },
  });
  const es = mcpServerEntries("/h/.claude.json", claudeJson)!;
  assert.deepEqual(es.map((e) => [e.name, e.transport, e.url]), [["u", "stdio", null], ["l", "http", "https://mcp.x.test/m"]]);
  assert.deepEqual(es[1]!.values.map((v) => [v.role, v.name]), [["header", "Authorization"], ["url", "url"]]);
  // projects are read only in .claude.json
  assert.deepEqual(mcpServerEntries("/w/.mcp.json", claudeJson)!.map((e) => e.name), ["u"]);
  const vscode = JSON.stringify({ servers: { s: { type: "sse", headers: { "X-Key": "v" } } }, inputs: [] });
  assert.deepEqual(mcpServerEntries("/w/.vscode/mcp.json", vscode)!.map((e) => [e.name, e.transport]), [["s", "http"]], "a remote type with no url is http");
  assert.deepEqual(mcpServerEntries("/h/.codeium/windsurf/mcp_config.json", JSON.stringify({ mcpServers: { w: { serverUrl: "https://w.test/sse" } } }))!.map((e) => e.url), ["https://w.test/sse"], "Windsurf's serverUrl");
  assert.equal(mcpServerEntries("/w/.mcp.json", "not json"), null);
  assert.equal(mcpServerEntries("/w/settings.json", MCP_JSON), null, "no MCP config by name");
});

test("codexTomlReading: [mcp_servers.<name>] tables, their env and http_headers, one-line inline tables and dotted keys; a file it cannot read in full is null", () => {
  const r = codexTomlReading(CODEX_TOML)!;
  const by = new Map(r.entries.map((e) => [e.name, e]));
  assert.deepEqual([...by.keys()], ["github", "linear", "brave", "opaque"]);
  assert.deepEqual(by.get("github")!.values.map((v) => [v.role, v.name, v.raw]), [["env", "GITHUB_PERSONAL_ACCESS_TOKEN", GH], ["env", "LOG", "info"]]);
  assert.equal(by.get("linear")!.transport, "http");
  assert.deepEqual(by.get("linear")!.values.map((v) => [v.role, v.name]), [["url", "url"], ["bearer", "bearer_token"]], "env_http_headers values are variable names: not read");
  assert.deepEqual(by.get("brave")!.values.map((v) => [v.role, v.name]), [["env", "BRAVE_API_KEY"]]);
  assert.deepEqual(by.get("opaque")!.values.map((v) => [v.role, v.name, v.raw]), [["env", "SERVICE", OPAQUE]]);
  for (const v of r.entries.flatMap((e) => e.values)) assert.equal(CODEX_TOML.slice(v.start, v.end), v.raw, "offsets on the file's own text");
  assert.equal(r.inline.length, 2, "the two inline tables it read in full");
  assert.equal(codexTomlReading('[mcp_servers.a]\nenv = { K = """x"""}\n'), null, "a multi-line string");
  assert.equal(codexTomlReading('[mcp_servers.a]\nenv = { K = ["x"] }\n'), null, "an inline table holding an array");
  assert.equal(codexTomlReading('[mcp_servers.a]\nenv = {\n  K = "x"\n}\n'), null, "a multi-line inline table");
});

test("the twin of each MCP config masks every server credential and keeps the rest as written; the Authorization credential carries its host", () => {
  for (const path of ["/w/p/.mcp.json", "/h/.claude.json", "/h/.cursor/mcp.json", "/h/.config/Claude/claude_desktop_config.json"]) {
    const x = extractSecretSpans(path, MCP_JSON);
    assert.equal(x.shape, "json-keys", path);
    const masked = new Set(x.spans.flatMap((s) => [s.value, ...(s.parts ?? []).map((p) => p.value)]));
    const twin = renderStructuredTwin(MCP_JSON, x.spans, (s) => `$MDU:nomodel_Read[abcd].${s.key}`);
    for (const raw of RAWS) assert.ok(!twin.includes(raw), `${path}: CONFIDENTIALITY: ${raw} stays out of the twin:\n${twin}`);
    for (const kept of ["@brave/brave-search-mcp-server", "ghcr.io/github/github-mcp-server", '"NODE_ENV": "production"', '"DEBUG": "1"', '"Content-Type": "application/json"', "${GITHUB_TOKEN}", "https://mcp.linear.app/mcp", "db.internal/prod"]) {
      assert.ok(twin.includes(kept), `${path}: the twin keeps ${kept}`);
    }
    assert.doesNotThrow(() => JSON.parse(twin), `${path}: the twin still parses`);
    assert.ok(masked.has(OPAQUE), "a credential-looking value under a name that says nothing");
    const auth = x.spans.find((s) => s.value === `Bearer ${LINEAR}`);
    assert.deepEqual(auth?.wire, { host: "mcp.linear.app", scheme: "bearer", httpsOnly: true }, `${path}: the Authorization credential goes to its own server's host`);
    const xkey = x.spans.find((s) => s.value === XKEY);
    assert.ok(xkey && xkey.wire === undefined, "another header carries no wire mark (put back only in the Authorization header)");
  }
  // The same text under a name that is no MCP config: the generic rules only.
  const plain = extractSecretSpans("/w/p/servers.json", MCP_JSON);
  assert.ok(!plain.spans.some((s) => s.value === OPAQUE), "the MCP rules apply to an MCP config only");
  assert.ok(!plain.spans.some((s) => s.wire !== undefined));
});

test("Codex's config.toml twins in place, its inline tables included; an Authorization credential's host comes from the entry's url", () => {
  const x = extractSecretSpans("/h/.codex/config.toml", CODEX_TOML);
  assert.equal(x.shape, "toml");
  const twin = renderStructuredTwin(CODEX_TOML, x.spans, (s) => `$MDU:nomodel_Read[abcd].${s.key}`);
  for (const raw of [GH, LINEAR, BRAVE, OPAQUE]) assert.ok(!twin.includes(raw), `CONFIDENTIALITY: ${raw} stays out of the twin:\n${twin}`);
  for (const kept of ['LOG = "info"', '"X-Org" = "LINEAR_ORG"', 'trust_level = "trusted"', 'model = "o3"', '@modelcontextprotocol/server-github']) assert.ok(twin.includes(kept), `the twin keeps ${kept}:\n${twin}`);
  const bearer = x.spans.find((s) => s.value === LINEAR);
  assert.equal(bearer?.key, "mcp_servers.linear.bearer_token");
  assert.deepEqual(bearer?.wire, { host: "mcp.linear.app", scheme: "bearer", httpsOnly: true });
  assert.equal(x.spans.find((s) => s.value === OPAQUE)?.key, "mcp_servers.opaque.env.SERVICE");
  // The generic TOML reading twins a file with an inline table whole; outside
  // an MCP server's table it still does.
  assert.equal(extractSecretSpans("/h/.codex/config.toml", `${CODEX_TOML}\n[model_providers.x]\nauth = { key = "v" }\n`).shape, null, "an inline table elsewhere: whole-file");
  assert.equal(extractSecretSpans("/w/p/config.toml", CODEX_TOML).shape, null, "not Codex's: the generic reading, whole-file");
});

test("mcpUrlHost: an http(s) URL's host and port, never a reference the client expands", () => {
  assert.deepEqual(mcpUrlHost("https://MCP.Linear.app/mcp"), { host: "mcp.linear.app", https: true });
  assert.deepEqual(mcpUrlHost("http://mcp.example.test:8080/sse"), { host: "mcp.example.test:8080", https: false });
  for (const u of ["${MCP_URL}", "https://${HOST}/mcp", "ws://x.test", "not a url", "file:///x"]) assert.equal(mcpUrlHost(u), null, u);
});

test("mcpConfigCredential labels a config that holds a server's credential, never one that only names variables or holds none", () => {
  assert.ok(mcpConfigCredential("/w/p/.mcp.json", MCP_JSON)?.startsWith("github."), "the first server whose value is a credential");
  assert.equal(mcpConfigCredential("/h/.codex/config.toml", CODEX_TOML), "github.mcp_servers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN");
  const negatives: Array<[string, string]> = [
    ["/w/p/.mcp.json", JSON.stringify({ mcpServers: { a: { command: "npx", args: ["-y", "pkg"], env: { GITHUB_TOKEN: "${GITHUB_TOKEN}", NODE_ENV: "production" } } } })],
    ["/w/p/.mcp.json", JSON.stringify({ mcpServers: { a: { type: "http", url: "https://mcp.x.test/m", headers: { Authorization: "Bearer ${input:token}" } } } })],
    ["/w/p/.mcp.json", JSON.stringify({ mcpServers: { a: { command: "node", args: ["server.js"] } } })],
    ["/w/p/.mcp.json", JSON.stringify({ mcpServers: { a: { env: { API_KEY: "test" } } } })],
    ["/w/p/.mcp.json", "{ not json"],
    ["/h/.codex/config.toml", 'model = "o3"\n[mcp_servers.a]\ncommand = "x"\nenv_vars = ["GITHUB_TOKEN"]\nbearer_token_env_var = "LINEAR_TOKEN"\n'],
    ["/w/p/settings.json", MCP_JSON],
  ];
  for (const [p, t] of negatives) assert.equal(mcpConfigCredential(p, t), null, `${p}: ${t.slice(0, 80)}`);
});

test("mcpConfigCandidate: a project's MCP configs in a workspace (not in its test data), the per-user ones in HOME, never an agent's login or store", () => {
  for (const r of [[".mcp.json"], ["svc", ".mcp.json"], [".cursor", "mcp.json"], [".vscode", "mcp.json"]]) assert.ok(mcpConfigCandidate(r, "workspace"), r.join("/"));
  for (const r of [["test", "fixtures", ".mcp.json"], ["docs", ".vscode", "mcp.json"], [".claude.json"], [".codex", "config.toml"], ["mcp.json"], [".config", "Claude", "claude_desktop_config.json"]]) assert.ok(!mcpConfigCandidate(r, "workspace"), r.join("/"));
  for (const r of [[".cursor", "mcp.json"], [".config", "Claude", "claude_desktop_config.json"], [".codeium", "windsurf", "mcp_config.json"], [".config", "Code", "User", "mcp.json"]]) assert.ok(mcpConfigCandidate(r, "home"), r.join("/"));
  for (const r of [[".claude.json"], [".codex", "config.toml"], [".mcp.json"]]) assert.ok(!mcpConfigCandidate(r, "home"), r.join("/"));
});

function homeTree(files: Record<string, string>): { home: string; ws: string; cleanup: () => void } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-mcp-cfg-")));
  const home = join(dir, "home");
  const ws = join(dir, "work", "proj");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  for (const [rel, text] of Object.entries(files)) {
    const p = rel.startsWith("~/") ? join(home, rel.slice(2)) : join(ws, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  return { home, ws, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("the walk's MCP pass: per launch, the agent's own configs are tagged agentConfig (left readable), every other config is a secret to twin", () => {
  const t = homeTree({
    "~/.claude.json": MCP_JSON,
    "~/.codex/config.toml": CODEX_TOML,
    "~/.cursor/mcp.json": MCP_JSON,
    "~/.config/Claude/claude_desktop_config.json": MCP_JSON,
    ".mcp.json": MCP_JSON,
    ".vscode/mcp.json": JSON.stringify({ servers: { s: { type: "http", url: "https://x.test/m", headers: { Authorization: `Bearer ${LINEAR}` } } } }),
    "sub/.mcp.json": MCP_JSON,
    "test/fixtures/.mcp.json": MCP_JSON,
  });
  try {
    const at = (rel: string): string => (rel.startsWith("~/") ? join(t.home, rel.slice(2)) : join(t.ws, rel));
    const run = (target: string, ullmBinary?: string) => {
      const r = discoverSecretsReport([t.home, t.ws], t.home, undefined, { target, ...(ullmBinary ? { ullmBinary } : {}) });
      assert.ok(!RAWS.some((v) => JSON.stringify(r).includes(v)), "paths and fields, never a value");
      return new Map(r.files.map((f) => [f.path, f]));
    };
    const asClaude = run("claude", "claude");
    assert.equal(asClaude.get(at("~/.claude.json"))?.agentConfig, "claude", "Claude Code's own config: left readable to it");
    assert.equal(asClaude.get(at(".mcp.json"))?.agentConfig, "claude", "the project .mcp.json at the workspace root: Claude Code reads it");
    assert.equal(asClaude.get(at(".mcp.json"))?.rule, CONTENT_RULE);
    assert.equal(asClaude.get(at("sub/.mcp.json"))?.agentConfig, undefined, "a .mcp.json below the root is not the one Claude Code reads there: twinned");
    assert.ok(asClaude.has(at("sub/.mcp.json")));
    assert.equal(asClaude.get(at("~/.codex/config.toml"))?.agentConfig, undefined, "Codex's config under mandu claude: a secret to twin");
    assert.equal(asClaude.get(at("~/.codex/config.toml"))?.level, "no-model");
    for (const rel of ["~/.cursor/mcp.json", "~/.config/Claude/claude_desktop_config.json", ".vscode/mcp.json"]) {
      const f = asClaude.get(at(rel));
      assert.ok(f && f.agentConfig === undefined && f.rule === CONTENT_RULE, `${rel}: an editor's config, twinned: ${JSON.stringify(f)}`);
    }
    assert.ok(!asClaude.has(at("test/fixtures/.mcp.json")), "test data is not read");

    const asCodex = run("codex", "codex");
    assert.equal(asCodex.get(at("~/.codex/config.toml"))?.agentConfig, "codex", "Codex's own config: left readable to it");
    assert.equal(asCodex.get(at(".mcp.json"))?.agentConfig, undefined, "Codex does not read .mcp.json: twinned");
    assert.equal(asCodex.get(at("~/.claude.json"))?.agentLogin, "claude", "Claude Code's .claude.json under codex: another agent's login, as before");
    assert.equal(asCodex.get(at("~/.claude.json"))?.agentConfig, undefined);

    const asShell = run("shell");
    assert.equal(asShell.get(at("~/.claude.json"))?.agentConfig, "claude", "a plain command keeps Claude Code's login: its config too");

    // a config that only names its variables is not listed, and a pass with
    // HOME not among the roots reads none of HOME's
    writeFileSync(at("~/.codex/config.toml"), 'model = "o3"\n[mcp_servers.a]\ncommand = "x"\nenv_vars = ["GITHUB_TOKEN"]\n');
    assert.ok(!run("claude").has(at("~/.codex/config.toml")), "a config.toml with no server credential stays out");
    const noHome = discoverSecretsReport([t.ws], t.home, undefined, { target: "claude" });
    assert.ok(!noHome.files.some((f) => f.path.startsWith(t.home + "/")), "HOME's configs are read only when HOME is walked");
  } finally {
    t.cleanup();
  }
});

test("registration: an editor's HOME config binds its Authorization credential to its server's host (a recorded wire grant); a workspace config, .claude.json and Codex's config.toml bind nothing", () => {
  const t = homeTree({
    "~/.cursor/mcp.json": MCP_JSON,
    "~/.claude.json": MCP_JSON,
    "~/.codex/config.toml": CODEX_TOML,
    ".mcp.json": MCP_JSON,
  });
  try {
    const dbPath = join(t.home, "..", "symbols.db");
    const map = loadSymbolMap(dbPath);
    const label: LabelLookup = () => ({ level: "no-model", bindings: [], via: "test", origin: "user" } as ReturnType<LabelLookup>);
    const fieldOf = (path: string, value: string): string => {
      for (const [name, e] of map.symbols) if (e.origin === path && e.field !== null && e.value === value) return name;
      throw new Error(`no field row for ${value} of ${path}`);
    };
    for (const rel of ["~/.cursor/mcp.json", "~/.claude.json", "~/.codex/config.toml", ".mcp.json"]) {
      const path = rel.startsWith("~/") ? join(t.home, rel.slice(2)) : join(t.ws, rel);
      const r = registerSecret(map, { path, home: t.home, resolveLabel: label }, dbPath);
      assert.ok(r.symbol && r.twin, `${rel}: ${r.reason}`);
      for (const raw of RAWS) assert.ok(!r.twin!.includes(raw), `${rel}: CONFIDENTIALITY: no ${raw} in the twin`);
      const authValue = rel.endsWith("config.toml") ? LINEAR : `Bearer ${LINEAR}`;
      const auth = fieldOf(path, authValue);
      const granted = rel === "~/.cursor/mcp.json";
      assert.deepEqual(getSymbolEntry(map, auth)?.bindings ?? [], granted ? ["mcp.linear.app"] : [], `${rel}: the Authorization credential's bindings`);
      assert.equal(wireGrantOf(map, auth), granted ? "mcp.linear.app" : undefined, `${rel}: the grant is recorded only for an editor's HOME config`);
      assert.equal(wireReleaseScheme(map, auth), "https", `${rel}: an https server's credential is put back over https only`);
      const gh = fieldOf(path, GH);
      assert.deepEqual(getSymbolEntry(map, gh)?.bindings ?? [], [], `${rel}: a stdio server's variable is bound nowhere by the config`);
      assert.equal(wireReleaseScheme(map, gh), null, "and is no wire credential");
    }
  } finally {
    t.cleanup();
  }
});

test("a session's exempt MCP configs: Codex's config.toml when Codex is kept, a project's .mcp.json when Claude Code is, nothing else", () => {
  const H = "/home/u";
  const of = (o: unknown): string[] => { const s = parseSessionLogins(o); return s === null ? [] : sessionMcpConfigPaths(s).sort(); };
  assert.deepEqual(of({ home: H, target: "codex" }), [`${H}/.codex/config.toml`]);
  assert.deepEqual(of({ home: H, target: "codex", loginEnv: { CODEX_HOME: "/srv/cx" } }), [`${H}/.codex/config.toml`, "/srv/cx/config.toml"]);
  assert.deepEqual(of({ home: H, target: "claude", mcpConfigs: ["/w/.mcp.json", "/w/.cursor/mcp.json", "/w/x.json"] }), ["/w/.mcp.json"], "a kind Claude Code reads only");
  assert.deepEqual(of({ home: H, target: "goose", mcpConfigs: ["/w/.mcp.json"] }), [], "no kept agent reads it");
  const many = Array.from({ length: 40 }, (_, i) => `/w${i}/.mcp.json`);
  assert.equal(of({ home: H, target: "claude", mcpConfigs: many }).length, 16, "bounded");
  assert.ok(sessionLoginPaths(parseSessionLogins({ home: H, target: "claude", mcpConfigs: ["/w/.mcp.json"] })!).includes("/w/.mcp.json"));
});
