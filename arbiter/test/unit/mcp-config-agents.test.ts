/**
 * mcp-config, the other agents' and tools' configs (secret-discovery.md
 * §2.10, "The other agents' and tools' configs", 2026-10-22): OpenCode's
 * `opencode.json(c)`, Goose's `config.yaml`, Gemini CLI's `settings.json`,
 * Zed's `settings.json`, Continue's YAML and JSON configs and blocks, and a
 * Codex `config.toml` that `CODEX_HOME` moved out of `.codex`. Per format:
 * the kind and its reader, the server entries with their offsets, what the
 * twin masks and keeps (comments, references, empty maps), the wire mark of
 * an HTTP server's Authorization credential, the content decision that
 * labels a config (never one that only names its variables), the walk's
 * per-launch tag (`agentConfig` for OpenCode's and Goose's own configs and
 * a moved Codex config), the wire grant of a HOME config no supported
 * agent reads (Gemini CLI's) and none for OpenCode's, and a session's exempt
 * paths.
 *
 * Fixtures are shaped after each tool's documentation (opencode.ai
 * docs/mcp-servers and docs/config; Goose's ExtensionConfig in
 * crates/goose/src/agents/extension.rs; Gemini CLI docs/tools/mcp-server.md;
 * zed.dev docs/ai/mcp; docs.continue.dev customize/deep-dives/mcp and the
 * config.yaml reference). Every value is fake, built by concatenation.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import yaml from "js-yaml";

import {
  mcpConfigKind, mcpConfigKindOf, mcpConfigLike, mcpConfigReader, mcpHomeConfigPaths, mcpReference, mcpServerEntries, mcpWholeReference,
  parseJsonPositions, yamlServerEntries,
} from "../../policy/mcp-config.js";
import { CONTENT_RULE, mcpConfigCandidate, mcpConfigCredential } from "../../policy/found-labels.js";
import { extractSecretSpans, renderStructuredTwin, secretFileShape } from "../../policy/secret-extract.js";
import { discoverSecretsReport, keptMcpReaders, parseSessionLogins, sessionMcpConfigPaths } from "../../policy/secret-discovery.js";
import { getSymbolEntry, loadSymbolMap, wireGrantOf } from "../../symbol-table/symbol-table.js";
import { registerSecret } from "../../secret-registry/registry.js";
import type { LabelLookup } from "../../policy/secret-catalog.js";

// Fake credentials, each built by concatenation so no scanner reads a whole
// one in this file; each a credential by its shape.
const OC_GH = "ghp_" + "OPENCODEcfgCANARY" + "0123456789abcdefAB";
const OC_AUTH = "oca_" + "OpencodeRemoteBearer" + "9z8y7x6w5v";
const OC_OPAQUE = "Zq8Wx7Ec6" + "Rv5Tb4Yn3OCODE";
const GOOSE_GH = "ghp_" + "GOOSEcfgCANARY" + "0123456789abcdefCD";
const GOOSE_AUTH = "gsa_" + "GooseStreamBearer" + "0123456789EF";
const GOOSE_Q = "gq_" + "GooseQuotedToken" + "7x9Q2wZ5";
const GEM_KEY = "AIza" + "SyGEMINIcfgCANARY" + "0123456789abcdefg";
const GEM_AUTH = "gma_" + "GeminiHttpBearer" + "0123456789GH";
const ZED_ENV = "zde_" + "ZedContextServer" + "0123456789IJ";
const ZED_OLD = "zdo_" + "ZedOlderCommandEnv" + "0123456789KL";
const ZED_EXT = "ghp_" + "ZEDextensionCANARY" + "0123456789abcdefMN";
const ZED_AUTH = "zda_" + "ZedRemoteBearer" + "0123456789OP";
const CON_ENV = "cne_" + "ContinueStdioToken" + "0123456789QR";
const CON_HDR = "cnh_" + "ContinueHeaderToken" + "0123456789ST";
const CON_BLOCK = "cnb_" + "ContinueBlockToken" + "0123456789UV";
const CON_JSON = "cnj_" + "ContinueJsonBlockTok" + "0123456789WX";
const CON_LEGACY = "cnl_" + "ContinueLegacyToken" + "0123456789YZ";
const CX_GH = "ghp_" + "CODEXHOMEmovedCANARY" + "0123456789abcd";
const ALL = [OC_GH, OC_AUTH, OC_OPAQUE, GOOSE_GH, GOOSE_AUTH, GOOSE_Q, GEM_KEY, GEM_AUTH, ZED_ENV, ZED_OLD, ZED_EXT, ZED_AUTH, CON_ENV, CON_HDR, CON_BLOCK, CON_JSON, CON_LEGACY, CX_GH];

/** OpenCode's opencode.jsonc: comments, `{env:…}` / `{file:…}`, an empty
 *  `environment`, a raw token, an HTTP server's raw bearer. */
const OPENCODE_JSONC = `{
  "$schema": "https://opencode.ai/config.json",
  // the MCP servers
  "mcp": {
    "github": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-github"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${OC_GH}", "LOG_LEVEL": "debug" },
      "enabled": true
    },
    "opaque": { "type": "local", "command": ["uvx", "mcp-x"], "environment": { "SERVICE": "${OC_OPAQUE}" } },
    "ref": { "type": "local", "command": ["npx", "-y", "srv"], "environment": { "API_KEY": "{env:MY_API_KEY}", "CERT": "{file:~/.secrets/cert}" } },
    "empty": { "type": "local", "command": ["node", "s.js"], "environment": {} },
    "remote": {
      "type": "remote",
      "url": "https://mcp.opencode-example.test/mcp",
      "headers": { "Authorization": "Bearer ${OC_AUTH}", "X-Ref": "{env:CONTEXT7_API_KEY}" }, /* a trailing comma below */
    },
  },
}
`;

/** Goose's config.yaml, as Goose writes it (flat scalars, an extensions
 *  map), with a comment, a block-scalar description, env_keys and an
 *  empty envs map. */
const GOOSE_YAML = `GOOSE_PROVIDER: anthropic
GOOSE_MODEL: claude-sonnet-4-5
# the extensions
extensions:
  developer:
    bundled: true
    enabled: true
    name: developer
    timeout: 300
    type: builtin
  github:
    args:
    - -y
    - '@modelcontextprotocol/server-github'
    cmd: npx
    description: |
      GitHub's MCP server:
        issues and pulls
    enabled: true
    env_keys:
    - GITHUB_ORG_TOKEN
    envs:
      GITHUB_PERSONAL_ACCESS_TOKEN: ${GOOSE_GH}
      LOG_LEVEL: info # verbose later
      QUOTED: "${GOOSE_Q}"
    name: github
    type: stdio
  remote:
    enabled: true
    envs: {}
    env_keys: []
    headers:
      Authorization: Bearer ${GOOSE_AUTH}
      Accept: application/json
    name: remote
    type: streamable_http
    uri: https://mcp.goose-example.test/mcp
  refs:
    cmd: uvx
    args: [mcp-refs]
    envs: { API_TOKEN: "\${API_TOKEN}" }
    type: stdio
`;

/** Gemini CLI's settings.json: `$VAR` and `${VAR}` references, a raw key,
 *  an httpUrl server with a raw bearer. */
const GEMINI_JSON = `${JSON.stringify({
  theme: "GitHub",
  mcpServers: {
    search: { command: "npx", args: ["-y", "search-mcp"], env: { API_KEY: GEM_KEY, LOG_LEVEL: "$LOG_LEVEL" } },
    refs: { command: "node", args: ["s.js"], env: { API_KEY: "$MY_API_TOKEN", OTHER: "${EXTERNAL_API_KEY}" } },
    remote: { httpUrl: "https://mcp.gemini-example.test/mcp", headers: { Authorization: `Bearer ${GEM_AUTH}` }, timeout: 30000, trust: false },
  },
}, null, 2)}\n`;

/** Zed's settings.json: JSONC, the current `command` + `env` form, the
 *  older `command: {path, args, env}`, an extension server's `settings`, a
 *  remote server's raw bearer. */
const ZED_JSONC = `// Zed settings
{
  "theme": "One Dark",
  "context_servers": {
    "local": { "command": "some-command", "args": ["arg-1"], "env": { "SERVICE_TOKEN": "${ZED_ENV}" } },
    "older": { "source": "custom", "command": { "path": "node", "args": ["s.js"], "env": { "API_KEY": "${ZED_OLD}" } } },
    "mcp-server-github": { "source": "extension", "settings": { "github_personal_access_token": "${ZED_EXT}" } },
    "remote": { "url": "https://mcp.zed-example.test/mcp", "headers": { "Authorization": "Bearer ${ZED_AUTH}" } },
    "empty": { "command": "x", "args": [], "env": {} },
  },
}
`;

/** Continue's config.yaml: an `mcpServers` list, `${{ secrets.X }}`
 *  references, a raw stdio token, a remote server's raw header. */
const CONTINUE_YAML = `name: My Config
version: 1.0.0
schema: v1
models:
  - name: local
    provider: ollama
    model: llama3
mcpServers:
  - name: SQLite
    command: uvx
    args:
      - mcp-server-sqlite
      - --db-path
      - ./test.db
    env:
      NODE_ENV: production
      SERVICE_TOKEN: ${CON_ENV}
  - name: GitHub
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: \${{ secrets.GITHUB_PERSONAL_ACCESS_TOKEN }}
  - name: Remote
    type: streamable-http
    url: https://mcp.continue-example.test/mcp
    requestOptions:
      headers:
        X-API-Key: ${CON_HDR}
`;

/** A Continue block file (`.continue/mcpServers/<name>.yaml`). */
const CONTINUE_BLOCK = `name: Playwright mcpServer
version: 0.0.1
schema: v1
mcpServers:
- name: Browser search
  command: npx
  args:
  - "@playwright/mcp@latest"
  env:
    BROWSER_TOKEN: "${CON_BLOCK}"
`;

/** A Claude Desktop shaped JSON copied into `.continue/mcpServers/`. */
const CONTINUE_JSON_BLOCK = `${JSON.stringify({ mcpServers: { s: { command: "npx", args: ["-y", "s"], env: { S_TOKEN: CON_JSON } } } }, null, 2)}\n`;

/** Continue's deprecated config.json. */
const CONTINUE_LEGACY = `${JSON.stringify({
  models: [],
  experimental: { modelContextProtocolServers: [{ transport: { type: "stdio", command: "uvx", args: ["mcp-server-sqlite"], env: { SQLITE_TOKEN: CON_LEGACY } } }] },
}, null, 2)}\n`;

/** A Codex config.toml where CODEX_HOME moved it. */
const CODEX_MOVED = `model = "o3"

[mcp_servers.github]
command = "npx"
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "${CX_GH}" }
`;

const ph = (s: { key: string }): string => `$MDU:nomodel_Read[abcd].${s.key}`;
const twinOf = (path: string, text: string): { values: string[]; twin: string; x: ReturnType<typeof extractSecretSpans> } => {
  const x = extractSecretSpans(path, text);
  return { x, values: x.spans.map((s) => s.value), twin: renderStructuredTwin(text, x.spans, ph) };
};

test("the new kinds by name, their readers, and a Codex config.toml by its text", () => {
  const kinds: Array<[string, string | null]> = [
    ["/w/p/opencode.json", "opencode"], ["/w/p/opencode.jsonc", "opencode"], ["/h/.config/opencode/opencode.json", "opencode"], ["/h/.config/opencode/config.json", "opencode"],
    ["/h/.config/goose/config.yaml", "goose"],
    ["/h/.gemini/settings.json", "gemini"], ["/w/p/.gemini/settings.json", "gemini"],
    ["/h/.config/zed/settings.json", "zed"], ["/w/p/.zed/settings.json", "zed"],
    ["/h/.continue/config.yaml", "continue"], ["/h/.continue/config.json", "continue"], ["/w/p/.continue/mcpServers/pw.yaml", "continue"], ["/w/p/.continue/mcpServers/mcp.json", "continue"],
    // not these
    ["/w/p/config.json", null], ["/w/p/goose/config.yaml", null], ["/w/p/settings.json", null], ["/w/p/zed/settings.json", null],
    ["/w/p/.continue/rules/r.yaml", null], ["/w/p/mcpServers/x.yaml", null], ["/h/.config/opencode/tui.json", null],
  ];
  for (const [p, k] of kinds) assert.equal(mcpConfigKind(p), k, p);
  assert.equal(mcpConfigReader("opencode"), "opencode");
  assert.equal(mcpConfigReader("goose"), "goose");
  for (const k of ["gemini", "zed", "continue"] as const) assert.equal(mcpConfigReader(k), null, `${k}: no supported agent reads it`);
  // CODEX_HOME's config.toml: no name tells it; its [mcp_servers.*] tables do.
  assert.equal(mcpConfigKind("/srv/cx/config.toml"), null);
  assert.equal(mcpConfigKindOf("/srv/cx/config.toml", CODEX_MOVED), "codex");
  assert.equal(mcpConfigKindOf("/srv/cx/config.toml", 'model = "o3"\n'), null, "no MCP table: no MCP config");
  assert.equal(mcpConfigKindOf("/w/p/Cargo.toml", CODEX_MOVED), null, "only a config.toml");
  assert.ok(mcpConfigLike("/srv/cx/config.toml") && mcpConfigLike("/w/p/opencode.json") && !mcpConfigLike("/w/p/x.toml"));
  assert.equal(secretFileShape("/w/p/opencode.jsonc"), "json-keys", "JSONC is read as JSON");
});

test("mcpHomeConfigPaths: the new per-user places", () => {
  const ps = mcpHomeConfigPaths("/home/u");
  for (const p of ["/home/u/.config/opencode/opencode.json", "/home/u/.config/opencode/opencode.jsonc", "/home/u/.config/goose/config.yaml", "/home/u/.gemini/settings.json", "/home/u/.config/zed/settings.json", "/home/u/.continue/config.yaml", "/home/u/.continue/config.json"]) assert.ok(ps.includes(p), p);
});

test("mcpReference: every syntax a client expands is a reference; a token beside one is not", () => {
  for (const r of ["${GITHUB_TOKEN}", "Bearer ${TOKEN}", "{env:MY_API_KEY}", "Bearer {env:MY_API_KEY}", "{file:~/.secrets/k}", "${{ secrets.GITHUB_TOKEN }}", "$MY_API_TOKEN", "Bearer $LINEAR_TOKEN", "${input:token}", "https://${HOST}/x"]) assert.ok(mcpReference(r), r);
  for (const r of ["${GITHUB_TOKEN}", "{env:X}", "${{ secrets.X }}", "$MY_TOKEN", "Bearer $T"]) assert.ok(mcpWholeReference(r), r);
  // Not references: a raw token, a token written beside a reference, a
  // lower-case `$word` (no environment name), a password with a `$` in it.
  for (const r of [OC_AUTH, `${OC_AUTH}{env:X}`, `Bearer ${GEM_AUTH} \${X}`, "$abc", "pa$Sw0rd", "Tr0ub4dor$X"]) assert.ok(!mcpWholeReference(r) || !mcpReference(r), r);
  assert.ok(!mcpReference(`${OC_AUTH}{env:X}`), "a token beside a reference is still a token");
  assert.ok(!mcpReference(OC_AUTH));
});

test("OpenCode: the mcp map, environment and headers, JSONC; references and empty maps kept; the Authorization credential's host", () => {
  const p = "/w/p/opencode.jsonc";
  const es = mcpServerEntries(p, OPENCODE_JSONC)!;
  assert.deepEqual(es.map((e) => [e.name, e.transport, e.url]), [["github", "stdio", null], ["opaque", "stdio", null], ["ref", "stdio", null], ["empty", "stdio", null], ["remote", "http", "https://mcp.opencode-example.test/mcp"]]);
  for (const v of es.flatMap((e) => e.values)) assert.equal(OPENCODE_JSONC.slice(v.start, v.end), v.raw, "offsets on the file's own text");
  const { x, values, twin } = twinOf(p, OPENCODE_JSONC);
  for (const v of [OC_GH, OC_OPAQUE, `Bearer ${OC_AUTH}`]) assert.ok(values.includes(v), `masks ${v.slice(0, 12)}`);
  for (const raw of [OC_GH, OC_OPAQUE, OC_AUTH]) assert.ok(!twin.includes(raw), "CONFIDENTIALITY: no value in the twin");
  for (const kept of ['"{env:MY_API_KEY}"', '"{file:~/.secrets/cert}"', '"{env:CONTEXT7_API_KEY}"', '"LOG_LEVEL": "debug"', '"environment": {}', "// the MCP servers", "/* a trailing comma below */"]) assert.ok(twin.includes(kept), `the twin keeps ${kept}`);
  assert.notEqual(parseJsonPositions(twin), null, "the twin still parses (JSONC)");
  assert.deepEqual(x.spans.find((s) => s.value === `Bearer ${OC_AUTH}`)?.wire, { host: "mcp.opencode-example.test", scheme: "bearer", httpsOnly: true });
  assert.ok(mcpConfigCredential(p, OPENCODE_JSONC)?.startsWith("github."));
  // the same file as opencode.json
  assert.equal(mcpServerEntries("/h/.config/opencode/opencode.json", OPENCODE_JSONC)!.length, 5);
});

test("Goose: the extensions map, envs and headers, a block-scalar description skipped, env_keys never read; the twin parses to the same structure", () => {
  const p = "/h/.config/goose/config.yaml";
  const es = mcpServerEntries(p, GOOSE_YAML)!;
  assert.deepEqual(es.map((e) => [e.name, e.transport, e.url]), [["developer", "stdio", null], ["github", "stdio", null], ["remote", "http", "https://mcp.goose-example.test/mcp"], ["refs", "stdio", null]]);
  const gh = es.find((e) => e.name === "github")!;
  assert.deepEqual(gh.values.map((v) => [v.role, v.name, v.field]), [
    ["env", "GITHUB_PERSONAL_ACCESS_TOKEN", "extensions.github.envs.GITHUB_PERSONAL_ACCESS_TOKEN"],
    ["env", "LOG_LEVEL", "extensions.github.envs.LOG_LEVEL"],
    ["env", "QUOTED", "extensions.github.envs.QUOTED"],
  ], "env_keys names a secret-store key, never a value");
  for (const v of es.flatMap((e) => e.values)) assert.equal(GOOSE_YAML.slice(v.start, v.end), v.raw, "offsets on the file's own text");
  const { x, values, twin } = twinOf(p, GOOSE_YAML);
  for (const v of [GOOSE_GH, GOOSE_Q, `Bearer ${GOOSE_AUTH}`]) assert.ok(values.includes(v), `masks ${v.slice(0, 12)}`);
  assert.ok(!values.includes("info") && !values.includes("application/json") && !values.includes("${API_TOKEN}"), "a plain setting, a benign header and a reference are kept");
  for (const raw of [GOOSE_GH, GOOSE_Q, GOOSE_AUTH]) assert.ok(!twin.includes(raw), "CONFIDENTIALITY: no value in the twin");
  assert.deepEqual(x.spans.find((s) => s.value === `Bearer ${GOOSE_AUTH}`)?.wire, { host: "mcp.goose-example.test", scheme: "bearer", httpsOnly: true });
  assert.equal(x.spans.find((s) => s.value === GOOSE_Q)?.key, "extensions.github.envs.QUOTED");
  // The twin is YAML of the same shape, each masked value its placeholder.
  const orig = yaml.load(GOOSE_YAML) as { extensions: Record<string, { envs?: Record<string, string>; headers?: Record<string, string>; description?: string }> };
  const back = yaml.load(twin) as typeof orig;
  assert.deepEqual(Object.keys(back.extensions), Object.keys(orig.extensions));
  assert.equal(back.extensions["github"]!.envs!["LOG_LEVEL"], "info");
  assert.match(back.extensions["github"]!.envs!["GITHUB_PERSONAL_ACCESS_TOKEN"]!, /^\$MDU:nomodel_Read\[abcd\]\./);
  assert.match(back.extensions["remote"]!.headers!["Authorization"]!, /^\$MDU:/);
  assert.equal(back.extensions["github"]!.description, orig.extensions["github"]!.description, "the block scalar is untouched");
  assert.ok(mcpConfigCredential(p, GOOSE_YAML)?.startsWith("github."));
  // No extensions section: no entry, and nothing to label.
  assert.deepEqual(mcpServerEntries(p, "GOOSE_PROVIDER: openai\nGOOSE_MODEL: gpt-5\n"), []);
});

test("YAML the reader cannot place: the whole-file twin, and the label decided on the file's words (fail-closed)", () => {
  const p = "/h/.config/goose/config.yaml";
  const anchored = `extensions:\n  github:\n    envs: &shared\n      GITHUB_PERSONAL_ACCESS_TOKEN: ${GOOSE_GH}\n    type: stdio\n  other:\n    envs: *shared\n`;
  const blockValue = `extensions:\n  github:\n    envs:\n      SERVICE: |\n        ${OC_OPAQUE}\n    type: stdio\n`;
  for (const text of [anchored, blockValue]) {
    assert.equal(yamlServerEntries(text, "goose"), null);
    assert.equal(extractSecretSpans(p, text).shape, null, "the whole-file twin");
    assert.ok(mcpConfigCredential(p, text)?.startsWith("<unread>."), "labelled: a word reads as a credential");
  }
  assert.equal(mcpConfigCredential(p, "extensions:\n  a:\n    envs: &x\n      LOG: info\n"), null, "an unreadable file with no credential word is not labelled");
});

test("Gemini CLI: env and headers, $VAR and ${VAR} references kept, httpUrl's Authorization host", () => {
  const p = "/h/.gemini/settings.json";
  const es = mcpServerEntries(p, GEMINI_JSON)!;
  assert.deepEqual(es.map((e) => [e.name, e.transport, e.url]), [["search", "stdio", null], ["refs", "stdio", null], ["remote", "http", "https://mcp.gemini-example.test/mcp"]]);
  const { x, values, twin } = twinOf(p, GEMINI_JSON);
  for (const v of [GEM_KEY, `Bearer ${GEM_AUTH}`]) assert.ok(values.includes(v));
  for (const kept of ['"API_KEY": "$MY_API_TOKEN"', '"OTHER": "${EXTERNAL_API_KEY}"', '"LOG_LEVEL": "$LOG_LEVEL"', '"theme": "GitHub"']) assert.ok(twin.includes(kept), `the twin keeps ${kept}`);
  assert.doesNotThrow(() => JSON.parse(twin));
  assert.deepEqual(x.spans.find((s) => s.value === `Bearer ${GEM_AUTH}`)?.wire, { host: "mcp.gemini-example.test", scheme: "bearer", httpsOnly: true });
  assert.ok(mcpConfigCredential(p, GEMINI_JSON) !== null);
});

test("Zed: context_servers, env beside command and in the older command object, an extension's settings, a remote bearer; JSONC kept", () => {
  const p = "/h/.config/zed/settings.json";
  const es = mcpServerEntries(p, ZED_JSONC)!;
  assert.deepEqual(es.map((e) => [e.name, e.transport]), [["local", "stdio"], ["older", "stdio"], ["mcp-server-github", "stdio"], ["remote", "http"], ["empty", "stdio"]]);
  const { x, values, twin } = twinOf(p, ZED_JSONC);
  for (const v of [ZED_ENV, ZED_OLD, ZED_EXT, `Bearer ${ZED_AUTH}`]) assert.ok(values.includes(v), `masks ${v.slice(0, 12)}`);
  for (const raw of [ZED_ENV, ZED_OLD, ZED_EXT, ZED_AUTH]) assert.ok(!twin.includes(raw));
  for (const kept of ["// Zed settings", '"theme": "One Dark"', '"env": {}', '"args": ["arg-1"]']) assert.ok(twin.includes(kept), `the twin keeps ${kept}`);
  assert.notEqual(parseJsonPositions(twin), null);
  assert.deepEqual(x.spans.find((s) => s.value === `Bearer ${ZED_AUTH}`)?.wire, { host: "mcp.zed-example.test", scheme: "bearer", httpsOnly: true });
});

test("Continue: the mcpServers list, ${{ secrets.X }} kept, requestOptions headers; a YAML block, a JSON block and the deprecated config.json", () => {
  const p = "/h/.continue/config.yaml";
  const es = mcpServerEntries(p, CONTINUE_YAML)!;
  assert.deepEqual(es.map((e) => [e.name, e.transport, e.url]), [["SQLite", "stdio", null], ["GitHub", "stdio", null], ["Remote", "http", "https://mcp.continue-example.test/mcp"]]);
  const { values, twin } = twinOf(p, CONTINUE_YAML);
  for (const v of [CON_ENV, CON_HDR]) assert.ok(values.includes(v));
  assert.ok(!values.includes("production") && !values.some((v) => v.includes("secrets.")) && !values.includes("./test.db") && !values.includes("mcp-server-sqlite"), "a setting, a reference and plain args are kept");
  assert.ok(twin.includes("${{ secrets.GITHUB_PERSONAL_ACCESS_TOKEN }}"));
  const back = yaml.load(twin) as { mcpServers: Array<{ name: string; env?: Record<string, string>; args?: string[] }> };
  assert.deepEqual(back.mcpServers.map((s) => s.name), ["SQLite", "GitHub", "Remote"]);
  assert.match(back.mcpServers[0]!.env!["SERVICE_TOKEN"]!, /^\$MDU:/);
  assert.ok(mcpConfigCredential(p, CONTINUE_YAML) !== null);

  const bp = "/w/p/.continue/mcpServers/playwright.yaml";
  const b = twinOf(bp, CONTINUE_BLOCK);
  assert.ok(b.values.includes(CON_BLOCK) && !b.twin.includes(CON_BLOCK));
  assert.equal(mcpServerEntries(bp, CONTINUE_BLOCK)![0]!.name, "Browser search", "a list at its key's indent");
  const jp = "/w/p/.continue/mcpServers/mcp.json";
  assert.ok(twinOf(jp, CONTINUE_JSON_BLOCK).values.includes(CON_JSON));
  const lp = "/h/.continue/config.json";
  assert.deepEqual(mcpServerEntries(lp, CONTINUE_LEGACY)!.map((e) => e.values.map((v) => v.name)), [["SQLITE_TOKEN"]]);
  assert.ok(twinOf(lp, CONTINUE_LEGACY).values.includes(CON_LEGACY));
  assert.ok(mcpConfigCredential(lp, CONTINUE_LEGACY) !== null);
});

test("negatives: a config of each new kind that only names its variables, or holds no credential, is not labelled; a plain arg is never taken", () => {
  const negatives: Array<[string, string]> = [
    ["/w/p/opencode.json", JSON.stringify({ mcp: { a: { type: "local", command: ["npx", "-y", "pkg"], environment: { GITHUB_TOKEN: "{env:GITHUB_TOKEN}", K: "{file:~/.k}" } }, r: { type: "remote", url: "https://x.test/m", headers: { Authorization: "Bearer {env:X_KEY}" } } } })],
    ["/w/p/opencode.json", JSON.stringify({ mcp: { a: { type: "local", command: ["node", "s.js"], environment: {} } } })],
    ["/h/.config/goose/config.yaml", "extensions:\n  github:\n    cmd: npx\n    args: [-y, pkg]\n    env_keys:\n    - GITHUB_PERSONAL_ACCESS_TOKEN\n    envs: {}\n    type: stdio\n"],
    ["/h/.gemini/settings.json", JSON.stringify({ mcpServers: { a: { command: "x", env: { API_KEY: "$MY_API_TOKEN", B: "${OTHER}" } } } })],
    ["/h/.config/zed/settings.json", '{ "context_servers": { "a": { "command": "x", "args": ["--port", "8080"], "env": {} } }, }'],
    ["/h/.continue/config.yaml", "mcpServers:\n  - name: gh\n    command: npx\n    env:\n      GITHUB_PERSONAL_ACCESS_TOKEN: ${{ secrets.GITHUB_PERSONAL_ACCESS_TOKEN }}\n"],
    ["/srv/cx/config.toml", 'model = "o3"\n[mcp_servers.a]\ncommand = "x"\nenv_vars = ["GITHUB_TOKEN"]\n'],
  ];
  for (const [p, t] of negatives) {
    assert.equal(mcpConfigCredential(p, t), null, `${p}: ${t.slice(0, 80)}`);
    const x = extractSecretSpans(p, t);
    assert.ok(!x.spans.some((s) => mcpReference(s.value)), `${p}: no reference is masked`);
  }
  // A plain argument and a plain setting are never taken.
  const v = twinOf("/w/p/opencode.json", OPENCODE_JSONC).values;
  for (const plain of ["npx", "-y", "@modelcontextprotocol/server-github", "debug", "local"]) assert.ok(!v.includes(plain), plain);
});

test("mcpConfigCandidate: the new project configs in a workspace, the per-user ones in HOME; Goose's has no project form", () => {
  for (const r of [["opencode.json"], ["svc", "opencode.jsonc"], [".gemini", "settings.json"], [".zed", "settings.json"], [".continue", "mcpServers", "a.yaml"], [".continue", "config.yaml"]]) assert.ok(mcpConfigCandidate(r, "workspace"), r.join("/"));
  for (const r of [["test", "opencode.json"], [".config", "goose", "config.yaml"], ["docs", ".gemini", "settings.json"]]) assert.ok(!mcpConfigCandidate(r, "workspace"), r.join("/"));
  for (const r of [[".config", "opencode", "opencode.json"], [".config", "goose", "config.yaml"], [".gemini", "settings.json"], [".config", "zed", "settings.json"], [".continue", "config.yaml"]]) assert.ok(mcpConfigCandidate(r, "home"), r.join("/"));
});

function tree(files: Record<string, string>): { home: string; ws: string; root: string; cleanup: () => void } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mdu-mcp-agents-")));
  const home = join(root, "home");
  const ws = join(root, "work", "proj");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  for (const [rel, text] of Object.entries(files)) {
    const p = rel.startsWith("~/") ? join(home, rel.slice(2)) : rel.startsWith("/") ? join(root, rel.slice(1)) : join(ws, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  return { home, ws, root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("the walk: OpenCode's and Goose's own configs are left readable to their launch (labelled, tagged agentConfig) and twinned in every other; Gemini's, Zed's and Continue's are twinned everywhere", () => {
  const t = tree({
    "~/.config/opencode/opencode.json": OPENCODE_JSONC,
    "~/.config/goose/config.yaml": GOOSE_YAML,
    "~/.gemini/settings.json": GEMINI_JSON,
    "~/.config/zed/settings.json": ZED_JSONC,
    "~/.continue/config.yaml": CONTINUE_YAML,
    "opencode.jsonc": OPENCODE_JSONC,
    "sub/opencode.json": OPENCODE_JSONC,
    ".continue/mcpServers/pw.yaml": CONTINUE_BLOCK,
  });
  try {
    const at = (rel: string): string => (rel.startsWith("~/") ? join(t.home, rel.slice(2)) : join(t.ws, rel));
    const run = (target: string) => {
      const r = discoverSecretsReport([t.home, t.ws], t.home, undefined, { target });
      assert.ok(!ALL.some((v) => JSON.stringify(r).includes(v)), "paths and fields, never a value");
      return new Map(r.files.map((f) => [f.path, f]));
    };
    const everywhere = ["~/.gemini/settings.json", "~/.config/zed/settings.json", "~/.continue/config.yaml", ".continue/mcpServers/pw.yaml"];
    const asOpencode = run("opencode");
    for (const rel of ["~/.config/opencode/opencode.json", "opencode.jsonc"]) {
      const f = asOpencode.get(at(rel));
      assert.equal(f?.agentConfig, "opencode", `${rel}: OpenCode's own config, left readable to it: ${JSON.stringify(f)}`);
      assert.equal(f?.rule, CONTENT_RULE, "labelled as found, so the guard gates every other program's open");
    }
    assert.equal(asOpencode.get(at("sub/opencode.json"))?.agentConfig, undefined, "below the workspace root: not the one OpenCode reads there");
    assert.equal(asOpencode.get(at("~/.config/goose/config.yaml"))?.agentConfig, undefined, "Goose's config under mandu opencode: twinned");
    for (const rel of everywhere) {
      const f = asOpencode.get(at(rel));
      assert.ok(f && f.agentConfig === undefined && f.rule === CONTENT_RULE, `${rel}: twinned: ${JSON.stringify(f)}`);
    }
    const asGoose = run("goose");
    assert.equal(asGoose.get(at("~/.config/goose/config.yaml"))?.agentConfig, "goose", "Goose's own config under mandu goose");
    assert.equal(asGoose.get(at("~/.config/opencode/opencode.json"))?.agentConfig, undefined);
    const asClaude = run("claude");
    for (const rel of ["~/.config/opencode/opencode.json", "~/.config/goose/config.yaml", "opencode.jsonc", ...everywhere]) {
      const f = asClaude.get(at(rel));
      assert.ok(f && f.agentConfig === undefined, `${rel}: twinned under mandu claude: ${JSON.stringify(f)}`);
    }
    assert.deepEqual([...keptMcpReaders("goose")], ["goose"]);
    assert.deepEqual([...keptMcpReaders("opencode")].sort(), ["opencode"]);
  } finally {
    t.cleanup();
  }
});

test("the walk: a config.toml CODEX_HOME moved is Codex's own under mandu codex (labelled, left readable) and twinned under any other", () => {
  const t = tree({ "/cx/config.toml": CODEX_MOVED, "/cx/auth.json": "{}" });
  try {
    const cx = join(t.root, "cx");
    const p = join(cx, "config.toml");
    const run = (target: string) => new Map(discoverSecretsReport([t.home, t.ws], t.home, undefined, { target, loginEnv: { CODEX_HOME: cx } }).files.map((f) => [f.path, f]));
    const asCodex = run("codex").get(p);
    assert.equal(asCodex?.agentConfig, "codex", JSON.stringify(asCodex));
    assert.equal(asCodex?.rule, CONTENT_RULE);
    const asClaude = run("claude").get(p);
    assert.ok(asClaude && asClaude.agentConfig === undefined, JSON.stringify(asClaude));
    // its values are Codex's MCP values, masked in the twin
    const x = extractSecretSpans(p, CODEX_MOVED);
    assert.deepEqual(x.spans.map((s) => s.value), [CX_GH]);
  } finally {
    t.cleanup();
  }
});

test("registration: Gemini CLI's HOME config grants its Authorization credential to its server's host; OpenCode's and Goose's grant nothing", () => {
  const t = tree({
    "~/.gemini/settings.json": GEMINI_JSON,
    "~/.config/opencode/opencode.json": OPENCODE_JSONC,
    "~/.config/goose/config.yaml": GOOSE_YAML,
    ".gemini/settings.json": GEMINI_JSON,
  });
  try {
    const dbPath = join(t.root, "symbols.db");
    const map = loadSymbolMap(dbPath);
    const label: LabelLookup = () => ({ level: "no-model", bindings: [], via: "test", origin: "user" } as ReturnType<LabelLookup>);
    const fieldOf = (path: string, value: string): string => {
      for (const [name, e] of map.symbols) if (e.origin === path && e.field !== null && e.value === value) return name;
      throw new Error(`no field row for ${value.slice(0, 8)} of ${path}`);
    };
    const cases: Array<[string, string, string | null]> = [
      ["~/.gemini/settings.json", `Bearer ${GEM_AUTH}`, "mcp.gemini-example.test"],
      [".gemini/settings.json", `Bearer ${GEM_AUTH}`, null],
      ["~/.config/opencode/opencode.json", `Bearer ${OC_AUTH}`, null],
      ["~/.config/goose/config.yaml", `Bearer ${GOOSE_AUTH}`, null],
    ];
    for (const [rel, auth, host] of cases) {
      const path = rel.startsWith("~/") ? join(t.home, rel.slice(2)) : join(t.ws, rel);
      const r = registerSecret(map, { path, home: t.home, resolveLabel: label }, dbPath);
      assert.ok(r.symbol && r.twin, `${rel}: ${r.reason}`);
      for (const raw of ALL) assert.ok(!r.twin!.includes(raw), `${rel}: CONFIDENTIALITY: no value in the twin`);
      const f = fieldOf(path, auth);
      assert.deepEqual(getSymbolEntry(map, f)?.bindings ?? [], host === null ? [] : [host], `${rel}: the Authorization credential's bindings`);
      assert.equal(wireGrantOf(map, f), host ?? undefined, `${rel}: a grant only for a HOME config no supported agent reads`);
    }
  } finally {
    t.cleanup();
  }
});

test("a session's exempt MCP configs: OpenCode's global and project ones under mandu opencode, Goose's under mandu goose, CODEX_HOME's under mandu codex", () => {
  const H = "/home/u";
  const of = (o: unknown): string[] => { const s = parseSessionLogins(o); return s === null ? [] : sessionMcpConfigPaths(s).sort(); };
  assert.deepEqual(of({ home: H, target: "opencode", mcpConfigs: ["/w/opencode.json", "/w/.mcp.json", "/w/.gemini/settings.json"] }),
    [`${H}/.config/opencode/config.json`, `${H}/.config/opencode/opencode.json`, `${H}/.config/opencode/opencode.jsonc`, "/w/opencode.json"]);
  assert.deepEqual(of({ home: H, target: "goose" }), [`${H}/.config/goose/config.yaml`]);
  assert.deepEqual(of({ home: H, target: "claude", mcpConfigs: ["/w/opencode.json"] }), [], "Claude Code reads no opencode.json");
  assert.deepEqual(of({ home: H, target: "codex", loginEnv: { CODEX_HOME: "/srv/cx" } }), [`${H}/.codex/config.toml`, "/srv/cx/config.toml"]);
  for (const p of of({ home: H, target: "opencode" })) assert.ok(!/gemini|zed|continue/.test(p), "never a config no supported agent reads");
});
