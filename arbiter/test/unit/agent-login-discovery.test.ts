/**
 * agent-login-discovery — the agents' login files are keyed per launch
 * (secret-discovery.md §1.10; secret-discovery.ts AGENT_LOGIN_FILES,
 * `keptLoginOwners`).
 *
 * Before (2026-10-09), one global list kept every agent's login out of the
 * walk whatever was launched: under `mandu claude`, `~/.codex/auth.json` (an
 * OpenAI key or ChatGPT tokens) was neither twinned nor registered, so a
 * program in the agent's tree read it raw and nothing recognized it leaving;
 * under `mandu codex` the same held for Claude Code's logins and
 * `~/.claude.json` (MCP server tokens). Now only the logins the launch runs
 * on stay raw: the launched agent's, and the AI helper's when it runs an
 * agent's CLI there (`claude -p` everywhere but under codex), and both
 * Claude Code's and Codex's under openclaw, which reads them itself. The
 * agents' own data (AGENT_STORES) stays out of every launch, as before, and
 * a policy.yaml label decides for a login the launch does not keep. A login
 * a variable moved out of the catalog's places is a login all the same
 * (2026-10-10), and a session's kept logins (what its net-proxy sends with
 * a tripwire scan) are login files only.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AGENT_LOGIN_FILES,
  AGENT_STORES,
  KNOWN_TARGETS,
  LOGIN_ENV,
  MAX_FILES,
  agentFileOf,
  agentLoginConfidentiality,
  agentLoginPaths,
  discoverSecretFiles,
  discoverSecretsReport,
  keptLoginOwners,
  loginOwnerOf,
  originUnder,
  parseSessionLogins,
  pickLoginEnv,
  sessionLoginPaths,
  type DiscoveryOptions,
} from "../../policy/secret-discovery.js";
import type { LabelLookup } from "../../policy/secret-catalog.js";
import { AGENTS } from "../../src/generated/agents.js";
import { registerSecret } from "../../secret-registry/registry.js";
import { getSymbolEntry, loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // discovery serves the confidentiality axis; the walk itself reads no axis

const RAW = {
  codex: '{"OPENAI_API_KEY":"sk-proj-CODEXLOGINCANARY0123456789"}',
  claudeCreds: '{"claudeAiOauth":{"accessToken":"sk-ant-oat01-CLAUDECREDCANARY"}}',
  claudeJson: '{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"ghp_CLAUDEJSONCANARY0123456789"}}}}',
  opencode: '{"anthropic":{"type":"api","key":"sk-ant-OPENCODECANARY"}}',
};

/** A HOME with every agent's login and some of each agent's own data. */
function agentsHome(): { home: string; p: Record<string, string>; cleanup: () => void } {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-logins-")));
  const put = (rel: string, body: string): string => {
    const f = join(home, rel);
    mkdirSync(join(f, ".."), { recursive: true });
    writeFileSync(f, body);
    return f;
  };
  const p = {
    codexAuth: put(".codex/auth.json", RAW.codex),
    codexSession: put(".codex/sessions/2026/10/09/rollout-1.jsonl", '{"output":"API_KEY=sk-live-x"}\n'),
    openai: put(".openai/api_key", "sk-OPENAISDKCANARY\n"),
    claudeCreds: put(".claude/.credentials.json", RAW.claudeCreds),
    claudeSettings: put(".claude/settings.json", "{}"),
    claudeTranscript: put(".claude/projects/x/session.jsonl", '{"tool_result":"API_KEY=sk-live-x"}\n'),
    claudeJson: put(".claude.json", RAW.claudeJson),
    anthropic: put(".anthropic/api_key", "sk-ant-SDKCANARY\n"),
    opencodeAuth: put(".local/share/opencode/auth.json", RAW.opencode),
    opencodeDb: put(".local/share/opencode/opencode.db", "SQLite format 3\0"),
    gooseStore: put(".local/share/goose/sessions/sessions.db", "SQLite format 3\0"),
    aws: put(".aws/credentials", "[default]\naws_secret_access_key=x\n"),
  };
  return { home, p, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

const LOGINS = ["codexAuth", "openai", "claudeCreds", "claudeJson", "anthropic", "opencodeAuth"] as const;
const OWNER: Record<(typeof LOGINS)[number], string> = {
  codexAuth: "codex", openai: "codex", claudeCreds: "claude", claudeJson: "claude", anthropic: "claude", opencodeAuth: "opencode",
};
const STORE_FILES = ["codexSession", "claudeSettings", "claudeTranscript", "opencodeDb", "gooseStore"] as const;

test("the known targets and the raw stores' owners, derived from the agent registry, are what they were (supported-agents.md §5.7)", () => {
  assert.deepEqual([...AGENTS], ["claude", "codex", "openclaw", "opencode", "goose"]);
  assert.deepEqual([...KNOWN_TARGETS], ["claude", "codex", "openclaw", "opencode", "goose", "shell"]);
  assert.deepEqual(Object.keys(AGENT_STORES), ["claude", "codex", "opencode", "goose"], "every agent but OpenClaw");
});

test("keptLoginOwners: the launched agent's logins and the AI helper's CLI's; a shell keeps Claude Code's; no target keeps every agent's", () => {
  const k = (t: string | undefined, u?: string): string[] => [...keptLoginOwners(t, u)].sort();
  assert.deepEqual(k("claude", "claude"), ["claude"]);
  assert.deepEqual(k("claude"), ["claude"], "the helper in API mode adds nothing");
  assert.deepEqual(k("codex", "codex"), ["codex"], "under codex the helper runs `codex exec`");
  assert.deepEqual(k("codex"), ["codex"]);
  assert.deepEqual(k("opencode", "claude"), ["claude", "opencode"], "the helper's `claude -p` runs in OpenCode's world");
  assert.deepEqual(k("opencode"), ["opencode"]);
  assert.deepEqual(k("goose", "claude"), ["claude"], "Goose's own login is keyed by the launcher");
  assert.deepEqual(k("goose"), []);
  assert.deepEqual(k("openclaw", "claude"), ["claude", "codex"], "OpenClaw reads Claude Code's and Codex's logins itself (its claude-cli / codex-cli profiles, its Codex harness)");
  assert.deepEqual(k("openclaw"), ["claude", "codex"], "whatever the helper does");
  assert.deepEqual(k("shell"), ["claude"], "a shell's routing is Claude Code's: a claude started in it must log in");
  assert.deepEqual(k("shell", "claude"), ["claude"]);
  assert.deepEqual(k(undefined), ["claude", "codex", "opencode"], "an older launcher or a dry run naming no agent: as before");
  assert.deepEqual(k("some-future-agent"), ["claude", "codex", "opencode"], "an unknown target fails toward the old behavior");
  assert.deepEqual(k("goose", "gpt"), [], "only the two CLIs the helper runs count");
});

test("under each target, the launch's own logins stay raw (agent-login) and every other agent's is discovered, tagged with its owner", () => {
  const { home, p, cleanup } = agentsHome();
  try {
    const cases: Array<{ opts: DiscoveryOptions; kept: string[] }> = [
      { opts: { target: "claude", ullmBinary: "claude" }, kept: ["claude"] },
      { opts: { target: "codex", ullmBinary: "codex" }, kept: ["codex"] },
      { opts: { target: "shell" }, kept: ["claude"] },
      { opts: { target: "opencode", ullmBinary: "claude" }, kept: ["claude", "opencode"] },
      { opts: { target: "goose" }, kept: [] },
      { opts: {}, kept: ["claude", "codex", "opencode"] },
    ];
    for (const { opts, kept } of cases) {
      const r = discoverSecretsReport([home], home, undefined, opts);
      const byPath = new Map(r.files.map((f) => [f.path, f]));
      const keptRecords = r.skipped.filter((s) => s.reason === "agent-login").map((s) => s.path);
      for (const key of LOGINS) {
        const owner = OWNER[key];
        const f = byPath.get(p[key]!);
        if (kept.includes(owner)) {
          // Since 2026-10-21 (secret-discovery.md §2.10) a kept
          // `.claude.json` holding an MCP server's token is listed as the
          // agent's own MCP config: registered, left readable (never
          // twinned, launcher `agentConfig`).
          if (key === "claudeJson" && f !== undefined) assert.equal(f.agentConfig, "claude", `${JSON.stringify(opts)}: ${key} is Claude Code's own MCP config, left readable`);
          else assert.equal(f, undefined, `${JSON.stringify(opts)}: ${key} is the launch's own login, never twinned`);
          // a login directory is one record (~/.openai, ~/.anthropic)
          assert.ok(keptRecords.some((k) => p[key]!.startsWith(k)), `${JSON.stringify(opts)}: ${key} is in the ledger as agent-login`);
        } else {
          assert.ok(f, `${JSON.stringify(opts)}: ${key} (${owner}'s login) is discovered: ${[...byPath.keys()].join(", ")}`);
          assert.equal(f!.level, "no-model");
          assert.equal(f!.agentLogin, owner, `${key} is tagged as ${owner}'s login`);
        }
      }
      for (const key of STORE_FILES) assert.ok(!byPath.has(p[key]!), `${JSON.stringify(opts)}: ${key} (an agent's own data) is never discovered`);
      assert.ok(byPath.has(p.aws), "an ordinary credential is still found");
      assert.equal(byPath.get(p.aws)!.agentLogin, undefined, "and is no agent's login");
      assert.ok(r.counts["agent-auth"] >= 4, `each store is skipped: ${JSON.stringify(r.counts)}`);
    }
  } finally {
    cleanup();
  }
});

test("another agent's store never spends the file cap: 300 transcripts under ~/.codex, mandu claude finds Codex's login and the user's key, untruncated", () => {
  const { home, p, cleanup } = agentsHome();
  try {
    const sessions = join(home, ".codex", "sessions", "2026", "10");
    mkdirSync(sessions, { recursive: true });
    for (let i = 0; i < MAX_FILES + 44; i++) writeFileSync(join(sessions, `rollout-${i}.jsonl`), "{}\n");
    const r = discoverSecretsReport([home], home, undefined, { target: "claude", ullmBinary: "claude" });
    assert.equal(r.truncated, false);
    assert.equal(r.counts["count"], 0);
    const paths = r.files.map((f) => f.path);
    assert.ok(paths.includes(p.codexAuth) && paths.includes(p.aws), paths.join(", "));
    assert.ok(!paths.some((f) => f.startsWith(join(home, ".codex", "sessions"))), "no transcript is discovered");
  } finally {
    cleanup();
  }
});

test("a policy.yaml label decides for a login the launch does not keep, never for one it keeps or for a store", () => {
  const { home, p, cleanup } = agentsHome();
  try {
    const labels = new Map<string, { level: "public" | "any-model" | "no-model" }>([
      [p.codexAuth, { level: "public" }],
      [p.claudeJson, { level: "any-model" }],
      [p.claudeTranscript, { level: "no-model" }],
    ]);
    const lookup: LabelLookup = (q) => {
      const l = labels.get(q);
      return l ? { level: l.level, bindings: [], via: q, origin: "user" } as ReturnType<LabelLookup> : null;
    };
    const asCodex = discoverSecretsReport([home], home, lookup, { target: "codex" });
    const byPath = new Map(asCodex.files.map((f) => [f.path, f]));
    assert.ok(!byPath.has(p.codexAuth), "Codex's own login stays raw under mandu codex whatever its label says");
    assert.ok(asCodex.skipped.some((s) => s.reason === "agent-login" && s.path === p.codexAuth));
    assert.equal(byPath.get(p.claudeJson)?.level, "any-model", "the user's label decides the level of another agent's login");
    assert.equal(byPath.get(p.claudeJson)?.rule, `label:${p.claudeJson}`);
    assert.ok(!byPath.has(p.claudeTranscript), "a label does not pull an agent's own data into the walk");

    const asClaude = discoverSecretsReport([home], home, lookup, { target: "claude" });
    assert.ok(!asClaude.files.some((f) => f.path === p.codexAuth), "a `public` label declassifies another agent's login: not twinned");
    // §2.10: listed as Claude Code's own MCP config (its servers' token is
    // registered), with the human's level, and left readable to it.
    const own = asClaude.files.find((f) => f.path === p.claudeJson);
    assert.equal(own?.agentConfig, "claude", "Claude Code's own login stays readable to it under mandu claude");
    assert.equal(own?.level, "any-model", "the human's label decides its level");
  } finally {
    cleanup();
  }
});

test("CODEX_HOME and CLAUDE_CONFIG_DIR move an agent's login: kept raw for the launch that runs it, a secret elsewhere (here with a label)", () => {
  const { home, p, cleanup } = agentsHome();
  try {
    // A Codex home the catalog does not name, labelled by the user; a Claude
    // config dir whose `.credentials.json` the catalog's `*credentials*`
    // shape matches (it was twinned even under mandu claude before).
    const codexHome = join(home, "tools", "codex-home");
    const ccd = join(home, "cfg", "claude");
    mkdirSync(codexHome, { recursive: true });
    mkdirSync(ccd, { recursive: true });
    const movedCodex = join(codexHome, "auth.json");
    const movedClaude = join(ccd, ".credentials.json");
    writeFileSync(movedCodex, RAW.codex);
    writeFileSync(movedClaude, RAW.claudeCreds);
    const loginEnv = { CODEX_HOME: codexHome, CLAUDE_CONFIG_DIR: ccd };
    const lookup: LabelLookup = (q) => (q === codexHome || q.startsWith(codexHome + "/") ? { level: "no-model", bindings: [], via: codexHome, origin: "user" } as ReturnType<LabelLookup> : null);

    assert.ok(agentLoginPaths("codex", home, loginEnv).includes(movedCodex));
    assert.ok(agentLoginPaths("codex", home, loginEnv).includes(p.codexAuth), "the default place stays Codex's login too");
    assert.equal(loginOwnerOf(movedCodex, home, loginEnv), "codex");
    assert.equal(loginOwnerOf(movedCodex, home), null, "without the variable it is no login");
    assert.equal(loginOwnerOf(movedClaude, home, loginEnv), "claude");

    const files = (opts: DiscoveryOptions): Map<string, { agentLogin?: string }> =>
      new Map(discoverSecretFiles([home], home, lookup, { ...opts, loginEnv }).map((f) => [f.path, f]));
    const codex = files({ target: "codex", ullmBinary: "codex" });
    assert.ok(!codex.has(movedCodex), "mandu codex keeps its moved login raw, over the user's label");
    assert.equal(codex.get(movedClaude)?.agentLogin, "claude", "Claude Code's moved login is twinned under codex");
    const claude = files({ target: "claude", ullmBinary: "claude" });
    assert.equal(claude.get(movedCodex)?.agentLogin, "codex", "Codex's moved login is discovered under claude (the label makes it secret)");
    assert.ok(!claude.has(movedClaude), "mandu claude keeps its moved login raw");
  } finally {
    cleanup();
  }
});

test("a store that is a file, or that this uid cannot list, does not break the walk", () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-logins-odd-")));
  try {
    writeFileSync(join(home, ".codex"), "not a directory\n"); // ~/.codex/auth.json lstat → ENOTDIR
    mkdirSync(join(home, ".claude"));
    writeFileSync(join(home, ".claude", ".credentials.json"), RAW.claudeCreds);
    mkdirSync(join(home, ".aws"));
    writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key=x\n");
    if (process.getuid?.() !== 0) chmodSync(join(home, ".claude"), 0o000);
    const r = discoverSecretsReport([home], home, undefined, { target: "codex" });
    assert.deepEqual(r.files.map((f) => f.path), [join(home, ".aws", "credentials")]);
    assert.ok(r.skipped.some((s) => s.reason === "agent-auth" && s.path === join(home, ".codex")));
  } finally {
    chmodSync(join(home, ".claude"), 0o700);
    rmSync(home, { recursive: true, force: true });
  }
});

test("a derived path and a file root are judged the same way", () => {
  const { home, p, cleanup } = agentsHome();
  try {
    const derived = discoverSecretsReport([], home, undefined, { target: "codex", derivedPaths: [p.claudeJson, p.codexAuth, p.claudeTranscript] });
    assert.deepEqual(derived.files.map((f) => [f.path, f.agentLogin]), [[p.claudeJson, "claude"]]);
    assert.ok(derived.skipped.some((s) => s.reason === "agent-login" && s.path === p.codexAuth));
    assert.ok(derived.skipped.some((s) => s.reason === "agent-auth" && s.path === p.claudeTranscript));
    const roots = discoverSecretsReport([p.codexAuth, p.claudeCreds], home, undefined, { target: "claude" });
    assert.deepEqual(roots.files.map((f) => [f.path, f.agentLogin]), [[p.codexAuth, "codex"]]);
    assert.ok(roots.skipped.some((s) => s.reason === "agent-login" && s.path === p.claudeCreds));
  } finally {
    cleanup();
  }
});

test("a moved login no catalog rule or label names is another agent's login all the same: no-model (agent-login), wherever it is; a `public` label still decides", () => {
  const { home, cleanup } = agentsHome();
  const outside = realpathSync(mkdtempSync(join(tmpdir(), "mandu-codex-home-")));
  try {
    // CODEX_HOME inside HOME where the catalog names nothing, and one under
    // no walked root at all; CLAUDE_CONFIG_DIR likewise (its `.claude.json`
    // matches no catalog shape).
    // (not `~/.config/codex`: the catalog names a CLI's `auth.json` there,
    // `shape:tool-login-file`, secret-discovery.md §2.6)
    const inHome = join(home, "tools", "codex");
    const ccd = join(outside, "claude-work");
    mkdirSync(inHome, { recursive: true });
    mkdirSync(ccd, { recursive: true });
    const movedCodex = join(inHome, "auth.json");
    const farCodex = join(outside, "auth.json");
    const movedClaudeJson = join(ccd, ".claude.json");
    writeFileSync(movedCodex, RAW.codex);
    writeFileSync(farCodex, RAW.codex);
    writeFileSync(movedClaudeJson, RAW.claudeJson);

    const asClaude = discoverSecretsReport([home], home, undefined, { target: "claude", ullmBinary: "claude", loginEnv: { CODEX_HOME: inHome } });
    const f = asClaude.files.find((x) => x.path === movedCodex);
    assert.ok(f, `the moved Codex login is discovered under claude: ${asClaude.files.map((x) => x.path).join(", ")}`);
    assert.equal(f!.level, "no-model");
    assert.equal(f!.rule, "agent-login:codex");
    assert.equal(f!.agentLogin, "codex");

    const far = discoverSecretsReport([home], home, undefined, { target: "shell", loginEnv: { CODEX_HOME: outside } });
    assert.equal(far.files.find((x) => x.path === farCodex)?.agentLogin, "codex", "a CODEX_HOME under no walked root is visited by its path");
    assert.equal(far.files.filter((x) => x.path === farCodex).length, 1);

    const asCodex = discoverSecretsReport([home], home, undefined, { target: "codex", ullmBinary: "codex", loginEnv: { CODEX_HOME: outside, CLAUDE_CONFIG_DIR: ccd } });
    assert.ok(!asCodex.files.some((x) => x.path === farCodex), "mandu codex keeps its own moved login raw");
    assert.equal(asCodex.files.find((x) => x.path === movedClaudeJson)?.rule, "agent-login:claude", "Claude Code's moved config is twinned under codex");

    const pub: LabelLookup = (q) => (q === movedCodex ? { level: "public", bindings: [], via: q, origin: "user" } as ReturnType<LabelLookup> : null);
    const declassified = discoverSecretsReport([home], home, pub, { target: "claude", loginEnv: { CODEX_HOME: inHome } });
    assert.ok(!declassified.files.some((x) => x.path === movedCodex), "the human's `public` label decides, as for any file");
  } finally {
    cleanup();
    rmSync(outside, { recursive: true, force: true });
  }
});

test("registerSecret registers a moved login the walk found (with the launch's login variables), and refuses it without them", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-moved-reg-")));
  try {
    const home = join(dir, "home");
    const cx = join(dir, "codex-home");
    mkdirSync(home, { recursive: true });
    mkdirSync(cx, { recursive: true });
    const moved = join(cx, "auth.json");
    writeFileSync(moved, RAW.codex);
    const dbPath = join(dir, "symbols.db");
    const map = loadSymbolMap(dbPath);
    const bare = registerSecret(map, { path: moved, home }, dbPath);
    assert.equal(bare.symbol, null, "no catalog rule names it: refused without the variables");
    const r = registerSecret(map, { path: moved, home, loginEnv: { CODEX_HOME: cx } }, dbPath);
    assert.ok(r.symbol, r.reason);
    assert.match(r.reason, /agent-login:codex/);
    assert.equal(getSymbolEntry(map, r.symbol!)?.confidentiality, "no-model");
    assert.ok(r.twin !== undefined && !r.twin.includes("CODEXLOGINCANARY"), "a structured twin without the key");
    const pub: LabelLookup = (q) => (q === moved ? { level: "public", bindings: [], via: q, origin: "user" } as ReturnType<LabelLookup> : null);
    assert.equal(registerSecret(map, { path: moved, home, loginEnv: { CODEX_HOME: cx }, resolveLabel: pub }, dbPath).symbol, null, "a `public` label still declassifies");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("agentLoginConfidentiality: a human label decides, then a catalog secret, else no-model under agent-login", () => {
  const none = { level: "public" as const, bindings: [], rule: null };
  assert.deepEqual(agentLoginConfidentiality(none, "codex"), { level: "no-model", bindings: [], rule: "agent-login:codex" });
  const pub = { level: "public" as const, bindings: [], rule: "label:/x" };
  assert.equal(agentLoginConfidentiality(pub, "codex"), pub, "a public label declassifies");
  const anyModel = { level: "any-model" as const, bindings: ["h"], rule: "label:/x" };
  assert.equal(agentLoginConfidentiality(anyModel, "claude"), anyModel);
  const cat = { level: "no-model" as const, bindings: [], rule: "prefix:~/.codex" };
  assert.equal(agentLoginConfidentiality(cat, "codex"), cat, "the catalog's own verdict stands");
});

test("a session's kept logins: its login files only (the walk's keying, or every agent's under the opt-out), malformed exempts nothing", () => {
  const H = "/home/u";
  const s = (o: unknown): string[] => { const p = parseSessionLogins(o); return p === null ? [] : sessionLoginPaths(p).sort(); };
  // Codex's config.toml since 2026-10-21 (§2.10): its MCP servers' values.
  assert.deepEqual(s({ home: H, target: "codex", ullmBinary: "codex" }), [`${H}/.codex/auth.json`, `${H}/.codex/config.toml`, `${H}/.openai`]);
  assert.deepEqual(s({ home: H, target: "codex", loginEnv: { CODEX_HOME: "/srv/cx", OPENAI_API_KEY: "sk-x" } }), [`${H}/.codex/auth.json`, `${H}/.codex/config.toml`, `${H}/.openai`, "/srv/cx/auth.json", "/srv/cx/config.toml"]);
  assert.deepEqual(s({ home: H, target: "claude" }), [`${H}/.anthropic`, `${H}/.claude.json`, `${H}/.claude/.credentials.json`]);
  assert.deepEqual(s({ home: H, target: "openclaw" }), [`${H}/.anthropic`, `${H}/.claude.json`, `${H}/.claude/.credentials.json`, `${H}/.codex/auth.json`, `${H}/.codex/config.toml`, `${H}/.openai`]);
  // Goose keeps no login here; its own MCP config since 2026-10-22 (§2.10).
  assert.deepEqual(s({ home: H, target: "goose" }), [`${H}/.config/goose/config.yaml`], "a goose session without the helper keeps none of the logins, only its own config.yaml");
  assert.deepEqual(s({ home: H, target: "opencode" }), [`${H}/.config/opencode/config.json`, `${H}/.config/opencode/opencode.json`, `${H}/.config/opencode/opencode.jsonc`, `${H}/.local/share/opencode/auth.json`]);
  assert.equal(s({ home: H, target: "claude", otherLoginsRaw: true }).length, 10, "the opt-out: every agent's login, and the MCP configs Codex and OpenCode read");
  // A project's MCP configs (§2.10): only a kind a kept agent reads.
  assert.deepEqual(s({ home: H, target: "claude", mcpConfigs: ["/w/p/.mcp.json", "/w/p/.vscode/mcp.json", "relative/.mcp.json", "/w/p/.env"] }), [`${H}/.anthropic`, `${H}/.claude.json`, `${H}/.claude/.credentials.json`, "/w/p/.mcp.json"]);
  assert.deepEqual(s({ home: H, target: "codex", mcpConfigs: ["/w/p/.mcp.json"] }), [`${H}/.codex/auth.json`, `${H}/.codex/config.toml`, `${H}/.openai`], "a codex session does not read a .mcp.json");
  assert.deepEqual(s({ target: "codex" }), [], "no home: nothing exempt");
  assert.deepEqual(s({ home: "relative", target: "codex" }), []);
  assert.deepEqual(s("codex"), []);
  assert.deepEqual(s(null), []);
  assert.deepEqual(s([H]), []);
  const kept = sessionLoginPaths(parseSessionLogins({ home: H, target: "claude" })!);
  assert.equal(originUnder(`${H}/.claude.json`, kept), true);
  assert.equal(originUnder(`${H}/.anthropic/api_key`, kept), true, "a file inside a login directory");
  assert.equal(originUnder(`${H}/.claude.json.bak`, kept), false);
  assert.equal(originUnder(`${H}/.aws/credentials`, kept), false, "never another path");
  assert.equal(originUnder("env:ANTHROPIC_API_KEY", kept), false);
});

test("pickLoginEnv keeps the known names with absolute values only; agentFileOf names logins and stores for `mandu why`", () => {
  assert.deepEqual([...LOGIN_ENV].sort(), ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_DATA_HOME"]);
  assert.deepEqual(
    pickLoginEnv({ CODEX_HOME: "/x/codex", CLAUDE_CONFIG_DIR: "relative/dir", XDG_DATA_HOME: 7, OPENAI_API_KEY: "sk-x", HOME: "/home/u" }),
    { CODEX_HOME: "/x/codex" },
  );
  assert.deepEqual(pickLoginEnv(null), {});
  assert.deepEqual(pickLoginEnv("CODEX_HOME=/x"), {});
  const H = "/home/u";
  assert.deepEqual(agentFileOf(`${H}/.codex/auth.json`, H), { kind: "login", agent: "codex" });
  assert.deepEqual(agentFileOf(`${H}/.claude.json`, H), { kind: "login", agent: "claude" });
  assert.deepEqual(agentFileOf(`${H}/.claude/.credentials.json`, H), { kind: "login", agent: "claude" });
  assert.deepEqual(agentFileOf(`${H}/.anthropic/key`, H), { kind: "login", agent: "claude" });
  assert.deepEqual(agentFileOf(`${H}/.local/share/opencode/auth.json`, H), { kind: "login", agent: "opencode" });
  assert.deepEqual(agentFileOf(`${H}/.claude/projects/a.jsonl`, H), { kind: "store", agent: "claude" });
  assert.deepEqual(agentFileOf(`${H}/.codex/sessions/r.jsonl`, H), { kind: "store", agent: "codex" });
  assert.deepEqual(agentFileOf(`${H}/.local/state/goose/logs/llm_request.0.jsonl`, H), { kind: "store", agent: "goose" });
  assert.deepEqual(agentFileOf("/srv/x/opencode/opencode.db", H), { kind: "store", agent: "opencode" });
  assert.deepEqual(agentFileOf("/srv/cx/auth.json", H, { CODEX_HOME: "/srv/cx" }), { kind: "login", agent: "codex" });
  assert.equal(agentFileOf(`${H}/.aws/credentials`, H), null);
  assert.equal(agentFileOf(`${H}/.config/goose/secrets.yaml`, H), null, "Goose's login is keyed by the launcher, not here");
  assert.deepEqual(Object.keys(AGENT_LOGIN_FILES).sort(), ["claude", "codex", "opencode"]);
});
