/**
 * agent-config.test — the config-file routing for openclaw/opencode
 * (services/agent-config.ts): pure doc builders + merge, and the one
 * writeAgentConfig enactment against a tmp dir. No agent is spawned.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AGENT_CONFIG_ENV_VAR,
  buildOpenclawWrapDoc,
  buildOpencodeWrapDoc,
  fenceOpenclawCodeMode,
  fenceOpenclawExecHost,
  fenceOpenclawMemorySearch,
  fenceOpenclawWebEgress,
  openclawHasCodeModeKey,
  fenceOpenclawWorkspace,
  opencodeRoutingContent,
  openaiRouteBaseUrl,
  readOpencodeAuthTypes,
  isConfigRouted,
  mergeConfig,
  openclawMemoryShape,
  openclawUserAnthropicModels,
  parseAgentConfigText,
  readAgentUserConfig,
  userConfigPath,
  writeAgentConfig,
  type AgentConfigInput,
} from "../../src/services/agent-config.js";
import { Layout } from "../../src/services/layout.js";
import type { LaunchPlan, Ullm } from "../../src/types.js";

const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };
const PLAN_SLICE = { arbiterSock: "/run/mandu/arbiter.sock", scopeId: "sid-1", tenant: "live", ullm: ULLM };

function input(over: Partial<AgentConfigInput> = {}): AgentConfigInput {
  return {
    target: "openclaw",
    scopeId: "sid-1", tenant: "live",
    proxyUrl: "http://127.0.0.1:8788",
    inspect: true,
    ...over,
  };
}

// ── mergeConfig ──────────────────────────────────────────────────────────────

test("mergeConfig: objects recurse, ours wins on conflict, user's siblings survive", () => {
  const user = {
    models: { mode: "replace", providers: { anthropic: { apiKey: "sk-user", baseUrl: "https://user.example" } } },
    agents: { defaults: { model: { primary: "anthropic/claude-opus-4-6" } } },
  };
  const ours = { models: { mode: "merge", providers: { anthropic: { baseUrl: "http://127.0.0.1:8788" } } } };
  const got = mergeConfig(user, ours) as typeof user;
  // Ours wins where set…
  assert.equal(got.models.mode, "merge");
  assert.equal(got.models.providers.anthropic.baseUrl, "http://127.0.0.1:8788");
  // …the user's credential NEXT TO our override survives (the wrap must not
  // strip their auth), and untouched subtrees ride through whole.
  assert.equal(got.models.providers.anthropic.apiKey, "sk-user");
  assert.equal(got.agents.defaults.model.primary, "anthropic/claude-opus-4-6");
});

test("mergeConfig: arrays and scalars are replaced, not concatenated", () => {
  const got = mergeConfig({ a: [1, 2], b: "user" }, { a: [3], b: "ours" });
  assert.deepEqual(got["a"], [3]);
  assert.equal(got["b"], "ours");
});

// ── buildOpenclawWrapDoc ─────────────────────────────────────────────────────

test("openclaw doc: routing override keeps the catalog (mode merge) and carries the session headers", () => {
  const doc = buildOpenclawWrapDoc(input({ batchId: "b-9" }), PLAN_SLICE, undefined) as Record<string, any>;
  const prov = doc["models"].providers.anthropic;
  assert.equal(doc["models"].mode, "merge");
  assert.equal(prov.baseUrl, "http://127.0.0.1:8788");
  assert.equal(prov.api, "anthropic-messages");
  assert.deepEqual(prov.models, []);
  assert.deepEqual(prov.headers, { "x-mandu-session-id": "sid-1", "x-mandu-batch-id": "b-9", "x-mandu-tenant": "live" });
  // No apiKey injected: the user's own auth (env/config) must keep working.
  assert.equal(prov.apiKey, undefined);
});

test("openclaw doc: no batch id → no batch header key at all", () => {
  const doc = buildOpenclawWrapDoc(input(), PLAN_SLICE, undefined) as Record<string, any>;
  assert.deepEqual(doc["models"].providers.anthropic.headers, { "x-mandu-session-id": "sid-1", "x-mandu-tenant": "live" });
});

test("openclaw doc: the plugin mount carries the arbiter + U-LLM facts and the alsoAllow lift", () => {
  const doc = buildOpenclawWrapDoc(input(), PLAN_SLICE, "/repo/interceptors/openclaw-inspect-plugin") as Record<string, any>;
  assert.deepEqual(doc["plugins"].load.paths, ["/repo/interceptors/openclaw-inspect-plugin"]);
  const cfg = doc["plugins"].entries["mandu-inspect"].config;
  assert.equal(cfg.arbiterSock, "/run/mandu/arbiter.sock");
  assert.equal(cfg.scopeId, "sid-1");
  assert.equal(cfg.ullmMode, "cli");
  assert.equal(cfg.ullmBinary, "claude");
  assert.equal(cfg.ullmBaseUrl, "https://api.anthropic.com");
  // tools.profile is an allowlist over the FINAL tool list — without the
  // additive alsoAllow the plugin tool loads and is then filtered out
  // (probe-verified; agent-provision.ts buildOpenclawConfig).
  assert.deepEqual(doc["tools"], { alsoAllow: ["inspect_symbol", "declassify_symbol"] });
});

test("openclaw doc: a live U-LLM forwarder rides into BOTH ullmBaseUrl and the ullmForwarder pin", () => {
  const doc = buildOpenclawWrapDoc(
    input(),
    { ...PLAN_SLICE, ullm: { ...ULLM, forwarderUrl: "http://127.0.0.1:9955" } },
    "/p",
  ) as Record<string, any>;
  const cfg = doc["plugins"].entries["mandu-inspect"].config;
  assert.equal(cfg.ullmBaseUrl, "http://127.0.0.1:9955");
  assert.equal(cfg.ullmForwarder, "http://127.0.0.1:9955");
});

test("openclaw doc: api-mode U-LLM carries the quarantined key; no plugin dir → no plugin block", () => {
  const api = buildOpenclawWrapDoc(
    input(),
    { ...PLAN_SLICE, ullm: { mode: "api", baseUrl: "https://api.anthropic.com", apiKey: "sk-q" } },
    "/p",
  ) as Record<string, any>;
  assert.equal(api["plugins"].entries["mandu-inspect"].config.ullmApiKey, "sk-q");

  const bare = buildOpenclawWrapDoc(input(), PLAN_SLICE, undefined) as Record<string, any>;
  assert.equal(bare["plugins"], undefined);
  assert.equal(bare["tools"], undefined);
});

test("openclaw doc: the user's cleaned anthropic model entries ride in place of the empty list", () => {
  const entry = { id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5", maxTokens: 64000 };
  const doc = buildOpenclawWrapDoc(input(), PLAN_SLICE, undefined, [entry]) as Record<string, any>;
  assert.deepEqual(doc["models"].providers.anthropic.models, [entry]);
  // Through the real merge, ours (the user's list, cleaned) replaces theirs.
  const merged = mergeConfig(
    { models: { providers: { anthropic: { models: [{ ...entry, baseUrl: "https://elsewhere.example" }] } } } },
    doc,
  ) as Record<string, any>;
  assert.deepEqual(merged["models"].providers.anthropic.models, [entry]);
});

// ── openclawUserAnthropicModels ──────────────────────────────────────────────

test("openclawUserAnthropicModels: model metadata survives; baseUrl/api/headers are dropped and named", () => {
  const user = { models: { providers: { anthropic: { models: [
    { id: "claude-sonnet-4-5", name: "S", reasoning: true, input: ["text", "image"], contextWindow: 200000,
      contextTokens: 150000, maxTokens: 64000, cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
      params: { temperature: 0 }, compat: {}, mediaInput: {}, thinkingLevelMap: {},
      baseUrl: "https://elsewhere.example", api: "openai-completions", headers: { a: "b" } },
    { id: "claude-x", someFutureRouteField: "http://x" },
  ] } } } };
  const got = openclawUserAnthropicModels(user);
  assert.deepEqual(got.models[0], {
    id: "claude-sonnet-4-5", name: "S", reasoning: true, input: ["text", "image"], contextWindow: 200000,
    contextTokens: 150000, maxTokens: 64000, cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
    params: { temperature: 0 }, compat: {}, mediaInput: {}, thinkingLevelMap: {},
  });
  // An allowlist: a field this code has never heard of is dropped too.
  assert.deepEqual(got.models[1], { id: "claude-x" });
  assert.deepEqual(got.dropped, [
    "claude-sonnet-4-5.baseUrl", "claude-sonnet-4-5.api", "claude-sonnet-4-5.headers", "claude-x.someFutureRouteField",
  ]);
});

test("openclawUserAnthropicModels: no list, a non-array, or junk entries → nothing kept", () => {
  assert.deepEqual(openclawUserAnthropicModels({}), { models: [], dropped: [] });
  assert.deepEqual(openclawUserAnthropicModels({ models: { providers: { anthropic: { models: "x" } } } }), { models: [], dropped: [] });
  assert.deepEqual(
    openclawUserAnthropicModels({ models: { providers: { anthropic: { models: [null, 3, ["a"], { id: "m" }] } } } }),
    { models: [{ id: "m" }], dropped: [] },
  );
  // Another provider's models are not ours to carry (they are merged as the user wrote them).
  assert.deepEqual(openclawUserAnthropicModels({ models: { providers: { other: { models: [{ id: "m" }] } } } }), { models: [], dropped: [] });
});

// ── buildOpencodeWrapDoc ─────────────────────────────────────────────────────

test("opencode doc: overrides the BUILT-IN anthropic provider's options — model choice stays the user's", () => {
  const doc = buildOpencodeWrapDoc(input({ target: "opencode" }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  const opts = doc["provider"].anthropic.options;
  assert.equal(opts.baseURL, "http://127.0.0.1:8788/v1");
  assert.deepEqual(opts.headers, { "x-mandu-session-id": "sid-1", "x-mandu-tenant": "live" });
  // No model / no custom provider forced, no apiKey injected.
  assert.equal(doc["model"], undefined);
  assert.equal(opts.apiKey, undefined);
});

test("opencode doc: the inspect channel is the same inspect-mcp server, in OpenCode's mcp spelling", () => {
  const doc = buildOpencodeWrapDoc(input({ target: "opencode" }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  const srv = doc["mcp"]["mandu-inspect"];
  assert.equal(srv.type, "local");
  assert.equal(srv.enabled, true);
  assert.equal(srv.timeout, 30_000);
  assert.ok(Array.isArray(srv.command) && srv.command.length >= 1);
  // The env the .mcp.json entry would carry, spelled `environment`.
  assert.equal(srv.environment.MANDU_ARBITER_SOCK, "/run/mandu/arbiter.sock");
  assert.equal(srv.environment.MANDU_SCOPE_ID, "sid-1");
});

test("opencode doc: the mandu-policy server mounts beside inspect; --no-policy-mcp (policy false) drops only it", () => {
  const doc = buildOpencodeWrapDoc(input({ target: "opencode" }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  const srv = doc["mcp"]["mandu-policy"];
  assert.equal(srv.type, "local");
  assert.match(srv.command[srv.command.length - 1], /policy-mcp.*server-main\.ts$/);
  assert.equal(srv.environment.MANDU_ARBITER_SOCK, "/run/mandu/arbiter.sock");
  assert.equal(srv.environment.MANDU_SCOPE_ID, "sid-1");
  const off = buildOpencodeWrapDoc(input({ target: "opencode", policy: false }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  assert.deepEqual(Object.keys(off["mcp"]), ["mandu-inspect"]);
});

test("opencode doc: --no-mcp (inspect false) drops the mcp section", () => {
  const doc = buildOpencodeWrapDoc(
    input({ target: "opencode", inspect: false }), PLAN_SLICE, Layout.dev("/repo"),
  ) as Record<string, any>;
  assert.equal(doc["mcp"], undefined);
});

// ── userConfigPath ───────────────────────────────────────────────────────────

test("userConfigPath: the agent's own resolution order, env override first", () => {
  assert.equal(userConfigPath("openclaw", { OPENCLAW_CONFIG_PATH: "/x/c.json" }, "/h"), "/x/c.json");
  assert.equal(userConfigPath("openclaw", { OPENCLAW_STATE_DIR: "/st" }, "/h"), "/st/openclaw.json");
  assert.equal(userConfigPath("openclaw", {}, "/h"), "/h/.openclaw/openclaw.json");
  assert.equal(userConfigPath("opencode", { OPENCODE_CONFIG: "/y/oc.json" }, "/h"), "/y/oc.json");
  assert.equal(userConfigPath("opencode", { XDG_CONFIG_HOME: "/xdg" }, "/h"), "/xdg/opencode/opencode.json");
  assert.equal(userConfigPath("opencode", {}, "/h"), "/h/.config/opencode/opencode.json");
});

// ── writeAgentConfig ─────────────────────────────────────────────────────────

function fullPlan(over: Partial<LaunchPlan>): LaunchPlan {
  return {
    target: "openclaw", argv: ["openclaw"], scopeId: "sid-1", tenant: "live",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned", arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/e", cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false,
    basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: ULLM, noScope: false, writeMcp: true, bestEffort: false, replyFilter: true,
    ...over,
  };
}

test("writeAgentConfig: merges the user's config under the routing override, into the scope run dir", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const userCfg = join(dir, "user-openclaw.json");
    writeFileSync(userCfg, JSON.stringify({
      agents: { defaults: { model: { primary: "anthropic/claude-opus-4-6" } } },
      models: { providers: { anthropic: { apiKey: "sk-user" } } },
    }));
    const warnings: string[] = [];
    const r = writeAgentConfig(
      fullPlan({}), Layout.dev("/repo"), dir, (m) => warnings.push(m),
      { OPENCLAW_CONFIG_PATH: userCfg },
    );
    assert.equal(r.envVar, "OPENCLAW_CONFIG_PATH");
    assert.equal(r.path, join(dir, "openclaw.json"));
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    // Routing override took…
    assert.equal(doc.models.providers.anthropic.baseUrl, "http://127.0.0.1:8788");
    // …user model choice + credential survived the merge.
    assert.equal(doc.agents.defaults.model.primary, "anthropic/claude-opus-4-6");
    assert.equal(doc.models.providers.anthropic.apiKey, "sk-user");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: the user's openclaw anthropic model entries survive, cleaned, with a warning naming what was dropped", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const userCfg = join(dir, "user-openclaw.json");
    writeFileSync(userCfg, JSON.stringify({
      models: { providers: { anthropic: { apiKey: "sk-user", models: [
        { id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5", maxTokens: 64000, baseUrl: "https://elsewhere.example" },
      ] } } },
    }));
    const warnings: string[] = [];
    const r = writeAgentConfig(fullPlan({}), Layout.dev("/repo"), dir, (m) => warnings.push(m), { OPENCLAW_CONFIG_PATH: userCfg });
    const prov = JSON.parse(readFileSync(r.path, "utf8")).models.providers.anthropic;
    assert.deepEqual(prov.models, [{ id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5", maxTokens: 64000 }]);
    assert.equal(prov.baseUrl, "http://127.0.0.1:8788");
    assert.equal(prov.apiKey, "sk-user");
    assert.ok(warnings.some((w) => w.includes("ignoring claude-sonnet-4-5.baseUrl")), warnings.join("\n"));
    // No user list → the empty list, and no warning about models.
    const w2: string[] = [];
    writeFileSync(userCfg, JSON.stringify({ agents: {} }));
    const r2 = writeAgentConfig(fullPlan({}), Layout.dev("/repo"), dir, (m) => w2.push(m), { OPENCLAW_CONFIG_PATH: userCfg });
    assert.deepEqual(JSON.parse(readFileSync(r2.path, "utf8")).models.providers.anthropic.models, []);
    assert.ok(!w2.some((w) => w.includes("ignoring")), w2.join("\n"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: a hand-edited JSON5 user config is read, and the user's settings survive", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const userCfg = join(dir, "user-openclaw.json");
    // OpenClaw configs are JSON5: a comment, unquoted keys, single quotes and
    // trailing commas are legal there and fatal to JSON.parse.
    writeFileSync(userCfg, "// my settings\n{ agents: { defaults: { model: { primary: 'anthropic/claude-sonnet-4-6', }, }, },\n  gateway: { port: 19001 }, }\n");
    const warnings: string[] = [];
    const r = writeAgentConfig(
      fullPlan({ agentVersion: "2026.9.6" }), Layout.dev("/repo"), dir, (m) => warnings.push(m),
      { OPENCLAW_CONFIG_PATH: userCfg },
    );
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(doc.models.providers.anthropic.baseUrl, "http://127.0.0.1:8788");
    assert.equal(doc.agents.defaults.model.primary, "anthropic/claude-sonnet-4-6");
    assert.equal(doc.gateway.port, 19001);
    assert.ok(!warnings.some((w) => w.includes("could not parse")), warnings.join("\n"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: a split OpenClaw config ($include) is written resolved, and the fences reach the included settings", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const home = join(dir, "state");
    mkdirSync(join(home, "parts"), { recursive: true });
    const userCfg = join(home, "openclaw.json");
    writeFileSync(join(home, "parts", "agents.json5"), `{
      defaults: { model: { primary: 'anthropic/claude-sonnet-4-6' },
        models: { 'openai/gpt-5.5': { alias: 'gpt' }, 'anthropic/claude-sonnet-4-6': { alias: 'sonnet' } } },
    }`);
    writeFileSync(join(home, "parts", "memory.json5"), "{ search: { provider: 'openai' } }");
    writeFileSync(userCfg, "{ agents: { $include: './parts/agents.json5' }, memory: { $include: './parts/memory.json5' }, gateway: { port: 19001 } }");
    const warnings: string[] = [];
    const r = writeAgentConfig(
      fullPlan({ agentVersion: "2026.9.6" }), Layout.dev("/repo"), dir, (m) => warnings.push(m),
      { OPENCLAW_CONFIG_PATH: userCfg },
    );
    const text = readFileSync(r.path, "utf8");
    assert.ok(!text.includes("$include"), "the run config carries no $include (it would not resolve from the scope run dir)");
    const doc = JSON.parse(text);
    assert.equal(doc.agents.defaults.model.primary, "anthropic/claude-sonnet-4-6");
    assert.equal(doc.gateway.port, 19001);
    assert.equal(doc.agents.defaults.models["openai/gpt-5.5"], undefined, "the model allowlist fence reached the included entry");
    assert.deepEqual(doc.memory.search, { provider: "none", fallback: "none" }, "the embeddings fence reached the included setting");
    assert.ok(warnings.some((w) => w.includes("your embedding setting (openai)")), warnings.join("\n"));
    assert.ok(!warnings.some((w) => w.includes("could not parse")), warnings.join("\n"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readAgentUserConfig: an OpenClaw include OpenClaw would refuse makes the config unreadable, naming the include", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const userCfg = join(dir, "openclaw.json");
    writeFileSync(userCfg, "{ agents: { $include: '../elsewhere.json5' } }");
    const got = readAgentUserConfig("openclaw", { OPENCLAW_CONFIG_PATH: userCfg });
    assert.equal(got.kind, "unreadable");
    assert.match(got.kind === "unreadable" ? got.reason : "", /^\$include "\.\.\/elsewhere\.json5": it is outside the config directory/);
    // OpenCode has no $include: the key is left to OpenCode.
    const oc = join(dir, "opencode.json");
    writeFileSync(oc, JSON.stringify({ $include: "./x.json" }));
    assert.deepEqual(readAgentUserConfig("opencode", { OPENCODE_CONFIG: oc }), { kind: "ok", path: oc, doc: { $include: "./x.json" } });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: an unparseable user config degrades to ours-only with a LOUD warning (protection intact)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const userCfg = join(dir, "user-openclaw.json");
    // Not JSON5 either: an unterminated object.
    writeFileSync(userCfg, "// my settings\n{ agents: {\n");
    const warnings: string[] = [];
    const r = writeAgentConfig(
      fullPlan({}), Layout.dev("/repo"), dir, (m) => warnings.push(m),
      { OPENCLAW_CONFIG_PATH: userCfg },
    );
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(doc.models.providers.anthropic.baseUrl, "http://127.0.0.1:8788");
    assert.ok(warnings.some((w) => w.includes("could not parse")), warnings.join("\n"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: opencode target lands in opencode.json under OPENCODE_CONFIG", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const r = writeAgentConfig(
      fullPlan({ target: "opencode", argv: ["opencode"] }), Layout.dev("/repo"), dir, () => {},
      {},
    );
    assert.equal(r.envVar, "OPENCODE_CONFIG");
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(doc.provider.anthropic.options.baseURL, "http://127.0.0.1:8788/v1");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: a missing openclaw plugin dir degrades to NO inspect channel, with a warning", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const warnings: string[] = [];
    // Layout.dev over a repo root that has no plugin package. The env pins the
    // user-config path INTO the tmp dir (nonexistent) — without it the probe
    // would read the developer's real ~/.openclaw/openclaw.json.
    const r = writeAgentConfig(
      fullPlan({ agentVersion: "2026.9.6" }), Layout.dev(join(dir, "not-a-repo")), dir, (m) => warnings.push(m),
      { OPENCLAW_CONFIG_PATH: join(dir, "no-user-config.json") },
    );
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(doc.plugins, undefined);
    assert.ok(warnings.some((w) => w.includes("inspect plugin not found")), warnings.join("\n"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: a REAL repo layout mounts the plugin (the dir exists in this tree)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    // This test file lives at <repo>/launcher/test/unit — the real repo root.
    const repoRoot = join(import.meta.dirname, "..", "..", "..");
    const r = writeAgentConfig(
      fullPlan({}), Layout.dev(repoRoot), dir, () => {},
      { OPENCLAW_CONFIG_PATH: join(dir, "no-user-config.json") },
    );
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    assert.ok(String(doc.plugins.load.paths[0]).endsWith(join("interceptors", "openclaw-inspect-plugin")));
    assert.deepEqual(doc.tools, { alsoAllow: ["inspect_symbol", "declassify_symbol"] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeAgentConfig: refuses a non-config-routed target; isConfigRouted agrees", () => {
  assert.throws(() => writeAgentConfig(fullPlan({ target: "claude" }), Layout.dev("/repo"), "/tmp", () => {}, {}), /not config-routed/);
  assert.equal(isConfigRouted("claude"), false);
  assert.equal(isConfigRouted("codex"), false);
  assert.equal(isConfigRouted("openclaw"), true);
  assert.equal(isConfigRouted("opencode"), true);
  assert.deepEqual(Object.keys(AGENT_CONFIG_ENV_VAR).sort(), ["openclaw", "opencode"]);
});

// ── OpenClaw memory-search embeddings (fenceOpenclawMemorySearch) ────────────

test("openclawMemoryShape: the release's own spelling, the plugin slot where it cannot be known", () => {
  assert.equal(openclawMemoryShape("2026.9.6"), "memory.search");
  assert.equal(openclawMemoryShape("2026.8.1"), "memory.search");
  assert.equal(openclawMemoryShape("2027.1.0"), "memory.search");
  assert.equal(openclawMemoryShape("2026.7.35"), "memorySearch");
  assert.equal(openclawMemoryShape("2026.7.1"), "memorySearch");
  assert.equal(openclawMemoryShape("2026.6.35"), "memorySearch");
  // 2026.3.12's provider enum has no "none"; no version read; a boundary prerelease.
  assert.equal(openclawMemoryShape("2026.6.34"), "slot");
  assert.equal(openclawMemoryShape("2026.3.12"), "slot");
  assert.equal(openclawMemoryShape(null), "slot");
  assert.equal(openclawMemoryShape(undefined), "slot");
  assert.equal(openclawMemoryShape("2026.8.1-beta.2"), "slot");
  assert.equal(openclawMemoryShape("2026.6.35-beta.1"), "slot");
  assert.equal(openclawMemoryShape("2026.9.1-beta.1"), "memory.search");
});

test("memory fence 2026.8+: memory.search turns embeddings off (keywords only), with a quiet note by default", () => {
  const r = fenceOpenclawMemorySearch({ agents: { defaults: { model: { primary: "anthropic/x" } } } }, "2026.9.6");
  const doc = r.doc as { memory: { search: Record<string, unknown> }; agents: { defaults: Record<string, unknown> }; plugins?: unknown };
  assert.deepEqual(doc.memory.search, { provider: "none", fallback: "none" });
  assert.equal(doc.agents.defaults["memorySearch"], undefined, "no legacy key: 2026.8+ rejects it");
  assert.equal(doc.plugins, undefined, "memory tools stay");
  assert.deepEqual(r.warnings, []);
  assert.match(r.notes.join("\n"), /keywords only/);
});

test("memory fence 2026.8+: a user's provider at every level is overridden and named in a WARNING", () => {
  const user = {
    memory: { search: { provider: "openai", model: "text-embedding-3-small", remote: { baseUrl: "https://emb.example/v1" }, extraPaths: ["notes"] } },
    agents: {
      entries: { work: { memory: { search: { provider: "gemini" } } } },
      list: [{ id: "old", memorySearch: { provider: "voyage", fallback: "openai" } }],
    },
  };
  const r = fenceOpenclawMemorySearch(user, "2026.9.6");
  const doc = r.doc as typeof user & { agents: { list: Array<{ memorySearch: Record<string, unknown> }> } };
  assert.equal(doc.memory.search.provider, "none");
  assert.equal((doc.memory.search as Record<string, unknown>)["fallback"], "none");
  assert.deepEqual(doc.memory.search.extraPaths, ["notes"], "the user's other search settings survive");
  assert.equal(doc.agents.entries.work.memory.search.provider, "none");
  // A legacy per-agent object is fenced too: startup migration would carry it over.
  assert.equal(doc.agents.list[0]!.memorySearch["provider"], "none");
  assert.equal(doc.agents.list[0]!.memorySearch["fallback"], "none");
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0]!, /keywords only under Mandu: your embedding setting \(openai, gemini, voyage, fallback openai\)/);
  // The input is not mutated.
  assert.equal(user.memory.search.provider, "openai");
});

test("memory fence 2026.6.35–2026.7.x: agents.defaults.memorySearch, never the new key", () => {
  const r = fenceOpenclawMemorySearch({ agents: { defaults: { memorySearch: { provider: "openai", enabled: true } } } }, "2026.7.1");
  const doc = r.doc as { memory?: unknown; agents: { defaults: { memorySearch: Record<string, unknown> } } };
  assert.equal(doc.memory, undefined, "2026.7.x rejects memory.search");
  assert.deepEqual(doc.agents.defaults.memorySearch, { provider: "none", enabled: true, fallback: "none" });
  assert.match(r.warnings.join("\n"), /your embedding setting \(openai\)/);
  const bare = fenceOpenclawMemorySearch({}, "2026.6.35").doc as { agents: { defaults: { memorySearch: unknown } } };
  assert.deepEqual(bare.agents.defaults.memorySearch, { provider: "none", fallback: "none" });
});

test("memory fence: an explicit local provider keeps its embeddings (they stay on this machine); its fallback does not", () => {
  const r = fenceOpenclawMemorySearch({ memory: { search: { provider: "local", fallback: "openai" } } }, "2026.9.6");
  assert.deepEqual((r.doc as { memory: { search: unknown } }).memory.search, { provider: "local", fallback: "none" });
  assert.match(r.warnings.join("\n"), /fallback openai/);
});

test("memory fence: an old or unread version unloads the memory plugin instead, with a WARNING", () => {
  for (const v of ["2026.3.12", null]) {
    const r = fenceOpenclawMemorySearch({ agents: { defaults: { memorySearch: { provider: "openai" } } } }, v);
    const doc = r.doc as { plugins: { slots: { memory: string } }; agents: { defaults: { memorySearch: Record<string, unknown> } } };
    assert.equal(doc.plugins.slots.memory, "none");
    // 2026.3.12's schema has no "none" provider: the object is left as it was.
    assert.equal(doc.agents.defaults.memorySearch["provider"], "openai");
    assert.match(r.warnings.join("\n"), /memory tools are off under Mandu/);
  }
});

test("memory fence: a third-party memory plugin is switched off; memory-core and an existing none are kept", () => {
  const lance = fenceOpenclawMemorySearch({ plugins: { slots: { memory: "memory-lancedb", contextEngine: "legacy" }, entries: { x: {} } } }, "2026.9.6");
  const ld = lance.doc as { plugins: { slots: Record<string, string>; entries: unknown } };
  assert.deepEqual(ld.plugins.slots, { memory: "none", contextEngine: "legacy" });
  assert.deepEqual(ld.plugins.entries, { x: {} });
  assert.match(lance.warnings.join("\n"), /memory plugin "memory-lancedb" is off/);
  const core = fenceOpenclawMemorySearch({ plugins: { slots: { memory: "memory-core" } } }, "2026.9.6");
  assert.equal((core.doc as { plugins: { slots: { memory: string } } }).plugins.slots.memory, "memory-core");
  assert.equal((core.doc as { memory: { search: { provider: string } } }).memory.search.provider, "none");
  const off = fenceOpenclawMemorySearch({ plugins: { slots: { memory: "none" } } }, "2026.9.6");
  assert.deepEqual(off.warnings, []);
  assert.equal((off.doc as { memory?: unknown }).memory, undefined);
});

test("writeAgentConfig: the openclaw run config carries the memory fence for the probed version", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const userCfg = join(dir, "user-openclaw.json");
    writeFileSync(userCfg, JSON.stringify({ memory: { search: { provider: "openai" } } }));
    const warnings: string[] = [];
    const r = writeAgentConfig(
      fullPlan({ agentVersion: "2026.9.6" }), Layout.dev("/repo"), dir, (m) => warnings.push(m),
      { OPENCLAW_CONFIG_PATH: userCfg },
    );
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(doc.memory.search.provider, "none");
    assert.ok(warnings.some((w) => /^agent-config: WARNING: OpenClaw memory search runs on keywords only/.test(w)), warnings.join("\n"));
    // The opencode config is untouched by it.
    const oc = writeAgentConfig(fullPlan({ target: "opencode", argv: ["opencode"], agentVersion: "1.18.13" }), Layout.dev("/repo"), dir, () => {}, {});
    const ocDoc = JSON.parse(readFileSync(oc.path, "utf8"));
    assert.equal(ocDoc.memory, undefined);
    assert.equal(ocDoc.plugins, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parseAgentConfigText: JSON5 objects only", () => {
  assert.deepEqual(parseAgentConfigText("{a: 1, // c\n}"), { a: 1 });
  assert.throws(() => parseAgentConfigText("[1]"), /not a JSON object/);
  assert.throws(() => parseAgentConfigText("{a:"), /line 1/);
});

// ── Routed OpenAI-family providers (agent-model-route.ts; 2026-09-28) ─────────

const ROUTES = [
  { id: "openai", api: "openai-responses" as const, upstream: "https://api.openai.com/v1" },
  { id: "deepseek", api: "openai-completions" as const, upstream: "https://api.deepseek.com/v1" },
];

test("openaiRouteBaseUrl: the proxy's per-provider prefix", () => {
  assert.equal(openaiRouteBaseUrl("http://127.0.0.1:8788", "openai"), "http://127.0.0.1:8788/_mandu/openai/openai");
});

test("openclaw doc: each routed provider points at its prefix, api pinned, headers carried, models cleaned", () => {
  const doc = buildOpenclawWrapDoc(input({ openaiRoutes: ROUTES }), PLAN_SLICE, undefined, [], { deepseek: [{ id: "deepseek-chat" }] }) as {
    models: { providers: Record<string, { baseUrl: string; api: string; headers: Record<string, string>; models: unknown[] }> };
  };
  const p = doc.models.providers;
  assert.deepEqual(Object.keys(p), ["anthropic", "openai", "deepseek"]);
  assert.equal(p["openai"]!.baseUrl, "http://127.0.0.1:8788/_mandu/openai/openai");
  assert.equal(p["openai"]!.api, "openai-responses");
  assert.deepEqual(p["openai"]!.models, [], "the models key is present (2026.3.12 rejects a provider without it)");
  assert.equal(p["deepseek"]!.api, "openai-completions");
  assert.deepEqual(p["deepseek"]!.models, [{ id: "deepseek-chat" }]);
  assert.equal(p["deepseek"]!.headers["x-mandu-session-id"], "sid-1");
});

test("opencode doc: routed providers join enabled_providers and point at their prefix; OPENCODE_CONFIG_CONTENT carries them", () => {
  const doc = buildOpencodeWrapDoc(input({ target: "opencode", openaiRoutes: ROUTES }), PLAN_SLICE, Layout.dev("/repo")) as {
    enabled_providers: string[]; provider: Record<string, { options: { baseURL: string } }>;
  };
  assert.deepEqual(doc.enabled_providers, ["anthropic", "openai", "deepseek"]);
  assert.equal(doc.provider["openai"]!.options.baseURL, "http://127.0.0.1:8788/_mandu/openai/openai");
  const content = JSON.parse(opencodeRoutingContent(doc as unknown as Record<string, unknown>,
    JSON.stringify({ provider: { openai: { options: { baseURL: "https://elsewhere.example/v1" } } } }), () => {}));
  assert.equal(content.provider.openai.options.baseURL, "http://127.0.0.1:8788/_mandu/openai/openai", "the user's own re-point is overridden");
  assert.deepEqual(content.enabled_providers, ["anthropic", "openai", "deepseek"]);
});

test("exec-host fence: host node (global and per agent) is dropped with a WARNING; local hosts and the rest are kept", () => {
  const merged = {
    tools: { exec: { host: "Node ", ask: "off" }, profile: "coding" },
    agents: { list: [{ id: "a", tools: { exec: { host: "gateway" } } }, { id: "b", tools: { exec: { host: "node" } } }], entries: { c: { tools: { exec: { host: "remote-box" } } } } },
  };
  const { doc, warnings } = fenceOpenclawExecHost(merged);
  const d = doc as typeof merged;
  assert.equal((d.tools.exec as Record<string, unknown>)["host"], undefined);
  assert.equal(d.tools.exec.ask, "off");
  assert.equal(d.agents.list[0]!.tools.exec.host, "gateway");
  assert.equal((d.agents.list[1]!.tools.exec as Record<string, unknown>)["host"], undefined);
  assert.equal((d.agents.entries.c.tools.exec as Record<string, unknown>)["host"], undefined);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /tools\.exec\.host "Node "/);
  assert.match(warnings[0]!, /agents\.list\[1\]\.tools\.exec\.host "node"/);
  assert.equal(merged.tools.exec.host, "Node ", "the input is not mutated");
  assert.deepEqual(fenceOpenclawExecHost({ tools: { exec: { host: "auto" } } }).warnings, []);
});

test("openclawHasCodeModeKey: 2026.5.18 and later accept tools.codeMode; earlier, unreadable or a boundary prerelease do not", () => {
  for (const v of ["2026.5.18", "2026.5.20", "2026.7.1-2", "2026.9.6", "2026.9.9", "2026.10.1-beta.2", "2027.1.1"]) assert.equal(openclawHasCodeModeKey(v), true, v);
  for (const v of [null, undefined, "", "garbage", "2026.3.12", "2026.5.12", "2026.5.18-beta.1"]) assert.equal(openclawHasCodeModeKey(v), false, String(v));
});

test("fenceOpenclawCodeMode: every codeMode the user set becomes false (global, per agent, per model), with a warning naming each that turned it on; the global key is written where the release accepts it", () => {
  const merged = {
    tools: { profile: "coding", codeMode: { enabled: "auto", executor: "quickjs" } },
    agents: {
      defaults: { models: { "anthropic/claude-opus-5": { codeMode: true, alias: "o5" }, "anthropic/x": { codeMode: false } } },
      list: [
        { id: "main", tools: { codeMode: true } },
        { id: "b", tools: { codeMode: { enabled: false, timeoutMs: 5000 } }, models: { "openai/gpt-5.5": { codeMode: "auto" } } },
      ],
    },
  };
  const { doc, warnings } = fenceOpenclawCodeMode(merged, "2026.9.9");
  const d = doc as typeof merged;
  assert.equal(d.tools.codeMode as unknown, false);
  assert.equal(d.tools.profile, "coding");
  assert.equal(d.agents.defaults.models["anthropic/claude-opus-5"]!.codeMode, false);
  assert.equal(d.agents.defaults.models["anthropic/claude-opus-5"]!.alias, "o5");
  assert.equal(d.agents.defaults.models["anthropic/x"]!.codeMode, false);
  assert.equal(d.agents.list[0]!.tools.codeMode as unknown, false);
  assert.equal(d.agents.list[1]!.tools.codeMode as unknown, false);
  assert.equal((d.agents.list[1]!.models as Record<string, Record<string, unknown>>)["openai/gpt-5.5"]!["codeMode"], false);
  assert.equal(warnings.length, 1);
  for (const where of ["tools.codeMode", "agents.defaults.models.anthropic/claude-opus-5.codeMode", "agents.list[0].tools.codeMode", "agents.list[1].models.openai/gpt-5.5.codeMode"]) {
    assert.ok(warnings[0]!.includes(where), `${where} in ${warnings[0]}`);
  }
  assert.ok(!warnings[0]!.includes("agents.list[1].tools.codeMode"), "a setting that was already off is not named");
  assert.ok(!warnings[0]!.includes("anthropic/x"));
  assert.equal(merged.tools.codeMode.enabled, "auto", "the input is not mutated");
  // nothing set: the global key is written only where the release accepts it, silently
  assert.deepEqual(fenceOpenclawCodeMode({ agents: {} }, "2026.9.9"), { doc: { agents: {}, tools: { codeMode: false } }, warnings: [] });
  assert.deepEqual(fenceOpenclawCodeMode({ agents: {} }, "2026.3.12"), { doc: { agents: {} }, warnings: [] });
  assert.deepEqual(fenceOpenclawCodeMode({ agents: {} }, null), { doc: { agents: {} }, warnings: [] });
  // a key the user wrote is overridden whatever the version (their release accepts it)
  assert.deepEqual(fenceOpenclawCodeMode({ tools: { codeMode: true } }, null).doc, { tools: { codeMode: false } });
});

test("writeAgentConfig: an openclaw run with routes carries them and the exec-host fence", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agentcfg-routes-"));
  try {
    const userCfg = join(dir, "user.json");
    writeFileSync(userCfg, JSON.stringify({
      models: { providers: { deepseek: { baseUrl: "https://api.deepseek.com/v1", api: "openai-completions", models: [{ id: "deepseek-chat", api: "anthropic-messages" }] } } },
      tools: { exec: { host: "node" } },
    }));
    const warned: string[] = [];
    const plan = {
      target: "openclaw", argv: ["openclaw", "gateway"], cwd: "/w", scopeId: "sid-r", tenant: "live", proxy: { host: "127.0.0.1", port: 9 }, writeMcp: false,
      arbiterSock: "/s", ullm: ULLM, openaiRoutes: ROUTES,
    } as unknown as LaunchPlan;
    const r = writeAgentConfig(plan, Layout.dev("/repo"), dir, (m) => warned.push(m), { OPENCLAW_CONFIG_PATH: userCfg });
    const out = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(out.models.providers.deepseek.baseUrl, "http://127.0.0.1:9/_mandu/openai/deepseek");
    assert.deepEqual(out.models.providers.deepseek.models, [{ id: "deepseek-chat" }]);
    assert.equal(out.tools.exec.host, undefined);
    assert.ok(warned.some((w) => /ignoring deepseek-chat\.api in your OpenClaw deepseek models/.test(w)));
    assert.ok(warned.some((w) => /paired device/.test(w)));
    assert.ok(out.agents.defaults.models["deepseek/*"] !== undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("readOpencodeAuthTypes: the sign-in type per provider; a missing or junk file is empty", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-oc-auth-"));
  try {
    assert.deepEqual(readOpencodeAuthTypes({ XDG_DATA_HOME: dir }), {});
    mkdirSync(join(dir, "opencode"));
    writeFileSync(join(dir, "opencode", "auth.json"), JSON.stringify({ openai: { type: "oauth", access: "x" }, deepseek: { type: "api", key: "k" }, bad: 3 }));
    assert.deepEqual(readOpencodeAuthTypes({ XDG_DATA_HOME: dir }), { openai: "oauth", deepseek: "api" });
    writeFileSync(join(dir, "opencode", "auth.json"), "{nope");
    assert.deepEqual(readOpencodeAuthTypes({ XDG_DATA_HOME: dir }), {});
    // default location under HOME
    assert.deepEqual(readOpencodeAuthTypes({}, join(dir, "no-home")), {});
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── The workspace pin (supported-agents.md §5.5 item 5; 2026-09-29) ──────────────────

test("fenceOpenclawWorkspace: the local shapes work in the launch directory, without OpenClaw's starter files", () => {
  const { doc, notes } = fenceOpenclawWorkspace({ agents: { defaults: { model: { primary: "anthropic/x" } } } }, ["openclaw", "chat"], "/home/u/proj");
  const d = (doc["agents"] as { defaults: Record<string, unknown> }).defaults;
  assert.equal(d["workspace"], "/home/u/proj");
  assert.equal(d["skipBootstrap"], true, "no AGENTS.md/SOUL.md/… written into the user's project");
  assert.deepEqual(d["model"], { primary: "anthropic/x" }, "the rest of the user's defaults kept");
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /^OpenClaw works in \/home\/u\/proj for this session/);
  // An empty doc gets the keys too.
  const empty = fenceOpenclawWorkspace({}, ["openclaw", "agent", "--local", "-m", "hi"], "/w").doc;
  assert.deepEqual(empty["agents"], { defaults: { workspace: "/w", skipBootstrap: true } });
});

test("fenceOpenclawWorkspace: the user's own workspaces are replaced for this run and named; the input doc is not mutated", () => {
  const user = {
    agents: {
      defaults: { workspace: "~/.openclaw/workspace", skipBootstrap: false },
      list: [{ id: "main", default: true, workspace: "/elsewhere" }, { id: "writer" }, "junk"],
    },
  };
  const before = JSON.stringify(user);
  const { doc, notes } = fenceOpenclawWorkspace(user, ["openclaw", "tui", "--local"], "/p");
  const agents = doc["agents"] as { defaults: Record<string, unknown>; list: unknown[] };
  assert.equal(agents.defaults["workspace"], "/p");
  assert.equal(agents.defaults["skipBootstrap"], true);
  assert.deepEqual(agents.list, [{ id: "main", default: true, workspace: "/p" }, { id: "writer" }, "junk"],
    "an agent's own workspace is pinned too; one without keeps OpenClaw's rule (<launch dir>/<id>)");
  assert.equal(JSON.stringify(user), before, "pure: the merged doc passed in is untouched");
  assert.equal(notes.length, 2);
  assert.match(notes[1]!, /agents\.defaults\.workspace "~\/\.openclaw\/workspace", agents\.list\[main\]\.workspace "\/elsewhere" applies when you run OpenClaw without Mandu/);
});

test("fenceOpenclawWorkspace: a relative workspace that already names the launch directory (the drill's \".\") is pinned without a note", () => {
  const { doc, notes } = fenceOpenclawWorkspace({ agents: { defaults: { workspace: ".", skipBootstrap: true } } }, ["openclaw", "chat"], "/p");
  assert.equal((doc["agents"] as { defaults: Record<string, unknown> }).defaults["workspace"], "/p");
  assert.equal(notes.length, 1, notes.join("\n"));
  assert.equal(fenceOpenclawWorkspace({ agents: { defaults: { workspace: "./sub" } } }, ["openclaw", "chat"], "/p").notes.length, 2);
});

test("fenceOpenclawWorkspace: the Gateway, a Gateway client and a wrapper keep the user's setting", () => {
  const user = { agents: { defaults: { workspace: "/theirs" } } };
  for (const argv of [["openclaw", "gateway"], ["openclaw", "gateway", "run"], ["openclaw", "tui"], ["./oc-wrapper.sh", "chat"]]) {
    const r = fenceOpenclawWorkspace(user, argv, "/p");
    assert.equal(r.doc, user, argv.join(" "));
    assert.deepEqual(r.notes, []);
  }
});

test("writeAgentConfig: a `chat` run config names the agent's working directory as OpenClaw's workspace", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const userCfg = join(dir, "user-openclaw.json");
    const userText = JSON.stringify({ agents: { defaults: { workspace: "~/.openclaw/workspace" } } });
    writeFileSync(userCfg, userText);
    const warnings: string[] = [];
    // `secrets`: the agent runs in the launch directory itself.
    const r = writeAgentConfig(fullPlan({ argv: ["openclaw", "chat"], cwd: "/home/u/proj", humanCwd: "/home/u/proj" }),
      Layout.dev("/repo"), dir, (m) => warnings.push(m), { OPENCLAW_CONFIG_PATH: userCfg });
    const doc = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(doc.agents.defaults.workspace, "/home/u/proj");
    assert.equal(doc.agents.defaults.skipBootstrap, true);
    assert.ok(warnings.some((w) => /^agent-config: OpenClaw works in \/home\/u\/proj/.test(w)), warnings.join("\n"));
    assert.ok(warnings.some((w) => /agents\.defaults\.workspace "~\/\.openclaw\/workspace" applies when you run OpenClaw without Mandu/.test(w)));
    assert.equal(readFileSync(userCfg, "utf8"), userText, "the user's file is untouched");
    // The frozen integrity axis rewrites the agent's cwd to the AgentView twin (manager.ts): the workspace follows it.
    const none = { OPENCLAW_CONFIG_PATH: join(dir, "absent.json") }; // never the real ~/.openclaw
    const twin = writeAgentConfig(fullPlan({ argv: ["openclaw", "chat"], cwd: "/state/views/proj", humanCwd: "/home/u/proj" }),
      Layout.dev("/repo"), dir, () => {}, none);
    assert.equal(JSON.parse(readFileSync(twin.path, "utf8")).agents.defaults.workspace, "/state/views/proj");
    // The Gateway keeps OpenClaw's own default: no workspace key written.
    const gw = writeAgentConfig(fullPlan({ argv: ["openclaw", "gateway"] }), Layout.dev("/repo"), dir, () => {}, none);
    assert.equal(JSON.parse(readFileSync(gw.path, "utf8")).agents?.defaults?.workspace, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── OpenClaw web egress through the net-proxy (fenceOpenclawWebEgress) ───────

const NET = "http://127.0.0.1:41861";

test("fenceOpenclawWebEgress: 2026.9.6 and later route OpenClaw's own fetches through the net-proxy (managed proxy, loopback direct) and web_fetch by its env proxy", () => {
  for (const v of ["2026.9.6", "2026.9.9", "OpenClaw 2026.10.1 (abc1234)"]) {
    const { doc, warnings, notes } = fenceOpenclawWebEgress({ tools: { profile: "coding" } }, v, NET);
    assert.deepEqual(doc, {
      tools: { profile: "coding", web: { fetch: { useTrustedEnvProxy: true } } },
      proxy: { enabled: true, proxyUrl: NET, loopbackMode: "gateway-only" },
    }, v);
    assert.deepEqual([warnings, notes], [[], []], v);
  }
});

test("fenceOpenclawWebEgress: 2026.5.3 to 2026.9.5 route web_fetch only (the managed proxy would send the loopback model call through the net-proxy there)", () => {
  for (const v of ["2026.5.3", "2026.7.1-2", "2026.9.5"]) {
    const { doc, warnings } = fenceOpenclawWebEgress({}, v, NET);
    assert.deepEqual(doc, { tools: { web: { fetch: { useTrustedEnvProxy: true } } } }, v);
    assert.deepEqual(warnings, [], v);
  }
});

test("fenceOpenclawWebEgress: before 2026.5.3, or an unreadable version, web_fetch is denied (merged with the user's deny list), with a warning", () => {
  for (const v of ["2026.5.2", "2026.3.12", null, undefined, "2026.5.3-beta.1"]) {
    const { doc, warnings } = fenceOpenclawWebEgress({ tools: { deny: ["browser"] } }, v, NET);
    assert.deepEqual(doc, { tools: { deny: ["browser", "web_fetch"] } }, String(v));
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /web_fetch is off under Mandu/);
  }
  // already denied: not listed twice
  assert.deepEqual(fenceOpenclawWebEgress({ tools: { deny: ["web_fetch"] } }, "2026.3.12", NET).doc, { tools: { deny: ["web_fetch"] } });
  // the version is named when it was read
  assert.match(fenceOpenclawWebEgress({}, "2026.3.12", NET).warnings[0]!, /OpenClaw 2026\.3\.12/);
});

test("fenceOpenclawWebEgress: the user's own proxy and useTrustedEnvProxy settings are replaced for the run, each named; no net-proxy leaves the doc alone", () => {
  const user = { proxy: { enabled: true, proxyUrl: "http://corp-proxy.example:3128" }, tools: { web: { fetch: { useTrustedEnvProxy: false, maxChars: 9 } } } };
  const r = fenceOpenclawWebEgress(user, "2026.9.9", NET);
  assert.deepEqual(r.doc, {
    proxy: { enabled: true, proxyUrl: NET, loopbackMode: "gateway-only" },
    tools: { web: { fetch: { useTrustedEnvProxy: true, maxChars: 9 } } },
  });
  assert.match(r.warnings.join("\n"), /your OpenClaw proxy setting is replaced/);
  assert.match(r.notes.join("\n"), /useTrustedEnvProxy: false applies without Mandu/);
  assert.equal(user.proxy.proxyUrl, "http://corp-proxy.example:3128", "the input is not mutated");
  // a user's `enabled: false` is replaced too: under Mandu the fetches go through the net-proxy
  assert.equal((fenceOpenclawWebEgress({ proxy: { enabled: false } }, "2026.9.9", NET).doc as { proxy: { enabled: boolean } }).proxy.enabled, true);
  // the net-proxy rung off: nothing to route to
  assert.deepEqual(fenceOpenclawWebEgress({ tools: {} }, "2026.9.9", undefined), { doc: { tools: {} }, warnings: [], notes: [] });
});

test("writeAgentConfig: the OpenClaw config the launcher writes routes web egress through the session's net-proxy", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-agent-config-"));
  try {
    const warnings: string[] = [];
    const plan = fullPlan({ netProxy: { host: "127.0.0.1", port: 41861 }, agentVersion: "2026.9.9" });
    const doc = JSON.parse(readFileSync(writeAgentConfig(plan, Layout.dev("/repo"), dir, (m) => warnings.push(m), {}).path, "utf8"));
    assert.deepEqual(doc.proxy, { enabled: true, proxyUrl: NET, loopbackMode: "gateway-only" });
    assert.equal(doc.tools.web.fetch.useTrustedEnvProxy, true);
    assert.equal(doc.models.providers.anthropic.baseUrl, "http://127.0.0.1:8788", "the model call keeps its loopback route");
    // the CI pin: web_fetch only
    const pin = JSON.parse(readFileSync(writeAgentConfig({ ...plan, agentVersion: "2026.7.1-2" }, Layout.dev("/repo"), dir, () => {}, {}).path, "utf8"));
    assert.equal(pin.proxy, undefined);
    assert.equal(pin.tools.web.fetch.useTrustedEnvProxy, true);
    // the oldest supported release: web_fetch denied, the launch says so
    const w3: string[] = [];
    const old = JSON.parse(readFileSync(writeAgentConfig({ ...plan, agentVersion: "2026.3.12" }, Layout.dev("/repo"), dir, (m) => w3.push(m), {}).path, "utf8"));
    assert.deepEqual(old.tools.deny, ["web_fetch"]);
    assert.ok(w3.some((w) => /WARNING: OpenClaw's web_fetch is off under Mandu/.test(w)), w3.join("\n"));
    // no net-proxy rung: the config carries none of it
    const off = JSON.parse(readFileSync(writeAgentConfig(fullPlan({ agentVersion: "2026.9.9" }), Layout.dev("/repo"), dir, () => {}, {}).path, "utf8"));
    assert.equal(off.proxy, undefined);
    assert.equal(off.tools?.web, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
