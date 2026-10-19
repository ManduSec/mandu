/**
 * opencode-v2-config.test — OpenCode 2's config spelling at launch
 * (supported-agents.md §2.3 part 4): src/opencode-config.ts (the
 * normalization), agent-model-route.ts opencodeV2ModelPlan (which launches
 * are refused, which providers are routed), and the 2.x routing Mandu writes
 * (services/agent-config.ts: the policy fence, the V2 spelling where the
 * user's doc uses it, the layer reader).
 *
 * Probe facts pinned here (2026-10-05, OpenCode 2.0.23; the real-binary pins
 * are test/component/opencode-v2-config.test.ts): a `providers.<id>` entry
 * replaces the `provider.<id>` entry of the same document whole; a V1
 * provider's `api` wins over its options.baseURL; the provider rule of the
 * LOWEST layer that names a provider wins, so only the global config sits
 * below Mandu's fence; a model's own base URL or package beats the
 * provider's.
 *
 * Axes: none. Pure config reading; no protection decision is made here.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  normalizeOpencodeDoc, opencodeGeneration, opencodeModelRefString, opencodePolicyFence,
  type OpencodeLayer,
} from "../../src/opencode-config.js";
import {
  agentModelPlan, opencodeV2ModelPlan, opencodeV2ProviderVerdict, OPENAI_API_BASE, type OpencodeV2Input,
} from "../../src/agent-model-route.js";
import {
  buildOpencodeConfigDir, buildOpencodeWrapDoc, OPENCODE_DENY_EXECUTE, OPENCODE_RUN_FILE, opencodeConfigDirOf, opencodeLockdownEnv,
  opencodeRoutingContent, opencodeWriteProtect, opencodeV2Input, opencodeV2McpServer, readOpencodeConfigLayers, withOpencodeV2Routing,
  writeAgentConfig, type AgentConfigInput,
} from "../../src/services/agent-config.js";
import { Layout } from "../../src/services/layout.js";
import type { LaunchPlan, Ullm } from "../../src/types.js";

const RUN = ["opencode", "run", "hi"];
const layer = (kind: OpencodeLayer["kind"], doc: Record<string, unknown>, path = `/${kind}/opencode.json`): OpencodeLayer => ({ kind, path, doc });
const v2 = (...layers: OpencodeLayer[]): OpencodeV2Input => ({ layers, unreadable: [] });
const plan = (input: OpencodeV2Input, argv: readonly string[] = RUN) => opencodeV2ModelPlan(argv, input);
const refusal = (input: OpencodeV2Input, argv: readonly string[] = RUN): string => plan(input, argv).refusal ?? "";

// ── which spelling ───────────────────────────────────────────────────────────

test("generation: opencode2 and every non-1 major read the 2.x spelling; an unread version keeps 1.x", () => {
  assert.equal(opencodeGeneration("opencode", "1.18.13"), 1);
  assert.equal(opencodeGeneration("/usr/bin/opencode", "opencode v2.0.23"), 2);
  assert.equal(opencodeGeneration("opencode", "0.0.0-beta-19507"), 2);
  assert.equal(opencodeGeneration("/x/opencode2", null), 2);
  assert.equal(opencodeGeneration("opencode", null), 1);
  assert.equal(opencodeGeneration("wrapper.sh", undefined), 1);
});

// ── normalization (both spellings) ───────────────────────────────────────────

test("normalize: model references in both spellings, with the #variant and the object form", () => {
  const n = normalizeOpencodeDoc({
    model: "anthropic/claude-sonnet-4-5#max",
    small_model: "openai/gpt-5-mini",
    agent: { build: { model: "google/gemini-3" }, rev: { model: "xai/grok-4" } },
    mode: { plan: { model: "mistral/large" } },
    agents: { rev: { model: { providerID: "anthropic", model: "claude-opus-4-8", variant: "high" } } },
    command: { c1: { template: "x", model: "deepseek/chat" } },
    commands: { c2: { template: "x", model: "anthropic/claude-haiku-4-5#fast" } },
  });
  assert.deepEqual(n.model, { ref: "anthropic/claude-sonnet-4-5#max", where: "model" });
  assert.deepEqual(n.agents, {
    title: { ref: "openai/gpt-5-mini", where: "small_model" },
    plan: { ref: "mistral/large", where: "mode.plan.model" },
    build: { ref: "google/gemini-3", where: "agent.build.model" },
    rev: { ref: "anthropic/claude-opus-4-8#high", where: "agents.rev.model" }, // V2 wins per name
  });
  assert.deepEqual(n.commands, {
    c1: { ref: "deepseek/chat", where: "command.c1.model" },
    c2: { ref: "anthropic/claude-haiku-4-5#fast", where: "commands.c2.model" },
  });
  assert.equal(opencodeModelRefString({ providerID: "anthropic", model: "x" }), "anthropic/x");
  assert.equal(opencodeModelRefString({ model: "x" }), undefined);
  assert.equal(opencodeModelRefString(" "), undefined);
});

test("normalize: providers — the V2 entry replaces the V1 one whole; a V1 api wins over options.baseURL", () => {
  const n = normalizeOpencodeDoc({
    provider: {
      anthropic: { options: { baseURL: "https://v1/v1", apiKey: "k" }, models: { m: { options: { baseURL: "https://m/v1" } } } },
      lm: { npm: "@ai-sdk/openai-compatible", api: "https://api-field/v1", options: { baseURL: "http://127.0.0.1:1/v1" } },
    },
    providers: { anthropic: { settings: { baseURL: "https://v2/v1" } }, deep: { package: "aisdk:@ai-sdk/openai-compatible", settings: { baseURL: "https://d/v1" } } },
  });
  assert.deepEqual(n.providers["anthropic"], { baseURL: "https://v2/v1", spelling: "providers" });
  assert.deepEqual(n.providers["lm"], { package: "aisdk:@ai-sdk/openai-compatible", baseURL: "https://api-field/v1", spelling: "provider" });
  assert.deepEqual(n.providers["deep"], { package: "aisdk:@ai-sdk/openai-compatible", baseURL: "https://d/v1", spelling: "providers" });
  // the replaced V1 anthropic entry's model keys are gone with it
  assert.deepEqual(n.endpointKeys, []);
});

test("normalize: a model's own endpoint, in every spelling OpenCode 2 reads", () => {
  const v1 = normalizeOpencodeDoc({ provider: { anthropic: { models: {
    a: { options: { baseURL: "https://x" } },
    b: { provider: { npm: "@ai-sdk/openai-compatible", api: "https://y" } },
    c: { variants: { hi: { baseURL: "https://z" } } },
    d: { api: "ignored-by-2.x", options: { thinking: {} } },
  } } } });
  assert.deepEqual(v1.endpointKeys.map((k) => k.where), [
    "provider.anthropic.models.a.options.baseURL",
    "provider.anthropic.models.b.provider.api",
    "provider.anthropic.models.b.provider.npm",
    "provider.anthropic.models.c.variants.hi.baseURL",
  ]);
  const n2 = normalizeOpencodeDoc({ providers: { anthropic: { models: {
    a: { settings: { baseURL: "https://x" } },
    b: { package: "aisdk:@ai-sdk/openai-compatible" },
    c: { variants: [{ id: "hi", settings: { baseURL: "https://z" } }, { id: "lo", settings: { effort: "low" } }] },
    d: { headers: { h: "1" }, settings: { effort: "high" } },
  } } } });
  assert.deepEqual(n2.endpointKeys.map((k) => k.where), [
    "providers.anthropic.models.a.settings.baseURL",
    "providers.anthropic.models.b.package",
    "providers.anthropic.models.c.variants[0].settings.baseURL",
  ]);
});

test("normalize: provider rules in OpenCode 2's order within a document (V1 lists, then experimental.policies)", () => {
  const n = normalizeOpencodeDoc({
    experimental: { policies: [{ action: "provider.use", resource: "openai", effect: "allow" }, { action: "permission", resource: "*", effect: "deny" }] },
    disabled_providers: ["google"],
    enabled_providers: ["anthropic"],
  });
  assert.deepEqual(n.policies.map((p) => `${p.effect} ${p.resource} @${p.where}`), [
    "deny * @enabled_providers",
    "allow anthropic @enabled_providers[0]",
    "deny google @disabled_providers[0]",
    "allow openai @experimental.policies[0]",
  ]);
  assert.deepEqual(opencodePolicyFence(["anthropic", "openai"]), [
    { action: "provider.use", resource: "*", effect: "deny" },
    { action: "provider.use", resource: "anthropic", effect: "allow" },
    { action: "provider.use", resource: "openai", effect: "allow" },
  ]);
});

// ── the launch-time plan ─────────────────────────────────────────────────────

test("v2 plan: anthropic models in either spelling launch; argv -m replaces the main model; a wrapper or --help is not checked", () => {
  assert.deepEqual(plan(v2(layer("global", { model: "anthropic/claude-sonnet-4-5#max", agents: { r: { model: "anthropic/claude-opus-4-8" } } }))), { refusal: null, routes: [] });
  assert.equal(refusal(v2(layer("project", { model: "google/gemini-3" })), ["opencode", "run", "-m", "anthropic/claude-sonnet-4-5", "hi"]), "");
  assert.match(refusal(v2(), ["opencode", "run", "-m", "google/gemini-3#fast", "hi"]), /model google\/gemini-3#fast \(--model\)/);
  assert.equal(refusal(v2(layer("project", { model: "google/gemini-3" })), ["opencode", "--help"]), "");
  assert.equal(refusal(v2(layer("project", { model: "google/gemini-3" })), ["oc-wrapper.sh"]), "");
  // opencode2 (only OpenCode 2 installs it) is OpenCode, not a wrapper
  assert.match(refusal(v2(layer("project", { model: "google/gemini-3" })), ["/usr/bin/opencode2", "run", "hi"]), /refusing to launch opencode/);
});

test("v2 plan: a model on a provider Mandu does not route is refused, from any layer, naming the key and the file", () => {
  const cases: Array<[OpencodeLayer, RegExp]> = [
    [layer("project", { model: "google/gemini-3" }), /google\/gemini-3 \(model in \/project\/opencode\.json\)/],
    [layer("global", { agents: { rev: { model: "xai/grok-4#fast" } } }), /xai\/grok-4#fast \(agents\.rev\.model in \/global\/opencode\.json\)/],
    [layer("inline", { agent: { build: { model: "mistral/large" } } }, "OPENCODE_CONFIG_CONTENT"), /agent\.build\.model in OPENCODE_CONFIG_CONTENT/],
    [layer("project", { commands: { c: { template: "x", model: { providerID: "deepseek", model: "chat" } } } }), /deepseek\/chat \(commands\.c\.model/],
    [layer("file", { small_model: "openrouter/x" }), /small_model in \/file\/opencode\.json/],
  ];
  for (const [l, re] of cases) {
    const r = refusal(v2(l));
    assert.match(r, re);
    assert.match(r, /^mandu: refusing to launch opencode with model /);
    assert.match(r, /aisdk:@ai-sdk\/openai-compatible package and settings\.baseURL/, "the hint is in OpenCode 2's spelling");
  }
});

test("v2 plan: the main model comes from the highest layer that sets it", () => {
  assert.equal(refusal(v2(layer("global", { model: "google/gemini-3" }), layer("project", { model: "anthropic/claude-sonnet-4-5" }))), "");
  assert.match(refusal(v2(layer("global", { model: "anthropic/claude-sonnet-4-5" }), layer("project", { model: "google/gemini-3" }))), /model in \/project/);
});

test("v2 plan: openai and a declared OpenAI-compatible provider (either spelling) are ROUTED", () => {
  const p = plan(v2(
    layer("global", { providers: { deep: { package: "aisdk:@ai-sdk/openai-compatible", settings: { baseURL: "https://api.deepseek.com/v1" } } } }),
    layer("project", { model: "openai/gpt-5", agents: { a: { model: "deep/chat" } }, provider: { lm: { npm: "@ai-sdk/openai-compatible", options: { baseURL: "http://127.0.0.1:1234/v1/" } } } }),
    layer("inline", { commands: { c: { template: "x", model: "lm/qwen3" } } }, "OPENCODE_CONFIG_CONTENT"),
  ));
  assert.equal(p.refusal, null);
  assert.deepEqual(p.routes, [
    { id: "openai", api: "openai-responses", upstream: OPENAI_API_BASE },
    { id: "deep", api: "openai-completions", upstream: "https://api.deepseek.com/v1" },
    { id: "lm", api: "openai-completions", upstream: "http://127.0.0.1:1234/v1" },
  ]);
});

test("v2 provider verdict: why a provider is not routed", () => {
  const why = (p: string, providers: Record<string, object> = {}, auth: Record<string, string> = {}): string => {
    const v = opencodeV2ProviderVerdict(p, Object.fromEntries(Object.entries(providers).map(([k, e]) => [k, { spelling: "providers" as const, ...e }])), auth);
    return v.kind === "refuse" ? v.why : v.kind;
  };
  assert.equal(why("anthropic"), "anthropic");
  assert.equal(why("openai"), "route");
  assert.match(why("openrouter"), /only when providers\.openrouter names the aisdk:@ai-sdk\/openai-compatible package and settings\.baseURL/);
  assert.match(why("x", { x: { package: "aisdk:@openrouter/ai-sdk-provider", baseURL: "https://x" } }), /uses the aisdk:@openrouter\/ai-sdk-provider package/);
  assert.match(why("x", { x: { package: "aisdk:@ai-sdk/openai-compatible" } }), /no base URL Mandu sends to \(settings\.baseURL/);
  assert.match(why("x", { x: { package: "aisdk:@ai-sdk/openai-compatible", baseURL: "http://lan:1/v1" } }), /no base URL/);
  assert.match(why("openai", {}, { openai: "oauth" }), /ChatGPT account/);
  assert.match(why("x", { x: { canonical: "openai", package: "aisdk:@ai-sdk/openai", baseURL: "https://x" } }), /canonical/);
});

test("v2 plan: a provider the user's config admits is not refused: under the lockdown the fence replaces every rule of theirs", () => {
  for (const kind of ["global", "project", "file", "inline"] as const) {
    assert.equal(refusal(v2(layer(kind, { enabled_providers: ["google"], experimental: { policies: [{ action: "provider.use", resource: "*", effect: "allow" }] } }))), "", kind);
  }
  // …and admits nothing to route: the fence keeps it to the routed providers.
  assert.deepEqual(plan(v2(layer("global", { enabled_providers: ["anthropic", "openai"] }))).routes, []);
});

test("v2 plan: a routed provider's model with its OWN endpoint is refused, in any layer and either spelling", () => {
  const cases: Array<[OpencodeLayer, RegExp]> = [
    [layer("project", { providers: { anthropic: { models: { "claude-sonnet-4-5": { settings: { baseURL: "https://evil/v1" } } } } } }),
      /providers\.anthropic\.models\.claude-sonnet-4-5\.settings\.baseURL in \/project\/opencode\.json gives one anthropic model its own endpoint/],
    [layer("project", { provider: { anthropic: { models: { m: { options: { baseURL: "https://evil/v1" } } } } } }), /provider\.anthropic\.models\.m\.options\.baseURL/],
    [layer("global", { provider: { anthropic: { models: { m: { provider: { api: "https://evil/v1" } } } } } }), /provider\.anthropic\.models\.m\.provider\.api in \/global/],
    [layer("inline", { providers: { anthropic: { models: { m: { variants: [{ id: "x", settings: { baseURL: "https://evil" } }] } } } } }, "OPENCODE_CONFIG_CONTENT"), /variants\[0\]\.settings\.baseURL in OPENCODE_CONFIG_CONTENT/],
    [layer("file", { providers: { anthropic: { models: { evil: { modelID: "claude-sonnet-4-5", package: "aisdk:@ai-sdk/openai-compatible" } } } } }), /models\.evil\.package/],
  ];
  for (const [l, re] of cases) assert.match(refusal(v2(l)), re);
  // A routed OpenAI-family provider's model too.
  assert.match(refusal(v2(layer("project", { model: "openai/gpt-5", providers: { openai: { models: { "gpt-5": { settings: { baseURL: "https://evil/v1" } } } } } }))),
    /providers\.openai\.models\.gpt-5\.settings\.baseURL/);
  // An unrouted provider's model endpoints are fenced off by the policy and not refused.
  assert.equal(refusal(v2(layer("global", { providers: { ollama: { models: { m: { settings: { baseURL: "http://127.0.0.1:11434/v1" } } } } } }))), "");
});

test("v2 plan: another SDK for the anthropic provider is refused; its own SDK and a re-pointed base URL are not", () => {
  assert.match(refusal(v2(layer("project", { providers: { anthropic: { package: "aisdk:@ai-sdk/azure", settings: { resourceName: "evil" } } } }))),
    /providers\.anthropic\.package in \/project\/opencode\.json makes the anthropic provider speak through another SDK/);
  assert.match(refusal(v2(layer("project", { provider: { anthropic: { npm: "@ai-sdk/openai-compatible" } } }))), /provider\.anthropic\.npm/);
  assert.match(refusal(v2(layer("project", { providers: { anthropic: { canonical: "openai" } } }))), /providers\.anthropic\.canonical/);
  assert.equal(refusal(v2(layer("project", { providers: { anthropic: { package: "aisdk:@ai-sdk/anthropic" } } }))), "");
  // The provider's own base URL, in either spelling and any layer, is overridden by the routing Mandu writes inline.
  assert.equal(refusal(v2(
    layer("global", { provider: { anthropic: { options: { baseURL: "https://evil/v1" } } } }),
    layer("project", { providers: { anthropic: { settings: { baseURL: "https://evil/v1" } } } }),
  )), "");
});

test("v2 plan: a config file it could not read is refused (it could hold any of the above)", () => {
  const r = refusal({ layers: [], unreadable: [{ path: "/p/opencode.jsonc", reason: "line 2: unexpected }" }] });
  assert.match(r, /could not read \/p\/opencode\.jsonc \(line 2: unexpected \}\)\. OpenCode 2 reads it/);
});

test("agentModelPlan: the OpenCode 2 input replaces the 1.x config read", () => {
  const cfg = { kind: "ok" as const, path: "/h/opencode.json", doc: { model: "anthropic/claude-sonnet-4-5" } };
  assert.equal(agentModelPlan("opencode", RUN, cfg).refusal, null);
  assert.match(agentModelPlan("opencode", RUN, cfg, {}, v2(layer("project", { model: "google/gemini-3" }))).refusal ?? "", /google\/gemini-3/);
});

// ── the routing Mandu writes for a 2.x launch ────────────────────────────────

const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };
const PLAN_SLICE = { arbiterSock: "/run/mandu/arbiter.sock", scopeId: "sid-1", tenant: "live" as const, ullm: ULLM };
const input = (over: Partial<AgentConfigInput> = {}): AgentConfigInput => ({
  target: "opencode", scopeId: "sid-1", tenant: "live", proxyUrl: "http://127.0.0.1:8788", inspect: false, ...over,
});
const ROUTES = [{ id: "openai", api: "openai-responses" as const, upstream: "https://api.openai.com/v1" }];

test("2.x doc: the policy fence in OpenCode 2's spelling; the 1.x doc is unchanged (OpenCode 1 rejects the 2.x keys)", () => {
  const d2 = buildOpencodeWrapDoc(input({ opencodeGeneration: 2, openaiRoutes: ROUTES }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  assert.deepEqual(d2["experimental"], { policies: opencodePolicyFence(["anthropic", "openai"]) });
  assert.deepEqual(d2["enabled_providers"], ["anthropic", "openai"]);
  assert.deepEqual(d2["permissions"], [OPENCODE_DENY_EXECUTE], "code mode off (defense in depth)");
  assert.equal(d2["provider"].anthropic.options.baseURL, "http://127.0.0.1:8788/v1");
  const d1 = buildOpencodeWrapDoc(input(), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  assert.equal(d1["experimental"], undefined);
  assert.equal(d1["providers"], undefined);
  assert.equal(d1["permissions"], undefined);
});

test("2.x doc: the inspect mount in V2 spelling with code mode off (else its tools live only inside the refused `execute`); 1.x keeps the V1 mount", () => {
  const d2 = buildOpencodeWrapDoc(input({ opencodeGeneration: 2, inspect: true }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  const servers = d2["mcp"].servers;
  assert.deepEqual(Object.keys(d2["mcp"]), ["servers"], "only the V2 key: 2.0.23 drops a V1 entry's codemode");
  for (const name of ["mandu-inspect", "mandu-policy"]) {
    const s = servers[name];
    assert.equal(s.type, "local");
    assert.equal(s.codemode, false, `${name}: direct tools, named <server>_<tool>`);
    assert.deepEqual(s.timeout, { startup: 30_000, catalog: 30_000, execution: 30_000 });
    assert.equal(s.enabled, undefined, "V2 has `disabled`, not `enabled`");
    assert.ok(Array.isArray(s.command) && s.command.length > 0);
    assert.equal(typeof s.environment, "object");
  }
  assert.equal(servers["mandu-inspect"].environment.MANDU_SCOPE_ID, "sid-1");
  assert.equal(opencodeV2McpServer({ command: "node", args: ["s.js"], env: { A: "1" } })["codemode"], false);
  // --no-policy-mcp drops the policy server alone; --no-mcp drops the key.
  const noPolicy = buildOpencodeWrapDoc(input({ opencodeGeneration: 2, inspect: true, policy: false }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  assert.deepEqual(Object.keys(noPolicy["mcp"].servers), ["mandu-inspect"]);
  assert.equal((buildOpencodeWrapDoc(input({ opencodeGeneration: 2 }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, unknown>)["mcp"], undefined);
  // OpenCode 1: the V1 entry, unchanged (1.18.13 rejects `servers` and `codemode`).
  const d1 = buildOpencodeWrapDoc(input({ inspect: true }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, any>;
  assert.equal(d1["mcp"].servers, undefined);
  assert.deepEqual({ ...d1["mcp"]["mandu-inspect"], command: undefined, environment: undefined }, {
    type: "local", command: undefined, enabled: true, timeout: 30_000, environment: undefined,
  });
});

test("2.x routing: written in V2 spelling too where the user's doc spells the provider in V2 (else their V2 entry would drop Mandu's)", () => {
  const ours = buildOpencodeWrapDoc(input({ opencodeGeneration: 2 }), PLAN_SLICE, Layout.dev("/repo")) as Record<string, unknown>;
  const user = { providers: { anthropic: { settings: { baseURL: "https://evil/v1", apiKey: "k" }, headers: { a: "1" } } } };
  const got = withOpencodeV2Routing(user, ours) as Record<string, any>;
  assert.deepEqual(got["providers"].anthropic, {
    settings: { baseURL: "http://127.0.0.1:8788/v1" },
    headers: { "x-mandu-session-id": "sid-1", "x-mandu-tenant": "live" },
  });
  // A user doc that spells anthropic in V1 only keeps the V1 routing alone (their V1 apiKey survives).
  assert.equal((withOpencodeV2Routing({ provider: { anthropic: { options: { apiKey: "k" } } } }, ours) as Record<string, unknown>)["providers"], undefined);

  // The inline content: the user's V2 re-point is overwritten, their other settings kept, their policies replaced.
  const content = JSON.parse(opencodeRoutingContent(ours, JSON.stringify({
    ...user, experimental: { policies: [{ action: "provider.use", resource: "openai", effect: "allow" }], subagent_depth: 2 },
  }), () => {})) as Record<string, any>;
  assert.equal(content["providers"].anthropic.settings.baseURL, "http://127.0.0.1:8788/v1");
  assert.equal(content["providers"].anthropic.settings.apiKey, "k");
  assert.equal(content["provider"].anthropic.options.baseURL, "http://127.0.0.1:8788/v1");
  assert.deepEqual(content["experimental"], { policies: opencodePolicyFence(["anthropic"]), subagent_depth: 2 });
  assert.deepEqual(content["permissions"], [OPENCODE_DENY_EXECUTE]);
  // The user's own permission rules stay, Mandu's deny after them (the last match wins).
  const mine = { action: "read", resource: "*.pem", effect: "deny" };
  const withTheirs = JSON.parse(opencodeRoutingContent(ours, JSON.stringify({ permissions: [mine, { action: "execute", resource: "*", effect: "allow" }] }), () => {})) as Record<string, any>;
  assert.deepEqual(withTheirs["permissions"], [mine, { action: "execute", resource: "*", effect: "allow" }, OPENCODE_DENY_EXECUTE]);
  // 1.x content: no 2.x key.
  const c1 = JSON.parse(opencodeRoutingContent(buildOpencodeWrapDoc(input(), PLAN_SLICE, Layout.dev("/repo")) as Record<string, unknown>, undefined, () => {}));
  assert.deepEqual(Object.keys(c1).sort(), ["enabled_providers", "provider"]);
});

function fullPlan(over: Partial<LaunchPlan>): LaunchPlan {
  return {
    target: "opencode", argv: ["opencode"], scopeId: "sid-1", tenant: "live",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned", arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/e", cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false,
    basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: ULLM, noScope: false, writeMcp: false, bestEffort: false, replyFilter: true,
    ...over,
  };
}

test("writeAgentConfig: a 2.x launch — the lockdown env, the run file in the launcher's directory with every user layer merged under the fence", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-oc2-config-"));
  try {
    const home = join(dir, "home"), gdir = join(home, ".config", "opencode"), proj = join(dir, "proj"), scope = join(dir, "scope");
    mkdirSync(gdir, { recursive: true });
    mkdirSync(join(proj, ".opencode", "agents"), { recursive: true });
    writeFileSync(join(gdir, "opencode.json"), JSON.stringify({ theme: "g", provider: { anthropic: { options: { apiKey: "k" } } } }));
    writeFileSync(join(proj, "opencode.json"), JSON.stringify({ theme: "p", enabled_providers: ["google"] }));
    writeFileSync(join(proj, ".opencode", "agents", "rev.md"), "---\ndescription: r\n---\nreview\n");
    const userCfg = join(dir, "user.json");
    writeFileSync(userCfg, JSON.stringify({
      providers: { anthropic: { settings: { baseURL: "https://evil/v1" } } },
      experimental: { policies: [{ action: "provider.use", resource: "*", effect: "allow" }] },
    }));
    const env = {
      HOME: home, OPENCODE_CONFIG: userCfg,
      OPENCODE_CONFIG_CONTENT: JSON.stringify({ providers: { anthropic: { settings: { baseURL: "https://evil2/v1" } } } }),
    };
    const r = writeAgentConfig(fullPlan({ agentVersion: "2.0.23", cwd: proj, writeMcp: true, writePolicyMcp: false }), Layout.dev("/repo"), scope, () => {}, env);
    const cfgDir = opencodeConfigDirOf(scope);
    assert.equal(r.envVar, "OPENCODE_CONFIG");
    assert.equal(r.path, join(cfgDir, OPENCODE_RUN_FILE));
    assert.deepEqual({ ...r.env, OPENCODE_CONFIG_CONTENT: undefined }, { ...opencodeLockdownEnv(cfgDir), OPENCODE_CONFIG_CONTENT: undefined });
    const file = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(file.theme, "p", "the project's settings survive, over the global ones");
    assert.equal(file.providers.anthropic.settings.baseURL, "http://127.0.0.1:8788/v1");
    assert.deepEqual(file.experimental.policies, opencodePolicyFence(["anthropic"]), "the user's allow-all is replaced");
    assert.deepEqual(file.enabled_providers, ["anthropic"], "the project's enabled_providers too");
    assert.ok(existsSync(join(cfgDir, "agents", "rev.md")), "the project's agents are linked in");
    // The inspect mount rides in the run file, in 2.x spelling with code mode off (!780).
    assert.equal(file.mcp.servers["mandu-inspect"].codemode, false);
    assert.equal(file.mcp["mandu-inspect"], undefined, "no V1-spelled entry beside it");
    const inline = JSON.parse(r.env!["OPENCODE_CONFIG_CONTENT"]!);
    assert.equal(inline.providers.anthropic.settings.baseURL, "http://127.0.0.1:8788/v1");
    assert.deepEqual(inline.experimental.policies, opencodePolicyFence(["anthropic"]));
    assert.deepEqual(file.permissions, [OPENCODE_DENY_EXECUTE]);
    assert.deepEqual(inline.permissions, [OPENCODE_DENY_EXECUTE]);
    // The same user files under OpenCode 1: the 1.x shape, no 2.x keys, no lockdown.
    const r1 = writeAgentConfig(fullPlan({ agentVersion: "1.18.13", cwd: proj }), Layout.dev("/repo"), join(dir, "v1"), () => {}, { HOME: home, OPENCODE_CONFIG: join(dir, "absent.json") });
    const f1 = JSON.parse(readFileSync(r1.path, "utf8"));
    assert.equal(f1.experimental, undefined);
    assert.equal(f1.providers, undefined);
    // OPENCODE_PURE: OpenCode 1's own "no external plugins" switch, with
    // confidentiality ON or unknown (opencode-global-code.ts, §2.3 item 12).
    assert.deepEqual(Object.keys(r1.env ?? {}), ["OPENCODE_CONFIG_CONTENT", "OPENCODE_PURE"]);
    assert.equal(r1.path, join(dir, "v1", "opencode.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("lockdown: the env switches, and the guard's deny entry for the launcher's directory", () => {
  assert.deepEqual(opencodeLockdownEnv("/s/opencode-config"), {
    OPENCODE_CONFIG_DIR: "/s/opencode-config",
    OPENCODE_DISABLE_PROJECT_CONFIG: "1", OPENCODE_CONFIG_PROJECT_DISABLE: "1",
    OPENCODE_DISABLE_FILEWATCHER: "1", OPENCODE_FILEWATCHER_DISABLE: "1",
  });
  assert.deepEqual(opencodeWriteProtect("/run/mandu/sid"), { path: "/run/mandu/sid/opencode-config", answer: "deny", label: "Mandu's own files" });
});

test("buildOpencodeConfigDir: the global dir and every project .opencode linked in (later wins), no config document, one composed AGENTS.md", () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-oc2-cfgdir-"));
  try {
    const home = join(root, "home"), gdir = join(home, ".config", "opencode");
    const repo = join(root, "repo"), sub = join(repo, "sub"), out = join(root, "out");
    for (const d of [join(gdir, "agents"), join(gdir, "node_modules", "x"), join(repo, ".git"), join(repo, ".opencode", "agents"), join(sub, ".opencode", "commands"), join(root, ".opencode", "agents")]) mkdirSync(d, { recursive: true });
    writeFileSync(join(gdir, "opencode.json"), "{}");
    writeFileSync(join(gdir, "AGENTS.md"), "GLOBAL\n");
    writeFileSync(join(gdir, "agents", "a.md"), "global-a");
    writeFileSync(join(gdir, "agents", "b.md"), "global-b");
    writeFileSync(join(root, ".opencode", "agents", "c.md"), "above-repo-c");
    writeFileSync(join(repo, ".opencode", "agents", "b.md"), "repo-b");
    writeFileSync(join(repo, ".opencode", "opencode.jsonc"), "{}");
    writeFileSync(join(repo, ".opencode", "package.json"), "{}");
    writeFileSync(join(sub, ".opencode", "commands", "go.md"), "go");
    writeFileSync(join(root, "AGENTS.md"), "OUTSIDE-REPO\n");
    writeFileSync(join(repo, "AGENTS.md"), "REPO\n");
    writeFileSync(join(sub, "AGENTS.md"), "SUB\n");
    mkdirSync(out);
    writeFileSync(join(out, "opencode.json"), "{\"stale\": true}");
    buildOpencodeConfigDir(out, {}, sub, () => {}, home);
    const read = (p: string): string => readFileSync(join(out, p), "utf8");
    assert.equal(existsSync(join(out, "opencode.json")), false, "a stale document is gone; none is linked in");
    assert.equal(existsSync(join(out, "opencode.jsonc")), false);
    assert.equal(existsSync(join(out, "package.json")), false, "a project's package files are not");
    assert.equal(read("agents/a.md"), "global-a");
    assert.equal(read("agents/b.md"), "repo-b", "a project's agent replaces the global one of the same name");
    assert.equal(read("agents/c.md"), "above-repo-c", "every ancestor's .opencode, as OpenCode 2 reads them");
    assert.equal(read("commands/go.md"), "go");
    assert.ok(lstatSync(join(out, "node_modules")).isSymbolicLink(), "the global plugins' packages, whole");
    assert.equal(read("AGENTS.md"), "GLOBAL\n\nREPO\n\nSUB\n", "global, then the repository root down to cwd");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── the layer reader ─────────────────────────────────────────────────────────

test("readOpencodeConfigLayers: global dir, OPENCODE_CONFIG, every ancestor's project files, then the inline content", () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-oc2-layers-"));
  try {
    const home = join(root, "home");
    const gdir = join(home, ".config", "opencode");
    mkdirSync(gdir, { recursive: true });
    writeFileSync(join(gdir, "opencode.json"), '{"model":"g"}');
    writeFileSync(join(gdir, "opencode.jsonc"), '{ // c\n "model": "gc" }');
    const repo = join(root, "repo"), sub = join(repo, "sub");
    mkdirSync(join(sub, ".opencode"), { recursive: true });
    mkdirSync(join(repo, ".opencode"), { recursive: true });
    writeFileSync(join(root, "opencode.json"), '{"model":"above-repo"}');
    writeFileSync(join(repo, "opencode.json"), '{"model":"repo"}');
    writeFileSync(join(repo, ".opencode", "opencode.json"), '{"model":"repo-dot"}');
    writeFileSync(join(sub, "opencode.jsonc"), '{"model":"sub"}');
    writeFileSync(join(sub, ".opencode", "opencode.json"), '{"model":"sub-dot"}');
    const file = join(root, "explicit.json");
    writeFileSync(file, '{"model":"file"}');
    const env = { HOME: home, OPENCODE_CONFIG: file, OPENCODE_CONFIG_CONTENT: '{"model":"inline"}' };
    const got = readOpencodeConfigLayers(env, [sub], home);
    assert.deepEqual(got.unreadable, []);
    const models = got.layers.map((l) => `${l.kind}:${String(l.doc["model"])}`);
    assert.deepEqual(models.filter((m) => !m.startsWith("project:") || /above-repo|repo|sub/.test(m)), [
      "global:g", "global:gc", "file:file",
      "project:above-repo", "project:repo", "project:sub", "project:repo-dot", "project:sub-dot",
      "inline:inline",
    ]);
    // OPENCODE_CONFIG_DIR replaces the global dir; the project switch drops every project layer.
    const g2 = join(root, "g2");
    mkdirSync(g2);
    writeFileSync(join(g2, "opencode.json"), '{"model":"g2"}');
    const noProj = readOpencodeConfigLayers({ OPENCODE_CONFIG_DIR: g2, OPENCODE_DISABLE_PROJECT_CONFIG: "1" }, [sub], home);
    assert.deepEqual(noProj.layers.map((l) => `${l.kind}:${String(l.doc["model"])}`), ["global:g2"]);
    // An unrecognized switch value reads the project layers anyway (more layers, a stricter check).
    assert.ok(readOpencodeConfigLayers({ OPENCODE_DISABLE_PROJECT_CONFIG: "yes-please" }, [sub], home).layers.some((l) => l.kind === "project"));
    // Started in the global config dir: no project layers, and nothing read twice.
    const inGlobal = readOpencodeConfigLayers({}, [gdir], home);
    assert.deepEqual(inGlobal.layers.map((l) => l.kind), ["global", "global"]);
    // A file that does not parse is listed, not skipped.
    writeFileSync(join(repo, "opencode.json"), "{ nope");
    const bad = readOpencodeConfigLayers({}, [sub], home);
    assert.equal(bad.unreadable.length, 1);
    assert.equal(bad.unreadable[0]!.path, join(repo, "opencode.json"));
    // An inline content that does not parse is replaced by Mandu's routing, so it is no layer.
    assert.ok(!readOpencodeConfigLayers({ OPENCODE_CONFIG_CONTENT: "nope" }, [sub], home).layers.some((l) => l.kind === "inline"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("opencodeV2Input: only for a 2.x launch; the `opencode <dir>` argument's project files are read too", () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-oc2-input-"));
  try {
    const home = join(root, "home"), cwd = join(root, "cwd"), other = join(root, "other");
    mkdirSync(home); mkdirSync(cwd); mkdirSync(other);
    writeFileSync(join(other, "opencode.json"), '{"model":"google/gemini-3"}');
    assert.equal(opencodeV2Input(["opencode", "run", "hi"], "1.18.13", {}, cwd, home), undefined);
    assert.deepEqual(opencodeV2Input(["opencode", "run", "hi"], "2.0.23", {}, cwd, home)?.layers.filter((l) => l.path.startsWith(root)), []);
    const withDir = opencodeV2Input(["opencode2", "../other"], null, {}, cwd, home);
    assert.ok(withDir?.layers.some((l) => l.path === join(other, "opencode.json")));
    assert.match(opencodeV2ModelPlan(["opencode2", "../other"], withDir!).refusal ?? "", /google\/gemini-3 \(model in .*other\/opencode\.json\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
