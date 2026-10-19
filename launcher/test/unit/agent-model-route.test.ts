/**
 * agent-model-route.test — which OpenClaw / OpenCode launches are refused
 * because a model they can run is not routed through Mandu's model proxy
 * (src/agent-model-route.ts), plus the two runtime fences in
 * services/agent-config.ts (OpenClaw's model allowlist, OpenCode's
 * enabled_providers in OPENCODE_CONFIG_CONTENT).
 *
 * Probe facts pinned here (2026-09-27): OpenClaw's built-in default is
 * openai/gpt-5.5 on 2026.6+; `-m` is --message for `openclaw agent`, only
 * `--model` names a model; OpenCode refs are provider/model and `-m` is its
 * model flag; a project opencode.json outranks OPENCODE_CONFIG but not
 * OPENCODE_CONFIG_CONTENT.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  openclawModelRefusal, opencodeModelRefusal, agentModelRefusal, openclawModelPlan, opencodeModelPlan,
  openclawProviderVerdict, opencodeProviderVerdict, routableUpstream, OPENAI_API_BASE, type AgentUserConfig,
} from "../../src/agent-model-route.js";
import { fenceOpenclawModelAllowlist, opencodeRoutingContent } from "../../src/services/agent-config.js";

// Axes: none. Pure routing logic; no protection decision is made here.

const ok = (doc: Record<string, unknown>): AgentUserConfig => ({ kind: "ok", path: "/h/.openclaw/openclaw.json", doc });
const absent: AgentUserConfig = { kind: "absent" };
const OC = ["openclaw", "agent", "--local", "-m", "hi"];

test("openclaw: an anthropic primary launches; the message flag -m is not a model", () => {
  assert.equal(openclawModelRefusal(OC, ok({ agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } } })), null);
  assert.equal(openclawModelRefusal(OC, ok({ agents: { defaults: { model: "anthropic/claude-opus-4-8" } } })), null);
  // `-m openai/x` is the message text, not a model
  assert.equal(openclawModelRefusal(["openclaw", "agent", "--local", "-m", "openai/gpt-5.5"],
    ok({ agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } } })), null);
});

test("openclaw: an unrouted primary, fallback, per-agent, sub-agent or compaction model is refused, naming where", () => {
  const cases: Array<[Record<string, unknown>, RegExp]> = [
    [{ defaults: { model: { primary: "deepseek/deepseek-chat" } } }, /deepseek\/deepseek-chat \(agents\.defaults\.model\.primary\)/],
    [{ defaults: { model: { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["mistral/mistral-large"] } } }, /agents\.defaults\.model\.fallbacks\[0\]/],
    [{ defaults: { model: "anthropic/claude-sonnet-4-6" }, list: [{ id: "main" }, { id: "ops", model: "google/gemini-3.1-pro" }] }, /agents\.list\[1\]\.model/],
    [{ defaults: { model: "anthropic/claude-sonnet-4-6", subagents: { model: "xai/grok-5" } } }, /agents\.defaults\.subagents\.model/],
    [{ defaults: { model: "anthropic/claude-sonnet-4-6", compaction: { model: "ollama/qwen3:8b" } } }, /agents\.defaults\.compaction\.model/],
  ];
  for (const [agents, re] of cases) {
    const msg = openclawModelRefusal(OC, ok({ agents }));
    assert.ok(msg !== null, JSON.stringify(agents));
    assert.match(msg, /^mandu: refusing to launch openclaw with model /);
    assert.match(msg, re);
  }
});

test("openclaw: the embedding model under memorySearch and media models are not conversation models", () => {
  assert.equal(openclawModelRefusal(OC, ok({ agents: { defaults: {
    model: "anthropic/claude-sonnet-4-6",
    memorySearch: { provider: "openai", model: "text-embedding-3-small" },
    imageGenerationModel: { primary: "google/gemini-3.1-flash-image-preview" },
  } } })), null);
});

test("openclaw: --model replaces the configured primary (its fallbacks still count); aliases resolve", () => {
  const cfg = ok({ agents: { defaults: {
    model: { primary: "google/gemini-3.1-pro", fallbacks: ["anthropic/claude-haiku-4-5"] },
    models: { "anthropic/claude-sonnet-4-6": { alias: "sonnet" }, "google/gemini-3.1-pro": { alias: "gpt" } },
  } } });
  assert.equal(openclawModelRefusal(["openclaw", "agent", "--local", "--model", "anthropic/claude-sonnet-4-6", "-m", "hi"], cfg), null);
  assert.equal(openclawModelRefusal(["openclaw", "agent", "--local", "--model=sonnet", "-m", "hi"], cfg), null);
  assert.match(openclawModelRefusal(["openclaw", "agent", "--local", "--model", "gpt", "-m", "hi"], cfg) ?? "", /gpt \(--model\)/);
  // a bare id that is no alias cannot be vouched for
  assert.match(openclawModelRefusal(["openclaw", "agent", "--local", "--model", "claude-sonnet-4-6", "-m", "hi"], cfg) ?? "",
    /write a bare model id as <provider>\/<id>/);
});

test("openclaw: a config that splits itself with $include is refused, naming where", () => {
  const cfg = ok({ agents: { defaults: { model: "anthropic/claude-sonnet-4-6" }, list: [{ id: "ops", $include: "./ops.json5" }] } });
  const got = openclawModelRefusal(OC, cfg) ?? "";
  assert.match(got, /refusing to launch openclaw: \/h\/\.openclaw\/openclaw\.json uses \$include \(agents\.list\[0\]\.\$include\)/);
  assert.match(openclawModelRefusal(OC, ok({ $include: ["./a.json5"], agents: { defaults: { model: "anthropic/x" } } })) ?? "", /uses \$include \(\$include\)/);
  // --help still runs, as for any refusal
  assert.equal(openclawModelRefusal(["openclaw", "--help"], cfg), null);
});

test("openclaw: Active Memory's recall model reads the conversation, so it must be an anthropic model too", () => {
  const withAm = (config: Record<string, unknown>) => ok({
    agents: { defaults: { model: "anthropic/claude-sonnet-4-6" } },
    plugins: { entries: { "active-memory": { enabled: true, config } } },
  });
  assert.match(openclawModelRefusal(OC, withAm({ model: "xai/grok-5" })) ?? "", /xai\/grok-5 \(plugins\.entries\.active-memory\.config\.model\)/);
  assert.match(openclawModelRefusal(OC, withAm({ modelFallback: "google/gemini-3-flash" })) ?? "", /plugins\.entries\.active-memory\.config\.modelFallback/);
  assert.equal(openclawModelRefusal(OC, withAm({ model: "anthropic/claude-haiku-4-5" })), null);
  assert.equal(openclawModelRefusal(OC, withAm({})), null);
});

test("openclaw: no model configured, or a config the launcher cannot read, is refused", () => {
  assert.match(openclawModelRefusal(OC, absent) ?? "", /no model configured/);
  assert.match(openclawModelRefusal(["openclaw", "chat"], ok({ agents: { defaults: {} } })) ?? "", /no model configured/);
  assert.match(openclawModelRefusal(OC, { kind: "unreadable", path: "/x.json", reason: "Unexpected token" }) ?? "", /could not read \/x\.json \(Unexpected token\)[^]*reads it as JSON5/);
  // the selected agent's own model is a primary
  assert.equal(openclawModelRefusal(["openclaw", "agent", "--local", "--agent", "ops", "-m", "hi"],
    ok({ agents: { list: [{ id: "ops", model: "anthropic/claude-sonnet-4-6" }] } })), null);
  // a --model on the command line is a primary too
  assert.equal(openclawModelRefusal(["openclaw", "agent", "--local", "--model", "anthropic/claude-sonnet-4-6", "-m", "hi"], absent), null);
});

test("openclaw: help/version and wrappers are not checked", () => {
  assert.equal(openclawModelRefusal(["openclaw", "--version"], absent), null);
  assert.equal(openclawModelRefusal(["openclaw", "agent", "--help"], absent), null);
  assert.equal(openclawModelRefusal(["./my-openclaw.sh", "agent", "--local"], absent), null);
});

test("opencode: -m / --model / the config's models must name a routed provider; unset is fine (fenced)", () => {
  const c = (doc: Record<string, unknown>): AgentUserConfig => ({ kind: "ok", path: "/h/opencode.json", doc });
  assert.equal(opencodeModelRefusal(["opencode", "run", "hi"], absent), null);
  assert.equal(opencodeModelRefusal(["opencode", "run", "-m", "anthropic/claude-sonnet-4-6", "hi"], absent), null);
  assert.match(opencodeModelRefusal(["opencode", "run", "-m", "google/gemini-3", "hi"], absent) ?? "", /google\/gemini-3 \(--model\)/);
  assert.match(opencodeModelRefusal(["opencode", "--model=google/gemini-3"], absent) ?? "", /--model/);
  assert.match(opencodeModelRefusal(["opencode"], c({ model: "google/gemini-3" })) ?? "", /model in \/h\/opencode\.json/);
  assert.match(opencodeModelRefusal(["opencode"], c({ model: "anthropic/claude-sonnet-4-6", small_model: "xai/grok-5" })) ?? "", /small_model/);
  assert.match(opencodeModelRefusal(["opencode"], c({ agent: { plan: { model: "openrouter/anthropic/claude-sonnet-4.6" } } })) ?? "", /agent\.plan\.model/);
  // -m replaces the configured main model for the run
  assert.equal(opencodeModelRefusal(["opencode", "run", "-m", "anthropic/claude-sonnet-4-6", "hi"], c({ model: "google/gemini-3" })), null);
  assert.equal(opencodeModelRefusal(["opencode", "--version"], c({ model: "google/gemini-3" })), null);
  assert.equal(opencodeModelRefusal(["opencode-wrapper.sh", "-m", "google/gemini-3"], absent), null);
  assert.equal(agentModelRefusal("claude", ["claude"], absent), null);
});

test("openclaw: openai/… and a declared OpenAI-compatible provider are ROUTED, not refused", () => {
  const plan = openclawModelPlan(OC, ok({
    agents: { defaults: { model: { primary: "openai/gpt-5.5", fallbacks: ["deepseek/deepseek-chat", "anthropic/claude-haiku-4-5"] } } },
    models: { providers: { deepseek: { baseUrl: "https://api.deepseek.com/v1", api: "openai-completions", apiKey: "x" } } },
  }));
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routes, [
    { id: "openai", api: "openai-responses", upstream: OPENAI_API_BASE },
    { id: "deepseek", api: "openai-completions", upstream: "https://api.deepseek.com/v1" },
  ]);
  // an Anthropic-only config routes nothing
  assert.deepEqual(openclawModelPlan(OC, ok({ agents: { defaults: { model: "anthropic/claude-sonnet-4-6" } } })).routes, []);
});

test("openclaw: which providers route, and why the others do not", () => {
  const v = (p: string, providers: Record<string, unknown> = {}) => openclawProviderVerdict(p, { models: { providers } });
  assert.deepEqual(v("anthropic"), { kind: "anthropic" });
  assert.equal(v("openai").kind, "route");
  assert.equal(v("openai", { openai: { baseUrl: "https://proxy.corp/v1" } }).kind === "route" && (v("openai", { openai: { baseUrl: "https://proxy.corp/v1" } }) as { route: { upstream: string } }).route.upstream, "https://proxy.corp/v1");
  assert.deepEqual(v("local", { local: { baseUrl: "http://127.0.0.1:11434/v1/", api: "openai-completions" } }), { kind: "route", route: { id: "local", api: "openai-completions", upstream: "http://127.0.0.1:11434/v1" } });
  const why = (r: ReturnType<typeof v>): string => (r.kind === "refuse" ? r.why : "");
  assert.match(why(v("openrouter")), /models\.providers\.openrouter names its baseUrl and api/);
  assert.match(why(v("x", { x: { baseUrl: "https://x/v1" } })), /names no api/);
  assert.match(why(v("x", { x: { baseUrl: "https://x/v1", api: "anthropic-messages" } })), /api "anthropic-messages"/);
  assert.match(why(v("x", { x: { baseUrl: "https://x/v1", api: "openai-chatgpt-responses" } })), /does not route/);
  assert.match(why(v("x", { x: { baseUrl: "http://lan-box:8000/v1", api: "openai-completions" } })), /baseUrl is missing or not a URL/);
  assert.match(why(v("openai-codex")), /baseUrl and api/);
});

test("opencode: openai/… and a declared openai-compatible provider route; a ChatGPT sign-in does not", () => {
  const c = (doc: Record<string, unknown>): AgentUserConfig => ({ kind: "ok", path: "/h/opencode.json", doc });
  const doc = { model: "openai/gpt-5", small_model: "lmstudio/qwen3", provider: { lmstudio: { npm: "@ai-sdk/openai-compatible", options: { baseURL: "http://127.0.0.1:1234/v1" } } } };
  const plan = opencodeModelPlan(["opencode", "run", "hi"], c(doc));
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routes, [
    { id: "openai", api: "openai-responses", upstream: OPENAI_API_BASE },
    { id: "lmstudio", api: "openai-completions", upstream: "http://127.0.0.1:1234/v1" },
  ]);
  assert.match(opencodeModelPlan(["opencode", "run", "hi"], c(doc), { openai: "oauth" }).refusal ?? "", /ChatGPT account/);
  assert.equal(opencodeModelPlan(["opencode", "run", "hi"], c(doc), { openai: "api" }).refusal, null);
  const why = (p: string, providers: Record<string, unknown>) => { const r = opencodeProviderVerdict(p, { provider: providers }); return r.kind === "refuse" ? r.why : ""; };
  assert.match(why("openrouter", {}), /@ai-sdk\/openai-compatible package and options\.baseURL/);
  assert.match(why("x", { x: { npm: "@openrouter/ai-sdk-provider", options: { baseURL: "https://x" } } }), /@openrouter\/ai-sdk-provider package/);
  assert.match(why("x", { x: { npm: "@ai-sdk/openai-compatible" } }), /no base URL/);
});

test("routableUpstream: https anywhere, http only to a literal loopback, no query or credentials", () => {
  assert.equal(routableUpstream("https://api.x.com/v1/"), "https://api.x.com/v1");
  assert.equal(routableUpstream("http://127.0.0.1:8080/v1"), "http://127.0.0.1:8080/v1");
  assert.equal(routableUpstream("http://[::1]:8080"), "http://[::1]:8080");
  for (const bad of ["http://localhost:1/v1", "http://10.0.0.2/v1", "ftp://x", "https://u:p@x/v1", "https://x/v1?k=1", "", 3]) {
    assert.equal(routableUpstream(bad), null, String(bad));
  }
});

test("fence: OpenClaw's allowlist admits the routed providers only, keeping their aliases", () => {
  const routed = fenceOpenclawModelAllowlist({ agents: { defaults: { models: { "openai/gpt-5.5": { alias: "g" }, "google/gemini": {} } } } }, ["openai"]);
  assert.deepEqual((routed["agents"] as { defaults: { models: unknown } }).defaults.models, { "anthropic/*": {}, "openai/*": {}, "openai/gpt-5.5": { alias: "g" } });

  const out = fenceOpenclawModelAllowlist({
    agents: { defaults: { model: "anthropic/claude-sonnet-4-6", models: { "anthropic/claude-sonnet-4-6": { alias: "sonnet" }, "openai/gpt-5.5": {}, "openai/*": {} } } },
    tools: { profile: "coding" },
  });
  assert.deepEqual((out["agents"] as { defaults: { models: unknown } }).defaults.models, { "anthropic/*": {}, "anthropic/claude-sonnet-4-6": { alias: "sonnet" } });
  assert.deepEqual(out["tools"], { profile: "coding" });
  assert.deepEqual((fenceOpenclawModelAllowlist({})["agents"] as { defaults: unknown }).defaults, { models: { "anthropic/*": {} } });
});

test("fence: OPENCODE_CONFIG_CONTENT carries enabled_providers + the anthropic endpoint over the user's own content", () => {
  const ours = { mcp: { x: {} }, enabled_providers: ["anthropic"], provider: { anthropic: { options: { baseURL: "http://127.0.0.1:1/v1", headers: { h: "1" } } } } };
  const warned: string[] = [];
  const got = JSON.parse(opencodeRoutingContent(ours, JSON.stringify({ theme: "t", enabled_providers: ["openai"], provider: { openai: {}, anthropic: { options: { baseURL: "https://x/v1" } } } }), (m) => warned.push(m)));
  assert.deepEqual(got.enabled_providers, ["anthropic"]);
  assert.equal(got.provider.anthropic.options.baseURL, "http://127.0.0.1:1/v1");
  assert.equal(got.theme, "t");
  assert.equal(got.mcp, undefined, "only the routing keys ride in the env var");
  assert.equal(warned.length, 0);
  const bad = JSON.parse(opencodeRoutingContent(ours, "not json", (m) => warned.push(m)));
  assert.deepEqual(bad.enabled_providers, ["anthropic"]);
  assert.equal(warned.length, 1);
});
