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
  openclawProviderVerdict, opencodeProviderVerdict, routableUpstream, routeUpstreamsEnv, OPENAI_API_BASE, GEMINI_API_BASE, type AgentUserConfig,
  googleRoutedKeyVars, openclawVertexVersionRefusal, VERTEX_GOOGLE_HOSTS,
  ollamaRoutedKeyVars, ollamaUpstreamOf, OLLAMA_BUILTIN_BASES,
  CHATGPT_BACKEND_BASE, azureRoutedKeyVars, azureRouteProblem, openclawConfigAzureEnv, wireUpstream,
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
    [{ defaults: { model: "anthropic/claude-sonnet-4-6" }, list: [{ id: "main" }, { id: "ops", model: "mistral/mistral-3.1-pro" }] }, /agents\.list\[1\]\.model/],
    [{ defaults: { model: "anthropic/claude-sonnet-4-6", subagents: { model: "xai/grok-5" } } }, /agents\.defaults\.subagents\.model/],
    [{ defaults: { model: "anthropic/claude-sonnet-4-6", compaction: { model: "together/qwen3:8b" } } }, /agents\.defaults\.compaction\.model/],
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
    imageGenerationModel: { primary: "mistral/mistral-3.1-flash-image-preview" },
  } } })), null);
});

test("openclaw: --model replaces the configured primary (its fallbacks still count); aliases resolve", () => {
  const cfg = ok({ agents: { defaults: {
    model: { primary: "mistral/mistral-3.1-pro", fallbacks: ["anthropic/claude-haiku-4-5"] },
    models: { "anthropic/claude-sonnet-4-6": { alias: "sonnet" }, "mistral/mistral-3.1-pro": { alias: "gpt" } },
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
  assert.match(openclawModelRefusal(OC, withAm({ modelFallback: "mistral/mistral-3-flash" })) ?? "", /plugins\.entries\.active-memory\.config\.modelFallback/);
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
  assert.match(opencodeModelRefusal(["opencode", "run", "-m", "mistral/mistral-3", "hi"], absent) ?? "", /mistral\/mistral-3 \(--model\)/);
  assert.match(opencodeModelRefusal(["opencode", "--model=mistral/mistral-3"], absent) ?? "", /--model/);
  assert.match(opencodeModelRefusal(["opencode"], c({ model: "mistral/mistral-3" })) ?? "", /model in \/h\/opencode\.json/);
  assert.match(opencodeModelRefusal(["opencode"], c({ model: "anthropic/claude-sonnet-4-6", small_model: "xai/grok-5" })) ?? "", /small_model/);
  assert.match(opencodeModelRefusal(["opencode"], c({ agent: { plan: { model: "openrouter/anthropic/claude-sonnet-4.6" } } })) ?? "", /agent\.plan\.model/);
  // -m replaces the configured main model for the run
  assert.equal(opencodeModelRefusal(["opencode", "run", "-m", "anthropic/claude-sonnet-4-6", "hi"], c({ model: "mistral/mistral-3" })), null);
  assert.equal(opencodeModelRefusal(["opencode", "--version"], c({ model: "mistral/mistral-3" })), null);
  assert.equal(opencodeModelRefusal(["opencode-wrapper.sh", "-m", "mistral/mistral-3"], absent), null);
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
  // OpenClaw 2026.3's name for the ChatGPT api is not routed (that release
  // has neither azure-openai-responses nor openai-chatgpt-responses).
  assert.match(why(v("x", { x: { baseUrl: "https://x/v1", api: "openai-codex-responses" } })), /does not route/);
  assert.match(why(v("x", { x: { baseUrl: "http://lan-box:8000/v1", api: "openai-completions" } })), /baseUrl is missing or not a URL/);
  assert.match(why(v("openai-codex")), /baseUrl and api/);
});

test("openclaw: GitHub Copilot is refused on every wire and spelling, its baseUrl notwithstanding (OpenClaw sends its calls where its Copilot sign-in says)", () => {
  const copilot = { api: "openai-completions", baseUrl: "https://api.individual.githubcopilot.com", models: [] };
  for (const id of ["github-copilot", "GitHub-Copilot"]) {
    for (const api of ["openai-completions", "openai-responses"]) {
      const r = openclawProviderVerdict(id, { models: { providers: { [id]: { ...copilot, api } } } });
      assert.equal(r.kind, "refuse", `${id} on ${api}`);
      assert.match(r.kind === "refuse" ? r.why : "", /endpoint its Copilot sign-in answers with \(a \*\.githubcopilot\.com host\), whatever the provider's baseUrl/);
    }
  }
  // The built-in (no models.providers entry) too, and the launch names it.
  assert.equal(openclawProviderVerdict("github-copilot", {}).kind, "refuse");
  const refusal = openclawModelRefusal(["openclaw", "agent", "--local", "-m", "hi"], ok({
    agents: { defaults: { model: { primary: "github-copilot/gpt-5.4-mini" } } },
    models: { providers: { "github-copilot": copilot } },
  }));
  assert.match(refusal ?? "", /refusing to launch openclaw with model github-copilot\/gpt-5\.4-mini \(agents\.defaults\.model\.primary\): OpenClaw sends GitHub Copilot's model calls/);
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
  assert.match(why("openrouter", {}), /@ai-sdk\/openai-compatible or @ai-sdk\/google package and options\.baseURL/);
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
  const routed = fenceOpenclawModelAllowlist({ agents: { defaults: { models: { "openai/gpt-5.5": { alias: "g" }, "mistral/mistral": {} } } } }, ["openai"]);
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

// ── Gemini providers (model-wires.md §5, 2026-10-25) ────────────────────────

test("openclaw: the built-in google provider and a google-generative-ai provider with a baseUrl are ROUTED; other Google apis are not", () => {
  assert.deepEqual(openclawProviderVerdict("google", {}), { kind: "route", route: { id: "google", api: "google-generative-ai", upstream: GEMINI_API_BASE } });
  const doc = { models: { providers: {
    google: { apiKey: "x" },
    corp: { api: "google-generative-ai", baseUrl: "https://gemini.corp.example/v1beta/" },
    nobase: { api: "google-generative-ai" },
    vertex: { api: "google-vertex", baseUrl: "https://us-central1-aiplatform.googleapis.com" },
    cli: { api: "google-gemini-cli", baseUrl: "https://cloudcode-pa.googleapis.com" },
    inter: { api: "google-interactions", baseUrl: "https://generativelanguage.googleapis.com/v1beta" },
  } } };
  assert.deepEqual(openclawProviderVerdict("google", doc), { kind: "route", route: { id: "google", api: "google-generative-ai", upstream: GEMINI_API_BASE } }, "a google entry without api or baseUrl is the built-in");
  assert.deepEqual(openclawProviderVerdict("corp", doc), { kind: "route", route: { id: "corp", api: "google-generative-ai", upstream: "https://gemini.corp.example/v1beta" } });
  assert.equal(openclawProviderVerdict("nobase", doc).kind, "refuse", "a custom provider must name its baseUrl");
  for (const p of ["vertex", "cli", "inter"]) assert.equal(openclawProviderVerdict(p, doc).kind, "refuse", p);
  const plan = openclawModelPlan(["openclaw", "agent", "--local", "-m", "hi"], { kind: "ok", path: "/h/openclaw.json", doc: { ...doc, agents: { defaults: { model: { primary: "google/gemini-3-pro", fallbacks: ["corp/gemini-2.5-flash"] } } } } });
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routes.map((r) => [r.id, r.api]), [["google", "google-generative-ai"], ["corp", "google-generative-ai"]]);
});

test("openclaw: its own google-vertex provider is ROUTED (model-wires.md §4.1): to Google's hosts per location, or the origin of the user's own baseUrl; another id, another api or an address Mandu does not send to is not", () => {
  const v = (p: string, providers: Record<string, unknown> = {}) => openclawProviderVerdict(p, { models: { providers } });
  const route = (upstream: string) => ({ kind: "route", route: { id: "google-vertex", api: "google-vertex", upstream } });
  assert.deepEqual(v("google-vertex"), route(VERTEX_GOOGLE_HOSTS), "the built-in, no entry");
  assert.deepEqual(v("google-vertex", { "google-vertex": { api: "google-vertex" } }), route(VERTEX_GOOGLE_HOSTS));
  assert.deepEqual(v("google-vertex", { "google-vertex": { baseUrl: "https://{location}-aiplatform.googleapis.com" } }), route(VERTEX_GOOGLE_HOSTS), "OpenClaw replaces a {location} template with Google's host");
  assert.deepEqual(v("google-vertex", { "google-vertex": { api: "google-vertex", baseUrl: "https://vertex-psc.corp.example/v1/ignored" } }), route("https://vertex-psc.corp.example"), "OpenClaw keeps only the origin");
  const why = (r: ReturnType<typeof v>): string => (r.kind === "refuse" ? r.why : "");
  assert.match(why(v("myvertex", { myvertex: { api: "google-vertex", baseUrl: "https://us-central1-aiplatform.googleapis.com" } })), /Mandu routes Vertex AI only as OpenClaw's own google-vertex provider/);
  assert.match(why(v("google-vertex", { "google-vertex": { api: "google-generative-ai", baseUrl: "https://x.example" } })), /names api "google-generative-ai"/);
  assert.match(why(v("google-vertex", { "google-vertex": { baseUrl: "http://10.0.0.5:8080" } })), /not a URL Mandu sends to/);
  assert.match(why(v("Google-Vertex")), /only as OpenClaw's own google-vertex provider/);
  const plan = openclawModelPlan(["openclaw", "agent", "--local", "-m", "hi"], ok({ agents: { defaults: { model: { primary: "google-vertex/gemini-2.5-flash" } } } }));
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routes, [{ id: "google-vertex", api: "google-vertex", upstream: VERTEX_GOOGLE_HOSTS }]);
  // The proxy's table: null for Google's hosts, the origin otherwise; one provider.
  assert.deepEqual(JSON.parse(routeUpstreamsEnv(plan.routes).MANDU_VERTEX_UPSTREAMS!), { "google-vertex": null });
  assert.equal(routeUpstreamsEnv(plan.routes).MANDU_GOOGLE_UPSTREAMS, undefined);
  assert.equal(routeUpstreamsEnv(plan.routes).MANDU_OPENAI_UPSTREAMS, undefined);
  assert.deepEqual(JSON.parse(routeUpstreamsEnv([{ id: "google-vertex", api: "google-vertex", upstream: "https://psc.example" }]).MANDU_VERTEX_UPSTREAMS!), { "google-vertex": "https://psc.example" });
  // Its express-mode key variable is the agent's own (left unmasked).
  assert.deepEqual(googleRoutedKeyVars("openclaw", plan.routes), ["GOOGLE_CLOUD_API_KEY"]);
});

test("openclaw: a Vertex route only on a release that takes it (2026.7.1 and later, a respin included); an older or unread one is refused before the launch", () => {
  const r = [{ id: "google-vertex", api: "google-vertex" as const, upstream: VERTEX_GOOGLE_HOSTS }];
  for (const ok of ["2026.7.1", "2026.7.1-2", "2026.9.9", "2026.10.7"]) assert.equal(openclawVertexVersionRefusal(r, ok), null, ok);
  for (const old of ["2026.3.12", "2026.6.35", "2026.7.1-beta.6"]) {
    assert.match(openclawVertexVersionRefusal(r, old) ?? "", new RegExp(`OpenClaw ${old.replace(/\./g, "\\.")} sends Vertex AI calls to Google's own host whatever the provider's baseUrl.*Update OpenClaw to 2026\\.7\\.1 or later`), old);
  }
  assert.match(openclawVertexVersionRefusal(r, null) ?? "", /an OpenClaw release Mandu could not read/);
  assert.equal(openclawVertexVersionRefusal([{ id: "google", api: "google-generative-ai", upstream: GEMINI_API_BASE }], null), null, "no Vertex route, no version rule");
});

test("opencode: the built-in google provider and an @ai-sdk/google provider are ROUTED (the Gemini API by default); Vertex is not", () => {
  const v = (p: string, providers: Record<string, unknown> = {}) => opencodeProviderVerdict(p, { provider: providers });
  assert.deepEqual(v("google"), { kind: "route", route: { id: "google", api: "google-generative-ai", upstream: GEMINI_API_BASE } });
  assert.deepEqual(v("gem", { gem: { npm: "@ai-sdk/google" } }), { kind: "route", route: { id: "gem", api: "google-generative-ai", upstream: GEMINI_API_BASE } });
  assert.deepEqual(v("gem", { gem: { npm: "@ai-sdk/google", options: { baseURL: "http://127.0.0.1:9000/v1beta" } } }), { kind: "route", route: { id: "gem", api: "google-generative-ai", upstream: "http://127.0.0.1:9000/v1beta" } });
  assert.equal(v("vertex", { vertex: { npm: "@ai-sdk/google-vertex" } }).kind, "refuse");
  assert.equal(v("google-vertex").kind, "refuse");
  const plan = opencodeModelPlan(["opencode", "run", "-m", "google/gemini-2.5-flash", "hi"], { kind: "absent" } as AgentUserConfig);
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routes, [{ id: "google", api: "google-generative-ai", upstream: GEMINI_API_BASE }]);
});

test("routeUpstreamsEnv: OpenAI-family routes in MANDU_OPENAI_UPSTREAMS, Gemini ones in MANDU_GOOGLE_UPSTREAMS, each UNSET when empty", () => {
  assert.deepEqual(routeUpstreamsEnv([]), { MANDU_OPENAI_UPSTREAMS: undefined, MANDU_GOOGLE_UPSTREAMS: undefined, MANDU_VERTEX_UPSTREAMS: undefined, MANDU_OLLAMA_UPSTREAMS: undefined });
  const env = routeUpstreamsEnv([
    { id: "openai", api: "openai-responses", upstream: OPENAI_API_BASE },
    { id: "google", api: "google-generative-ai", upstream: GEMINI_API_BASE },
    { id: "deepseek", api: "openai-completions", upstream: "https://api.deepseek.com/v1" },
  ]);
  assert.deepEqual(JSON.parse(env.MANDU_OPENAI_UPSTREAMS!), { openai: OPENAI_API_BASE, deepseek: "https://api.deepseek.com/v1" });
  assert.deepEqual(JSON.parse(env.MANDU_GOOGLE_UPSTREAMS!), { google: GEMINI_API_BASE });
  assert.deepEqual(routeUpstreamsEnv([{ id: "google", api: "google-generative-ai", upstream: GEMINI_API_BASE }]).MANDU_OPENAI_UPSTREAMS, undefined);
});

test("openclaw: the built-in ollama and ollama-cloud providers and any `api: \"ollama\"` provider are ROUTED on Ollama's native chat API (model-wires.md, \"The Ollama wire\")", () => {
  const v = (p: string, providers: Record<string, unknown> = {}) => openclawProviderVerdict(p, { models: { providers } });
  assert.deepEqual(v("ollama"), { kind: "route", route: { id: "ollama", api: "ollama", upstream: "http://127.0.0.1:11434" } }, "the built-in: a local Ollama");
  assert.deepEqual(v("ollama-cloud"), { kind: "route", route: { id: "ollama-cloud", api: "ollama", upstream: "https://ollama.com" } });
  assert.deepEqual(v("ollama", { ollama: { apiKey: "ollama-local" } }), { kind: "route", route: { id: "ollama", api: "ollama", upstream: OLLAMA_BUILTIN_BASES["ollama"] } }, "an entry without api or baseUrl is the built-in");
  assert.deepEqual(v("ollama", { ollama: { baseUrl: "http://127.0.0.1:21434/v1/" } }), { kind: "route", route: { id: "ollama", api: "ollama", upstream: "http://127.0.0.1:21434" } }, "the /v1 OpenClaw strips is dropped");
  assert.deepEqual(v("gpu", { gpu: { api: "ollama", baseUrl: "https://ollama.gpu.example/" } }), { kind: "route", route: { id: "gpu", api: "ollama", upstream: "https://ollama.gpu.example" } });
  assert.deepEqual(v("ollama", { ollama: { api: "openai-completions", baseUrl: "http://127.0.0.1:11434/v1" } }), { kind: "route", route: { id: "ollama", api: "openai-completions", upstream: "http://127.0.0.1:11434/v1" } }, "Ollama's OpenAI-compatible endpoint stays a Chat route");
  const why = (r: ReturnType<typeof v>): string => (r.kind === "refuse" ? r.why : "");
  assert.match(why(v("lan", { lan: { api: "ollama", baseUrl: "http://192.168.1.20:11434" } })), /baseUrl is missing or not a URL Mandu sends to/, "plain http off this machine is refused");
  assert.match(why(v("lan", { lan: { api: "ollama" } })), /baseUrl is missing/);
  const plan = openclawModelPlan(["openclaw", "agent", "--local", "-m", "hi"], { kind: "ok", path: "/h/openclaw.json", doc: { agents: { defaults: { model: { primary: "ollama/qwen3:8b", fallbacks: ["gpu/llama3.1"] } } }, models: { providers: { gpu: { api: "ollama", baseUrl: "https://ollama.gpu.example" } } } } });
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routes.map((r) => [r.id, r.api, r.upstream]), [["ollama", "ollama", "http://127.0.0.1:11434"], ["gpu", "ollama", "https://ollama.gpu.example"]]);
  const env = routeUpstreamsEnv(plan.routes);
  assert.deepEqual(JSON.parse(env.MANDU_OLLAMA_UPSTREAMS!), { ollama: "http://127.0.0.1:11434", gpu: "https://ollama.gpu.example" });
  assert.equal(env.MANDU_OPENAI_UPSTREAMS, undefined, "an Ollama route is not an OpenAI-family route");
  assert.deepEqual(ollamaRoutedKeyVars("openclaw", plan.routes), ["OLLAMA_API_KEY"]);
  assert.deepEqual(ollamaRoutedKeyVars("openclaw", [{ id: "openai", api: "openai-responses", upstream: OPENAI_API_BASE }]), []);
  assert.deepEqual(ollamaRoutedKeyVars("opencode", plan.routes), []);
  assert.equal(ollamaUpstreamOf("http://127.0.0.1:11434/V1/"), "http://127.0.0.1:11434");
});

test("openclaw: an azure-openai-responses or openai-chatgpt-responses provider is ROUTED on the Responses wire, to the base OpenClaw itself calls (model-wires.md §9)", () => {
  const doc = { models: { providers: {
    azure: { api: "azure-openai-responses", baseUrl: "https://res.openai.azure.com/openai" },
    foundry: { api: "azure-openai-responses", baseUrl: "https://p.services.ai.azure.com/openai/v1" },
    aznobase: { api: "azure-openai-responses" },
    openai: { api: "openai-chatgpt-responses" },
    cgw: { api: "openai-chatgpt-responses", baseUrl: "https://gw.example/x/codex/responses" },
  } } };
  assert.deepEqual(openclawProviderVerdict("azure", doc), { kind: "route", route: { id: "azure", api: "azure-openai-responses", upstream: "https://res.openai.azure.com/openai/v1" } });
  assert.deepEqual(openclawProviderVerdict("openai", doc), { kind: "route", route: { id: "openai", api: "openai-chatgpt-responses", upstream: CHATGPT_BACKEND_BASE } });
  assert.deepEqual(openclawProviderVerdict("cgw", doc), { kind: "route", route: { id: "cgw", api: "openai-chatgpt-responses", upstream: "https://gw.example/x/codex" } });
  const foundry = openclawProviderVerdict("foundry", doc);
  assert.ok(foundry.kind === "refuse" && /AI Foundry/.test(foundry.why), "an AI Foundry OpenAI-v1 endpoint is not routed");
  assert.equal(openclawProviderVerdict("aznobase", doc).kind, "refuse", "an Azure provider must name its baseUrl");
  // The launch plan: one Azure provider routes.
  const run = (d: Record<string, unknown>, hasZstd = true) => openclawModelPlan(OC, ok({ ...d, agents: { defaults: { model: { primary: "azure/gpt-5-deploy", fallbacks: ["openai/gpt-5.5"] } } } }), { hasZstd });
  const plan = run(doc);
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routes.map((r) => [r.id, r.api]), [["azure", "azure-openai-responses"], ["openai", "openai-chatgpt-responses"]]);
  // The built-in openai on the ChatGPT api sends zstd bodies: on a Node.js
  // without zstd the launch is refused, saying so (model-wires.md §8.3).
  assert.match(run(doc, false).refusal ?? "", /zstd-compresses the requests of its built-in openai provider .* has no zstd/);
  // The config's env block naming Azure's endpoint variables: refused (it would win over the route).
  const envd = run({ ...doc, env: { vars: { AZURE_OPENAI_BASE_URL: "https://other.openai.azure.com/openai/v1" } } });
  assert.match(envd.refusal ?? "", /AZURE_OPENAI_BASE_URL \(env\.vars\.AZURE_OPENAI_BASE_URL in the OpenClaw config\)/);
  // Two Azure providers: refused (one endpoint variable for all of them).
  const two = openclawModelPlan(OC, ok({ models: { providers: { a1: { api: "azure-openai-responses", baseUrl: "https://a.openai.azure.com" }, a2: { api: "azure-openai-responses", baseUrl: "https://b.openai.azure.com" } } }, agents: { defaults: { model: { primary: "a1/m", fallbacks: ["a2/m"] } } } }));
  assert.match(two.refusal ?? "", /more than one Azure OpenAI provider \(a1, a2\)/);
});

test("wireUpstream / azureRouteProblem / openclawConfigAzureEnv / azureRoutedKeyVars: pure helpers of the Azure and ChatGPT routes", () => {
  assert.equal(wireUpstream("azure-openai-responses", "https://r.openai.azure.com"), "https://r.openai.azure.com/openai/v1");
  assert.equal(wireUpstream("azure-openai-responses", "https://r.cognitiveservices.azure.com/openai"), "https://r.cognitiveservices.azure.com/openai/v1");
  assert.equal(wireUpstream("azure-openai-responses", "https://r.openai.azure.com/openai/deployments/d"), "https://r.openai.azure.com/openai/deployments/d");
  assert.equal(wireUpstream("azure-openai-responses", "https://apim.corp.example"), "https://apim.corp.example", "not an Azure host: as is");
  assert.equal(wireUpstream("openai-chatgpt-responses", "https://chatgpt.com/backend-api/codex/v1"), CHATGPT_BACKEND_BASE);
  assert.equal(wireUpstream("openai-chatgpt-responses", "http://127.0.0.1:9/codex"), "http://127.0.0.1:9/codex", "a /codex base as is: the proxy takes both transports' paths below it");
  assert.equal(wireUpstream("openai-chatgpt-responses", "http://127.0.0.1:9/gw"), "http://127.0.0.1:9/gw");
  assert.equal(wireUpstream("openai-responses", "https://x.example/v1"), "https://x.example/v1");
  assert.equal(azureRouteProblem("https://r.openai.azure.com/openai/v1"), null);
  assert.match(azureRouteProblem("https://p.services.ai.azure.com/api/projects/x/openai/v1") ?? "", /AI Foundry/);
  assert.equal(azureRouteProblem("https://p.services.ai.azure.com/models"), null, "only the OpenAI-v1 path switches OpenClaw's client");
  assert.deepEqual(openclawConfigAzureEnv({ env: { azure_openai_resource_name: "r", vars: { AZURE_OPENAI_BASE_URL: "" } } }), ["AZURE_OPENAI_RESOURCE_NAME (env.azure_openai_resource_name in the OpenClaw config)"]);
  assert.deepEqual(openclawConfigAzureEnv({}), []);
  const az = [{ id: "az", api: "azure-openai-responses" as const, upstream: "https://r.openai.azure.com/openai/v1" }];
  assert.deepEqual(azureRoutedKeyVars("openclaw", az), ["AZURE_OPENAI_API_KEY"]);
  assert.deepEqual(azureRoutedKeyVars("opencode", az), []);
  assert.deepEqual(azureRoutedKeyVars("openclaw", [{ id: "openai", api: "openai-responses", upstream: OPENAI_API_BASE }]), []);
  // Both ride the OpenAI table.
  assert.deepEqual(JSON.parse(routeUpstreamsEnv([...az, { id: "openai", api: "openai-chatgpt-responses", upstream: CHATGPT_BACKEND_BASE }]).MANDU_OPENAI_UPSTREAMS!),
    { az: "https://r.openai.azure.com/openai/v1", openai: CHATGPT_BACKEND_BASE });
});
