/**
 * openclaw-providers tests — Route 1 of `mandu openclaw install`
 * (src/openclaw-providers.ts, docs/design/agents/openclaw-plugin.md §8.1):
 * every provider shape of an OpenClaw config classified by wire, its own
 * address recorded as the proxy's upstream (base URLs only, never a
 * credential), what Mandu cannot route reported with why, the one-Messages-
 * address rule, a second install keeping the recorded address, and the
 * restoration record uninstall puts back exactly.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { planProviders, isMandusRoute } from "../../src/openclaw-providers.js";
import { planInstall, planUninstall, type AttachFacts } from "../../src/openclaw-attach.js";
import { parseDeclared, renderDeclared, declareAttachment, type DeclaredProvider } from "../../src/attachment-contract.js";
import { resolveOpenclawIncludes } from "../../src/services/openclaw-include.js";
import { tmpDir } from "../lib/tmp-dir.js";

type Json = Record<string, unknown>;

const FACTS: AttachFacts = {
  pluginDir: "/src/mandu/interceptors/openclaw-inspect-plugin",
  agentId: "main",
  session: "openclaw:main",
  proxyUrl: "http://127.0.0.1:41234",
  arbiterSock: "/run/user/1000/mandu/instances/x/arbiter.sock",
  manduPaths: ["/home/u/.mandu", "/run/user/1000/mandu"],
};

// Node.js with zstd, stated (the CI floor, 22.13, has none; model-wires.md §9.3).
const plan = (doc: Json, prior: DeclaredProvider[] = []) => planProviders(doc, doc, prior, [], { hasZstd: true });
const routes = (doc: Json, prior: DeclaredProvider[] = []) => plan(doc, prior).routed.map((p) => [p.id, p.wire, p.upstream]);

/** The config every shape below is added to (a user's own settings). */
const BASE: Json = { agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } }, channels: { telegram: { botToken: "tg" } } };

test("the built-ins: anthropic and openai are always routed, each to its own built-in address (null upstream)", () => {
  assert.deepEqual(routes(BASE), [["anthropic", "anthropic-messages", null], ["openai", "openai-responses", null]]);
  assert.deepEqual(plan(BASE).cannot, []);
  // Anthropic's own endpoint spelled out is its built-in address too.
  const spelled = { ...BASE, models: { providers: { anthropic: { baseUrl: "https://api.anthropic.com/v1/", models: [] } } } };
  assert.deepEqual(routes(spelled)[0], ["anthropic", "anthropic-messages", null]);
  // The built-in openai with an address of its own (a compatible server).
  const openai = { ...BASE, models: { providers: { openai: { baseUrl: "https://llm.corp.example/v1", models: [] } } } };
  assert.deepEqual(routes(openai)[1], ["openai", "openai-responses", "https://llm.corp.example/v1"]);
});

test("Gemini providers (model-wires.md §5): the built-in google and a google-generative-ai provider are routed to /_mandu/google/<id>; Vertex AI and the Gemini CLI login are not", () => {
  const doc = {
    agents: { defaults: { model: { primary: "google/gemini-2.5-flash", fallbacks: ["corpgem/gemini-2.5-pro"] } } },
    models: { providers: {
      corpgem: { api: "google-generative-ai", baseUrl: "https://gemini.corp.example/v1beta/", models: [] },
      vx: { api: "google-vertex", baseUrl: "https://us-central1-aiplatform.googleapis.com", models: [] },
      cli: { api: "google-gemini-cli", baseUrl: "https://cloudcode-pa.googleapis.com", models: [] },
    } },
  };
  const p = plan(doc);
  const routed = Object.fromEntries(p.routed.map((r) => [r.id, r]));
  assert.equal(routed["google"]!.wire, "google-generative-ai");
  assert.equal(routed["google"]!.upstream, null, "the built-in google: its own address (null)");
  assert.equal(routed["corpgem"]!.wire, "google-generative-ai");
  assert.equal(routed["corpgem"]!.upstream, "https://gemini.corp.example/v1beta");
  assert.deepEqual(p.cannot.map((c) => c.id).sort(), ["cli", "vx"]);
  const { doc: installed } = planInstall(doc, { ...FACTS, providers: p.routed });
  const prov = (installed["models"] as Json)["providers"] as Record<string, Json>;
  assert.equal(prov["google"]!["baseUrl"], "http://127.0.0.1:41234/_mandu/google/google");
  assert.equal(prov["google"]!["api"], "google-generative-ai");
  assert.equal(prov["corpgem"]!["baseUrl"], "http://127.0.0.1:41234/_mandu/google/corpgem");
  assert.equal((prov["corpgem"]!["headers"] as Json)["x-mandu-session-id"] !== undefined, true, "the session header rides along");
});

test("Azure OpenAI and a ChatGPT sign-in (model-wires.md §9): routed on the Responses wire to /_mandu/openai/<id>, each to the base OpenClaw itself would call", () => {
  const doc = {
    agents: { defaults: { model: { primary: "azure/gpt-5-deploy", fallbacks: ["openai/gpt-5.5", "azure2/gpt-5", "cgw/gpt-5.5"] } } },
    models: { providers: {
      // A traditional Azure host with no path: OpenClaw normalizes it to /openai/v1.
      azure: { api: "azure-openai-responses", baseUrl: "https://res-a.openai.azure.com/", apiKey: "k", models: [] },
      azure2: { api: "azure-openai-responses", baseUrl: "https://res-b.cognitiveservices.azure.com/openai/v1", models: [] },
      // The built-in openai on its ChatGPT sign-in, no baseUrl: the backend's own base.
      openai: { api: "openai-chatgpt-responses", models: [] },
      // A ChatGPT-shaped gateway of the user's: its base as is.
      cgw: { api: "openai-chatgpt-responses", baseUrl: "https://gw.corp.example/chatgpt/codex", models: [] },
    } },
  };
  const p = plan(doc);
  assert.deepEqual(p.cannot, []);
  const routed = Object.fromEntries(p.routed.map((r) => [r.id, [r.wire, r.upstream]]));
  assert.deepEqual(routed["azure"], ["azure-openai-responses", "https://res-a.openai.azure.com/openai/v1"]);
  assert.deepEqual(routed["azure2"], ["azure-openai-responses", "https://res-b.cognitiveservices.azure.com/openai/v1"]);
  assert.deepEqual(routed["openai"], ["openai-chatgpt-responses", "https://chatgpt.com/backend-api/codex"]);
  assert.deepEqual(routed["cgw"], ["openai-chatgpt-responses", "https://gw.corp.example/chatgpt/codex"]);
  const { doc: installed } = planInstall(doc, { ...FACTS, providers: p.routed });
  const prov = (installed["models"] as Json)["providers"] as Record<string, Json>;
  assert.equal(prov["azure"]!["baseUrl"], "http://127.0.0.1:41234/_mandu/openai/azure");
  assert.equal(prov["azure"]!["api"], "azure-openai-responses", "the api stays named: the proxy reads exactly that wire");
  assert.equal(prov["azure"]!["apiKey"], "k", "the key is untouched");
  assert.equal(prov["openai"]!["baseUrl"], "http://127.0.0.1:41234/_mandu/openai/openai");
  assert.equal(prov["openai"]!["api"], "openai-chatgpt-responses");
  // The ChatGPT backend's own address, any spelling of it.
  for (const base of ["https://chatgpt.com/backend-api", "https://chatgpt.com/backend-api/codex", "https://chatgpt.com/backend-api/codex/responses/"]) {
    const d = { ...BASE, models: { providers: { openai: { api: "openai-chatgpt-responses", baseUrl: base, models: [] } } } };
    assert.equal(plan(d).routed.find((r) => r.id === "openai")!.upstream, "https://chatgpt.com/backend-api/codex", base);
  }
});

test("Azure OpenAI fail-closed (model-wires.md §9.1): an AI Foundry OpenAI-v1 endpoint, no baseUrl, and the endpoint variables install can see are each refused", () => {
  const azure = (entry: Json, extra: Json = {}): Json => ({ ...BASE, ...extra, models: { providers: { az: { api: "azure-openai-responses", models: [], ...entry } } } });
  const why = (doc: Json, opts = {}): string | undefined => planProviders(doc, doc, [], [], opts).cannot.find((c) => c.id === "az")?.why;
  assert.match(why(azure({ baseUrl: "https://proj.services.ai.azure.com/openai/v1" }))!, /AI Foundry OpenAI-v1 endpoint/);
  assert.match(why(azure({ baseUrl: "https://x.api.cognitive.microsoft.com/openai/v1/" }))!, /AI Foundry/);
  assert.match(why(azure({}))!, /names no baseUrl/);
  // The config's own env block (OpenClaw applies it where the variable is unset).
  assert.match(why(azure({ baseUrl: "https://r.openai.azure.com" }, { env: { vars: { AZURE_OPENAI_BASE_URL: "https://elsewhere.openai.azure.com/openai/v1" } } }))!,
    /AZURE_OPENAI_BASE_URL \(env\.vars\.AZURE_OPENAI_BASE_URL in the OpenClaw config\)/);
  assert.match(why(azure({ baseUrl: "https://r.openai.azure.com" }, { env: { AZURE_OPENAI_RESOURCE_NAME: "other" } }))!, /AZURE_OPENAI_RESOURCE_NAME/);
  // What install saw in its own environment or OpenClaw's dotenv files.
  assert.match(why(azure({ baseUrl: "https://r.openai.azure.com" }), { azureEndpointEnv: ["AZURE_OPENAI_BASE_URL (/home/u/.openclaw/.env)"] })!, /\/home\/u\/\.openclaw\/\.env/);
  // Empty values set nothing; the variables refuse only an Azure provider.
  assert.equal(why(azure({ baseUrl: "https://r.openai.azure.com" }, { env: { vars: { AZURE_OPENAI_BASE_URL: "  " } } })), undefined);
  const other = { ...BASE, env: { vars: { AZURE_OPENAI_BASE_URL: "https://x" } } };
  assert.deepEqual(planProviders(other, other).cannot, []);
});

test("OpenAI-compatible providers (OpenRouter, LiteLLM, vLLM, Ollama) are routed to their own base URL, path kept, trailing slash dropped", () => {
  const doc = {
    ...BASE,
    models: {
      providers: {
        openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1/", apiKey: "sk-or-v1-x", headers: { "HTTP-Referer": "https://me" }, models: [{ id: "x" }] },
        litellm: { api: "openai-responses", baseUrl: "https://litellm.corp.example", models: [] },
        vllm: { api: "openai-completions", baseUrl: "http://127.0.0.1:8000/v1", models: [] },
        ollama: { api: "openai-completions", baseUrl: "http://127.0.0.1:11434/v1", models: [] },
      },
    },
  };
  assert.deepEqual(routes(doc).slice(2), [
    ["openrouter", "openai-completions", "https://openrouter.ai/api/v1"],
    ["litellm", "openai-responses", "https://litellm.corp.example"],
    ["vllm", "openai-completions", "http://127.0.0.1:8000/v1"],
    ["ollama", "openai-completions", "http://127.0.0.1:11434/v1"],
  ]);
  assert.deepEqual(plan(doc).cannot, []);
});

test("OpenClaw's built-in openrouter: every model the config names must be listed (an unlisted one went to openrouter.ai whatever the baseUrl, OpenClaw 2026.3.12)", () => {
  const or = (models: unknown[], primary: string, extra: Json = {}): Json => ({
    agents: { defaults: { model: { primary }, models: extra } },
    models: { providers: { openrouter: { api: "openai-completions", baseUrl: "http://127.0.0.1:4000/api/v1", models } } },
  });
  // Listed under OpenClaw's own id: routed.
  assert.ok(plan(or([{ id: "anthropic/claude-sonnet-4.5" }], "openrouter/anthropic/claude-sonnet-4.5")).routed.some((p) => p.id === "openrouter"));
  assert.ok(plan(or([{ id: "openrouter/auto" }], "openrouter/auto")).routed.some((p) => p.id === "openrouter"), "an id without `/` is OpenClaw's openrouter/<id>");
  // Not listed (or listed under another id): cannot be routed, naming the id to list.
  for (const [models, primary, id] of [
    [[], "openrouter/deepseek/deepseek-chat", "deepseek/deepseek-chat"],
    [[{ id: "auto" }], "openrouter/auto", "openrouter/auto"],
  ] as const) {
    const p = plan(or([...models], primary));
    assert.equal(p.routed.some((r) => r.id === "openrouter"), false);
    const c = p.cannot.find((x) => x.id === "openrouter")!;
    assert.match(c.why, new RegExp(`list "${id.replace(/\//g, "\\/")}" in models\\.providers\\.openrouter\\.models`));
  }
  // Through an alias too.
  const aliased = plan(or([], "fast", { "openrouter/qwen/qwen3": { alias: "fast" } }));
  assert.match(aliased.cannot.find((x) => x.id === "openrouter")!.why, /"qwen\/qwen3"/);
  // Another provider id at OpenRouter's address is a plain OpenAI-compatible provider.
  assert.ok(plan({ models: { providers: { myrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", models: [] } } }, agents: { defaults: { model: { primary: "myrouter/deepseek/x" } } } }).routed.some((p) => p.id === "myrouter"));
});

test("an Anthropic-wire provider at its own address: routed; the anthropic provider's own address included", () => {
  const corp = { ...BASE, models: { providers: { anthropic: { baseUrl: "https://gw.corp.example/anthropic", models: [] } } } };
  assert.deepEqual(routes(corp)[0], ["anthropic", "anthropic-messages", "https://gw.corp.example/anthropic"]);
  // A second Anthropic-wire provider at the same address rides the same route.
  const same = { ...BASE, models: { providers: { anthropic: { baseUrl: "https://gw.corp.example/anthropic" }, team: { api: "anthropic-messages", baseUrl: "https://gw.corp.example/anthropic/" } } } };
  assert.deepEqual(plan(same).routed.map((p) => p.id), ["anthropic", "openai", "team"]);
  // At another address: one Messages endpoint per session, so it cannot be routed (yet).
  const minimax = { ...BASE, models: { providers: { minimax: { api: "anthropic-messages", baseUrl: "https://api.minimax.io/anthropic", models: [] } } } };
  const p = plan(minimax);
  assert.deepEqual(p.routed.map((r) => r.id), ["anthropic", "openai"]);
  assert.equal(p.cannot[0]!.id, "minimax");
  assert.match(p.cannot[0]!.why, /second Anthropic Messages endpoint \(https:\/\/api\.minimax\.io\) beside anthropic's \(Anthropic's\)/);
});

test("what Mandu cannot route is named with why, and where a model names it", () => {
  const doc = {
    agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["xai/grok-4"] } }, list: [{ id: "ops", model: "bedrock/claude" }] },
    plugins: { entries: { "active-memory": { config: { model: "mistral/small" } } } },
    models: {
      providers: {
        vertex: { api: "google-vertex", baseUrl: "https://vertex.example", models: [] },
        bedrock: { api: "bedrock-converse-stream", baseUrl: "https://bedrock.example", models: [] },
        noapi: { baseUrl: "https://x.example/v1", models: [] },
        nobase: { api: "openai-completions", models: [] },
        lan: { api: "openai-completions", baseUrl: "http://192.168.1.5:11434/v1", models: [] },
        named: { api: "openai-completions", baseUrl: "http://localhost:11434/v1", models: [] },
        creds: { api: "openai-completions", baseUrl: "https://u:p@x.example/v1", models: [] },
        keyq: { api: "openai-completions", baseUrl: "https://x.example/v1?key=abc", models: [] },
      },
    },
  };
  const why = Object.fromEntries(plan(doc).cannot.map((c) => [c.id, c]));
  assert.match(why["vertex"]!.why, /OpenClaw 2026\.3\.x \(the Mandu plugin's oldest supported release\) sends Vertex AI calls to Google's own host whatever the provider's baseUrl/);
  assert.match(why["bedrock"]!.why, /api "bedrock-converse-stream"/);
  assert.match(why["noapi"]!.why, /names no api/);
  assert.match(why["nobase"]!.why, /names no baseUrl/);
  assert.match(why["lan"]!.why, /not an address Mandu's proxy sends to \(https, or plain http to a literal loopback/);
  assert.match(why["named"]!.why, /not an address Mandu's proxy sends to/, "`localhost` is a name a hosts file can point anywhere");
  assert.match(why["creds"]!.why, /carries a user or password; Mandu records base URLs only, never a credential/);
  assert.match(why["keyq"]!.why, /carries a query or fragment; Mandu records base URLs only/);
  // A catalog provider only a model names (not in models.providers).
  assert.match(why["xai"]!.why, /not declared in models\.providers/);
  assert.deepEqual(why["xai"]!.refs, ["agents.defaults.model.fallbacks[0]"]);
  assert.deepEqual(why["bedrock"]!.refs, ["agents.list[0].model"], "the declared bedrock provider is the one the model names");
  assert.deepEqual(why["mistral"]!.refs, ["plugins.entries.active-memory.config.model"]);
  assert.equal(Object.values(why).some((c) => c.hard === true), false, "each can be left as it is on purpose");
  // No credential ever reaches a record.
  for (const p of plan(doc).routed) assert.ok(p.upstream === null || !/[@?]/.test(p.upstream));
});

test("GitHub Copilot is never routed (OpenClaw sends its calls to the endpoint its sign-in answers with, whatever the baseUrl); one an earlier install routed cannot be left", () => {
  // Every spelling OpenClaw reads as github-copilot, on any wire Mandu reads.
  for (const id of ["github-copilot", "GitHub-Copilot"]) {
    const doc = {
      agents: { defaults: { model: { primary: `${id}/gpt-5.4-mini` } } },
      models: { providers: { [id]: { api: "openai-completions", baseUrl: "https://api.individual.githubcopilot.com", models: [] } } },
    };
    const p = plan(doc);
    assert.equal(p.routed.some((r) => r.id === id), false, `${id} is not routed`);
    const c = p.cannot.find((x) => x.id === id)!;
    assert.match(c.why, /OpenClaw sends GitHub Copilot's model calls to the endpoint its Copilot sign-in answers with \(a \*\.githubcopilot\.com host\), whatever the provider's baseUrl \(every release since 2026\.3\.22\)/);
    assert.deepEqual(c.refs, ["agents.defaults.model.primary"]);
    assert.equal(c.hard, undefined, "it can be left as it is on purpose");
  }
  // A catalog-only Copilot (a model names it, no models.providers entry) says the same.
  assert.match(plan({ agents: { defaults: { model: { primary: "github-copilot/claude-sonnet-4.6" } } } }).cannot[0]!.why, /endpoint its Copilot sign-in answers with/);
  // An install before this rule routed one: its baseUrl is Mandu's route.
  const routed = {
    models: { providers: { "github-copilot": { api: "openai-completions", baseUrl: "http://127.0.0.1:41234/_mandu/openai/github-copilot", headers: { "x-mandu-session-id": "openclaw:main" }, models: [] } } },
  };
  const prior: DeclaredProvider = { id: "github-copilot", wire: "openai-completions", upstream: "https://api.individual.githubcopilot.com", original: { existed: true, baseUrl: "https://api.individual.githubcopilot.com", api: "openai-completions", headers: false, models: true } };
  const c = plan(routed, [prior]).cannot.find((x) => x.id === "github-copilot")!;
  assert.equal(c.hard, true, "left, its baseUrl would keep Mandu's address with no record to put the user's back");
  assert.match(c.why, /an earlier install routed it: run mandu openclaw uninstall/);
  assert.equal(plan(routed, [prior]).routed.some((r) => r.id === "github-copilot"), false);
});

test("providers from $include files are classified like the main file's, with the main file's entry recorded as the original", () => {
  const dir = tmpDir("mdu-r1-inc-");
  mkdirSync(join(dir, "oc"));
  writeFileSync(join(dir, "oc", "providers.json5"), `{ openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", models: [] } }`);
  const raw = { ...BASE, models: { providers: { $include: "./providers.json5" } } };
  const effective = resolveOpenclawIncludes(raw, join(dir, "oc", "openclaw.json"), { env: {} }) as Json;
  const p = planProviders(effective, raw);
  const or = p.routed.find((r) => r.id === "openrouter")!;
  assert.equal(or.upstream, "https://openrouter.ai/api/v1");
  assert.deepEqual(or.original, { existed: false, headers: false }, "the main file had no entry of its own: uninstall removes the one install adds");
  // Install's main-file keys merge over the included ones, and the result routes.
  const { doc } = planInstall(raw, { ...FACTS, providers: p.routed });
  const after = resolveOpenclawIncludes(doc, join(dir, "oc", "openclaw.json"), { env: {} }) as Json;
  const entry = ((after["models"] as Json)["providers"] as Json)["openrouter"] as Json;
  assert.equal(entry["baseUrl"], "http://127.0.0.1:41234/_mandu/openai/openrouter");
  assert.equal(entry["api"], "openai-completions");
});

test("a provider already routed: the record from the earlier install keeps its address and original; a route lost since is taken back to the recorded address", () => {
  const user = { ...BASE, models: { providers: { openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", apiKey: "k", models: [] } } } };
  const first = plan(user);
  const installed = planInstall(user, { ...FACTS, providers: first.routed }).doc;
  assert.ok(isMandusRoute(((installed["models"] as Json)["providers"] as Json)["openrouter"] as Json));
  const second = planProviders(installed, installed, first.routed);
  assert.deepEqual(second.routed, first.routed, "a second install changes nothing");
  assert.deepEqual(second.kept, []);
  // The agent's programs re-point it after the install: the recorded address wins.
  const tampered = JSON.parse(JSON.stringify(installed)) as Json;
  (((tampered["models"] as Json)["providers"] as Json)["openrouter"] as Json)["baseUrl"] = "https://evil.example/v1";
  delete ((((tampered["models"] as Json)["providers"] as Json)["openrouter"] as Json)["headers"] as Json)["x-mandu-session-id"];
  const back = planProviders(tampered, tampered, first.routed);
  assert.equal(back.routed.find((r) => r.id === "openrouter")!.upstream, "https://openrouter.ai/api/v1");
  assert.deepEqual(back.kept, [{ id: "openrouter", now: "https://evil.example/v1", recorded: "https://openrouter.ai/api/v1" }]);
  // Routed with no record (the declaration lost): no flag can leave it.
  const orphan = planProviders(installed, installed, []).cannot.find((c) => c.id === "openrouter");
  assert.equal(orphan?.hard, true);
  // An Anthropic route from before Route 1 (no record): Anthropic's own address.
  const legacy = { models: { providers: { anthropic: { baseUrl: "http://127.0.0.1:9", api: "anthropic-messages", headers: { "x-mandu-session-id": "openclaw:main", "x-mandu-tenant": "live" }, models: [] } } } };
  const l = planProviders(legacy, legacy, []);
  assert.deepEqual(l.routed[0], { id: "anthropic", wire: "anthropic-messages", upstream: null, original: { existed: false, headers: false } });
});

test("install then uninstall gives every shape back exactly (Route 1's records), and the record survives the declared file", () => {
  const shapes: Json[] = [
    {},
    BASE,
    { ...BASE, models: { providers: { anthropic: { models: [] } } } },
    { ...BASE, models: { mode: "merge", providers: { anthropic: { baseUrl: "https://gw.corp.example/anthropic", headers: { "x-team": "a" }, models: [{ id: "c", maxTokens: 8000 }] } } } },
    { ...BASE, models: { providers: { openai: { apiKey: "sk-x" } } } },
    { ...BASE, models: { providers: { openrouter: { baseUrl: "https://openrouter.ai/api/v1/", api: "openai-completions", apiKey: "sk-or", headers: { "HTTP-Referer": "https://me", "X-Title": "gw" }, models: [{ id: "deepseek/x", contextWindow: 64000 }] } } } },
    { ...BASE, models: { providers: { ollama: { api: "openai-completions", baseUrl: "http://127.0.0.1:11434/v1", headers: {}, models: [] }, vertex: { api: "google-generative-ai", baseUrl: "https://v.example", models: [] } } } },
    // Gemini (model-wires.md §5): the built-in google with its key only, and a declared one
    { ...BASE, models: { providers: { google: { apiKey: "AIza-x" } } } },
    { ...BASE, models: { providers: { corpgem: { api: "google-generative-ai", baseUrl: "https://gemini.corp.example/v1beta", headers: { "x-team": "g" }, models: [{ id: "gemini-2.5-pro" }] } } } },
    // Ollama's native chat API (model-wires.md, "The Ollama wire"): the built-in with its marker key only, a declared one with /v1
    { ...BASE, models: { providers: { ollama: { apiKey: "ollama-local" } } } },
    { ...BASE, models: { providers: { box: { api: "ollama", baseUrl: "http://127.0.0.1:21434/v1", models: [{ id: "qwen3:8b", contextWindow: 32768 }] } } } },
    // Azure OpenAI and a ChatGPT sign-in (model-wires.md §9): the recorded upstream is normalized, the entry is not
    { ...BASE, models: { providers: { azure: { api: "azure-openai-responses", baseUrl: "https://res.openai.azure.com", apiKey: "k", models: [{ id: "gpt-5-deploy" }] } } } },
    { ...BASE, models: { providers: { openai: { api: "openai-chatgpt-responses" } } } },
    { ...BASE, models: { providers: { openai: { api: "openai-chatgpt-responses", baseUrl: "https://chatgpt.com/backend-api/codex", models: [] } } } },
  ];
  for (const user of shapes) {
    const p = planProviders(user, user, [], [], { hasZstd: true });
    // Through the declared file and back, as uninstall reads it.
    const text = renderDeclared(declareAttachment([], "main", 41234, undefined, { providers: p.routed, unprotected: p.cannot.map((c) => c.id) }).list);
    const recorded = parseDeclared(text).attachments[0]!.providers!;
    assert.deepEqual(recorded, p.routed);
    const installed = planInstall(user, { ...FACTS, providers: p.routed }).doc;
    const { doc, unrestored } = planUninstall(installed, FACTS.pluginDir, recorded);
    assert.equal(JSON.stringify(doc), JSON.stringify(user), `byte for byte: ${JSON.stringify(user)}`);
    assert.deepEqual(unrestored, []);
  }
});

test("uninstall without a record: the Anthropic route by the old rule; another provider keeps the Mandu address and is named", () => {
  const user = { ...BASE, models: { providers: { openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", models: [] } } } };
  const p = planProviders(user, user);
  const installed = planInstall(user, { ...FACTS, providers: p.routed }).doc;
  const { doc, unrestored } = planUninstall(installed, FACTS.pluginDir);
  assert.deepEqual(unrestored.sort(), ["openai", "openrouter"]);
  const or = ((doc["models"] as Json)["providers"] as Json)["openrouter"] as Json;
  assert.equal(or["headers"], undefined, "Mandu's headers go");
  assert.equal(((doc["models"] as Json)["providers"] as Json)["anthropic"], undefined, "the old rule undoes the Anthropic route");
});

test("a provider re-pointed by the user after the install keeps their address at uninstall; Mandu's headers go", () => {
  const user = { ...BASE, models: { providers: { openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", models: [] } } } };
  const p = planProviders(user, user);
  const installed = planInstall(user, { ...FACTS, providers: p.routed }).doc as any;
  installed.models.providers.openrouter.baseUrl = "https://new.example/v1";
  const { doc } = planUninstall(installed, FACTS.pluginDir, p.routed) as { doc: any };
  assert.equal(doc.models.providers.openrouter.baseUrl, "https://new.example/v1");
  assert.equal(doc.models.providers.openrouter.headers, undefined);
});

test("Ollama providers (model-wires.md, \"The Ollama wire\"): the built-in ollama and ollama-cloud and an `api: \"ollama\"` provider are routed to /_mandu/ollama/<id>, each to its own address", () => {
  const doc = {
    agents: { defaults: { model: { primary: "ollama/qwen3:8b", fallbacks: ["ollama-cloud/glm-5.2", "box/llama3.1"] } } },
    models: { providers: {
      box: { api: "ollama", baseUrl: "http://127.0.0.1:21434/v1/", models: [] },
      lan: { api: "ollama", baseUrl: "http://192.168.1.20:11434", models: [] },
    } },
  };
  const p = plan(doc);
  const routed = Object.fromEntries(p.routed.map((r) => [r.id, r]));
  assert.equal(routed["ollama"]!.wire, "ollama");
  assert.equal(routed["ollama"]!.upstream, null, "the built-in: its own address (null)");
  assert.equal(routed["ollama-cloud"]!.wire, "ollama");
  assert.equal(routed["box"]!.upstream, "http://127.0.0.1:21434", "the /v1 OpenClaw strips is dropped");
  assert.deepEqual(p.cannot.map((c) => c.id), ["lan"], "plain http off this machine is not an address the proxy sends to");
  const { doc: installed } = planInstall(doc, { ...FACTS, providers: p.routed });
  const prov = (installed["models"] as Json)["providers"] as Record<string, Json>;
  assert.equal(prov["ollama"]!["baseUrl"], "http://127.0.0.1:41234/_mandu/ollama/ollama");
  assert.equal(prov["ollama"]!["api"], "ollama");
  assert.equal(prov["box"]!["baseUrl"], "http://127.0.0.1:41234/_mandu/ollama/box");
  assert.equal((prov["box"]!["headers"] as Json)["x-mandu-session-id"] !== undefined, true, "the session header rides along");
  // A config that names no Ollama model routes no Ollama provider.
  assert.ok(!plan(BASE).routed.some((r) => r.wire === "ollama"));
});

test("the built-in openai on a ChatGPT sign-in, on a Node.js without zstd (model-wires.md §9.3): not routed, said why; another id on the ChatGPT api, or zstd present, routes", () => {
  const doc = { ...BASE, models: { providers: { openai: { api: "openai-chatgpt-responses" }, cgw: { api: "openai-chatgpt-responses", baseUrl: "https://gw.example/x", models: [] } } } };
  const without = planProviders(doc, doc, [], [], { hasZstd: false });
  assert.deepEqual(without.routed.map((p) => p.id).sort(), ["anthropic", "cgw"]);
  assert.match(without.cannot.find((c) => c.id === "openai")!.why, /zstd-compresses .* has no zstd.*Node\.js 22\.15 or later/);
  assert.deepEqual(planProviders(doc, doc, [], [], { hasZstd: true }).cannot, []);
});
