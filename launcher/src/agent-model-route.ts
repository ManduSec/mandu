/**
 * agent-model-route — the launch refuses a config-routed agent (openclaw /
 * opencode) whose model would not go through Mandu's model proxy
 * (docs/design/testing/agent-e2e-harness.md §9, "Only Anthropic models are routed" and
 * "Other providers through the model proxy").
 *
 * WHY (probe-verified 2026-09-27, OpenClaw 2026.7.1 and OpenCode 1.18.13 /
 * 1.18.32, a URL-logging stand-in model): the routing override
 * (services/agent-config.ts) points only the agent's ANTHROPIC provider at the
 * anthropic-proxy. A model from any other provider went straight to that
 * provider:
 *   - OpenClaw's built-in default is `openai/gpt-5.5` on 2026.6 and later
 *     (`anthropic/claude-opus-4-6` on 2026.3.12). `mandu openclaw agent
 *     --local` with no model configured sent its turn to
 *     https://api.openai.com/v1/responses under the default posture: the
 *     whole-agent connect guard admits any :443 host, and NO_PROXY lists
 *     api.openai.com.
 *   - `mandu --mode full openclaw …` with `openai/gpt-5.5` and `mandu --mode
 *     full opencode run -m openai/gpt-5 …` sent a file's untrusted text to the
 *     model RAW (`function_call_output: "# notes\nIPIMARKER…"`), while the
 *     banner said "untrusted text masked". In `secrets` mode a registered
 *     credential file still reached the model as its twin (the file layer
 *     does not depend on the route).
 * The same class as the Codex `exec -c` bypass (codex-argv.ts).
 *
 * The rule, pure and unit-tested (test/unit/agent-model-route.test.ts):
 *   - every model reference the agent can run from its own config (primary,
 *     fallbacks, per-agent and sub-agent models) and from argv (`--model`)
 *     must name a provider Mandu routes; any other provider is refused
 *     before anything launches, naming where the reference came from and
 *     why its provider is not routed. Routed providers (2026-09-28,
 *     agent-e2e-harness.md §9 "Other providers through the model proxy"):
 *       * `anthropic`, as before;
 *       * an OpenAI-family provider (`openaiRouteFor*` below): OpenClaw's
 *         built-in `openai` (the Responses API at api.openai.com) and any
 *         `models.providers.<id>` that names its `baseUrl` and an `api` of
 *         `openai-completions` or `openai-responses`; OpenCode's built-in
 *         `openai` and any `provider.<id>` with the `@ai-sdk/openai` or
 *         `@ai-sdk/openai-compatible` package and a base URL. The launcher
 *         points each at the session's model proxy (agent-config.ts), which
 *         reads that wire with the SAME gates (anthropic-proxy
 *         openai-wire.ts) and forwards to the provider's own URL. OpenCode
 *         signed in to OpenAI with a ChatGPT account is refused: that login
 *         rewrites Chat Completions requests to chatgpt.com whatever the
 *         base URL (read from OpenCode 1.18.32);
 *   - OpenClaw with NO model configured is refused: its built-in default
 *     depends on the release (openai on 2026.6+), so the launcher cannot
 *     vouch for it;
 *   - an OpenClaw config the launcher cannot read is refused: the launch
 *     would drop it, and OpenClaw would fall back to that built-in default.
 *     It is read as JSON5 (services/json5.ts), as OpenClaw reads it, with
 *     its `$include` files resolved the way OpenClaw resolves them
 *     (services/openclaw-include.ts), so the models in included files are
 *     checked like the rest; an include OpenClaw would refuse (outside the
 *     config directory, a cycle, a missing file) makes the config
 *     unreadable, and a `$include` still present in the doc handed here (a
 *     reader that skipped the resolver) is refused;
 *   - OpenClaw's Active Memory plugin runs its own recall model over the
 *     conversation (`plugins.entries.active-memory.config.model` and
 *     `.modelFallback`): those references must name the anthropic provider
 *     as well;
 *   - OpenCode with no model configured is NOT refused: the routing override
 *     also fences OpenCode to the anthropic provider (`enabled_providers`,
 *     delivered in OPENCODE_CONFIG_CONTENT, which outranks a project config),
 *     so its own default is provably routed.
 * These are the clear-message layer; the runtime fences in agent-config.ts
 * (OpenCode `enabled_providers`, OpenClaw's `agents.defaults.models`
 * allowlist) hold the line for a mid-session `/model` switch.
 *
 * OpenCode 2 (opencodeV2ModelPlan below; supported-agents.md §2.3 part 4)
 * reads its own spelling (`providers` with `package` and `settings.baseURL`,
 * `agents.<n>.model` with a `#variant`, `experimental.policies`; V1 keys
 * normalized, opencode-config.ts) from EVERY config layer, and two of its
 * rules are not fenced by the routing Mandu writes: the provider rule of the
 * LOWEST layer wins (so the global config can re-admit a provider), and a
 * model's own endpoint beats its provider's base URL (from any layer). The
 * 2.x check reads every layer and refuses both, besides the unrouted models.
 *
 * An argv the launcher cannot read as the agent (a wrapper script under
 * `--target`) is not checked: `--target` is the user vouching for the
 * wrapper, the contract parse.ts applies to every wrapper target.
 */
import { basename } from "node:path";
import * as zlib from "node:zlib";
import { compareAgentVersions, parseAgentVersion } from "./agent-versions.js";
import { readOpenclawArgv } from "./openclaw-argv.js";
import { configAzureEndpointEnv } from "./attachment-contract.js";
import {
  normalizeOpencodeDoc, opencodePackageName,
  type OcNormalized, type OcProvider, type OpencodeLayer,
} from "./opencode-config.js";
import {
  activeMemoryRefs, collectModelKeys, openclawRouteIgnoredWhy, providerOf, type ModelRef,
} from "./openclaw-model-refs.js";
// The models an OpenClaw config names and its openrouter bypass live in
// openclaw-model-refs.ts (shared with the dashboard's route check).
export {
  OPENCLAW_OPENROUTER_BASEURL_SINCE, isOpenrouterId, openclawModelRefs, openclawOpenrouterId, openclawOpenrouterKey,
  openclawOpenrouterReach, openclawOpenrouterUnlisted, type ModelRef, type OpenrouterReach,
} from "./openclaw-model-refs.js";

type Json = Record<string, unknown>;

/** The OpenAI wires the model proxy reads (anthropic-proxy openai-wire.ts).
 *  OpenClaw's `azure-openai-responses` and `openai-chatgpt-responses` apis
 *  are the Responses wire at Azure OpenAI and at the ChatGPT backend
 *  (model-wires.md §9): the same adapter, each with its own path, query and
 *  key header. */
export type OpenAiApi = "openai-responses" | "openai-completions" | AzureApi | ChatgptApi;

/** OpenClaw's Azure OpenAI api (the Responses wire; key in `api-key`). */
export type AzureApi = "azure-openai-responses";
/** OpenClaw's ChatGPT sign-in api (the Responses wire at `…/codex/responses`). */
export type ChatgptApi = "openai-chatgpt-responses";

/** The ChatGPT backend's Responses base: OpenClaw's
 *  `openai-chatgpt-responses` canonicalizes every chatgpt.com address to it
 *  and POSTs `<base>/responses` (its OpenAI-SDK transport), or
 *  `<base minus /codex>/codex/responses` (@openclaw/ai's own transport); the
 *  proxy takes either below it (route.ts upstreamRest). */
export const CHATGPT_BACKEND_BASE = "https://chatgpt.com/backend-api/codex";

/** The variables OpenClaw's Azure client reads its endpoint from BEFORE the
 *  provider's baseUrl (@openclaw/ai `resolveAzureConfig`, 2026.7.1-2 to
 *  2026.10.7; pi-ai 0.57.1 the same): set, every Azure call goes there,
 *  around the route (model-wires.md §9.1). */
export const AZURE_ENDPOINT_ENV = ["AZURE_OPENAI_BASE_URL", "AZURE_OPENAI_RESOURCE_NAME"] as const;

/** The Gemini wire the model proxy reads (anthropic-proxy gemini-wire.ts,
 *  model-wires.md §4); OpenClaw's name for it. */
export type GoogleApi = "google-generative-ai";

/** Vertex AI's Gemini models, OpenClaw's name for it (model-wires.md §4.1,
 *  "Vertex AI at the root"): the Gemini wire on Vertex resource paths, which
 *  OpenClaw sends to the ORIGIN of the provider's baseUrl. */
export type VertexApi = "google-vertex";

/** Ollama's native chat API (anthropic-proxy ollama-wire.ts, model-wires.md
 *  "The Ollama wire"); OpenClaw's name for it. */
export type OllamaApi = "ollama";

/** Every non-Anthropic wire a route may name. */
export type RouteApi = OpenAiApi | GoogleApi | VertexApi | OllamaApi;

/** A traditional Azure OpenAI host (OpenClaw's `isTraditionalAzureOpenAIHost`). */
function traditionalAzureHost(host: string): boolean {
  const h = host.toLowerCase();
  return h.endsWith(".openai.azure.com") || h.endsWith(".cognitiveservices.azure.com");
}

/**
 * Where the proxy sends a route of `api` whose base URL (routableUpstream's
 * form, no trailing slash) is `base`, so that `<upstream><the path OpenClaw
 * sends below the route>` is the URL OpenClaw would have called itself
 * (model-wires.md §9). Azure: OpenClaw's own normalization (a traditional
 * Azure host with no path, or `/openai`, means `/openai/v1`); the proxy is
 * sent `/responses?api-version=…`. ChatGPT: the backend's `/codex` base for
 * any chatgpt.com address (OpenClaw canonicalizes those), a base ending in
 * `/codex/responses` cut to its `/codex`, any other as is (OpenClaw's two
 * transports join `/responses` or `/codex/responses` to it; the proxy's
 * upstreamRest takes either). Every other wire: as is. Pure.
 */
export function wireUpstream(api: RouteApi, base: string): string {
  let u: URL;
  try { u = new URL(base); } catch { return base; }
  if (api === "azure-openai-responses") {
    const path = u.pathname.replace(/\/+$/, "");
    if (traditionalAzureHost(u.hostname) && (path === "" || path === "/openai")) return `${u.origin}/openai/v1`;
    return base;
  }
  if (api === "openai-chatgpt-responses") {
    if (u.hostname.toLowerCase() === "chatgpt.com") return CHATGPT_BACKEND_BASE;
    return base.replace(/\/codex\/responses$/, "/codex");
  }
  return base;
}

/**
 * Why an Azure base URL cannot be routed, or null: an Azure AI Foundry
 * OpenAI-v1 endpoint (`*.services.ai.azure.com` or
 * `*.api.cognitive.microsoft.com` ending in `/openai/v1`), which OpenClaw
 * calls with the plain OpenAI client (a bearer, no `api-version`); behind the
 * route, whose address is not that host, OpenClaw would call it with the
 * Azure client instead (an `api-key` header, `?api-version=v1`): not the
 * request the user's endpoint was set up for (model-wires.md §9.1). Pure.
 */
export function azureRouteProblem(base: string): string | null {
  let u: URL;
  try { u = new URL(base); } catch { return null; }
  const h = u.hostname.toLowerCase();
  if (!(h.endsWith(".services.ai.azure.com") || h.endsWith(".api.cognitive.microsoft.com"))) return null;
  const path = u.pathname.replace(/\/+$/, "");
  if (!(path === "/openai/v1" || path.endsWith("/openai/v1"))) return null;
  return "its baseUrl is an Azure AI Foundry OpenAI-v1 endpoint, which OpenClaw calls with the plain OpenAI client; behind Mandu's route " +
    "OpenClaw would call it with the Azure OpenAI client instead (an api-key header and an api-version query), so Mandu does not route it " +
    "(use the resource's https://<name>.openai.azure.com address)";
}

/** Where an OpenClaw config's own `env` block sets one of
 *  AZURE_ENDPOINT_ENV (attachment-contract.ts configAzureEndpointEnv, which
 *  the route check reads too). Pure. */
export const openclawConfigAzureEnv = configAzureEndpointEnv;

/** Whether a route speaks the Gemini wire (the proxy serves it under
 *  `/_mandu/google/<id>`, its upstream goes in MANDU_GOOGLE_UPSTREAMS). */
export function isGoogleApi(api: RouteApi): api is GoogleApi {
  return api === "google-generative-ai";
}

/** Whether a route is the session's Vertex AI provider (the proxy serves it
 *  at its root, its upstream goes in MANDU_VERTEX_UPSTREAMS). */
export function isVertexApi(api: RouteApi): api is VertexApi {
  return api === "google-vertex";
}

/** A Vertex route's upstream when the user names no address of their own:
 *  Google's own Vertex host for each request's location, spelled as
 *  OpenClaw's built-in google-vertex provider spells it. Not a URL: it goes
 *  to the proxy as null (MANDU_VERTEX_UPSTREAMS). */
export const VERTEX_GOOGLE_HOSTS = "https://{location}-aiplatform.googleapis.com";

/** The first OpenClaw release whose google-vertex model calls go to the
 *  origin of the provider's baseUrl, measured on the real binary: OpenClaw
 *  2026.3.x sends them through `@google/genai` with no base URL (pi-ai's
 *  google-vertex provider), to Google's Vertex host whatever the baseUrl;
 *  OpenClaw's own Vertex transport, which takes the configured origin,
 *  arrived in 2026.4.29 (read from the dists) and is measured from 2026.7.1-2
 *  (model-wires.md §4.1; a numeric suffix is a respin of the release, not a
 *  prerelease: agent-versions.ts). A release before it, or one the launch
 *  could not read, is refused. */
export const OPENCLAW_VERTEX_BASEURL_SINCE = "2026.7.1";

/** Whether a route speaks Ollama's native chat API (the proxy serves it
 *  under `/_mandu/ollama/<id>`, its upstream goes in MANDU_OLLAMA_UPSTREAMS). */
export function isOllamaApi(api: RouteApi): api is OllamaApi {
  return api === "ollama";
}

/** One non-Anthropic provider (an OpenAI-family one, or a Gemini one since
 *  2026-10-25) routed through the session's model proxy. */
export interface OpenAiRoute {
  /** The agent's provider id (also the proxy path segment). */
  id: string;
  api: RouteApi;
  /** The provider's own base URL, where the proxy sends the gated request. */
  upstream: string;
  /** The agent runs a tool call the model WRITES in its text on this route
   *  (Goose's ollama provider, `<function=name>…`): the proxy ends a
   *  response whose text carries that markup (MANDU_OPENAI_TEXT_CALLS,
   *  anthropic-proxy openai-sse.ts). */
  textCalls?: boolean;
}

/**
 * The model proxy's route tables for a launch (anthropic-proxy server-main):
 * MANDU_OPENAI_UPSTREAMS for the OpenAI-family routes, MANDU_GOOGLE_UPSTREAMS
 * for the Gemini ones, each a JSON object of provider id → base URL, or
 * explicitly undefined (UNSET) when the launch routes none, so an ambient
 * value cannot add a route. Pure.
 */
export function routeUpstreamsEnv(routes: readonly OpenAiRoute[]): {
  MANDU_OPENAI_UPSTREAMS: string | undefined; MANDU_GOOGLE_UPSTREAMS: string | undefined; MANDU_VERTEX_UPSTREAMS: string | undefined;
  MANDU_OLLAMA_UPSTREAMS: string | undefined;
} {
  const table = (rs: readonly OpenAiRoute[]): string | undefined =>
    rs.length > 0 ? JSON.stringify(Object.fromEntries(rs.map((r) => [r.id, r.upstream === VERTEX_GOOGLE_HOSTS ? null : r.upstream]))) : undefined;
  return {
    MANDU_OPENAI_UPSTREAMS: table(routes.filter((r) => !isGoogleApi(r.api) && !isVertexApi(r.api) && !isOllamaApi(r.api))),
    MANDU_GOOGLE_UPSTREAMS: table(routes.filter((r) => isGoogleApi(r.api))),
    // The session's one Vertex provider (the proxy serves it at its root):
    // null for Google's own host per location.
    MANDU_VERTEX_UPSTREAMS: table(routes.filter((r) => isVertexApi(r.api)).slice(0, 1)),
    MANDU_OLLAMA_UPSTREAMS: table(routes.filter((r) => isOllamaApi(r.api))),
  };
}

/**
 * The key variables an OpenClaw or OpenCode launch that routes a Gemini
 * provider leaves unmasked in the agent's environment, as the arbiter leaves
 * ANTHROPIC_API_KEY and OPENAI_API_KEY and the launch leaves a routed Goose
 * provider's (goose-route.ts gooseRoutedKeyVars): the agent's own model
 * credential, which its Google client sends to the model proxy, which
 * relays it to the provider. Masked, the agent would send the placeholder
 * and every turn would fail authentication (found by the real OpenCode
 * 1.18.13 against a scripted Gemini upstream, 2026-10-25). Read from the
 * clients: OpenCode's `@ai-sdk/google` reads GOOGLE_GENERATIVE_AI_API_KEY
 * (its catalog also names GEMINI_API_KEY), OpenClaw's google provider
 * GEMINI_API_KEY. None when the launch routes no Gemini provider. Pure.
 */
export function googleRoutedKeyVars(target: string, routes: readonly OpenAiRoute[] | undefined): string[] {
  const out: string[] = [];
  if ((routes ?? []).some((r) => isGoogleApi(r.api))) {
    if (target === "opencode") out.push("GOOGLE_GENERATIVE_AI_API_KEY", "GEMINI_API_KEY");
    if (target === "openclaw") out.push("GEMINI_API_KEY");
  }
  // OpenClaw's google-vertex provider in Vertex AI express mode reads its key
  // from GOOGLE_CLOUD_API_KEY (its provider manifest); with ADC it sends an
  // OAuth bearer it mints itself, which no variable carries.
  if (target === "openclaw" && (routes ?? []).some((r) => isVertexApi(r.api))) out.push("GOOGLE_CLOUD_API_KEY");
  return out;
}

/**
 * The key variable an OpenClaw launch that routes an Ollama provider leaves
 * unmasked (OpenClaw's ollama and ollama-cloud providers read
 * OLLAMA_API_KEY), as googleRoutedKeyVars does for Gemini: the agent sends it
 * to the model proxy, which relays it to the provider. None when the launch
 * routes no Ollama provider. Pure.
 */
export function ollamaRoutedKeyVars(target: string, routes: readonly OpenAiRoute[] | undefined): string[] {
  if (!(routes ?? []).some((r) => isOllamaApi(r.api))) return [];
  return target === "openclaw" ? ["OLLAMA_API_KEY"] : [];
}

/**
 * The key variable an OpenClaw launch that routes an Azure OpenAI provider
 * leaves unmasked (as googleRoutedKeyVars does for Gemini): OpenClaw's Azure
 * client reads AZURE_OPENAI_API_KEY when the provider names no apiKey, sends
 * it to the model proxy in `api-key`, and the proxy relays it to the
 * provider. Masked, every turn would fail authentication. Pure.
 */
export function azureRoutedKeyVars(target: string, routes: readonly OpenAiRoute[] | undefined): string[] {
  return target === "openclaw" && (routes ?? []).some((r) => r.api === "azure-openai-responses") ? ["AZURE_OPENAI_API_KEY"] : [];
}

/** Whether this Node.js has zstd (22.15 and later, which is Mandu's floor
 *  since 2026-10-26; a launch below the floor is refused before this runs,
 *  so the probe is the backstop of a from-source run). Mandu's model proxy
 *  decodes a zstd request body only where it has (anthropic-proxy
 *  request-encoding.ts). */
export const NODE_HAS_ZSTD = typeof (zlib as unknown as Record<string, unknown>)["zstdDecompressSync"] === "function";

/**
 * Why the built-in `openai` provider on OpenClaw's ChatGPT sign-in cannot be
 * routed on a Node.js without zstd, or null (model-wires.md §9.3):
 * OpenClaw's ChatGPT transport zstd-compresses that provider's request
 * body, and a proxy that cannot decode it refuses every turn (415, nothing
 * sent). Said before anything starts instead of as a wall of refused turns.
 * Pure.
 */
export function chatgptZstdProblem(routes: ReadonlyArray<{ id: string; api: string }>, hasZstd: boolean): string | null {
  if (hasZstd || !routes.some((r) => r.id === "openai" && r.api === "openai-chatgpt-responses")) return null;
  return `OpenClaw zstd-compresses the requests of its built-in openai provider on a ChatGPT sign-in, and the Node.js running Mandu ` +
    `(${process.version}) has no zstd, so Mandu's model proxy could not read them and would refuse every turn; run Mandu on Node.js 22.15 or later`;
}

/** OpenAI's API base, the built-in `openai` provider's in both agents. */
export const OPENAI_API_BASE = "https://api.openai.com/v1";

/** The Gemini API base, the built-in `google` provider's in OpenClaw and
 *  OpenCode (both join `/models/{model}:…` to it). */
export const GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta";

/** OpenClaw's built-in Ollama providers and their own addresses: a local
 *  Ollama (`ollama`) and Ollama Cloud (`ollama-cloud`), both on its native
 *  chat API (`api: "ollama"`). */
export const OLLAMA_BUILTIN_BASES: Readonly<Record<string, string>> = {
  ollama: "http://127.0.0.1:11434",
  "ollama-cloud": "https://ollama.com",
};

/** The address an Ollama provider's chat requests go to, as OpenClaw joins
 *  `/api/chat` to its base URL: with a trailing `/v1` dropped (OpenClaw
 *  strips it, the OpenAI-compatible path users often configure). Pure. */
export function ollamaUpstreamOf(base: string): string {
  return base.replace(/\/+$/, "").replace(/\/v1$/i, "");
}

const ROUTED_APIS: ReadonlySet<string> = new Set<RouteApi>(["openai-responses", "openai-completions", "google-generative-ai", "ollama", "azure-openai-responses", "openai-chatgpt-responses"]);

/** A provider id the proxy path and MANDU_OPENAI_UPSTREAMS accept. */
const ROUTABLE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** How one provider's models are reached under Mandu. */
export type ProviderVerdict =
  | { kind: "anthropic" }
  | { kind: "route"; route: OpenAiRoute }
  | { kind: "refuse"; why: string };

/**
 * A base URL the proxy may send to: https anywhere, plain http only to a
 * literal loopback address (the proxy's fetcher enforces the same rule per
 * request; refusing here gives the reason before anything starts). No query,
 * fragment or credentials. Returns the URL without a trailing slash, or null.
 */
export function routableUpstream(url: unknown): string | null {
  if (typeof url !== "string" || url.trim() === "") return null;
  let u: URL;
  try { u = new URL(url.trim()); } catch { return null; }
  if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") return null;
  if (u.protocol === "http:") {
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (host !== "::1" && !/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return null;
  } else if (u.protocol !== "https:") {
    return null;
  }
  return url.trim().replace(/\/+$/, "");
}

/** OpenClaw: how provider `p` is reached (its `models.providers` entry, else built-in). */
export function openclawProviderVerdict(p: string, doc: Json): ProviderVerdict {
  if (p === ROUTED_PROVIDER) return { kind: "anthropic" };
  const models = isObj(doc["models"]) ? doc["models"] : {};
  const providers = isObj(models["providers"]) ? models["providers"] : {};
  const entry = isObj(providers[p]) ? providers[p] : undefined;
  if (!ROUTABLE_ID_RE.test(p)) return { kind: "refuse", why: "its provider id is not a plain name" };
  // A provider whose calls go where OpenClaw decides at run time (GitHub
  // Copilot): no route the launcher writes holds (openclaw-model-refs.ts).
  const ignored = openclawRouteIgnoredWhy(p);
  if (ignored !== null) return { kind: "refuse", why: ignored };
  // Vertex AI (model-wires.md §4.1): OpenClaw's own google-vertex provider.
  if (p.toLowerCase() === "google-vertex" || entry?.["api"] === "google-vertex") return openclawVertexVerdict(p, entry);
  if (entry === undefined) {
    if (p === "openai") return { kind: "route", route: { id: p, api: "openai-responses", upstream: OPENAI_API_BASE } };
    // The built-in `google` provider speaks the Gemini API (model-wires.md §5).
    if (p === "google") return { kind: "route", route: { id: p, api: "google-generative-ai", upstream: GEMINI_API_BASE } };
    // The built-in Ollama providers speak Ollama's native chat API
    // (model-wires.md, "The Ollama wire").
    const ollamaBase = OLLAMA_BUILTIN_BASES[p];
    if (ollamaBase !== undefined) return { kind: "route", route: { id: p, api: "ollama", upstream: ollamaBase } };
    return { kind: "refuse", why: `Mandu routes an OpenAI-compatible, Gemini or Ollama provider only when models.providers.${p} names its baseUrl and api ("openai-completions", "openai-responses", "google-generative-ai" or "ollama")` };
  }
  const api = entry["api"];
  const ollamaBuiltin = OLLAMA_BUILTIN_BASES[p];
  if (api === undefined && p !== "openai" && p !== "google" && ollamaBuiltin === undefined) {
    return { kind: "refuse", why: `models.providers.${p} names no api, and Mandu routes only "openai-completions", "openai-responses", "google-generative-ai" and "ollama"` };
  }
  // OpenClaw's Ollama providers default to its native chat API.
  const apiName = typeof api === "string" ? api : p === "google" ? "google-generative-ai" : ollamaBuiltin !== undefined ? "ollama" : "openai-responses";
  if (!ROUTED_APIS.has(apiName)) return { kind: "refuse", why: `models.providers.${p} uses api "${String(api)}", which Mandu does not route` };
  const builtInBase = p === "openai" && apiName === "openai-chatgpt-responses" ? CHATGPT_BACKEND_BASE
    : p === "openai" && apiName !== "google-generative-ai" && apiName !== "ollama" && apiName !== "azure-openai-responses" ? OPENAI_API_BASE
    : p === "google" && apiName === "google-generative-ai" ? GEMINI_API_BASE
      : ollamaBuiltin !== undefined && apiName === "ollama" ? ollamaBuiltin : undefined;
  const base = entry["baseUrl"] === undefined && builtInBase !== undefined ? builtInBase : routableUpstream(entry["baseUrl"]);
  if (base === null) {
    return { kind: "refuse", why: `models.providers.${p}.baseUrl is missing or not a URL Mandu sends to (https, or http to 127.0.0.1)` };
  }
  if (apiName === "azure-openai-responses") {
    const problem = azureRouteProblem(base);
    if (problem !== null) return { kind: "refuse", why: `models.providers.${p}: ${problem}` };
  }
  return { kind: "route", route: { id: p, api: apiName as RouteApi, upstream: apiName === "ollama" ? ollamaUpstreamOf(base) : wireUpstream(apiName as RouteApi, base) } };
}

/**
 * OpenClaw's google-vertex provider (Vertex AI's Gemini models; model-wires.md
 * §4.1, "Vertex AI at the root"). OpenClaw's Vertex transport (2026.4.29 and
 * later) sends `<origin of baseUrl>/v1/projects/{p}/locations/{l}/publishers/
 * google/models/{m}:streamGenerateContent?alt=sse`: the launcher points the
 * provider's baseUrl at the proxy's origin and hands the proxy the user's own
 * address (an origin), or, with no baseUrl or one carrying `{location}`
 * (which OpenClaw replaces with Google's own host per location), Google's
 * hosts (VERTEX_GOOGLE_HOSTS). Only OpenClaw's own id is routed: the proxy
 * serves one Vertex provider per session (the request carries no provider
 * id), and the bundled google plugin's Vertex transport is measured for that
 * provider. Its api must be `google-vertex` or unset. The release must take
 * the configured origin (openclawVertexVersionRefusal).
 */
function openclawVertexVerdict(p: string, entry: Json | undefined): ProviderVerdict {
  if (p !== "google-vertex") {
    return { kind: "refuse", why: `models.providers.${p} uses api "google-vertex"; Mandu routes Vertex AI only as OpenClaw's own google-vertex provider (models.providers.google-vertex)` };
  }
  const api = entry?.["api"];
  if (api !== undefined && api !== "google-vertex") {
    return { kind: "refuse", why: `models.providers.google-vertex names api ${JSON.stringify(api)}; Mandu routes OpenClaw's Vertex AI provider on api "google-vertex" (or none)` };
  }
  const base = entry?.["baseUrl"];
  const route = (upstream: string): ProviderVerdict => ({ kind: "route", route: { id: p, api: "google-vertex", upstream } });
  if (base === undefined || (typeof base === "string" && base.includes("{location}"))) return route(VERTEX_GOOGLE_HOSTS);
  const u = routableUpstream(base);
  if (u === null) {
    return { kind: "refuse", why: "models.providers.google-vertex.baseUrl is not a URL Mandu sends to (https, or http to 127.0.0.1)" };
  }
  return route(new URL(u).origin);
}

/**
 * The launch's refusal of a Vertex route on an OpenClaw release that sends
 * Vertex calls to Google whatever the provider's baseUrl (before
 * OPENCLAW_VERTEX_BASEURL_SINCE), or on one the launch could not read
 * (fail-closed); null when no route is Vertex or the release takes the
 * route. Pure.
 */
export function openclawVertexVersionRefusal(routes: readonly OpenAiRoute[], version: string | null | undefined): string | null {
  if (!routes.some((r) => isVertexApi(r.api))) return null;
  const v = parseAgentVersion(version ?? null);
  const since = parseAgentVersion(OPENCLAW_VERTEX_BASEURL_SINCE)!;
  const ok = v !== null && compareAgentVersions(v, since) >= 0 && !(v.prerelease !== null && v.parts.every((n, i) => n === since.parts[i]));
  if (ok) return null;
  return (
    `mandu: refusing to launch openclaw with a google-vertex model: ${v !== null ? `OpenClaw ${v.raw}` : "an OpenClaw release Mandu could not read"} ` +
    "sends Vertex AI calls to Google's own host whatever the provider's baseUrl, so they would go around Mandu's model proxy " +
    `with tool results unmasked. Update OpenClaw to ${OPENCLAW_VERTEX_BASEURL_SINCE} or later, choose another model, or run openclaw without mandu.`
  );
}

/** The OpenCode auth types by provider (its auth.json: "api", "oauth", "wellknown"). */
export type OpencodeAuthTypes = Readonly<Record<string, string>>;

/** OpenCode: how provider `p` is reached (its `provider` entry, else built-in). */
export function opencodeProviderVerdict(p: string, doc: Json, auth: OpencodeAuthTypes = {}): ProviderVerdict {
  if (p === ROUTED_PROVIDER) return { kind: "anthropic" };
  if (!ROUTABLE_ID_RE.test(p)) return { kind: "refuse", why: "its provider id is not a plain name" };
  const providers = isObj(doc["provider"]) ? doc["provider"] : {};
  const entry = isObj(providers[p]) ? providers[p] : undefined;
  const npm = entry && typeof entry["npm"] === "string" ? entry["npm"] : BUILT_IN_PACKAGES[p];
  const api = npm === undefined ? undefined : ROUTED_PACKAGES[npm];
  if (api === undefined) {
    return {
      kind: "refuse",
      why: entry === undefined
        ? `Mandu routes an OpenAI-compatible or Gemini provider only when provider.${p} names the @ai-sdk/openai-compatible or @ai-sdk/google package and options.baseURL`
        : `provider.${p} uses ${npm === undefined ? "no npm package" : `the ${npm} package`}, which Mandu does not route`,
    };
  }
  if (auth[p] === "oauth" && p === "openai") {
    return {
      kind: "refuse",
      why: "OpenCode is signed in to OpenAI with a ChatGPT account, and that login sends requests to chatgpt.com whatever the base URL; sign in with an API key (`opencode auth login`) to use it under Mandu",
    };
  }
  const options = entry && isObj(entry["options"]) ? entry["options"] : {};
  // @ai-sdk/google with no base URL talks to the Gemini API, as the built-in
  // `google` provider does.
  const raw = options["baseURL"] ?? entry?.["api"] ?? (p === "openai" ? OPENAI_API_BASE : api === "google-generative-ai" ? GEMINI_API_BASE : undefined);
  const base = routableUpstream(raw);
  if (base === null) {
    return { kind: "refuse", why: `provider.${p} has no base URL Mandu sends to (options.baseURL: https, or http to 127.0.0.1)` };
  }
  return { kind: "route", route: { id: p, api, upstream: base } };
}

/** What the launcher read of the agent's own config file. */
export type AgentUserConfig =
  | { kind: "absent" }
  | { kind: "unreadable"; path: string; reason: string }
  | { kind: "ok"; path: string; doc: Json };

const HELP_OR_VERSION = new Set(["-h", "--help", "-V", "-v", "--version"]);
const ROUTED_PROVIDER = "anthropic";
/** The OpenCode commands: `opencode` (both generations) and `opencode2` (2.x only). */
const OPENCODE_BINS: ReadonlySet<string> = new Set(["opencode", "opencode2"]);

function isObj(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The value of `--model X` / `--model=X` (and `-m X` / `-mX` when `short`)
 *  before any `--`; the last one wins, as in both agents' parsers. */
function flagValue(args: readonly string[], short: boolean): string | undefined {
  let v: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") break;
    if (a === "--model" || (short && a === "-m")) v = args[++i];
    else if (a.startsWith("--model=")) v = a.slice("--model=".length);
    else if (short && a.startsWith("-m") && a.length > 2 && !a.startsWith("--")) v = a.slice(2);
  }
  return v;
}


/** The first `$include` key in `node`, as a dotted path, or null. OpenClaw
 *  splices the named files in at load time (its "split config" feature);
 *  readAgentUserConfig resolves them first, so one left here was not read. */
function includePath(node: unknown, where: string): string | null {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) { const p = includePath(node[i], `${where}[${i}]`); if (p) return p; }
    return null;
  }
  if (!isObj(node)) return null;
  for (const [k, v] of Object.entries(node)) {
    const at = where ? `${where}.${k}` : k;
    if (k === "$include") return at;
    const p = includePath(v, at);
    if (p) return p;
  }
  return null;
}


type Judged = ModelRef & { provider: string | null; verdict: ProviderVerdict };

/** The routed-provider hint of a refusal, in the config spelling the agent reads. */
const OPENCODE1_HINT = "an OpenAI-compatible or Gemini provider declared with the @ai-sdk/openai-compatible or @ai-sdk/google package and options.baseURL";
const OPENCODE2_HINT = "an OpenAI-compatible or Gemini provider declared with the aisdk:@ai-sdk/openai-compatible or aisdk:@ai-sdk/google package and settings.baseURL";

function refuseLines(agent: string, bad: readonly Judged[], hint?: string): string {
  const shown = bad.slice(0, 4).map((b) => `${b.ref} (${b.where})`).join(", ");
  const more = bad.length > 4 ? ` and ${bad.length - 4} more` : "";
  const whys = [...new Set(bad.slice(0, 4).map((b) => b.verdict.kind === "refuse" ? b.verdict.why : ""))].filter((w) => w !== "");
  const configHint = hint ?? (agent === "openclaw"
    ? "an OpenAI-compatible, Azure OpenAI, Gemini or Ollama provider declared in models.providers with its baseUrl and api \"openai-completions\", \"openai-responses\", \"azure-openai-responses\", \"openai-chatgpt-responses\", \"google-generative-ai\" or \"ollama\""
    : OPENCODE1_HINT);
  return (
    `mandu: refusing to launch ${agent} with model ${shown}${more}: ` +
    (whys.length > 0 ? `${whys.join("; ")}. ` : "") +
    `Mandu protects ${agent} by routing its model provider through Mandu's model proxy, and a model it does not ` +
    "route would receive tool results unmasked. Choose an anthropic/…, openai/… or google/… model, or " + configHint +
    (bad.some((b) => b.provider === null) ? "; write a bare model id as <provider>/<id>" : "") +
    `, or run ${agent} without mandu.`
  );
}

function judge(refs: readonly ModelRef[], aliases: Json | undefined, verdictOf: (p: string) => ProviderVerdict): Judged[] {
  return refs.map((r) => {
    const provider = providerOf(r.ref, aliases);
    const verdict: ProviderVerdict = provider === null
      ? { kind: "refuse", why: "" }
      : verdictOf(provider);
    return { ...r, provider, verdict };
  });
}

/** The unique routes the judged references need, in first-seen order. */
function routesOf(judged: readonly Judged[]): OpenAiRoute[] {
  const out = new Map<string, OpenAiRoute>();
  for (const j of judged) if (j.verdict.kind === "route" && !out.has(j.verdict.route.id)) out.set(j.verdict.route.id, j.verdict.route);
  return [...out.values()];
}

/** The launch-time model decision: a refusal, or the OpenAI-family
 *  providers to route (empty when every model is Anthropic). */
export interface ModelPlan {
  refusal: string | null;
  routes: OpenAiRoute[];
}



/** The `--model` an `openclaw agent` argv names (null: none, or not
 *  `agent`, or an argv the launcher cannot read as OpenClaw's). */
export function openclawCliModel(argv: readonly string[]): ModelRef | null {
  const oc = readOpenclawArgv(argv);
  if (!oc || oc.sub !== "agent") return null;
  const v = flagValue(oc.rest, false);
  return v === undefined || v.trim() === "" ? null : { ref: v.trim(), where: "--model" };
}

/** OpenClaw: the refusal message, or null when every model it can run is routed. */
export function openclawModelRefusal(argv: readonly string[], cfg: AgentUserConfig): string | null {
  return openclawModelPlan(argv, cfg).refusal;
}

const NONE: ModelPlan = { refusal: null, routes: [] };
const refused = (refusal: string): ModelPlan => ({ refusal, routes: [] });

/** OpenClaw: the refusal, or the OpenAI-family providers to route. */
export function openclawModelPlan(argv: readonly string[], cfg: AgentUserConfig, opts: { hasZstd?: boolean } = {}): ModelPlan {
  const oc = readOpenclawArgv(argv);
  if (!oc) return NONE; // a wrapper: --target vouches for it
  if ([...oc.globals, oc.sub, ...oc.rest].some((a) => HELP_OR_VERSION.has(a)) || oc.sub === "help") return NONE;
  if (cfg.kind === "unreadable") {
    return refused(
      `mandu: refusing to launch openclaw: could not read ${cfg.path} (${cfg.reason}). The launch would run without ` +
      "your settings, and OpenClaw would fall back to its built-in model, which Mandu cannot vouch for. Fix the " +
      "file (Mandu reads it as JSON5 and resolves its $include files, as OpenClaw does), or run openclaw without mandu."
    );
  }
  const doc = cfg.kind === "ok" ? cfg.doc : {};
  const include = cfg.kind === "ok" ? includePath(doc, "") : null;
  if (include !== null) {
    return refused(
      `mandu: refusing to launch openclaw: ${cfg.kind === "ok" ? cfg.path : "its config"} uses $include (${include}), ` +
      "and Mandu checks every model your config can run before the launch but did not read the included files, so " +
      "a model there could go around Mandu's model proxy. Put the included settings into the file itself, or run " +
      "openclaw without mandu."
    );
  }
  const agents = isObj(doc["agents"]) ? doc["agents"] : {};
  const defaults = isObj(agents["defaults"]) ? agents["defaults"] : {};
  const aliases = isObj(defaults["models"]) ? defaults["models"] : undefined;
  // `-m` is --message for OpenClaw: only the long flag names a model.
  const cli = oc.sub === "agent" ? flagValue(oc.rest, false) : undefined;

  const refs: ModelRef[] = [];
  collectModelKeys(agents, "agents", refs);
  activeMemoryRefs(doc, refs);
  // Which primary this run starts on: --model, else the selected agent's own
  // model, else agents.defaults.model. With --model, the configured primaries
  // of the selected agent and the defaults do not run (fallbacks still do).
  const list = Array.isArray(agents["list"]) ? agents["list"].filter(isObj) : [];
  const agentFlag = oc.sub === "agent" ? (() => {
    for (let i = 0; i < oc.rest.length; i++) {
      const a = oc.rest[i]!;
      if (a === "--agent") return oc.rest[i + 1];
      if (a.startsWith("--agent=")) return a.slice("--agent=".length);
    }
    return undefined;
  })() : undefined;
  const selectedIdx = agentFlag !== undefined
    ? list.findIndex((e) => e["id"] === agentFlag)
    : Math.max(list.findIndex((e) => e["default"] === true), list.length > 0 ? 0 : -1);
  const primaryOf = (m: unknown): string | undefined =>
    typeof m === "string" ? m : isObj(m) && typeof m["primary"] === "string" ? m["primary"] : undefined;
  const selected = selectedIdx >= 0 ? list[selectedIdx] : undefined;
  const primary = cli ?? primaryOf(selected?.["model"]) ?? primaryOf(defaults["model"]);

  let effective = refs;
  if (cli !== undefined) {
    const skip = new Set(["agents.defaults.model", "agents.defaults.model.primary"]);
    if (selectedIdx >= 0) { skip.add(`agents.list[${selectedIdx}].model`); skip.add(`agents.list[${selectedIdx}].model.primary`); }
    effective = [...refs.filter((r) => !skip.has(r.where)), { ref: cli, where: "--model" }];
  }
  const judged = judge(effective, aliases, (p) => openclawProviderVerdict(p, doc));
  const bad = judged.filter((j) => j.verdict.kind === "refuse");
  if (bad.length > 0) return refused(refuseLines("openclaw", bad));
  // Azure OpenAI (model-wires.md §9.1): OpenClaw's Azure client reads
  // AZURE_OPENAI_BASE_URL / AZURE_OPENAI_RESOURCE_NAME before the provider's
  // baseUrl. The launch pins AZURE_OPENAI_BASE_URL at the route (agent-config
  // writeAgentConfig), which outranks the config's `env` block only where
  // that block is not read first: a config that sets them is refused, and so
  // is a second Azure provider (one variable serves every Azure provider).
  const azure = routesOf(judged).filter((r) => r.api === "azure-openai-responses");
  if (azure.length > 0) {
    const set = openclawConfigAzureEnv(doc);
    if (set.length > 0) {
      return refused(
        `mandu: refusing to launch openclaw: your config sets ${set.join(", ")}, and OpenClaw's Azure OpenAI client sends every ` +
        `Azure call there instead of to the provider's baseUrl, around Mandu's model proxy. Remove it (models.providers.${azure[0]!.id}.baseUrl names the endpoint), ` +
        "or run openclaw without mandu.",
      );
    }
    if (azure.length > 1) {
      return refused(
        `mandu: refusing to launch openclaw with more than one Azure OpenAI provider (${azure.map((r) => r.id).join(", ")}): OpenClaw's ` +
        "Azure client takes one endpoint variable for all of them, which Mandu pins at one provider's route. Keep one Azure provider in this run, " +
        "or run openclaw without mandu.",
      );
    }
  }
  const zstd = chatgptZstdProblem(routesOf(judged), opts.hasZstd ?? NODE_HAS_ZSTD);
  if (zstd !== null) return refused(`mandu: refusing to launch openclaw: ${zstd}.`);
  if (primary === undefined || primary.trim() === "") {
    return refused(
      "mandu: refusing to launch openclaw with no model configured: OpenClaw would run its built-in default model, " +
      "which depends on the release (anthropic on 2026.3, openai on 2026.6 and later), so Mandu cannot vouch for " +
      "where it sends tool results. Set one, e.g. `openclaw config set agents.defaults.model.primary " +
      "anthropic/claude-sonnet-4-6`, or pass --model to `openclaw agent`."
    );
  }
  return { refusal: null, routes: routesOf(judged) };
}

/** OpenCode: the refusal message, or null. An unset model is fine here: the
 *  routing override fences OpenCode to the routed providers. */
export function opencodeModelRefusal(argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}): string | null {
  return opencodeModelPlan(argv, cfg, auth).refusal;
}

/** OpenCode: the refusal, or the OpenAI-family providers to route. */
export function opencodeModelPlan(argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}): ModelPlan {
  if (argv.length === 0 || !OPENCODE_BINS.has(basename(argv[0]!))) return NONE; // a wrapper
  const args = argv.slice(1);
  if (args.some((a) => HELP_OR_VERSION.has(a))) return NONE;
  const refs: ModelRef[] = [];
  if (cfg.kind === "ok") {
    const d = cfg.doc;
    if (typeof d["model"] === "string") refs.push({ ref: d["model"], where: `model in ${cfg.path}` });
    if (typeof d["small_model"] === "string") refs.push({ ref: d["small_model"], where: `small_model in ${cfg.path}` });
    for (const key of ["agent", "mode"]) {
      const sect = d[key];
      if (!isObj(sect)) continue;
      for (const [name, a] of Object.entries(sect)) {
        if (isObj(a) && typeof a["model"] === "string") refs.push({ ref: a["model"], where: `${key}.${name}.model in ${cfg.path}` });
      }
    }
  }
  const cli = flagValue(args, true);
  if (cli !== undefined) {
    // The flag replaces the configured main model for this run.
    const i = refs.findIndex((r) => r.where.startsWith("model in "));
    if (i >= 0) refs.splice(i, 1);
    refs.push({ ref: cli, where: "--model" });
  }
  const doc = cfg.kind === "ok" ? cfg.doc : {};
  const judged = judge(refs, undefined, (p) => opencodeProviderVerdict(p, doc, auth));
  const bad = judged.filter((j) => j.verdict.kind === "refuse");
  return bad.length > 0 ? refused(refuseLines("opencode", bad)) : { refusal: null, routes: routesOf(judged) };
}

// ─── OpenCode 2 (supported-agents.md §2.3 part 4) ────────────────────────────

/** What the launcher read of every config layer OpenCode 2 will read
 *  (services/agent-config.ts readOpencodeConfigLayers), lowest first. */
export interface OpencodeV2Input {
  layers: readonly OpencodeLayer[];
  /** Files OpenCode 2 would read that the launcher could not parse. */
  unreadable: ReadonlyArray<{ path: string; reason: string }>;
}

/** The npm packages Mandu routes, and the wire each speaks (both OpenCode
 *  generations). */
const ROUTED_PACKAGES: Readonly<Record<string, RouteApi>> = {
  "@ai-sdk/openai": "openai-responses",
  "@ai-sdk/openai-compatible": "openai-completions",
  "@ai-sdk/google": "google-generative-ai",
};

/** OpenCode's built-in providers Mandu routes, by the package each loads. */
const BUILT_IN_PACKAGES: Readonly<Record<string, string>> = {
  openai: "@ai-sdk/openai",
  google: "@ai-sdk/google",
};

/** One provider's endpoint settings merged across the layers (each field
 *  from the highest layer that sets it, as OpenCode 2 merges them). */
export type OpencodeV2Providers = Readonly<Record<string, OcProvider>>;

function mergeV2Providers(layers: ReadonlyArray<OcNormalized>): Record<string, OcProvider> {
  const out: Record<string, OcProvider> = {};
  for (const n of layers) for (const [id, e] of Object.entries(n.providers)) out[id] = { ...out[id], ...e };
  return out;
}

/** OpenCode 2: how provider `p` is reached (its merged `providers` entry, else built-in). */
export function opencodeV2ProviderVerdict(p: string, providers: OpencodeV2Providers, auth: OpencodeAuthTypes = {}): ProviderVerdict {
  if (p === ROUTED_PROVIDER) return { kind: "anthropic" };
  if (!ROUTABLE_ID_RE.test(p)) return { kind: "refuse", why: "its provider id is not a plain name" };
  const entry = providers[p];
  if (entry?.canonical !== undefined) {
    return { kind: "refuse", why: `providers.${p}.canonical makes it a copy of another provider, which Mandu does not route` };
  }
  const pkg = opencodePackageName(entry?.package) ?? BUILT_IN_PACKAGES[p];
  const api = pkg === undefined ? undefined : ROUTED_PACKAGES[pkg];
  if (api === undefined) {
    return {
      kind: "refuse",
      why: entry?.package === undefined
        ? `Mandu routes an OpenAI-compatible or Gemini provider only when providers.${p} names the aisdk:@ai-sdk/openai-compatible or aisdk:@ai-sdk/google package and settings.baseURL`
        : `providers.${p} uses the ${entry.package} package, which Mandu does not route`,
    };
  }
  if (auth[p] === "oauth" && p === "openai") {
    return {
      kind: "refuse",
      why: "OpenCode is signed in to OpenAI with a ChatGPT account, and that login sends requests to chatgpt.com whatever the base URL; sign in with an API key (`opencode auth login`) to use it under Mandu",
    };
  }
  const base = routableUpstream(entry?.baseURL ?? (p === "openai" ? OPENAI_API_BASE : api === "google-generative-ai" ? GEMINI_API_BASE : undefined));
  if (base === null) {
    return { kind: "refuse", why: `providers.${p} has no base URL Mandu sends to (settings.baseURL: https, or http to 127.0.0.1)` };
  }
  return { kind: "route", route: { id: p, api, upstream: base } };
}

/** The anthropic package a config may name (the provider's own SDK). */
const ANTHROPIC_PACKAGES: ReadonlySet<string> = new Set(["@ai-sdk/anthropic"]);

/**
 * OpenCode 2: the refusal, or the OpenAI-family providers to route. Reads
 * EVERY config layer OpenCode 2 reads (the global config dir, the
 * OPENCODE_CONFIG file, every project file from `/` down to the start
 * directory, OPENCODE_CONFIG_CONTENT), in both spellings (opencode-config.ts).
 * Refuses, before anything starts:
 *   - a layer it could not read (it could hold any of the below);
 *   - a model the session can run (`model` or `-m`, each `agents.<n>.model`
 *     with its `#variant`, each `commands.<n>.model`; V1 `small_model`,
 *     `agent`, `mode`, `command`), from the highest layer that sets it, on a
 *     provider Mandu does not route: the clear-message layer, as for 1.x
 *     (the policy fence holds the line at run time);
 *   - a model-level endpoint on a routed provider (a model's or variant's
 *     own base URL or package; V1 `options.baseURL`, `provider.api`,
 *     `provider.npm`, `variants.<v>.baseURL`), in ANY layer: OpenCode 2
 *     sends that model's requests there, around the provider's base URL that
 *     Mandu points at its proxy. So is a `package` or `canonical` on the
 *     anthropic provider (another SDK may read its endpoint from other
 *     settings).
 * A re-pointed provider base URL (either spelling, any layer) is not
 * refused: the routing Mandu writes in OPENCODE_CONFIG_CONTENT outranks it,
 * in both spellings (agent-config.ts opencodeRoutingContent). Nor is a
 * provider the user's config admits (`enabled_providers`, an
 * `experimental.policies` allow): OpenCode 2 lets the LOWEST layer's provider
 * rule win, which once let the global config re-admit a provider, but under
 * Mandu OpenCode 2 reads no file of the user's (agent-config.ts
 * opencodeLockdownEnv): every layer is merged into the run file, whose fence
 * replaces the user's rules (supported-agents.md §2.3 item 8).
 */
export function opencodeV2ModelPlan(argv: readonly string[], input: OpencodeV2Input, auth: OpencodeAuthTypes = {}): ModelPlan {
  if (argv.length === 0 || !OPENCODE_BINS.has(basename(argv[0]!))) return NONE; // a wrapper
  const args = argv.slice(1);
  if (args.some((a) => HELP_OR_VERSION.has(a))) return NONE;
  if (input.unreadable.length > 0) {
    const u = input.unreadable[0]!;
    return refused(
      `mandu: refusing to launch opencode: could not read ${u.path} (${u.reason}). OpenCode 2 reads it, and Mandu ` +
      "checks every config layer for a model or endpoint that would go around Mandu's model proxy before the launch. " +
      "Fix the file (Mandu reads it as JSONC), or run opencode without mandu."
    );
  }
  const norm = input.layers.map((layer) => ({ layer, n: normalizeOpencodeDoc(layer.doc) }));
  const at = (where: string, layer: OpencodeLayer): string => `${where} in ${layer.path}`;

  // The models the session can run, each from the highest layer that sets it.
  let main: ModelRef | undefined;
  const named = new Map<string, ModelRef>();
  for (const { layer, n } of norm) {
    if (n.model) main = { ref: n.model.ref, where: at(n.model.where, layer) };
    for (const [name, r] of Object.entries(n.agents)) named.set(`agents.${name}`, { ref: r.ref, where: at(r.where, layer) });
    for (const [name, r] of Object.entries(n.commands)) named.set(`commands.${name}`, { ref: r.ref, where: at(r.where, layer) });
  }
  const cli = flagValue(args, true);
  const refs: ModelRef[] = [];
  if (cli !== undefined) refs.push({ ref: cli, where: "--model" }); // replaces the main model for the run
  else if (main) refs.push(main);
  refs.push(...named.values());

  const providers = mergeV2Providers(norm.map((x) => x.n));
  const verdictOf = (p: string): ProviderVerdict => opencodeV2ProviderVerdict(p, providers, auth);
  const judged = judge(refs, undefined, verdictOf);
  const bad = judged.filter((j) => j.verdict.kind === "refuse");
  if (bad.length > 0) return refused(refuseLines("opencode", bad, OPENCODE2_HINT));

  const routes = routesOf(judged);
  const routed = new Set([ROUTED_PROVIDER, ...routes.map((r) => r.id)]);

  // A routed provider's model with its own endpoint, or another SDK for anthropic.
  for (const { layer, n } of norm) {
    const key = n.endpointKeys.find((k) => routed.has(k.provider.toLowerCase()));
    if (key) {
      return refused(
        `mandu: refusing to launch opencode: ${at(key.where, layer)} gives one ${key.provider} model its own ` +
        "endpoint. OpenCode 2 sends that model's requests there instead of to the provider's base URL, which Mandu " +
        "points at its model proxy, so they would leave with tool results unmasked. Remove the key (Mandu routes " +
        `every ${key.provider} model through its proxy), or run opencode without mandu.`
      );
    }
    const a = n.providers[ROUTED_PROVIDER];
    const pkg = opencodePackageName(a?.package);
    if (a && ((pkg !== undefined && !ANTHROPIC_PACKAGES.has(pkg)) || a.canonical !== undefined)) {
      const which = a.canonical !== undefined ? "canonical" : a.spelling === "providers" ? "package" : "npm";
      return refused(
        `mandu: refusing to launch opencode: ${at(`${a.spelling}.anthropic.${which}`, layer)} makes the anthropic ` +
        "provider speak through another SDK, which may take its endpoint from other settings than the base URL " +
        "Mandu points at its model proxy. Remove it, or run opencode without mandu."
      );
    }
  }
  return { refusal: null, routes };
}

/** The refusal for any target (null for the targets this module does not own). */
export function agentModelRefusal(
  target: string, argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}, opencodeV2?: OpencodeV2Input,
): string | null {
  return agentModelPlan(target, argv, cfg, auth, opencodeV2).refusal;
}

/** The model plan for any target (nothing to route for the targets this
 *  module does not own). `opencodeV2` is given for an OpenCode 2 launch
 *  (opencode-config.ts opencodeGeneration): its layers replace `cfg`. */
export function agentModelPlan(
  target: string, argv: readonly string[], cfg: AgentUserConfig, auth: OpencodeAuthTypes = {}, opencodeV2?: OpencodeV2Input,
): ModelPlan {
  if (target === "openclaw") return openclawModelPlan(argv, cfg);
  if (target === "opencode") return opencodeV2 ? opencodeV2ModelPlan(argv, opencodeV2, auth) : opencodeModelPlan(argv, cfg, auth);
  return NONE;
}
