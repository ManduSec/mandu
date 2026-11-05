/**
 * route — which requests the model-API proxy may send upstream, and how
 * (docs/design/architecture/mandu.md §4.1, "Which requests go upstream").
 *
 * The proxy symbolizes the Messages wire only. Until 2026-09-27 every other
 * request was relayed raw, so an agent that spoke another generation wire
 * through ANTHROPIC_BASE_URL (Anthropic's OpenAI-compatible
 * /v1/chat/completions, legacy /v1/complete, /v1/messages/batches) reached the
 * model with its tool results unmasked. Found by the fresh-agents VM suite,
 * when an OpenClaw config without `api` POSTed /chat/completions through it
 * (os-test-matrix.md §10.14.1).
 *
 * The rule is fail-closed. A request is sent upstream only when the proxy can
 * vouch for what it carries:
 *   - `messages`: POST …/v1/messages, symbolized (rewrite-request.ts);
 *   - `count_tokens`: POST …/v1/messages/count_tokens. It carries the whole
 *     conversation (raw tool results, secret values), so it runs through the
 *     SAME symbolization, minus the handling prompt (Claude Code counts its
 *     context one category at a time, and the prompt would inflate each).
 *     Refusing it would also be safe for Claude Code 2.1.283, which logs a
 *     failed count and falls back to its own estimate, but `/context` issues
 *     a dozen of them and would lose its numbers;
 *   - `relay`: a bodyless GET or HEAD (model listings, Claude Code's
 *     `HEAD /api/hello` connectivity probe). A read with no body cannot put
 *     conversation content in front of the model;
 *   - `refuse`: everything else, answered locally (403) and never sent.
 */

export type RouteKind = "messages" | "count_tokens" | "relay" | "refuse";

export interface Route {
  kind: RouteKind;
  /** For `refuse`: the message the agent surfaces (names mandu and the path). */
  message?: string;
}

function pathOnly(path: string): string {
  return (path.split("?")[0] ?? "").replace(/\/+$/, "");
}

/** POST …/v1/messages (a base-URL path prefix is tolerated). */
export function isMessagesPath(path: string): boolean {
  const p = pathOnly(path);
  return p === "/v1/messages" || p.endsWith("/v1/messages");
}

/** POST …/v1/messages/count_tokens. */
export function isCountTokensPath(path: string): boolean {
  const p = pathOnly(path);
  return p === "/v1/messages/count_tokens" || p.endsWith("/v1/messages/count_tokens");
}

/**
 * Classify one request. `bodyLength` is the buffered request body's size: a
 * GET or HEAD that carries a body is not a plain read and is refused.
 */
export function classifyRoute(method: string, path: string, bodyLength: number): Route {
  const m = method.toUpperCase();
  if (m === "POST" && isMessagesPath(path)) return { kind: "messages" };
  if (m === "POST" && isCountTokensPath(path)) return { kind: "count_tokens" };
  if ((m === "GET" || m === "HEAD") && bodyLength === 0) return { kind: "relay" };
  return {
    kind: "refuse",
    message:
      `mandu: refusing ${m} ${pathOnly(path) || "/"}: the Mandu model proxy masks tool results only on ` +
      "POST /v1/messages (and /v1/messages/count_tokens), so it does not send other requests to the model " +
      "provider. Point the agent at the Anthropic Messages API (for OpenClaw: api \"anthropic-messages\").",
  };
}

/**
 * The OpenAI-family routes (agent-e2e-harness.md §9; openai-wire.ts): an
 * OpenClaw, OpenCode or Goose provider that speaks an OpenAI wire is pointed at
 * `<proxy>/_mandu/openai/<provider id>`, and the launcher tells the proxy
 * each routed provider's real base URL (MANDU_OPENAI_UPSTREAMS). Under that
 * prefix:
 *   - `chat`: POST …/chat/completions, gated (openai-wire.ts chatShadow);
 *   - `responses`: POST …/responses, gated (responsesShadow);
 *     each also with one `/v1` before it (`…/v1/chat/completions`,
 *     `…/v1/responses`): Goose's openai provider appends its base path
 *     `v1/chat/completions` to the host it is given, and keeps that default
 *     path so that it picks Chat or Responses per model (supported-agents.md
 *     §5.6), so its route's upstream is the provider's host and the `/v1`
 *     rides the path; or with `/api/v1` before it: Goose's openrouter
 *     provider joins `api/v1/chat/completions` to its host (supported-agents.md
 *     §5.6.4). Same gates; the provider gets `<upstream><path>` either way;
 *     `responses` also on POST …/codex/responses: OpenClaw's
 *     `openai-chatgpt-responses` api (a ChatGPT sign-in) joins
 *     `/codex/responses` to its base URL (@openclaw/ai's own transport;
 *     its OpenAI-SDK transport joins `/responses`), and the launcher
 *     records the ChatGPT backend's `/codex` base as the upstream
 *     (upstreamRest below; model-wires.md §9). Azure OpenAI (`azure-openai-responses`)
 *     POSTs `/responses?api-version=…`: the query rides `rest` to the
 *     provider;
 *   - `relay`: a bodyless GET or HEAD (a model listing), sent as is;
 *   - `refuse`: everything else (embeddings, the legacy /completions, files,
 *     a provider the launcher did not route), answered 403, never sent.
 * Null for a path outside the prefix (the Messages routes above).
 */
export const OPENAI_ROUTE_PREFIX = "/_mandu/openai/";

export type OpenAiRouteKind = "chat" | "responses" | "relay" | "refuse";

export interface OpenAiRoute {
  kind: OpenAiRouteKind;
  provider: string;
  /** The path below the provider (with its query), e.g. `/chat/completions`. */
  rest: string;
  message?: string;
}

export function classifyOpenAiRoute(
  method: string,
  path: string,
  bodyLength: number,
  providers: ReadonlySet<string>,
): OpenAiRoute | null {
  if (!path.startsWith(OPENAI_ROUTE_PREFIX)) return null;
  const tail = path.slice(OPENAI_ROUTE_PREFIX.length);
  const slash = tail.indexOf("/");
  const rawId = slash < 0 ? tail.split("?")[0]! : tail.slice(0, slash);
  let provider: string;
  try { provider = decodeURIComponent(rawId); } catch { provider = rawId; }
  const rest = slash < 0 ? "/" : tail.slice(slash);
  const p = pathOnly(rest);
  const m = method.toUpperCase();
  if (!providers.has(provider)) {
    return {
      kind: "refuse", provider, rest,
      message: `mandu: refusing ${m} for provider "${provider}": Mandu did not route that provider for this session, so nothing was sent.`,
    };
  }
  const op = p.startsWith("/v1/") ? p.slice(3) : p.startsWith("/api/v1/") ? p.slice(7) : p;
  if (m === "POST" && op === "/chat/completions") return { kind: "chat", provider, rest };
  if (m === "POST" && (op === "/responses" || p === "/codex/responses")) return { kind: "responses", provider, rest };
  if ((m === "GET" || m === "HEAD") && bodyLength === 0) return { kind: "relay", provider, rest };
  return {
    kind: "refuse", provider, rest,
    message:
      `mandu: refusing ${m} ${p || "/"} for provider "${provider}": the Mandu model proxy masks tool results only on ` +
      "POST …/chat/completions and POST …/responses (…/codex/responses for a ChatGPT sign-in), so it does not send other requests to the model provider.",
  };
}

/**
 * The path sent below a routed provider's base URL (model-wires.md §9): the
 * agent's `rest`, except that an upstream ending in `/codex` takes
 * `/codex/responses` as `/responses`. OpenClaw reaches the ChatGPT backend
 * two ways: its OpenAI-SDK transport (the agent's turns, 2026.7.1-2 to
 * 2026.10.7) POSTs `<base>/responses` with the base canonicalized to
 * `https://chatgpt.com/backend-api/codex`, and @openclaw/ai's own ChatGPT
 * transport POSTs `<base>/codex/responses` (`/responses` after a base ending
 * in `/codex`). Behind the route the base is the proxy's, so both arrive;
 * with the upstream recorded as the `/codex` base each reaches the URL
 * OpenClaw would itself have called. Pure.
 */
export function upstreamRest(upstream: string | undefined, rest: string): string {
  if (upstream === undefined) return rest;
  let base: string;
  try { base = new URL(upstream).pathname.replace(/\/+$/, ""); } catch { return rest; }
  if (base.endsWith("/codex") && (rest === "/codex/responses" || rest.startsWith("/codex/responses?") || rest.startsWith("/codex/responses/"))) {
    return rest.slice("/codex".length);
  }
  return rest;
}

/**
 * The Google Gemini routes (model-wires.md §4.1; gemini-wire.ts): a provider
 * that speaks the Gemini API (OpenClaw's `google-generative-ai`, OpenCode's
 * `@ai-sdk/google`, Goose's `google`) is pointed at
 * `<proxy>/_mandu/google/<provider id>`, and the launcher tells the proxy
 * each routed provider's real base URL (MANDU_GOOGLE_UPSTREAMS). Under that
 * prefix, with an optional API version (`/v1beta`, `/v1`, `/v1alpha`) and an
 * optional Vertex AI resource path before `/models/`:
 *   - `generate`: POST …/models/{model}:generateContent (buffered answer);
 *   - `stream`: POST …/models/{model}:streamGenerateContent, SSE with
 *     `alt=sse`, else the JSON-array stream, read whole;
 *   - `relay`: a bodyless GET or HEAD (the `/models` listing), sent as is;
 *   - `refuse`: everything else (`:countTokens`, `:embedContent`,
 *     `:batchGenerateContent`, `cachedContents`, `files`, `/interactions`, a
 *     provider the launcher did not route), answered 403, never sent.
 * Null for a path outside the prefix.
 */
export const GOOGLE_ROUTE_PREFIX = "/_mandu/google/";

export type GoogleRouteKind = "generate" | "stream" | "relay" | "refuse";

export interface GoogleRoute {
  kind: GoogleRouteKind;
  provider: string;
  /** The path below the provider (with its query), e.g. `/models/m:generateContent?alt=sse`. */
  rest: string;
  /** The model the path names (generate / stream). */
  model?: string;
  /** stream: the answer is SSE (`alt=sse`), else a JSON array. */
  sse?: boolean;
  message?: string;
}

/**
 * Vertex AI at the proxy's ROOT (model-wires.md §4.1, "Vertex AI at the
 * root"). OpenClaw's Vertex transport (its google-vertex api, 2026.4.29 and
 * later) builds the request URL from the ORIGIN of the provider's `baseUrl`:
 * the path is dropped, so `<proxy>/_mandu/google/<id>` arrives as
 * `<proxy>/v1/projects/{p}/locations/{l}/publishers/google/models/{m}:{op}`
 * and no provider id rides the path. The session routes at most one Vertex
 * provider (MANDU_VERTEX_UPSTREAMS), and these root paths are its:
 *   - `generate` / `stream`: POST …/publishers/google/models/{m}:generateContent
 *     or :streamGenerateContent, gated as the Gemini wire (gemini-wire.ts);
 *   - `relay`: a bodyless GET or HEAD under the same project and location;
 *   - `refuse`: everything else (another publisher: Anthropic's Claude on
 *     Vertex is `rawPredict`, OpenClaw's separate anthropic-vertex provider;
 *     `:countTokens`, `:predict`, a location that is not a plain region name,
 *     a session that routes no Vertex provider), answered 403, never sent.
 * Null for a path that is not a Vertex resource path (`/v1/messages` and the
 * rest of the Messages routes).
 */
const VERTEX_ROOT_RE = /^\/v1(?:beta1)?\/projects\/[^/]+\/locations\/([^/]+)(\/.*)?$/;
const VERTEX_OP_RE = /^\/publishers\/([^/]+)\/models\/([^/:]+):([A-Za-z]+)$/;

/** A Vertex location as Google names them (`us-central1`, `europe-west4`,
 *  `global`, `us`, `eu`): lower-case letters and digits in dash-joined
 *  words. Only such a name reaches a host name (vertexOrigin). */
export const VERTEX_LOCATION_RE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/**
 * Where a Vertex request for `location` goes: the session's own address
 * (`upstream`, an origin), or, with none, Google's own Vertex host for that
 * location, as OpenClaw picks it (its resolveGoogleVertexBaseOrigin):
 * `global` → aiplatform.googleapis.com, `us` / `eu` → the multi-region
 * `aiplatform.<l>.rep.googleapis.com`, a region → `<l>-aiplatform.googleapis.com`.
 * Null for a location that is not a plain region name. Pure.
 */
export function vertexOrigin(upstream: string | null, location: string): string | null {
  if (!VERTEX_LOCATION_RE.test(location) || location.length > 63) return null;
  if (upstream !== null) return upstream;
  if (location === "global") return "https://aiplatform.googleapis.com";
  if (location === "us" || location === "eu") return `https://aiplatform.${location}.rep.googleapis.com`;
  return `https://${location}-aiplatform.googleapis.com`;
}

export interface VertexRoute extends GoogleRoute {
  /** The location the path names (generate / stream / relay). */
  location?: string;
}

export function classifyVertexRoute(method: string, path: string, bodyLength: number, provider: string | null): VertexRoute | null {
  const p = pathOnly(path);
  let decoded = p;
  try { decoded = decodeURIComponent(p); } catch { /* keep it as sent */ }
  const root = VERTEX_ROOT_RE.exec(decoded);
  if (!root) return null;
  const m = method.toUpperCase();
  const refuse = (why: string): VertexRoute => ({ kind: "refuse", provider: provider ?? "", rest: path, message: `mandu: refusing ${m} ${p}: ${why}, so nothing was sent.` });
  if (provider === null) return refuse("this session routes no Vertex AI provider through Mandu");
  const location = root[1]!;
  if (vertexOrigin(null, location) === null) return refuse(`the location ${JSON.stringify(location.slice(0, 64))} is not a Vertex region name`);
  const op = VERTEX_OP_RE.exec(root[2] ?? "");
  if (m === "POST" && op && op[1] === "google" && op[3] === "generateContent") return { kind: "generate", provider, rest: path, model: op[2]!, location };
  if (m === "POST" && op && op[1] === "google" && op[3] === "streamGenerateContent") {
    const query = new URLSearchParams(path.includes("?") ? path.slice(path.indexOf("?") + 1) : "");
    return { kind: "stream", provider, rest: path, model: op[2]!, sse: query.get("alt") === "sse", location };
  }
  if ((m === "GET" || m === "HEAD") && bodyLength === 0) return { kind: "relay", provider, rest: path, location };
  if (op && op[1] !== "google") {
    return refuse(`Mandu reads Google's Gemini models on Vertex AI (publishers/google) only, not publisher ${JSON.stringify(op[1]!.slice(0, 64))} ` +
      "(Anthropic's Claude on Vertex AI is OpenClaw's anthropic-vertex provider, which Mandu does not route)");
  }
  return refuse("the Mandu model proxy masks tool results on Vertex AI only on POST …/publishers/google/models/{model}:generateContent and :streamGenerateContent");
}

/** `[/v1beta][/projects/p/locations/l/publishers/google]/models/{model}:{op}` */
const GEMINI_OP_RE = /^(?:\/v1(?:alpha|beta)?\d*)?(?:\/projects\/[^/]+\/locations\/[^/]+\/publishers\/google)?\/models\/([^/:]+):([A-Za-z]+)$/;

export function classifyGoogleRoute(
  method: string,
  path: string,
  bodyLength: number,
  providers: ReadonlySet<string>,
): GoogleRoute | null {
  if (!path.startsWith(GOOGLE_ROUTE_PREFIX)) return null;
  const tail = path.slice(GOOGLE_ROUTE_PREFIX.length);
  const slash = tail.indexOf("/");
  const rawId = slash < 0 ? tail.split("?")[0]! : tail.slice(0, slash);
  let provider: string;
  try { provider = decodeURIComponent(rawId); } catch { provider = rawId; }
  const rest = slash < 0 ? "/" : tail.slice(slash);
  const p = pathOnly(rest);
  const m = method.toUpperCase();
  if (!providers.has(provider)) {
    return {
      kind: "refuse", provider, rest,
      message: `mandu: refusing ${m} for provider "${provider}": Mandu did not route that provider for this session, so nothing was sent.`,
    };
  }
  let decoded = p;
  try { decoded = decodeURIComponent(p); } catch { /* keep it as sent */ }
  const op = GEMINI_OP_RE.exec(decoded);
  if (m === "POST" && op && op[2] === "generateContent") return { kind: "generate", provider, rest, model: op[1]! };
  if (m === "POST" && op && op[2] === "streamGenerateContent") {
    const query = new URLSearchParams(rest.includes("?") ? rest.slice(rest.indexOf("?") + 1) : "");
    return { kind: "stream", provider, rest, model: op[1]!, sse: query.get("alt") === "sse" };
  }
  if ((m === "GET" || m === "HEAD") && bodyLength === 0) return { kind: "relay", provider, rest };
  return {
    kind: "refuse", provider, rest,
    message:
      `mandu: refusing ${m} ${p || "/"} for provider "${provider}": the Mandu model proxy masks tool results only on ` +
      "POST …/models/{model}:generateContent and :streamGenerateContent, so it does not send other requests to the model provider.",
  };
}

/**
 * The Ollama native routes (model-wires.md, "The Ollama wire";
 * ollama-wire.ts): a provider that speaks Ollama's own chat API (OpenClaw's
 * `api: "ollama"`, its built-in `ollama` and `ollama-cloud` providers) is
 * pointed at `<proxy>/_mandu/ollama/<provider id>`, and the launcher tells
 * the proxy each routed provider's real base URL (MANDU_OLLAMA_UPSTREAMS).
 * Under that prefix:
 *   - `chat`: POST …/api/chat, gated (an NDJSON answer, or one object with
 *     `stream: false`);
 *   - `show`: POST …/api/show, a model lookup (OpenClaw's model discovery):
 *     relayed only when its body names one model and nothing else
 *     (ollama-wire.ts ollamaShowRefusal, checked by the proxy);
 *   - `relay`: a bodyless GET or HEAD (`/api/tags`, `/api/version`,
 *     `/api/ps`), sent as is;
 *   - `refuse`: everything else (`/api/generate`, `/api/embed`, the pulls,
 *     pushes, creates, copies and deletes, `/api/blobs`, `/api/web_search`,
 *     the OpenAI-compatible `/v1/…`, a provider the launcher did not route),
 *     answered 403, never sent.
 * Null for a path outside the prefix.
 */
export const OLLAMA_ROUTE_PREFIX = "/_mandu/ollama/";

export type OllamaRouteKind = "chat" | "show" | "relay" | "refuse";

export interface OllamaRoute {
  kind: OllamaRouteKind;
  provider: string;
  /** The path below the provider (with its query), e.g. `/api/chat`. */
  rest: string;
  message?: string;
}

export function classifyOllamaRoute(
  method: string,
  path: string,
  bodyLength: number,
  providers: ReadonlySet<string>,
): OllamaRoute | null {
  if (!path.startsWith(OLLAMA_ROUTE_PREFIX)) return null;
  const tail = path.slice(OLLAMA_ROUTE_PREFIX.length);
  const slash = tail.indexOf("/");
  const rawId = slash < 0 ? tail.split("?")[0]! : tail.slice(0, slash);
  let provider: string;
  try { provider = decodeURIComponent(rawId); } catch { provider = rawId; }
  const rest = slash < 0 ? "/" : tail.slice(slash);
  const p = pathOnly(rest);
  const m = method.toUpperCase();
  if (!providers.has(provider)) {
    return {
      kind: "refuse", provider, rest,
      message: `mandu: refusing ${m} for provider "${provider}": Mandu did not route that provider for this session, so nothing was sent.`,
    };
  }
  if (m === "POST" && p === "/api/chat") return { kind: "chat", provider, rest };
  if (m === "POST" && p === "/api/show") return { kind: "show", provider, rest };
  if ((m === "GET" || m === "HEAD") && bodyLength === 0) return { kind: "relay", provider, rest };
  return {
    kind: "refuse", provider, rest,
    message:
      `mandu: refusing ${m} ${p || "/"} for provider "${provider}": the Mandu model proxy masks tool results only on ` +
      "POST …/api/chat, so it does not send other requests to the model provider.",
  };
}
