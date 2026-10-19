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
  if (m === "POST" && op === "/responses") return { kind: "responses", provider, rest };
  if ((m === "GET" || m === "HEAD") && bodyLength === 0) return { kind: "relay", provider, rest };
  return {
    kind: "refuse", provider, rest,
    message:
      `mandu: refusing ${m} ${p || "/"} for provider "${provider}": the Mandu model proxy masks tool results only on ` +
      "POST …/chat/completions and POST …/responses, so it does not send other requests to the model provider.",
  };
}
