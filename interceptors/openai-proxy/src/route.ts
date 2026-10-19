/**
 * route — which requests the Responses-API proxy may send upstream
 * (docs/design/architecture/mandu.md §4.1, "Which requests go upstream").
 *
 * The proxy symbolizes the Responses wire only. Until 2026-09-27 every other
 * request was relayed raw, so an agent that spoke Chat Completions, legacy
 * Completions or `…/responses/compact` through the routed base URL reached the
 * model with its tool outputs unmasked (the sibling of the anthropic-proxy
 * gap found by the fresh-agents VM suite, os-test-matrix.md §10.14.1).
 *
 * The rule is fail-closed. A request is sent upstream only when the proxy can
 * vouch for what it carries:
 *   - `responses`: POST …/responses, symbolized (rewrite-request.ts). Codex
 *     0.154 sends every turn here, its compaction included (probe-verified
 *     2026-09-27 under both a custom provider name and "OpenAI");
 *   - `chat`: POST …/chat/completions, read as the Responses request it
 *     carries and symbolized the same way (chat-wire.ts, 2026-09-29): the wire
 *     of Kimi Code, Aider, the OpenHands CLI, nanobot and most local models;
 *   - `relay`: a bodyless GET or HEAD (the `/models` listing). A read with no
 *     body cannot put conversation content in front of the model;
 *   - `refuse`: everything else, answered locally (403) and never sent. This
 *     covers `/responses/compact` (older Codex compaction), `/responses/
 *     input_tokens`, `/completions`, `/embeddings`,
 *     `/files`, `/realtime/calls`.
 */

export type RouteKind = "responses" | "chat" | "relay" | "refuse";

export interface Route {
  kind: RouteKind;
  /** For `refuse`: the message the agent surfaces (names mandu and the path). */
  message?: string;
}

function pathOnly(path: string): string {
  return (path.split("?")[0] ?? "").replace(/\/+$/, "");
}

/**
 * The Responses API endpoint we must transform. Codex POSTs to
 * `{base_url}/responses`; any path whose final segment is `responses` matches
 * (tolerant of base-url path prefixes). `…/responses/compact` does NOT match.
 */
export function isResponsesPath(path: string): boolean {
  const p = pathOnly(path);
  return p === "/responses" || p.endsWith("/responses");
}

/** The Chat Completions endpoint: any path whose last two segments are
 *  `chat/completions` (tolerant of base-url path prefixes). */
export function isChatCompletionsPath(path: string): boolean {
  const p = pathOnly(path);
  return p === "/chat/completions" || p.endsWith("/chat/completions");
}

/**
 * Classify one request. `bodyLength` is the buffered request body's size: a
 * GET or HEAD that carries a body is not a plain read and is refused.
 */
export function classifyRoute(method: string, path: string, bodyLength: number): Route {
  const m = method.toUpperCase();
  if (m === "POST" && isResponsesPath(path)) return { kind: "responses" };
  if (m === "POST" && isChatCompletionsPath(path)) return { kind: "chat" };
  if ((m === "GET" || m === "HEAD") && bodyLength === 0) return { kind: "relay" };
  return {
    kind: "refuse",
    message:
      `mandu: refusing ${m} ${pathOnly(path) || "/"}: the Mandu model proxy masks tool output only on ` +
      "POST /v1/responses and POST /v1/chat/completions, so it does not send other requests to the model " +
      "provider. Use the Responses API (Codex: wire_api = \"responses\") or Chat Completions.",
  };
}
