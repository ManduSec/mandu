/**
 * ullm-timeout — how long `inspect_symbol` may wait for a declared model, and
 * the agent-side MCP timeouts derived from it (model-endpoints.md §1.9).
 *
 * inspect-mcp bounds each call to a declared endpoint by
 * `MANDU_ULLM_ENDPOINT_TIMEOUT_MS` (a positive integer of milliseconds, at
 * most ten minutes), else 60 s (interceptors/inspect-mcp/src/ullm-config.ts
 * `endpointTimeoutMs`). The live demo runs of 2026-10-17 found three ways a
 * local model on a CPU lost its answer:
 *
 *   - Codex hands a stdio MCP server only the env in its entry, so a
 *     user's `MANDU_ULLM_ENDPOINT_TIMEOUT_MS` never reached inspect-mcp
 *     ("U-LLM request timed out after 60000ms");
 *   - the agent's own MCP call timeout cut the call first (OpenCode's 30 s,
 *     "MCP error -32001: Request timed out"; Codex's `tool_timeout_sec`,
 *     60 s by default);
 *   - Claude Code moved a call past 120 s to the background
 *     (claude-mcp-background.ts).
 *
 * So the launcher decides one endpoint timeout per launch: the user's valid
 * value, else, when `models:` declare a `local: true` endpoint, a local
 * default that covers a cold load on a CPU (about 200 s measured for a 32B
 * model), else none (inspect-mcp's 60 s). It writes that value into the
 * inspect-mcp entry every agent receives, and derives each agent's own MCP
 * call timeout from the longest one `inspect_symbol` call can take.
 *
 * Utility only: a timeout is a refusal like any other failure (the call never
 * moves to another model), so a longer one only waits longer. Pure;
 * unit-tested.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import type { ModelEndpoint } from "./model-endpoints.js";

/** The variable inspect-mcp reads. */
export const ULLM_ENDPOINT_TIMEOUT_ENV = "MANDU_ULLM_ENDPOINT_TIMEOUT_MS";

/** inspect-mcp's own per-call default (its client's 60 s). */
export const ULLM_ENDPOINT_DEFAULT_TIMEOUT_MS = 60_000;

/** The per-call default when a `local: true` model is declared: a cold
 *  32B load on a CPU took about 200 s (the blood-test demo, 2026-10-17),
 *  with margin for a warm call (21 to 82 s on the same CPU). */
export const LOCAL_ULLM_ENDPOINT_TIMEOUT_MS = 240_000;

/** inspect-mcp's ceiling for the variable (ten minutes). */
export const ULLM_ENDPOINT_MAX_TIMEOUT_MS = 600_000;

/** The margin over the model waits: the arbiter round trips, the
 *  re-symbolization and the MCP framing around them. */
export const INSPECT_CALL_MARGIN_MS = 60_000;

/** The sequential model waits one `inspect_symbol` call can make: the
 *  summary, then at most one retry call (inspect-symbol.ts, step 2c). The
 *  triage runs beside the summary, and not at all at a `local: true`
 *  endpoint (model-endpoints.md §1.8 item 1), so this bound is generous. */
export const INSPECT_SEQUENTIAL_CALLS = 2;

/** The user's own value, read with inspect-mcp's rule; undefined when unset
 *  or invalid (inspect-mcp then ignores it too). */
export function userUllmEndpointTimeoutMs(env: Record<string, string | undefined>): number | undefined {
  const raw = (env[ULLM_ENDPOINT_TIMEOUT_ENV] ?? "").trim();
  if (!/^[1-9][0-9]{0,6}$/.test(raw)) return undefined;
  const ms = Number(raw);
  return ms <= ULLM_ENDPOINT_MAX_TIMEOUT_MS ? ms : undefined;
}

/** Does the launch declare the user's own model? */
export function declaresLocalModel(endpoints: readonly Pick<ModelEndpoint, "local">[] | undefined): boolean {
  return (endpoints ?? []).some((e) => e.local);
}

/**
 * The value the launcher writes into the inspect-mcp entry, or undefined to
 * write none (inspect-mcp's 60 s, the entry as before): the user's valid
 * value, else the local default when a `local: true` model is declared.
 */
export function entryUllmEndpointTimeoutMs(
  env: Record<string, string | undefined>,
  endpoints: readonly Pick<ModelEndpoint, "local">[] | undefined,
): number | undefined {
  return userUllmEndpointTimeoutMs(env) ?? (declaresLocalModel(endpoints) ? LOCAL_ULLM_ENDPOINT_TIMEOUT_MS : undefined);
}

/** The per-call timeout inspect-mcp will apply: the entry's value, else its
 *  own default. */
export function effectiveUllmEndpointTimeoutMs(entryMs: number | undefined): number {
  return entryMs ?? ULLM_ENDPOINT_DEFAULT_TIMEOUT_MS;
}

/** The longest one `inspect_symbol` call can take with that per-call
 *  timeout: the agent's own MCP call timeout must be at least this. */
export function inspectCallBoundMs(endpointTimeoutMs: number): number {
  return INSPECT_SEQUENTIAL_CALLS * endpointTimeoutMs + INSPECT_CALL_MARGIN_MS;
}
