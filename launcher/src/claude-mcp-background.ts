/**
 * claude-mcp-background — Claude Code's MCP auto-background window, widened
 * for a session with the user's own model (model-endpoints.md §1.9).
 *
 * Claude Code (2.1.295, the CI pin, and 2.1.302 read the same way) moves an
 * MCP tool call that is still running after 120 s to the background in an
 * interactive session: the model gets "MCP tool … is still running after
 * 120s. It was moved to the background as task …" as the tool result, and
 * typically ends its turn saying the answer is still coming. `inspect_symbol`
 * at a local model on a CPU takes about that long (the second live demo
 * battery, 2026-10-17: 89 s, 102 s, and over 120 s in the take that failed).
 * The window is the environment variable `CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS`
 * (milliseconds; 0 turns the auto-background off), measured on both versions
 * with a slow stand-in MCP tool.
 *
 * When the session declares a `local: true` model (policy.yaml `models:`),
 * the launcher sets the window above the longest an `inspect_symbol` call can
 * wait for that model (ullm-timeout.ts `inspectCallBoundMs`: twice the
 * per-call endpoint timeout the launch gives inspect-mcp, plus a margin). A
 * value the user set stands, larger or smaller: the launcher only fills an
 * unset variable. Claude Code also applies a settings file's `env` block
 * over its environment, so a value set there wins as well.
 *
 * Utility only: the window decides whether the answer reaches the model in
 * the same turn or as a later task notification. Nothing about what the
 * model may read changes. Pure; unit-tested.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import type { ModelEndpoint } from "./model-endpoints.js";
import { effectiveUllmEndpointTimeoutMs, entryUllmEndpointTimeoutMs, inspectCallBoundMs } from "./ullm-timeout.js";

/** Claude Code's MCP auto-background window (milliseconds). */
export const CLAUDE_MCP_AUTO_BACKGROUND_ENV = "CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS";

/**
 * The window to set for this launch, or null to set none: a Claude Code
 * launch whose `models:` declare a `local: true` endpoint and whose
 * environment does not set the variable already (an empty value counts as
 * unset, which is how Claude Code reads it).
 */
export function claudeMcpAutoBackgroundMs(o: {
  target: string;
  endpoints: readonly Pick<ModelEndpoint, "local">[] | undefined;
  env: Record<string, string | undefined>;
}): number | null {
  if (o.target !== "claude") return null;
  if (!(o.endpoints ?? []).some((e) => e.local)) return null;
  const own = o.env[CLAUDE_MCP_AUTO_BACKGROUND_ENV];
  if (own !== undefined && own.trim() !== "") return null;
  return inspectCallBoundMs(effectiveUllmEndpointTimeoutMs(entryUllmEndpointTimeoutMs(o.env, o.endpoints)));
}

/** The launch note for a window the launcher set. */
export function autoBackgroundNote(ms: number): string {
  return (
    `mandu: Claude Code waits up to ${Math.round(ms / 1000)} s for inspect_symbol before moving it to the background ` +
    `(${CLAUDE_MCP_AUTO_BACKGROUND_ENV}=${ms}): your own model can be slow, and its answer then still arrives in the same turn`
  );
}
