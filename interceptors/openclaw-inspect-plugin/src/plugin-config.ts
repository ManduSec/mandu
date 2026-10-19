/**
 * plugin-config — resolve the plugin's validated config + env fallbacks into
 * the deps wiring needs. PURE (no I/O), fail-loud.
 *
 * Mandu U-LLM channel for OpenClaw (interceptors/openclaw-inspect-plugin).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE
 *   Mirrors launcher/src/services/mcp.ts `inspectMcpConfigDoc` — the single
 *   source of truth for what the inspect channel is configured WITH (arbiter
 *   socket, scope id, U-LLM mode/binary/model/base-url/forwarder/key) — and
 *   interceptors/inspect-mcp/src/server-main.ts's env contract. What changed
 *   in the lift: the values arrive through OpenClaw's validated plugin config
 *   (plugins.entries.mandu-inspect.config) first, with env-var fallbacks,
 *   because an OpenClaw plugin has no launcher-curated private env of its own.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * THE TWO DELIBERATE ENV DIVERGENCES from server-main (SECURITY-relevant):
 * the MCP server runs in its OWN process whose env the launcher curates
 * per-server (.mcp.json `env`), so there ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY
 * genuinely describe the U-LLM channel. This plugin runs INSIDE the OpenClaw
 * gateway process, where — in a Mandu-wrapped run — ANTHROPIC_BASE_URL is
 * the INSTRUMENTED anthropic-proxy and ANTHROPIC_API_KEY is the T-LLM path's
 * credential (the live harness sets a dummy). Falling back to either would at
 * best trip the loopback guard and at worst mis-route or mis-bill the
 * quarantine. So the plugin reads ONLY the dedicated names:
 *   base url  ← config.ullmBaseUrl  ?? env MANDU_ULLM_BASE_URL
 *   api key   ← config.ullmApiKey   ?? env MANDU_ULLM_API_KEY
 * and NEVER the host process's ANTHROPIC_* pair. (The cli-mode child still
 * inherits the host env, and inspect-mcp's CliUllmClient.buildChildEnv already
 * strips ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN there —
 * that enforcement stays on the path unchanged, as does
 * assertNonProxyBaseUrl inside selectUllmConfig.)
 */

import type { UllmEnv } from "../../inspect-mcp/src/ullm-config.js";

/** What the registrar needs, resolved from pluginConfig + env. */
export interface ResolvedPluginConfig {
  /** The arbiter Unix socket path. Present or resolvePluginConfig threw. */
  arbiterSock: string;
  /** Session/scope key for symbolize + events; undefined → per-session
   * fallback (the OpenClaw sessionKey) at tool-resolution time. */
  scopeId?: string;
  /** The env slice for inspect-mcp's selectUllmConfig (ullm-config.ts). The
   * ANTHROPIC_* keys in this SLICE are the U-LLM channel's own values mapped
   * from the dedicated config/env names above — never the host process's. */
  ullmEnv: UllmEnv;
}

/** Read one optional string key from the (already JSON-schema-validated)
 * plugin config; non-strings and empty strings read as absent. */
function cfgString(cfg: Record<string, unknown> | undefined, key: string): string | undefined {
  const v = cfg?.[key];
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined;
}

/** Read one env var; empty reads as absent. */
function envString(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const v = env[key];
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined;
}

/**
 * Resolve the plugin config. FAIL-LOUD: a missing arbiter socket throws (the
 * loader surfaces it as a plugin load error) — the plugin must never register
 * a tool that would silently run with no arbiter, because without the arbiter
 * there is no symbol table and no re-symbolization.
 */
export function resolvePluginConfig(
  pluginConfig: Record<string, unknown> | undefined,
  env: NodeJS.ProcessEnv,
): ResolvedPluginConfig {
  const arbiterSock =
    cfgString(pluginConfig, "arbiterSock") ?? envString(env, "MANDU_ARBITER_SOCK");
  if (!arbiterSock) {
    throw new Error(
      "mandu-inspect: no arbiter socket configured — set plugins.entries.mandu-inspect.config.arbiterSock " +
        "or env MANDU_ARBITER_SOCK. Refusing to register inspect_symbol without an arbiter (fail closed).",
    );
  }

  const scopeId = cfgString(pluginConfig, "scopeId") ?? envString(env, "MANDU_SCOPE_ID");

  const ullmEnv: UllmEnv = {
    MANDU_ULLM_MODE:
      cfgString(pluginConfig, "ullmMode") ?? envString(env, "MANDU_ULLM_MODE"),
    MANDU_ULLM_BINARY:
      cfgString(pluginConfig, "ullmBinary") ?? envString(env, "MANDU_ULLM_BINARY"),
    MANDU_ULLM_MODEL:
      cfgString(pluginConfig, "ullmModel") ?? envString(env, "MANDU_ULLM_MODEL"),
    // DEDICATED names only — see the header. The host's ANTHROPIC_BASE_URL /
    // ANTHROPIC_API_KEY (proxy + T-LLM credential in a wrapped run) must not
    // leak into the quarantined channel's selection.
    ANTHROPIC_BASE_URL:
      cfgString(pluginConfig, "ullmBaseUrl") ?? envString(env, "MANDU_ULLM_BASE_URL"),
    ANTHROPIC_API_KEY:
      cfgString(pluginConfig, "ullmApiKey") ?? envString(env, "MANDU_ULLM_API_KEY"),
    MANDU_ULLM_FORWARDER:
      cfgString(pluginConfig, "ullmForwarder") ?? envString(env, "MANDU_ULLM_FORWARDER"),
  };

  return { arbiterSock, scopeId, ullmEnv };
}
