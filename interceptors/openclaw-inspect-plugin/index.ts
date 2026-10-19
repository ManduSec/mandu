/**
 * index — the OpenClaw plugin entry (module export the loader consumes).
 *
 * Mandu U-LLM channel for OpenClaw (interceptors/openclaw-inspect-plugin).
 * OpenClaw has NO MCP client, so the inspect-mcp stdio server cannot mount for
 * it; this plugin registers the SAME inspect_symbol and declassify_symbol
 * surface as native OpenClaw plugin tools instead
 * (docs/design/testing/agent-e2e-harness.md §8, §8.5). The
 * security core is interceptors/inspect-mcp/src/inspect-symbol.ts, reused —
 * see src/inspect-tool.ts and src/register.ts for the seam-by-seam provenance.
 *
 * PROVENANCE: the module/manifest FORMAT (default-exported definition object
 * with a `register(api)`, package.json `main` + `openclaw.extensions`,
 * openclaw.plugin.json with id + configSchema) mirrors the reference plugin
 *   https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/index.ts
 * and is what openclaw-src/src/plugins/loader.ts `resolvePluginModuleExport`
 * unwraps. LOAD-BEARING: register() must be SYNCHRONOUS — the loader ignores
 * a returned promise (warn only) — and a throw here fails the plugin load
 * loudly, which is this plugin's fail-closed misconfiguration behavior.
 */

import { registerInspectPlugin } from "./src/register.js";
import type { OpenClawPluginApiLike } from "./src/openclaw-api.js";

const definition = {
  // Must match openclaw.plugin.json `id` (the manifest is authoritative for
  // the loader; this field is informational on the module side).
  id: "mandu-inspect",
  name: "Mandu inspect_symbol (U-LLM quarantine channel)",
  description:
    "Process the untrusted data behind an opaque $MDU:* symbol in a quarantined " +
    "model call and return the result re-symbolized — raw untrusted text never " +
    "enters the privileged model's context.",
  register(api: OpenClawPluginApiLike): void {
    registerInspectPlugin(api);
  },
};

export default definition;

// Re-exported for tests and for any embedding caller that wants the seams.
export { registerInspectPlugin, type RegisterOptions } from "./src/register.js";
export { createDeclassifySymbolPluginTool, DECLASSIFY_TOOL_NAME } from "./src/declassify-tool.js";
export {
  createInspectSymbolPluginTool,
  buildInspectToolResult,
  INSPECT_TOOL_NAME,
} from "./src/inspect-tool.js";
export { resolvePluginConfig } from "./src/plugin-config.js";
