/**
 * openclaw-api — MINIMAL structural types for the OpenClaw plugin surface this
 * package touches.
 *
 * Mandu U-LLM channel for OpenClaw (interceptors/openclaw-inspect-plugin).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE
 *   Declared structurally against
 *     OpenClaw source, src/plugins/types.ts
 *       (`OpenClawPluginApi` — id/pluginConfig/logger/registerTool;
 *        `OpenClawPluginToolContext`; `OpenClawPluginToolOptions`)
 *     OpenClaw dependency @mariozechner/pi-agent-core,
 *       dist/types.d.ts (`AgentTool` / `AgentToolResult` — the
 *        name/label/description/parameters/execute tool shape the reference
 *        plugin builds in
 *        adfi-openclaw/plugin/dualview/dualview-inspect-symbol.ts and casts
 *        `as AnyAgentTool`).
 *   The reference imports `type { OpenClawPluginApi, AnyAgentTool } from
 *   "openclaw/plugin-sdk/core"`; this package deliberately does NOT — that
 *   import only resolves with openclaw installed as a dependency, and pulling
 *   the whole OpenClaw package in as a dep of a Mandu interceptor would be
 *   a heavyweight coupling for four structural fields. TypeScript's structural
 *   typing makes the narrow local declaration equivalent at the seam: the real
 *   api object satisfies these interfaces, and the loader consumes our tool
 *   object by shape, not by class.
 * ─────────────────────────────────────────────────────────────────────────────
 */

/** OpenClaw's plugin logger (subset — the four levels every impl carries). */
export interface PluginLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  debug?(message: string): void;
}

/** The per-resolution context OpenClaw hands a registered tool FACTORY
 * (openclaw-src/src/plugins/types.ts OpenClawPluginToolContext, subset). */
export interface PluginToolContext {
  sessionKey?: string;
  sessionId?: string;
  workspaceDir?: string;
  agentId?: string;
}

/** One text content block of a tool result (pi-agent-core TextContent). */
export interface PluginToolTextBlock {
  type: "text";
  text: string;
}

/** A tool result (pi-agent-core AgentToolResult, text-only subset). `details`
 * is UI/transcript metadata — it does not reach the model context. */
export interface PluginToolResult {
  content: PluginToolTextBlock[];
  details?: unknown;
}

/** The tool object api.registerTool consumes (pi-agent-core AgentTool shape;
 * the reference builds exactly this and casts `as AnyAgentTool`). */
export interface PluginAgentTool {
  name: string;
  label: string;
  description: string;
  /** Tool Search placement (OpenClaw 2026.9.x, src/agents/tool-search.ts
   *  `shouldCatalogTool`): `"direct-only"` keeps the tool model-visible by its
   *  own name instead of cataloging it behind `tool_search` / `tool_call`,
   *  which 2026.9.x does to every other plugin tool by default. Releases
   *  without Tool Search ignore the field. */
  catalogMode?: "direct-only";
  /** JSON-schema parameters object ({type:"object", required, properties}). */
  parameters: {
    type: "object";
    required?: readonly string[];
    additionalProperties?: boolean;
    properties: Record<string, unknown>;
  };
  execute(
    toolCallId: string,
    params: Record<string, unknown> | undefined,
    signal?: unknown,
    onUpdate?: unknown,
  ): Promise<PluginToolResult>;
}

/** A tool factory, invoked per session/tool resolution with the context. */
export type PluginToolFactory = (
  ctx: PluginToolContext,
) => PluginAgentTool | PluginAgentTool[] | null | undefined;

/** registerTool options (openclaw-src/src/plugins/types.ts
 * OpenClawPluginToolOptions). NOTE the load-bearing gotcha: `optional: true`
 * tools are FILTERED OUT unless the run's effective tool allowlist names them
 * (openclaw-src/src/plugins/tools.ts isOptionalToolAllowed) — under the
 * harness's `tools.profile` config an optional registration silently drops
 * the tool. This plugin therefore never passes options at all. */
export interface PluginToolOptions {
  name?: string;
  names?: string[];
  optional?: boolean;
}

/** The narrow slice of OpenClawPluginApi this plugin depends on. The real api
 * object (openclaw-src/src/plugins/loader.ts createApi) satisfies it
 * structurally; tests drive the registrar with a fake. */
export interface OpenClawPluginApiLike {
  id: string;
  /** The plugin's own config (plugins.entries.<id>.config), already
   * JSON-schema-validated by the loader BEFORE register() runs. */
  pluginConfig?: Record<string, unknown>;
  logger: PluginLogger;
  registerTool(
    tool: PluginAgentTool | PluginToolFactory,
    opts?: PluginToolOptions,
  ): void;
}
