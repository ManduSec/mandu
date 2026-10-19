/**
 * mapped-tools — which tools Mandu has a mapping for, and policy.yaml
 * `mapped_tools:`, the person's opt-in for the others (confidentiality plan
 * 10 §11.18; P0 item 4b, the maintainer's decision of 2026-10-07).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin).
 *
 * The rule: with the confidentiality axis on, a tool Mandu has no mapping for
 * (an MCP server's tool it cannot tie to a configured server, a plugin's
 * custom tool, a tool a new agent release added or renamed) has its result
 * masked WHOLE, one placeholder, whatever the session read: no check of
 * Mandu's can see what such a tool returns, so it fails closed. A tool HAS a
 * mapping when it is
 *   - one of Mandu's own (inspect, declassify, policy), in any agent's
 *     spelling;
 *   - named by the session's inbound spec (its built-ins), or one of its
 *     harness tools whose result is its own bookkeeping
 *     (HARNESS_MAPPED_TOOLS: Claude Code's `ToolSearch`, …);
 *   - named by the session's gate surface (tool-gate-surface.ts: a tool whose
 *     paths, command, host or patch Mandu reads, as Goose's `analyze`, left
 *     out of the spec on purpose so its input is scanned);
 *   - an MCP tool (`mcp__<server>__…`) of a server the launcher registered
 *     from the agent's config (§11.13; its own per-server rule applies);
 *   - listed under policy.yaml `mapped_tools:`.
 * Codex's built-ins have no inbound spec: the openai-proxy names them
 * (`CODEX_MAPPED_TOOLS`) and asks only about the others.
 *
 * `mapped_tools:` entries:
 *   - `<tool>`          a tool by the name the agent gives it
 *                       (`mcp__notes__search`, `notes_search`, `crm__lookup`);
 *   - `<prefix>*`       every tool whose name starts with the prefix;
 *   - `mcp:<server>`    every tool of that MCP server, in each agent's
 *                       spelling (`mcp__<server>__` for Claude Code and Codex,
 *                       `<server>_` for OpenCode, `<server>__` for Goose).
 * A listed tool is then treated as a tool Mandu knows: its result is not
 * masked for being unmapped (the input scan and every path, command and
 * session rule still apply). Only the person's own policy.yaml lists one:
 * the agent's policy tools cannot propose it (policy-edit.schema.json does
 * not carry the key), and the Mandu home is write-protected.
 */

import { isManduDeclassifyTool, isManduInspectTool } from "./inspect-tool.js";
import { isManduPolicyTool } from "./policy-tool.js";

/** Validate a `mapped_tools:` value; problems are pushed to `out`. Pure. */
export function checkMappedTools(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of tool names (a name, a name ending in '*', or 'mcp:<server>')`);
    return;
  }
  v.forEach((e, i) => {
    const where = `${at}[${i}]`;
    if (typeof e !== "string" || e.trim() === "") {
      out.push(`${where}: must be a tool name (a non-empty string)`);
      return;
    }
    if (e !== e.trim()) out.push(`${where}: has leading or trailing spaces`);
    if (e.startsWith("mcp:")) {
      const server = e.slice(4);
      if (server === "" || /[*\s]/.test(server)) out.push(`${where}: 'mcp:' needs one server name, as the agent's config names it (got ${JSON.stringify(e)})`);
      return;
    }
    const star = e.indexOf("*");
    if (star >= 0 && star !== e.length - 1) out.push(`${where}: '*' may only end a name (got ${JSON.stringify(e)})`);
    else if (e === "*") out.push(`${where}: '*' would let every tool Mandu has no mapping for through; name the tools or their prefix`);
  });
}

/** The well-formed entries of a `mapped_tools:` value (a loader that skipped
 *  the validator keeps only what the validator accepts). Pure. */
export function compileMappedTools(v: unknown): readonly string[] {
  if (!Array.isArray(v)) return Object.freeze([]);
  const probs: string[] = [];
  const out: string[] = [];
  v.forEach((e, i) => {
    const before = probs.length;
    checkMappedTools([e], `[${i}]`, probs);
    if (probs.length === before && typeof e === "string") out.push(e);
  });
  return Object.freeze(out);
}

/** The tool-name prefixes an MCP server's tools carry in each agent's
 *  spelling (Claude Code keeps `-`, Codex turns non-word characters into
 *  `_`; OpenCode `<server>_`, Goose `<server>__`). Pure. */
export function mcpServerToolPrefixes(server: string): string[] {
  const forms = [...new Set([server, server.replace(/[^A-Za-z0-9_-]/g, "_"), server.replace(/[^A-Za-z0-9_]/g, "_")])];
  return [...new Set([...forms.map((n) => `mcp__${n}__`), ...forms.map((n) => `${n}__`), ...forms.map((n) => `${n}_`)])];
}

/** Does one of `entries` (compiled `mapped_tools:`) name `tool`? Pure. */
export function policyMapsTool(tool: string, entries: readonly string[]): boolean {
  if (tool === "") return false;
  for (const e of entries) {
    if (e.startsWith("mcp:")) {
      if (mcpServerToolPrefixes(e.slice(4)).some((p) => tool.startsWith(p) && tool.length > p.length)) return true;
    } else if (e.endsWith("*")) {
      if (tool.startsWith(e.slice(0, -1))) return true;
    } else if (tool === e) {
      return true;
    }
  }
  return false;
}

/**
 * Harness tools an agent's inbound spec leaves out on purpose (their trust
 * is UNTRUSTED by omission) whose RESULT is the agent's own bookkeeping, so
 * they are mapped for this rule: Claude Code's `ToolSearch` and Goose's code
 * mode `list_functions` / `get_function_details` return the agent's tool
 * catalog (names, descriptions and schemas the model already reads in every
 * request's `tools[]`); OpenCode's `invalid` answers a malformed call with
 * its own error, and `plan_exit` with its own confirmation. Keyed by the
 * session's spec id. Pure data.
 */
export const HARNESS_MAPPED_TOOLS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "claude-code": Object.freeze(["ToolSearch"]),
  goose: Object.freeze(["list_functions", "get_function_details"]),
  opencode: Object.freeze(["invalid", "plan_exit"]),
});

/**
 * Tools an agent's tables leave WITHOUT a mapping on purpose: the result is
 * masked whole like any unmapped tool's (toolMapping answers null for them,
 * and policy.yaml `mapped_tools:` still lifts one), but the session-health
 * answer (`toolSurface`, the `tool_surface` event's unknown list) does not
 * report them as drift, since the decision is made. Keyed by the session's
 * spec id; tool → why. Pure data.
 *
 * Goose (2026-10-09): `extensionmanager__list_resources` and
 * `extensionmanager__read_resource` list and read the MCP resources of
 * whichever extension the MODEL names (`extension_name`). An extension's own
 * tools are masked whole until the person maps its server (`mcp:<server>`),
 * and its resources are the same server's data, so they stay masked the
 * same way. Claude Code's MCP resource tools are left unmapped for the same
 * reason (anthropic-proxy rewrite-request.ts secretTaintFor).
 */
export const MASKED_BY_DECISION: Readonly<Record<string, Readonly<Record<string, string>>>> = Object.freeze({
  goose: Object.freeze({
    extensionmanager__list_resources: "lists the MCP resources of the extension the model names, a server Mandu has no mapping for",
    extensionmanager__read_resource: "reads an MCP resource of the extension the model names, a server Mandu has no mapping for",
  }),
});

/** Is `tool` masked whole by decision for the spec `specId`
 *  (MASKED_BY_DECISION)? Pure. */
export function maskedByDecision(tool: string, specId: string): boolean {
  const t = MASKED_BY_DECISION[specId];
  return t !== undefined && Object.prototype.hasOwnProperty.call(t, tool);
}

/** Why a tool has a mapping, or null when it has none. */
export type ToolMapping = "own" | "spec" | "harness" | "surface" | "mcp-config" | "policy" | "builtin";

export interface ToolMappingDeps {
  /** The session's inbound spec names the tool (inboundSpecNamesInput). */
  specNames: (tool: string) => boolean;
  /** The session's spec id (HARNESS_MAPPED_TOOLS). */
  specId: string;
  /** The session's gate surface names the tool in any table. */
  surfaceNames: (tool: string) => boolean;
  /** An `mcp__` tool of a server the launcher registered for the session. */
  registeredMcp: (tool: string) => boolean;
  /** Compiled policy.yaml `mapped_tools:`. */
  mappedTools: readonly string[];
  /** The session runs under the file guard: a launch on the attested human
   *  plane claimed it `confined` (GUARD_MAPPED_TOOLS). Absent = false. */
  guarded?: boolean;
}

/**
 * Tools mapped ONLY in a session the file guard confines (2026-10-09):
 * they read a file the model names by a NAME, not a path, in the agent's
 * own process, so no model-context gate can see which file it is. What keeps
 * a labelled file's bytes from the model is the guard, which hands the
 * agent's own open the file's twin (rootless-confinement-ubuntu-2404.md
 * §0.1). Without it (posture `gated`, a launch the arbiter has no attested
 * record of, no session key) the tool has no mapping and its result is
 * masked whole, whatever its spec entry says, and policy.yaml
 * `mapped_tools:` does not lift it: fail-closed. Keyed by spec id;
 * tool → why. Pure data.
 *
 * Goose: `load` (a recipe's or agent's body, a background task's result)
 * and `load_skill` (a skill, or a supporting file of it by
 * `<skill>/<file>`; probed on 1.53.0 and 1.54.0: a supporting `creds.env`
 * comes back verbatim).
 */
export const GUARD_MAPPED_TOOLS: Readonly<Record<string, Readonly<Record<string, string>>>> = Object.freeze({
  goose: Object.freeze({
    load: "reads a recipe, an agent or a background task's result by name in Goose's own process",
    load_skill: "reads a skill or a file of it by name in Goose's own process",
  }),
});

/** Is `tool` mapped only under the guard for the spec `specId`? Pure. */
export function requiresGuard(tool: string, specId: string): boolean {
  const t = GUARD_MAPPED_TOOLS[specId];
  return t !== undefined && Object.prototype.hasOwnProperty.call(t, tool);
}

/** The note a guard-only tool's masked result carries. Product copy. */
export function unguardedToolWhy(tool: string): string {
  return `${tool} reads a file by name inside the AI agent, where Mandu cannot see which file it is, and this session runs without Mandu's file guard, so its whole result is hidden from the AI: it may carry a secret file's contents. Run it where the guard is on (\`mandu doctor\` shows the posture; \`mandu setup\` fixes most hosts)`;
}

/** Has Mandu a mapping for `tool`? The order is the order of the header's
 *  list; the first that holds is the answer. Pure over `deps`. */
export function toolMapping(tool: string, deps: ToolMappingDeps): ToolMapping | null {
  if (isManduInspectTool(tool) || isManduDeclassifyTool(tool) || isManduPolicyTool(tool)) return "own";
  if (requiresGuard(tool, deps.specId) && deps.guarded !== true) return null;
  if (deps.specNames(tool)) return "spec";
  if ((HARNESS_MAPPED_TOOLS[deps.specId] ?? []).includes(tool)) return "harness";
  if (deps.surfaceNames(tool)) return "surface";
  if (tool.startsWith("mcp__") && deps.registeredMcp(tool)) return "mcp-config";
  if (policyMapsTool(tool, deps.mappedTools)) return "policy";
  return null;
}

/** The note a masked result carries: why it is hidden and how to let it
 *  through. Product copy (the model reads it, the dashboard shows it). */
export function unmappedToolWhy(tool: string): string {
  const mcp = /^mcp__([^_].*?)__/.exec(tool)?.[1];
  const how = mcp !== undefined
    ? `list \`${tool}\` (or \`mcp:${mcp}\` for every tool of that MCP server) under \`mapped_tools:\` in policy.yaml`
    : `list \`${tool}\` under \`mapped_tools:\` in policy.yaml (\`mcp:<server>\` covers every tool of an MCP server)`;
  return `Mandu has no mapping for the tool ${tool}, so its whole result is hidden from the AI: it may carry a secret no check of Mandu's can see. To let it through, ${how}`;
}
